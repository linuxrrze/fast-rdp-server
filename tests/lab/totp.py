#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (prints a valid second factor for a lab user; never point it at a real
# account's secret). For automated lab runs: the orchestrator types the code into the
# waiting screen's code field ([mfa] mode code_or_web, Keycloak OTP).
#
# RFC 6238 TOTP (RFC 4226 HOTP with a time counter), standard library only. Also the TOTP
# of tests/keycloak/kc_fixture.py, which imports totp() from here.
#
# Usage:
#   tests/lab/totp.py [--secret-file FILE|-] [--secret-env VAR] [--raw]
#                     [--algorithm SHA1|SHA256|SHA512] [--digits N] [--period S]
#                     [--min-left S] [--state FILE] [--no-wait] [--seconds-left]
# The secret is never taken from argv (it would show in ps):
#   --secret-file FILE  first non-empty line of FILE; "-" = stdin (also the default when
#                       neither option is given and stdin is not a terminal)
#   --secret-env VAR    environment variable VAR
# Accepted forms: base32 as Keycloak shows it (any case, spaces, with or without "="),
# or an otpauth://totp/...?secret=...&algorithm=...&digits=...&period=... URI (its
# parameters apply unless the options below are given). --raw: the secret is the raw HMAC
# key text as Keycloak stores it (credential secretData "value" in a realm export).
# Defaults are Keycloak's realm defaults (otpPolicyAlgorithm HmacSHA1, otpPolicyDigits 6,
# otpPolicyPeriod 30); "HmacSHA256" style names are accepted too.
#   --min-left S     if fewer than S seconds are left in the step, wait for the next one
#                    (so a code never expires while it is being typed)
#   --state FILE     remembers the last step handed out (flock'ed, mode 0600) and never
#                    hands it out again: with otpPolicyCodeReusable false a second login
#                    in the same step needs the next code, so this waits for it
#   --no-wait        instead of waiting: exit 75 with the seconds to wait on stderr
#   --seconds-left   second output line: whole seconds left in the printed code's step
# Output: the code (and the seconds-left line) on stdout, nothing else. Errors go to
# stderr and never contain the secret. Exit: 0 ok, 2 usage/secret error, 75 must wait.
"""LAB ONLY: print an RFC 6238 TOTP code for a lab user's secret (see header)."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import math
import os
import struct
import sys
import time
import urllib.parse
from typing import Callable

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
EX_TEMPFAIL = 75


class SecretError(ValueError):
    """A secret or option that cannot be used; the message never contains the secret."""


def algorithm(name: str) -> str:
    """Normalise SHA1, sha-256, HmacSHA512 (Keycloak's otpPolicyAlgorithm) ..."""
    n = name.strip().upper().replace("-", "")
    if n.startswith("HMAC"):
        n = n[4:]
    if n not in ALGORITHMS:
        raise SecretError(f"unsupported algorithm {name!r} (SHA1, SHA256, SHA512)")
    return n


def hotp(key: bytes, counter: int, digits: int = 6, alg: str = "SHA1") -> str:
    """RFC 4226 HOTP with dynamic truncation; RFC 6238 allows SHA256 and SHA512 too."""
    mac = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm(alg)]).digest()
    off = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return f"{value % 10 ** digits:0{digits}d}"


def counter_at(at: float, period: int = 30) -> int:
    return int(at // period)


def totp(key: bytes, at: float | None = None, period: int = 30, digits: int = 6,
         alg: str = "SHA1") -> str:
    """RFC 6238 TOTP of the raw key at Unix time at (now if None), T0 = 0."""
    return hotp(key, counter_at(time.time() if at is None else at, period), digits, alg)


def b32decode(text: str) -> bytes:
    s = "".join(text.split()).replace("-", "").upper().rstrip("=")
    if not s:
        raise SecretError("empty secret")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        raise SecretError("secret is not valid base32 (use --raw for a raw key)") from None


def parse_secret(text: str, raw: bool = False) -> tuple[bytes, dict]:
    """Key bytes and the otpauth URI's parameters (algorithm, digits, period) if any."""
    text = text.strip()
    if not text:
        raise SecretError("empty secret")
    if raw:
        return text.encode(), {}
    if not text.lower().startswith("otpauth://"):
        return b32decode(text), {}
    u = urllib.parse.urlsplit(text)
    if u.netloc.lower() != "totp":
        raise SecretError(f"otpauth URI of type {u.netloc!r}, need totp")
    q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query)}
    if "secret" not in q:
        raise SecretError("otpauth URI without secret")
    params: dict = {}
    try:
        if "algorithm" in q:
            params["algorithm"] = algorithm(q["algorithm"])
        if "digits" in q:
            params["digits"] = int(q["digits"])
        if "period" in q:
            params["period"] = int(q["period"])
    except ValueError:
        raise SecretError("otpauth URI with a non-numeric digits or period") from None
    return b32decode(q["secret"]), params


def plan(now: float, period: int, min_left: float, last_used: int | None) -> int:
    """The first step that is not used yet and has at least min_left seconds left."""
    c = counter_at(now, period)
    if last_used is not None and c <= last_used:
        c = last_used + 1
    if (c + 1) * period - max(now, c * period) < min_left:
        c += 1
    return c


class StateFile:
    """The last step handed out, one integer, locked against parallel runs."""

    def __init__(self, path: str):
        import fcntl
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    def read(self) -> int | None:
        os.lseek(self.fd, 0, os.SEEK_SET)
        data = os.read(self.fd, 64).decode(errors="replace").strip()
        try:
            return int(data) if data else None
        except ValueError:
            raise SecretError("state file does not hold a step number") from None

    def write(self, counter: int) -> None:
        os.ftruncate(self.fd, 0)
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.write(self.fd, f"{counter}\n".encode())
        os.fsync(self.fd)

    def close(self) -> None:
        os.close(self.fd)  # releases the lock


def read_secret(args, stdin=None, environ=None) -> str:
    stdin = sys.stdin if stdin is None else stdin
    environ = os.environ if environ is None else environ
    if args.secret_file and args.secret_env:
        raise SecretError("give either --secret-file or --secret-env")
    if args.secret_env:
        if not environ.get(args.secret_env):
            raise SecretError(f"environment variable {args.secret_env} is empty or unset")
        return environ[args.secret_env]
    if args.secret_file in (None, "-"):
        if args.secret_file is None and stdin.isatty():
            raise SecretError("no secret: use --secret-file FILE|- or --secret-env VAR")
        lines = stdin.read().splitlines()
    else:
        try:
            with open(args.secret_file, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            raise SecretError(f"cannot read {args.secret_file}: {e.strerror}") from None
    for line in lines:
        if line.strip():
            return line
    raise SecretError("empty secret")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="totp.py", allow_abbrev=False,
        description="LAB ONLY: print an RFC 6238 TOTP code. The secret comes from a file, "
        "stdin or an environment variable, never from argv.")
    p.add_argument("--secret-file", metavar="FILE|-")
    p.add_argument("--secret-env", metavar="VAR")
    p.add_argument("--raw", action="store_true", help="secret is the raw key text (Keycloak secretData)")
    p.add_argument("--algorithm", help="SHA1 (default), SHA256, SHA512; HmacSHA1 etc. too")
    p.add_argument("--digits", type=int)
    p.add_argument("--period", type=int)
    p.add_argument("--min-left", type=float, default=0, metavar="S")
    p.add_argument("--state", metavar="FILE")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--seconds-left", action="store_true")
    return p


def run(argv: list[str], out=None, err=None, stdin=None, environ=None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep) -> int:
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    args = parser().parse_args(argv)
    state = None
    try:
        key, params = parse_secret(read_secret(args, stdin, environ), args.raw)
        alg = algorithm(args.algorithm) if args.algorithm else params.get("algorithm", "SHA1")
        digits = args.digits if args.digits is not None else params.get("digits", 6)
        period = args.period if args.period is not None else params.get("period", 30)
        if not 6 <= digits <= 10:
            raise SecretError("digits must be 6..10")
        if period < 1 or not 0 <= args.min_left < period:
            raise SecretError("need period >= 1 and 0 <= --min-left < period")
        if args.state:
            try:
                state = StateFile(args.state)
            except OSError as e:
                raise SecretError(f"cannot open state file: {e.strerror}") from None
        last = state.read() if state else None
        now = clock()
        c = plan(now, period, args.min_left, last)
        wait = c * period - now
        if wait > 0:
            if args.no_wait:
                print(f"totp: wait {math.ceil(wait)} s for a fresh step", file=err)
                return EX_TEMPFAIL
            sleep(wait)
        code = hotp(key, c, digits, alg)
        if state:
            state.write(c)
        out.write(code + "\n")
        if args.seconds_left:
            out.write(f"{int((c + 1) * period - max(clock(), c * period))}\n")
        out.flush()
        return 0
    except SecretError as e:
        print(f"totp: {e}", file=err)
        return 2
    finally:
        if state:
            state.close()


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
