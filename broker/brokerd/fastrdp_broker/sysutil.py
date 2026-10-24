# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Subprocess, systemd and filesystem helpers."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass

from . import netcheck
from .identity import LocalUser

log = logging.getLogger(__name__)


class CommandError(Exception):
    pass


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str


async def run(*argv: str, input: str | None = None, timeout: float = 30, check: bool = True) -> Result:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input.encode() if input is not None else None), timeout
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise CommandError(f"timeout: {argv[0]} {argv[1] if len(argv) > 1 else ''}") from None
    res = Result(proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"))
    if check and res.rc != 0:
        raise CommandError(f"{describe(argv)} failed ({res.rc}): {summarize(res.stderr or res.stdout)}")
    return res


def describe(argv: tuple[str, ...] | list[str]) -> str:
    """Short name of a command for logs: the program run through systemd-run, not
    systemd-run's own options."""
    if argv and os.path.basename(argv[0]) == "systemd-run" and "--" in argv:
        sep = list(argv).index("--")
        inner = list(argv[sep + 1:])
        how = "systemd-run as the user" if "--user" in argv[:sep] else "systemd-run"
        return f"{' '.join(inner[:4])}{' ...' if len(inner) > 4 else ''} ({how})"
    return f"{' '.join(argv[:3])}{' ...' if len(argv) > 3 else ''}"


def summarize(text: str, max_lines: int = 3, max_len: int = 400) -> str:
    """The meaningful lines of a command's error output, on one line: no blank lines,
    no GLib "**" separators, no repeats (GLib prints an assertion twice, the second
    time after "Bail out! ")."""
    seen, lines = set(), []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Bail out! "):
            line = line[len("Bail out! "):]
        if not line or not any(c.isalnum() for c in line) or line in seen:
            continue
        seen.add(line)
        lines.append(line)
        if len(lines) == max_lines:
            break
    out = "; ".join(lines) or "no error output"
    return out if len(out) <= max_len else out[:max_len - 3] + "..."


async def unit_active(unit: str) -> bool:
    return (await run("systemctl", "is-active", "--quiet", unit, check=False)).rc == 0


async def start_unit(unit: str) -> None:
    await run("systemctl", "start", "--no-block", unit)


async def reset_failed(unit: str) -> None:
    """Clear a unit's failed state and start limit: a session unit that failed before
    (e.g. "Start request repeated too quickly") would refuse the next start at once."""
    await run("systemctl", "reset-failed", unit, check=False)


async def unit_failed(unit: str) -> bool:
    return (await run("systemctl", "is-failed", "--quiet", unit, check=False)).rc == 0


async def unit_last_message(unit: str) -> str:
    """The last line the unit's own processes logged (not systemd's), printable and
    short, for an error message; "" if there is none or journalctl is unavailable."""
    try:
        res = await run("journalctl", f"_SYSTEMD_UNIT={unit}", "-n", "1", "-o", "cat", "-q",
                        "--no-pager", check=False, timeout=10)
    except (CommandError, OSError):
        return ""
    line = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
    return "".join(c if c.isprintable() else "?" for c in line)[:200]


async def stop_unit(unit: str) -> None:
    await run("systemctl", "stop", "--no-block", unit, check=False)


async def user_sessions(user_name: str) -> list[dict[str, str]]:
    """The user's logind sessions with their Id, Type, Class, Service and State
    (loginctl; an empty list if loginctl fails)."""
    res = await run("loginctl", "list-sessions", "--no-legend", check=False)
    out = []
    for line in res.stdout.splitlines():
        cols = line.split()
        if len(cols) < 3 or cols[2] != user_name:
            continue
        info = await run("loginctl", "show-session", cols[0], "-p", "Id", "-p", "Type", "-p", "Class",
                         "-p", "Service", "-p", "State", check=False)
        props = dict(kv.split("=", 1) for kv in info.stdout.splitlines() if "=" in kv)
        props.setdefault("Id", cols[0])
        out.append(props)
    return out


async def ensure_user_manager(user: LocalUser) -> None:
    await run("systemctl", "start", f"user@{user.uid}.service", timeout=60)


async def run_as_user(user: LocalUser, *argv: str, input: str | None = None, timeout: float = 30) -> Result:
    """Run a command inside the user's systemd manager (has the session D-Bus for GSettings)."""
    await ensure_user_manager(user)
    return await run(
        "systemd-run",
        # The uid, not the name: systemd splits "USER@HOST" at the first '@', so a fully
        # qualified SSSD name ('alice@example.com') would not work (systemd >= 252).
        f"--machine={user.uid}@.host",
        "--user",
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
        "--",
        *argv,
        input=input,
        timeout=timeout,
    )


# Environment for commands run with the user's ids outside the user's manager: no
# variable of the broker leaks in (KRB5CCNAME, KRB5_CONFIG, ...), and HOME=/ so that
# nothing reads the (possibly Kerberized NFS) home, like rpc.gssd's set-home.
DROPPED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/", "LANG": "C.UTF-8"}


async def run_dropped(user: LocalUser, *argv: str, env: dict[str, str] | None = None,
                      timeout: float = 15) -> Result:
    """Run a short command as the user (uid, gid, no supplementary groups) without the
    user's systemd manager, in "/" and with a clean environment. For checks that must
    not start user@UID.service (e.g. klist before the session exists)."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        user=user.uid,
        group=user.gid,
        extra_groups=[],
        cwd="/",
        env={**DROPPED_ENV, **(env or {})},
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise CommandError(f"timeout: {argv[0]}") from None
    return Result(proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"))


def _root_dir(path: str, mode: int) -> None:
    """Root-owned directory with exactly `mode` (the broker runs with umask 077)."""
    os.makedirs(path, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        raise CommandError(f"{path} is not a root-owned directory")
    os.chmod(path, mode)


def _valid_user_file(path: str, user: LocalUser) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == user.uid


async def ensure_backend_cert(user: LocalUser, state_dir: str) -> tuple[str, str]:
    """Per-user self-signed cert for loopback back-ends (g-r-d, KRdp run as the user).

    Layout: <state>/users/<name>/tls.{crt,key}. Every directory is root-owned and
    not writable by the user, so the user cannot plant symlinks there. The files
    belong to the user (key 0600) so the user's g-r-d/KRdp can read them. Never
    use the user's primary group: on AD that is usually "Domain Users".
    """
    _root_dir(state_dir, 0o711)
    users_dir = os.path.join(state_dir, "users")
    _root_dir(users_dir, 0o711)
    udir = os.path.join(users_dir, user.name)
    _root_dir(udir, 0o711)
    crt, key = os.path.join(udir, "tls.crt"), os.path.join(udir, "tls.key")
    if _valid_user_file(crt, user) and _valid_user_file(key, user):
        return crt, key
    with tempfile.TemporaryDirectory(dir=state_dir) as tmp:  # root-only, same filesystem
        tkey, tcrt = os.path.join(tmp, "tls.key"), os.path.join(tmp, "tls.crt")
        await run(
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "3650", "-subj", f"/CN=fastrdp-backend-{user.name}",
            "-keyout", tkey, "-out", tcrt,
        )
        for src, dst, mode in ((tkey, key, 0o600), (tcrt, crt, 0o644)):
            os.chown(src, user.uid, 0)
            os.chmod(src, mode)
            os.replace(src, dst)  # replaces whatever was there, including a symlink
    return crt, key


_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")


def cert_sha256(path: str) -> str:
    """SHA-256 of the (first) certificate in a PEM file, over its DER encoding: what the
    proxy module compares with the certificate the back-end presents (lower-case hex)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as fh:
            pem = fh.read(1 << 20)
    except OSError as exc:
        raise CommandError(f"back-end certificate {path}: {exc.strerror}") from None
    m = _PEM_CERT.search(pem)
    try:
        der = base64.b64decode(b"".join(m.group(1).split()), validate=True) if m else b""
    except binascii.Error:
        der = b""
    if not der:
        raise CommandError(f"back-end certificate {path}: no PEM certificate")
    return hashlib.sha256(der).hexdigest()


UNIT_CHECK_INTERVAL = 2.0  # seconds between unit state checks while waiting for a listener


async def wait_for_listener(port: int, uid: int, timeout: float, unit: str | None = None) -> None:
    """Wait until `port` is listening on loopback and owned by `uid` only. With `unit`
    (the session's system unit), stop as soon as that unit has failed (systemd gave up
    restarting it) instead of waiting out `timeout`; the error names the unit's last
    message."""
    deadline = time.monotonic() + timeout
    next_check = time.monotonic() + UNIT_CHECK_INTERVAL
    while time.monotonic() < deadline:
        uids = netcheck.listener_uids(port)
        if uids:
            if uids != {uid}:
                raise CommandError(f"port {port} is held by unexpected uid(s) {sorted(uids)}")
            return
        if unit and time.monotonic() >= next_check:
            next_check = time.monotonic() + UNIT_CHECK_INTERVAL
            if await unit_failed(unit):
                last = await unit_last_message(unit)
                raise CommandError(f"{unit} failed" + (f": {last}" if last else "")
                                   + f" (journalctl -u {unit})")
        await asyncio.sleep(0.5)
    raise CommandError(f"no listener on port {port} after {timeout:.0f}s")
