# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Subprocess, systemd and filesystem helpers."""

from __future__ import annotations

import asyncio
import logging
import os
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
        raise CommandError(f"{' '.join(argv[:3])}... failed ({res.rc}): {res.stderr.strip()[:500]}")
    return res


async def unit_active(unit: str) -> bool:
    return (await run("systemctl", "is-active", "--quiet", unit, check=False)).rc == 0


async def start_unit(unit: str) -> None:
    await run("systemctl", "start", "--no-block", unit)


async def stop_unit(unit: str) -> None:
    await run("systemctl", "stop", "--no-block", unit, check=False)


async def ensure_user_manager(user: LocalUser) -> None:
    await run("systemctl", "start", f"user@{user.uid}.service", timeout=60)


async def run_as_user(user: LocalUser, *argv: str, input: str | None = None, timeout: float = 30) -> Result:
    """Run a command inside the user's systemd manager (has the session D-Bus for GSettings)."""
    await ensure_user_manager(user)
    return await run(
        "systemd-run",
        f"--machine={user.name}@.host",
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


async def wait_for_listener(port: int, uid: int, timeout: float) -> None:
    """Wait until `port` is listening on loopback and owned by `uid` only."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        uids = netcheck.listener_uids(port)
        if uids:
            if uids != {uid}:
                raise CommandError(f"port {port} is held by unexpected uid(s) {sorted(uids)}")
            return
        await asyncio.sleep(0.5)
    raise CommandError(f"no listener on port {port} after {timeout:.0f}s")
