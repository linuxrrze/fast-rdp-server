# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""The user's home directory, checked (and created) before any back-end starts.

xrdp and Plasma sessions open a PAM session with pam_mkhomedir; GNOME's do not
(grdctl runs in the user's systemd manager, PAM services systemd-user and login).
A missing or unusable home then fails deep inside the back-end, e.g. grdctl
"Error creating directory /autofs: Permission denied". So, for every back-end
([broker] home_check):

- the home exists and is a directory (a symlink to one is fine; stat with a trailing
  slash so an autofs browse-mode placeholder is mounted first): ok. Owned by
  another uid (NFSv4 id mapping "nobody", wrong directory attribute): the user
  must be able to write to it, tested as the user;
- only its last component is missing: created like pam_mkhomedir does
  (mkhomedir_helper <user> 0077 /etc/skel 0700), but only in a parent that is one
  of [broker] home_create_roots (default /home) or below one, an existing
  root-owned parent that nobody else can write to, on a local file system (not
  NFS/CIFS/FUSE/...: provisioned on the server) and not an automount point. The
  parent is verified first because mkhomedir_helper itself would create missing
  parents (0755). Parallel first logins: the broker's per-user lock;
- a parent is missing (/autofs/srv/home/<user> without autofs): refused. Never
  create automount roots or directories under a missing mount (pam_mkhomedir
  would: mkhomedir_helper creates missing parents).

Refusals raise HomeError (a BackendError: reason "backend", RDP 0x400) with a log
line naming the cause. Root often cannot look into homes (NFS sec=krb5*,
root_squash: EACCES) and NFS may hang: both only skip the check, the time limit
is [broker] home_read_timeout, in the broker's home thread pool.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import stat
from concurrent.futures import Executor
from dataclasses import dataclass

from . import sysutil
from .backends.base import BackendError
from .identity import LocalUser

log = logging.getLogger("fastrdp.home")

MOUNTINFO = "/proc/self/mountinfo"
NOBODY = 65534
SKEL = "/etc/skel"
DEFAULT_ROOTS = ("/home",)  # [broker] home_create_roots
# Inaccessible to root (Kerberized NFS, root_squash) or credentials expired: unknown.
UNKNOWN_ERRNOS = (errno.EACCES, errno.EPERM, errno.EKEYEXPIRED, errno.EIO, errno.ESTALE)
# Homes there are provisioned on the file server (root is squashed or has no Kerberos
# credentials), never by the broker; fuse.* too (sshfs, glusterfs client, ...).
NETWORK_FS = frozenset({"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs",
                        "lustre", "gpfs", "beegfs", "ocfs2", "gfs2", "autofs"})


class HomeError(BackendError):
    """The session cannot start because of the user's home directory."""


@dataclass(frozen=True)
class Inspection:
    state: str              # "ok" | "missing" | "no_parent" | "unknown" | "bad"
    path: str
    uid: int | None = None  # owner ("ok")
    parent: str = ""        # existing parent ("missing")
    missing: str = ""       # first missing ancestor ("no_parent")
    detail: str = ""        # "bad", "unknown", "no_parent": why


def _unescape(field: str) -> str:
    # mountinfo escapes space, tab, newline and backslash as \ooo
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def mounts(mountinfo: str = MOUNTINFO) -> dict[str, str]:
    """Mount point -> file system type (the last mount on a point wins)."""
    found = {}
    try:
        with open(mountinfo, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                fields = line.split()
                if "-" in fields and len(fields) > 4:
                    sep = fields.index("-")
                    if len(fields) > sep + 1:
                        found[_unescape(fields[4])] = fields[sep + 1]
    except OSError:
        pass
    return found


def autofs_mounts(mountinfo: str = MOUNTINFO) -> set[str]:
    """Mount points of type autofs (automount roots and indirect map directories)."""
    return {p for p, fs in mounts(mountinfo).items() if fs == "autofs"}


def fstype(path: str, mountinfo: str = MOUNTINFO) -> str:
    """File system type of the mount that holds `path` (longest mount point prefix)."""
    table = mounts(mountinfo)
    probe = path
    while True:
        if probe in table:
            return table[probe]
        if probe == "/":
            return ""
        probe = os.path.dirname(probe)


def _network_fs(fs: str) -> bool:
    return fs in NETWORK_FS or fs.startswith("fuse")


def inspect(home: str, mountinfo: str = MOUNTINFO) -> Inspection:
    """What is at `home` (blocking; may hang on NFS: run it in the home pool)."""
    norm = os.path.normpath(home) if home else ""
    if not os.path.isabs(norm) or norm == "/" or ".." in home.split("/") or norm.startswith("//"):
        return Inspection("bad", home, detail="is not an absolute path below /")
    try:
        st = os.lstat(norm)
    except FileNotFoundError:
        return _missing(norm, mountinfo)
    except NotADirectoryError:
        return Inspection("bad", norm, detail="has a parent that is not a directory")
    except OSError as exc:
        if exc.errno in UNKNOWN_ERRNOS:
            return Inspection("unknown", norm, detail=os.strerror(exc.errno))
        raise
    if stat.S_ISLNK(st.st_mode):
        try:
            st = os.stat(norm)
        except FileNotFoundError:
            return Inspection("bad", norm, detail="is a symbolic link to a missing target")
        except OSError as exc:
            if exc.errno in UNKNOWN_ERRNOS:
                return Inspection("unknown", norm, detail=os.strerror(exc.errno))
            return Inspection("bad", norm, detail=f"is a symbolic link that cannot be followed: {exc.strerror}")
    if not stat.S_ISDIR(st.st_mode):
        return Inspection("bad", norm, detail="is not a directory")
    # With a trailing slash: an autofs browse-mode ("ghost") directory is mounted now, so
    # the owner is the real home's, and a failing mount shows here.
    try:
        st = os.stat(norm + "/")
    except FileNotFoundError:
        return Inspection("bad", norm, detail="cannot be mounted (automount map entry or file server?)")
    except OSError as exc:
        if exc.errno in UNKNOWN_ERRNOS:
            return Inspection("unknown", norm, detail=os.strerror(exc.errno))
        return Inspection("bad", norm, detail=f"cannot be opened: {exc.strerror}")
    return Inspection("ok", norm, uid=st.st_uid)


def _missing(norm: str, mountinfo: str) -> Inspection:
    """`norm` does not exist: is it only the last component, or a parent too?"""
    missing, parent = norm, os.path.dirname(norm)
    while True:
        try:
            st = os.stat(parent)
        except FileNotFoundError:
            missing, parent = parent, os.path.dirname(parent)
            continue
        except NotADirectoryError:
            return Inspection("bad", norm, detail="has a parent that is not a directory")
        except OSError as exc:
            if exc.errno in UNKNOWN_ERRNOS:
                return Inspection("unknown", norm, detail=f"{parent}: {os.strerror(exc.errno)}")
            raise
        break
    if not stat.S_ISDIR(st.st_mode):
        return Inspection("bad", norm, detail=f"has a parent that is not a directory ({parent})")
    if missing == norm:
        return Inspection("missing", norm, parent=parent)
    if parent in autofs_mounts(mountinfo):
        why = f"parent {missing} missing below the automount point {parent}: no map entry, or server down?"
    else:
        why = f"parent {missing} missing: automount not set up?"
    return Inspection("no_parent", norm, missing=missing, detail=why)


def _below(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def creation_refusal(parent: str, roots=DEFAULT_ROOTS, mountinfo: str = MOUNTINFO) -> str | None:
    """Why the broker (root) must not create a directory in `parent`, or None.

    `parent` must be one of `roots` ([broker] home_create_roots) or below one, as
    named and with symlinks resolved (a root that is a symlink, /home -> /var/home,
    is fine; a symlink below a root that leads out of it is not). Every directory
    from / down to `parent` must be root-owned and writable by nobody else (or
    nobody could swap a path component for a symlink), on a local file system, and
    `parent` must not be an automount point (its entries come from the map)."""
    if not roots:
        return "[broker] home_create_roots is empty (homes are provisioned elsewhere)"
    resolved = os.path.realpath(parent)
    if not any(_below(parent, r) and _below(resolved, os.path.realpath(r)) for r in roots):
        return (f"{parent} is not below [broker] home_create_roots ({', '.join(roots)})"
                + (f", it resolves to {resolved}" if resolved != parent else ""))
    if parent in autofs_mounts(mountinfo):
        return f"{parent} is an automount point: the home must come from its map"
    fs = fstype(parent, mountinfo)
    if _network_fs(fs):
        return f"{parent} is on {fs}: provision the home on the file server"
    # the path as named and as resolved: a symlink in it (/home -> /var/home) is fine
    # when every directory on both ways is root's alone
    for named in dict.fromkeys((parent, os.path.realpath(parent))):
        path = "/"
        for part in [""] + [p for p in named.split("/") if p]:
            path = os.path.join(path, part) if part else "/"
            try:
                st = os.stat(path)
            except OSError as exc:
                return f"{path}: {exc.strerror}"
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                return f"{path} is not a directory owned and writable only by root"
    return None


async def prepare(user: LocalUser, mode: str, pool: Executor, timeout: float,
                  roots=DEFAULT_ROOTS) -> None:
    """Check (and with mode "create" create) the user's home; HomeError if unusable."""
    if mode == "off":
        return
    loop = asyncio.get_running_loop()
    timeout = timeout or 3.0  # home_read_timeout = 0 (never read homes) still stats it

    async def in_pool(fn, *args):
        return await asyncio.wait_for(loop.run_in_executor(pool, fn, *args), timeout)

    home = user.home
    try:
        ins = await in_pool(inspect, home)
        if ins.state == "missing" and mode == "create":
            refusal = await in_pool(creation_refusal, ins.parent, list(roots))
            if refusal:
                raise HomeError(f"home directory {ins.path} of {user.name} does not exist, "
                                f"and the broker does not create it: {refusal}")
            await create(user)
            ins = await in_pool(inspect, home)
    except TimeoutError:
        log.warning("%s: no answer from %s within %.1fs (home on a hung network filesystem?); "
                    "home directory not checked", user.name, home, timeout)
        return

    if ins.state == "unknown":
        # Kerberized NFS (no root credentials) or root_squash: the user's session may
        # well have access; nothing to say here.
        log.debug("%s: home directory %s not checked (%s)", user.name, ins.path, ins.detail)
        return
    if ins.state == "bad":
        raise HomeError(f"home directory {ins.path} of {user.name} {ins.detail}")
    if ins.state == "no_parent":
        raise HomeError(f"home directory {ins.path} of {user.name} does not exist ({ins.detail})")
    if ins.state == "missing":
        raise HomeError(f"home directory {ins.path} of {user.name} does not exist"
                        + (" ([broker] home_check = check: create it first)" if mode == "check" else ""))
    if ins.uid != user.uid:
        await _writable_by_user(user, ins, timeout)


async def create(user: LocalUser) -> None:
    """Create the home like pam_mkhomedir umask=0077 (xrdp-sesman, fastrdp-session).

    Through systemd-run, in a transient system unit: the broker's own unit has
    ProtectHome=read-only, which its children inherit (mkhomedir_helper would fail
    with EROFS), and keeps it for everything else the broker does."""
    try:
        await sysutil.run("systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--",
                          "mkhomedir_helper", user.name, "0077", SKEL, "0700", timeout=30)
    except sysutil.CommandError as exc:
        raise HomeError(f"home directory {user.home} of {user.name} could not be created: {exc}") from None
    log.info("%s: created home directory %s (mode 0700, files from %s)", user.name, user.home, SKEL)


async def _writable_by_user(user: LocalUser, ins: Inspection, timeout: float) -> None:
    """A home owned by another uid: refuse unless the user can write to it."""
    try:
        res = await sysutil.run_dropped(user, "test", "-w", ins.path, "-a", "-x", ins.path,
                                        timeout=max(timeout, 2.0))
    except sysutil.CommandError:
        log.warning("%s: no answer from %s within %.1fs (as the user); home directory not checked",
                    user.name, ins.path, max(timeout, 2.0))
        return
    if res.rc != 0:
        hint = " (nobody: NFSv4 id mapping, idmapd Domain?)" if ins.uid == NOBODY else ""
        raise HomeError(f"home directory {ins.path} of {user.name} belongs to uid {ins.uid}{hint}, "
                        f"not {user.uid}, and {user.name} cannot write to it")
