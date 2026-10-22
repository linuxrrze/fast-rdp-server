# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Desktops users chose for their RDP logins on the webgate's chooser page.

Layout: <state_dir>/desktop-prefs/<local account name>, one desktop name and a newline.
The directory belongs to the broker (root) with mode 0700; users never write here, so
unlike ~/.config/fastrdp/desktop the broker can read it on Kerberized NFS homes too
(docs/nfs-kerberos-homes.md). Every access goes through the directory's file descriptor
(opened with O_NOFOLLOW), files are opened with O_NOFOLLOW and replaced by rename, so a
symlink planted in place of the directory or a file is never followed.
"""

from __future__ import annotations

import errno
import logging
import os
import re
import secrets
import stat

log = logging.getLogger("fastrdp.desktopprefs")

PREFS_DIR = "desktop-prefs"
# Desktop names as broker.toml allows them ([desktops.<name>]); anything else in a file is ignored.
SAFE_DESKTOP = re.compile(r"[A-Za-z0-9_-]{1,64}")
_TMP_PREFIX = ".tmp-"


class PrefsError(Exception):
    pass


def _check_name(name: str) -> str:
    # Resolved local account names (identity.SAFE_NAME); never a path ('..', '/').
    if not name or "/" in name or "\0" in name or name.startswith(".") or len(name) > 256:
        raise PrefsError(f"unusable account name for a desktop preference: {name!r}")
    return name


class DesktopPrefs:
    def __init__(self, state_dir: str):
        self.path = os.path.join(state_dir, PREFS_DIR)

    def _open_dir(self, create: bool) -> int | None:
        """fd of the directory, which must be a real directory owned by the broker's uid
        (root). None if it does not exist and `create` is false."""
        if create:
            try:
                os.mkdir(self.path, 0o700)
            except FileExistsError:
                pass
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        except OSError as exc:  # ELOOP / ENOTDIR: a symlink or a file in its place
            raise PrefsError(f"{self.path}: {exc.strerror}") from None
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            os.close(fd)
            raise PrefsError(f"{self.path} is not owned by uid {os.geteuid()}")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
        return fd

    def get(self, name: str) -> str | None:
        """The stored desktop of account `name`; None if none (or the file is unusable)."""
        _check_name(name)
        try:
            dfd = self._open_dir(create=False)
        except PrefsError as exc:
            log.warning("desktop preference of %s ignored: %s", name, exc)
            return None
        if dfd is None:
            return None
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd)
            except FileNotFoundError:
                return None
            except OSError as exc:  # ELOOP: a symlink
                log.warning("desktop preference of %s ignored: %s", name, exc.strerror)
                return None
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                    log.warning("desktop preference of %s ignored: not a regular file of uid %d",
                                name, os.geteuid())
                    return None
                data = os.read(fd, 128)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
        lines = data.decode(errors="ignore").splitlines()
        value = lines[0].strip() if lines else ""
        return value if SAFE_DESKTOP.fullmatch(value) else None

    def set(self, name: str, desktop: str | None) -> None:
        """Store `desktop` for account `name` (temporary file + rename); None removes it."""
        _check_name(name)
        if desktop is not None and not SAFE_DESKTOP.fullmatch(desktop):
            raise PrefsError(f"invalid desktop name {desktop!r}")
        dfd = self._open_dir(create=desktop is not None)
        if dfd is None:
            return  # nothing stored, nothing to remove
        try:
            if desktop is None:
                try:
                    os.unlink(name, dir_fd=dfd)
                except FileNotFoundError:
                    pass
                return
            tmp = f"{_TMP_PREFIX}{secrets.token_hex(8)}"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dfd)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(desktop + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                # replaces whatever is there, a symlink included (never follows it)
                os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        log.warning("%s: cannot remove %s: %s", self.path, tmp, exc.strerror)
                raise
        finally:
            os.close(dfd)
