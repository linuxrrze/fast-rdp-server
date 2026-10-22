# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Users' subscriptions for approval notifications (docs/notifications.md).

Layout: <[notify] state_dir>/notify/<local account>.json, a JSON object
{"subscriptions": [...]}, each one {"type": "webpush"|"ntfy", "id": str, "label": str,
"created": int, ...}: webpush with "endpoint", "p256dh", "auth" (the browser's push
subscription), ntfy with "topic" (random, the user's own). Only the webgate writes here:
the directory belongs to its uid with mode 0700 (systemd StateDirectory), files are 0600.
As in the broker's desktopprefs.py every access goes through the directory's file
descriptor (opened with O_NOFOLLOW), files are opened with O_NOFOLLOW and replaced by
rename, so a symlink planted in place of the directory or a file is never followed.
One lock serialises all changes (the HTTP threads and the notifier's send threads).
"""

from __future__ import annotations

import errno
import json
import logging
import os
import re
import secrets
import stat
import threading
import time

log = logging.getLogger("fastrdp.webgate.notify")

NOTIFY_DIR = "notify"
# Local account names as the broker resolves them (SSSD: also user@domain); never a path.
SAFE_ACCOUNT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@-]{0,255}")
MAX_SUBSCRIPTIONS = 10
MAX_FILE = 64 * 1024
TYPES = ("webpush", "ntfy")
_TMP_PREFIX = ".tmp-"


class StoreError(Exception):
    pass


class TooManyError(StoreError):
    """The account has MAX_SUBSCRIPTIONS already."""


def check_account(name: str) -> str:
    if not isinstance(name, str) or not SAFE_ACCOUNT.fullmatch(name):
        raise StoreError(f"unusable account name for notifications: {name!r}")
    return name


class SubscriptionStore:
    def __init__(self, state_dir: str, clock=time.time):
        self.path = os.path.join(state_dir, NOTIFY_DIR)
        self.clock = clock
        self.lock = threading.Lock()

    def _open_dir(self, create: bool) -> int | None:
        """fd of the directory, a real directory owned by this process's uid. None if it
        does not exist and `create` is false."""
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
            raise StoreError(f"{self.path}: {exc.strerror}") from None
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            os.close(fd)
            raise StoreError(f"{self.path} is not owned by uid {os.geteuid()}")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
        return fd

    def _read(self, dfd: int, name: str) -> list[dict]:
        try:
            fd = os.open(f"{name}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            return []
        except OSError as exc:  # ELOOP: a symlink
            raise StoreError(f"subscriptions of {name}: {exc.strerror}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                raise StoreError(f"subscriptions of {name}: not a regular file of uid {os.geteuid()}")
            data = os.read(fd, MAX_FILE + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_FILE:
            raise StoreError(f"subscriptions of {name}: file too large")
        try:
            subs = json.loads(data).get("subscriptions", [])
        except (ValueError, AttributeError):
            raise StoreError(f"subscriptions of {name}: not valid JSON") from None
        return [s for s in subs if isinstance(s, dict) and s.get("type") in TYPES and isinstance(s.get("id"), str)]

    def _write(self, dfd: int, name: str, subs: list[dict]) -> None:
        if not subs:
            try:
                os.unlink(f"{name}.json", dir_fd=dfd)
            except FileNotFoundError:
                pass
            return
        tmp = f"{_TMP_PREFIX}{secrets.token_hex(8)}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"subscriptions": subs}, fh, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            # replaces whatever is there, a symlink included (never follows it)
            os.replace(tmp, f"{name}.json", src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    log.warning("%s: cannot remove %s: %s", self.path, tmp, exc.strerror)
            raise

    def list(self, name: str) -> list[dict]:
        """The account's subscriptions, oldest first ([] if none)."""
        check_account(name)
        with self.lock:
            dfd = self._open_dir(create=False)
            if dfd is None:
                return []
            try:
                return self._read(dfd, name)
            finally:
                os.close(dfd)

    def add(self, name: str, sub: dict) -> dict:
        """Store a subscription (type and its fields); returns it with "id" and "created".
        A web push subscription with an endpoint already stored replaces that one; an ntfy
        subscription replaces the account's earlier one (one topic per user). Raises
        TooManyError beyond MAX_SUBSCRIPTIONS."""
        check_account(name)
        if sub.get("type") not in TYPES:
            raise StoreError(f"unknown subscription type {sub.get('type')!r}")
        entry = {**sub, "id": secrets.token_urlsafe(9), "created": int(self.clock())}
        with self.lock:
            dfd = self._open_dir(create=True)
            assert dfd is not None
            try:
                subs = self._read(dfd, name)
                if sub["type"] == "ntfy":
                    subs = [s for s in subs if s["type"] != "ntfy"]
                else:
                    subs = [s for s in subs if s.get("endpoint") != sub.get("endpoint")]
                if len(subs) >= MAX_SUBSCRIPTIONS:
                    raise TooManyError(f"{name} has {len(subs)} subscriptions already (at most {MAX_SUBSCRIPTIONS})")
                self._write(dfd, name, subs + [entry])
            finally:
                os.close(dfd)
        return entry

    def remove(self, name: str, sub_id: str) -> bool:
        """Remove one subscription; False if there was none with that id."""
        check_account(name)
        with self.lock:
            dfd = self._open_dir(create=False)
            if dfd is None:
                return False
            try:
                subs = self._read(dfd, name)
                left = [s for s in subs if s["id"] != sub_id]
                if len(left) == len(subs):
                    return False
                self._write(dfd, name, left)
                return True
            finally:
                os.close(dfd)
