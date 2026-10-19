# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Mapping RDP identities to local accounts, groups and desktop choice."""

from __future__ import annotations

import grp
import os
import pwd
import re
from dataclasses import dataclass

from .config import AuthSection, Config

SAFE_NAME = re.compile(r"^[A-Za-z0-9._@-]{1,256}$")
DESKTOP_PREF = ".config/fastrdp/desktop"


class IdentityError(Exception):
    pass


@dataclass(frozen=True)
class LocalUser:
    name: str
    uid: int
    gid: int
    home: str
    groups: frozenset[str]


def split_principal(principal: str) -> tuple[str, str]:
    """'alice@EXAMPLE.COM' -> ('alice', 'EXAMPLE.COM')."""
    if "@" not in principal:
        raise IdentityError(f"principal without realm: {principal!r}")
    user, realm = principal.rsplit("@", 1)
    return user, realm.upper()


def normalize_rdp_user(user: str) -> str:
    """Accept 'alice', 'DOMAIN\\alice', 'alice@realm' -> bare account name."""
    if "\\" in user:
        user = user.split("\\", 1)[1]
    if "@" in user:
        user = user.rsplit("@", 1)[0]
    return user


def resolve(name: str, realm: str | None, auth: AuthSection) -> LocalUser:
    if not SAFE_NAME.match(name):
        raise IdentityError("invalid user name")
    candidates = [name] if auth.strip_realm else []
    if realm:
        candidates.append(f"{name}@{realm.lower()}")
    if not auth.strip_realm:
        candidates.append(name)
    for cand in candidates:
        try:
            pw = pwd.getpwnam(cand)
            break
        except KeyError:
            continue
    else:
        raise IdentityError(f"unknown user {name!r}")
    if pw.pw_uid == 0:
        raise IdentityError("root logins are not allowed")
    # getgrouplist() asks NSS (incl. SSSD) for this user's groups without enumerating all groups.
    groups: set[str] = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            groups.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return LocalUser(pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir, frozenset(groups))


def user_allowed(user: LocalUser, auth: AuthSection) -> bool:
    return not auth.allow_groups or bool(user.groups & set(auth.allow_groups))


def read_desktop_pref(user: LocalUser) -> str | None:
    """Read ~/.config/fastrdp/desktop without following symlinks (we run as root)."""
    path = os.path.join(user.home, DESKTOP_PREF)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if st.st_uid != user.uid or not (st.st_mode & 0o170000 == 0o100000):
            return None
        data = os.read(fd, 64)
    finally:
        os.close(fd)
    value = data.decode(errors="ignore").strip().splitlines()
    return value[0].strip() if value else None


def desktop_allowed(cfg: Config, name: str, user: LocalUser) -> bool:
    desk = cfg.desktops.get(name)
    return desk is not None and (not desk.groups or bool(user.groups & set(desk.groups)))


def choose_desktop(cfg: Config, user: LocalUser, hint: str | None) -> str:
    """Client hint > user preference file > group default > global default."""
    if hint:
        hint = hint.strip()
        if hint.lower().startswith("fastrdp:"):
            hint = hint.split(":", 1)[1]
        if desktop_allowed(cfg, hint, user):
            return hint
    pref = read_desktop_pref(user)
    if pref and desktop_allowed(cfg, pref, user):
        return pref
    for group, desk in cfg.group_defaults.items():
        if group in user.groups and desktop_allowed(cfg, desk, user):
            return desk
    if desktop_allowed(cfg, cfg.default_desktop, user):
        return cfg.default_desktop
    raise IdentityError("no desktop is permitted for this user")
