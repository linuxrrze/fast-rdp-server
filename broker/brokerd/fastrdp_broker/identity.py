# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Mapping RDP identities to local accounts, groups and desktop choice."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import functools
import grp
import logging
import os
import pwd
import re
from dataclasses import dataclass

from .config import AuthSection, Config

log = logging.getLogger("fastrdp.identity")

SAFE_NAME = re.compile(r"[A-Za-z0-9._@-]{1,256}")   # fullmatch: no trailing newline
DESKTOP_PREF = ".config/fastrdp/desktop"


class IdentityError(Exception):
    """`reason`: the refusal reason the broker reports (protocol.py)."""

    def __init__(self, message: str, reason: str = "denied"):
        super().__init__(message)
        self.reason = reason


class UnknownUser(IdentityError):
    """No local account (NSS) by that name."""


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


def qualifiers(auth: AuthSection, realm: str | None = None) -> list[str]:
    """Domain parts of qualified account names ('alice@example.com'), lower case: the
    given realm, the accepted realms, then [auth] domains (SSSD domain names, which may
    differ from the realm on FreeIPA). SSSD with use_fully_qualified_names = true knows
    directory users and groups only as 'name@<sssd domain>'."""
    quals = [realm] if realm else []
    quals += [*auth.realms, *auth.domains]
    return list(dict.fromkeys(q.lower() for q in quals if q))


def short_name(name: str, auth: AuthSection) -> str:
    """'alice@example.com' -> 'alice' if example.com is one of ours (qualifiers()),
    else unchanged: the name other systems (privacyIDEA) know a directory user by,
    whether SSSD uses fully qualified names or not."""
    if "@" in name:
        local, dom = name.rsplit("@", 1)
        if local and dom.lower() in qualifiers(auth):
            return local
    return name


def _candidates(name: str, quals: list[str], auth: AuthSection) -> list[str]:
    qualified = [f"{name}@{q}" for q in quals]
    # strip_realm = true: the short name first (SSSD with short names; a local account
    # of the same name wins). false (SSSD with fully qualified names): the directory's
    # qualified name first, so a local account with the same short name never shadows it.
    return [name, *qualified] if auth.strip_realm else [*qualified, name]


def _lookup(candidates: list[str], what: str):
    for cand in candidates:
        try:
            return pwd.getpwnam(cand)
        except KeyError:
            continue
    raise UnknownUser(f"unknown user {what!r}")


def _local_user(pw, auth: AuthSection, realm: str | None = None) -> LocalUser:
    if pw.pw_uid == 0:
        raise IdentityError("root logins are not allowed")
    quals = qualifiers(auth, realm)
    # getgrouplist() asks NSS (incl. SSSD) for this user's groups without enumerating all groups.
    groups: set[str] = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            name = grp.getgrgid(gid).gr_name
        except KeyError:
            continue
        groups.add(name)
        # SSSD with fully qualified names qualifies groups too ('rdp-users@example.com'):
        # group names in broker.toml without a domain match them, as with short names.
        if "@" in name:
            local, dom = name.rsplit("@", 1)
            if local and dom.lower() in quals:
                groups.add(local)
    return LocalUser(pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir, frozenset(groups))


def resolve(name: str, realm: str | None, auth: AuthSection) -> LocalUser:
    """The account of `name` from realm `realm` (None: `name` exactly as given).

    Candidates 'name' and 'name@<realm>' (for an accepted realm also 'name@<domain>'
    for each [auth] domains), in the order [auth] strip_realm gives.
    """
    if not SAFE_NAME.fullmatch(name):
        raise IdentityError("invalid user name")
    quals = [realm] if realm else []
    if realm and realm.upper() in auth.realms:
        quals += auth.domains  # FreeIPA: the SSSD domain name may differ from the realm
    quals = list(dict.fromkeys(q.lower() for q in quals))
    return _local_user(_lookup(_candidates(name, quals, auth), name), auth, realm)


def resolve_login(rdp_user: str, auth: AuthSection) -> LocalUser:
    """The account of a user name without Kerberos principal: typed at a TLS login,
    or from the web gateway. 'alice', 'DOMAIN\\alice' or 'alice@example.com'.

    Candidates: the short name and the short name qualified with our realms and
    [auth] domains (only the typed one if it is one of them), in the order
    [auth] strip_realm gives. With short SSSD names this is the short name, as before.
    """
    typed = rdp_user.split("\\", 1)[1] if "\\" in rdp_user else rdp_user
    name = normalize_rdp_user(rdp_user)
    if not SAFE_NAME.fullmatch(name):
        raise IdentityError("invalid user name")
    quals = qualifiers(auth)
    if "@" in typed and typed.rsplit("@", 1)[1].lower() in quals:
        quals = [typed.rsplit("@", 1)[1].lower()]
    return _local_user(_lookup(_candidates(name, quals, auth), name), auth)


def unescape_principal_name(name: str) -> str:
    """Undo krb5_unparse_name() quoting: 'a\\@b' -> 'a@b' (enterprise names, RFC 6806)."""
    out, i = [], 0
    while i < len(name):
        c = name[i]
        if c == "\\" and i + 1 < len(name):
            i += 1
            c = {"n": "\n", "t": "\t", "b": "\b", "0": "\0"}.get(name[i], name[i])
        elif c == "/":
            # Unquoted '/' separates components: service or admin principals
            # (host/x, alice/admin) never log in to a desktop.
            raise IdentityError(f"multi-component principal {name!r} refused")
        out.append(c)
        i += 1
    return "".join(out)


@functools.cache
def _libkrb5():
    try:
        return ctypes.CDLL(ctypes.util.find_library("krb5") or "libkrb5.so.3")
    except OSError:
        return None


def krb5_localname(principal: str) -> str | None:
    """krb5_aname_to_localname(): krb5.conf auth_to_local rules and localauth plugins
    (SSSD's maps a principal to the account whose UPN it is). None if not mapped or
    libkrb5 is not available."""
    lib = _libkrb5()
    if lib is None:
        return None
    ctx, princ = ctypes.c_void_p(), ctypes.c_void_p()
    buf = ctypes.create_string_buffer(257)
    if lib.krb5_init_context(ctypes.byref(ctx)):
        return None
    try:
        if lib.krb5_parse_name(ctx, principal.encode(), ctypes.byref(princ)):
            return None
        try:
            rc = lib.krb5_aname_to_localname(ctx, princ, ctypes.c_int(len(buf) - 1), buf)
        finally:
            lib.krb5_free_principal(ctx, princ)
        return buf.value.decode(errors="replace") if rc == 0 and buf.value else None
    finally:
        lib.krb5_free_context(ctx)


def resolve_principal(name: str, realm: str, auth: AuthSection) -> LocalUser:
    """The local account of the Kerberos principal name@realm (NLA logins).

    The principal is the identity; the CredSSP user name is not used. Order:
    1. a plain name (AD puts the sAMAccountName in tickets, FreeIPA the uid) resolves
       like before: 'name' / 'name@realm' (resolve(), honours strip_realm; with
       [auth] domains also 'name@<domain>');
    2. an enterprise name ('marcel.ritter\\@corp.example.com', UPN in an NT-ENTERPRISE
       principal) resolves by its UPN: SSSD answers getpwnam('<upn>') with a UPN
       search. Its local part is never used on its own: it may be another person's
       account name;
    3. otherwise krb5_aname_to_localname() (auth_to_local, SSSD localauth plugin).
    Nothing found: IdentityError, the login is refused.
    """
    plain = unescape_principal_name(name)
    try:
        # enterprise: the UPN alone, never with the realm appended or the suffix cut off
        return resolve(plain, None if "@" in plain else realm, auth)
    except UnknownUser:
        pass
    local = krb5_localname(f"{name}@{realm}")
    if local:
        log.info("principal %s@%s mapped to %s by krb5 localauth", name, realm, local)
        return resolve(local, None, auth)
    raise IdentityError(f"principal {name}@{realm} maps to no local account")


def names_other_account(rdp_user: str, user: LocalUser, auth: AuthSection | None = None) -> bool:
    """True if the CredSSP user name ('alice', 'DOM\\alice', a UPN) is clearly a
    different local account than `user`. Unknown names are not a conflict. With
    `auth`, the short name qualified with our realms/domains counts as well: with
    fully qualified SSSD names, 'alice' may be a local account while the user is
    'alice@example.com'."""
    short = normalize_rdp_user(rdp_user)
    candidates = [rdp_user, short]
    if auth is not None:
        candidates += [f"{short}@{q}" for q in qualifiers(auth)]
    other = False
    for cand in dict.fromkeys(candidates):
        if not SAFE_NAME.fullmatch(cand):
            continue
        try:
            uid = pwd.getpwnam(cand).pw_uid
        except KeyError:
            continue
        if uid == user.uid:
            return False
        other = True
    return other


def user_allowed(user: LocalUser, auth: AuthSection) -> bool:
    return not auth.allow_groups or bool(user.groups & set(auth.allow_groups))


# [broker] session_tgt_groups: a user in groups with different modes gets the strictest.
SESSION_TGT_STRICTNESS = {"off": 0, "auto": 1, "required": 2}


def session_tgt_mode(cfg: Config, user: LocalUser) -> tuple[str, str | None]:
    """(effective [broker] session_tgt mode, group it comes from or None = the default).

    Members of groups in session_tgt_groups get the strictest mode of those groups
    (required > auto > off; ties: the first listed group), others session_tgt. Group
    names match as for allow_groups (user.groups has the short aliases of qualified
    names)."""
    best: tuple[str, str] | None = None
    for group, mode in cfg.broker.session_tgt_groups.items():
        if group in user.groups and (
            best is None or SESSION_TGT_STRICTNESS[mode] > SESSION_TGT_STRICTNESS[best[0]]
        ):
            best = (mode, group)
    return best if best else (cfg.broker.session_tgt, None)


def read_desktop_pref(user: LocalUser) -> str | None:
    """Read ~/.config/fastrdp/desktop without following symlinks (we run as root).

    Any error means "no preference": root often cannot read the home directory at all
    (NFS with sec=krb5*: root has no user credentials, EACCES/EKEYEXPIRED; root_squash),
    and a login must never fail because of this optional file. Blocking (unreachable NFS
    server) is handled by the caller, see Broker.read_desktop_pref.
    """
    path = os.path.join(user.home, DESKTOP_PREF)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            log.debug("%s: cannot open %s: %s", user.name, path, exc)
        return None
    try:
        st = os.fstat(fd)
        if st.st_uid != user.uid or not (st.st_mode & 0o170000 == 0o100000):
            return None
        data = os.read(fd, 64)
    except OSError as exc:  # e.g. EIO, or EKEYEXPIRED when the credentials expire mid-read
        log.debug("%s: cannot read %s: %s", user.name, path, exc)
        return None
    finally:
        os.close(fd)
    value = data.decode(errors="ignore").strip().splitlines()
    return value[0].strip() if value else None


def desktop_allowed(cfg: Config, name: str, user: LocalUser) -> bool:
    desk = cfg.desktops.get(name)
    return desk is not None and (not desk.groups or bool(user.groups & set(desk.groups)))


def hinted_desktop(cfg: Config, user: LocalUser, hint: str | None) -> str | None:
    """The desktop named by the client hint, if the user may use it."""
    if hint:
        hint = hint.strip()
        if hint.lower().startswith("fastrdp:"):
            hint = hint.split(":", 1)[1]
        if desktop_allowed(cfg, hint, user):
            return hint
    return None


_READ_PREF = object()


def choose_desktop(cfg: Config, user: LocalUser, hint: str | None, pref=_READ_PREF,
                   web_pref: str | None = None) -> str:
    """Client hint > desktop chosen on the webgate (`web_pref`, desktopprefs.py) >
    user preference file > group default > global default. Each only if allowed.

    `pref`: the preference already read by the caller (None = none); by default the
    file is read here, synchronously (not at all if `web_pref` decides).
    """
    return desktop_choice(cfg, user, hint, pref, web_pref)[0]


def desktop_choice(cfg: Config, user: LocalUser, hint: str | None, pref=_READ_PREF,
                   web_pref: str | None = None) -> tuple[str, str, str | None]:
    """choose_desktop() and why: (desktop, source, group). source: "hint", "web_pref",
    "home_file", "group_default" (group: the group whose default it is) or "default"."""
    hinted = hinted_desktop(cfg, user, hint)
    if hinted:
        return hinted, "hint", None
    if web_pref and desktop_allowed(cfg, web_pref, user):
        return web_pref, "web_pref", None
    if pref is _READ_PREF:
        pref = read_desktop_pref(user)
    if pref and desktop_allowed(cfg, pref, user):
        return pref, "home_file", None
    for group, desk in cfg.group_defaults.items():
        if group in user.groups and desktop_allowed(cfg, desk, user):
            return desk, "group_default", group
    if desktop_allowed(cfg, cfg.default_desktop, user):
        return cfg.default_desktop, "default", None
    raise IdentityError("no desktop is permitted for this user", "not_allowed")
