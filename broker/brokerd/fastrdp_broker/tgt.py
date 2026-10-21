# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Kerberos TGT for sessions whose back-end never sees the user's password (GNOME, Plasma).

Kerberized NFS homes, SMB and other Kerberos services need a TGT in the user's
credential cache before the session first touches them (docs/nfs-kerberos-homes.md).
The broker authenticates the user once more through PAM service fastrdp-tgt
(pam_sss only, no pam_faillock): sssd's krb5_child gets the TGT and writes it to the
user's ccache (KCM:) with the user's ids, and registers it for sssd's renewal. Then
the broker checks, with the user's ids, the cache that the session's processes use.

The session's processes (gdm-autologin, fastrdp-session, the user's systemd manager)
get no KRB5CCNAME: they use default_ccache_name from krb5.conf (KCM:), the uid's KCM
collection, i.e. its primary cache. So the checks run without KRB5CCNAME too:
- the cache pam_sss reported must have the type of the default cache; a FILE cache
  from a krb5_ccname_template in sssd.conf would never be found by the session;
- in a collection, the login's cache is made primary (kswitch) if another one is
  primary, e.g. after `kinit admin@REALM` in a session: sssd's krb5_child switches
  only to caches it creates, not to the existing cache it refreshes;
- `klist -s` then checks that the primary cache has a valid TGT (sssd authenticates
  offline from its cache without creating one).

Why PAM and not `kinit` as the user: sssd knows the user's real principal (UPN,
enterprise names), its KDCs and offline state, stores the TGT with the configured
ccache template and renews it (krb5_renew_interval); `kinit` in the user's systemd
manager would also need user@UID.service to start before the TGT exists.
"""

from __future__ import annotations

import asyncio
import logging
import re

from . import identity, pamauth, sysutil
from .config import AuthSection
from .identity import LocalUser

PAM_SERVICE = "fastrdp-tgt"
# Cache types with several caches and a primary one (krb5_cc_support_switch).
COLLECTIONS = frozenset({"KCM", "DIR", "KEYRING"})

log = logging.getLogger("fastrdp.tgt")

_CACHE = re.compile(r"^Ticket cache: (\S+)$", re.M)
_PRINCIPAL = re.compile(r"^Default principal: (\S+)$", re.M)


class TgtError(Exception):
    """No TGT. The message never contains the password."""


def cache_type(name: str) -> str:
    """'KCM:1500:123' -> 'KCM'; a bare path is a FILE cache (krb5_cc_resolve)."""
    if ":" not in name or name.startswith("/"):
        return "FILE"
    return name.split(":", 1)[0].upper()


def parse_caches(klist_out: str) -> list[tuple[str, str]]:
    """(cache, principal) of every block in `klist` / `klist -A` output (C locale)."""
    out = []
    for block in re.split(r"\n(?=Ticket cache: )", klist_out):
        cache, princ = _CACHE.search(block), _PRINCIPAL.search(block)
        if cache and princ:
            out.append((cache.group(1), princ.group(1)))
    return out


async def _klist(user: LocalUser, *args: str) -> sysutil.Result:
    # run_dropped: clean environment, so no KRB5CCNAME (the session's view).
    return await sysutil.run_dropped(user, "klist", *args)


async def _is_users(principal: str, user: LocalUser, auth: AuthSection) -> bool:
    """The principal maps to `user` like an NLA login's (identity.resolve_principal)."""
    try:
        name, realm = identity.split_principal(principal)
        found = await asyncio.to_thread(identity.resolve_principal, name, realm, auth)
    except (identity.IdentityError, OSError):
        return False
    return found.uid == user.uid


async def _make_primary(user: LocalUser, auth: AuthSection, primary: tuple[str, str] | None) -> None:
    """In a collection, switch to the user's own valid cache unless it is primary."""
    if primary and await _is_users(primary[1], user, auth) and (await _klist(user, "-s")).rc == 0:
        return
    listing = await _klist(user, "-A")
    for cache, principal in parse_caches(listing.stdout):
        if primary and cache == primary[0]:
            continue
        if not await _is_users(principal, user, auth):
            continue
        if (await _klist(user, "-s", cache)).rc != 0:
            continue
        res = await sysutil.run_dropped(user, "kswitch", "-c", cache)
        if res.rc == 0:
            log.info("%s: %s (%s) made the primary credential cache (was %s)", user.name, cache,
                     principal, primary[1] if primary else "none")
        else:
            log.warning("%s: kswitch -c %s failed: %s", user.name, cache, res.stderr.strip())
        return


async def obtain(user: LocalUser, password: str, auth: AuthSection) -> None:
    """Get a TGT for `user` into the cache the user's session uses. Raises TgtError."""
    try:
        ccname = await asyncio.to_thread(pamauth.establish_credentials, PAM_SERVICE, user.name, password)
    except pamauth.PamError as exc:
        raise TgtError(f"PAM service {PAM_SERVICE}: {exc}") from None
    try:
        found = parse_caches((await _klist(user)).stdout)
        primary = found[0] if found else None
        # pam_sss reports the cache sssd used ("KCM:" for the krb5.conf default).
        if ccname and primary and cache_type(ccname) != cache_type(primary[0]):
            raise TgtError(
                f"sssd stored the TGT in {ccname}, but sessions use the default cache {primary[0]}: "
                "remove krb5_ccname_template from sssd.conf (sssd then follows "
                "default_ccache_name = KCM: in /etc/krb5.conf.d/fastrdp) and restart sssd")
        if cache_type(ccname or (primary[0] if primary else "")) in COLLECTIONS:
            await _make_primary(user, auth, primary)
        res = await _klist(user, "-s")
    except (sysutil.CommandError, OSError) as exc:
        raise TgtError(f"klist: {exc}") from None
    if res.rc != 0:
        where = f" (sssd reported {ccname})" if ccname else ""
        raise TgtError("authenticated, but no valid TGT in the user's default credential cache"
                       f"{where} (sssd offline or cached authentication, or not a Kerberos account)")
