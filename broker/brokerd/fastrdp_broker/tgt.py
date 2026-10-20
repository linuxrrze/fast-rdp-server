# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Kerberos TGT for sessions whose back-end never sees the user's password (GNOME, Plasma).

Kerberized NFS homes, SMB and other Kerberos services need a TGT in the user's
credential cache before the session first touches them (docs/nfs-kerberos-homes.md).
The broker authenticates the user once more through PAM service fastrdp-tgt
(pam_sss only, no pam_faillock): sssd's krb5_child gets the TGT and writes it to the
user's ccache (KCM:) with the user's ids, and registers it for sssd's renewal. Then
`klist -s`, run with the user's ids, checks that a valid TGT is really there (sssd
authenticates offline from its cache without creating one).

Why PAM and not `kinit` as the user: sssd knows the user's real principal (UPN,
enterprise names), its KDCs and offline state, stores the TGT with the configured
ccache template and renews it (krb5_renew_interval); `kinit` in the user's systemd
manager would also need user@UID.service to start before the TGT exists.
"""

from __future__ import annotations

import asyncio

from . import pamauth, sysutil
from .identity import LocalUser

PAM_SERVICE = "fastrdp-tgt"


class TgtError(Exception):
    """No TGT. The message never contains the password."""


async def obtain(user: LocalUser, password: str) -> None:
    """Get a TGT for `user` into the user's credential cache. Raises TgtError."""
    try:
        ccname = await asyncio.to_thread(pamauth.establish_credentials, PAM_SERVICE, user.name, password)
    except pamauth.PamError as exc:
        raise TgtError(f"PAM service {PAM_SERVICE}: {exc}") from None
    # pam_sss puts the cache sssd used into the PAM environment ("KCM:" by default);
    # check that one, not whatever the default would be for another ccache template.
    env = {"KRB5CCNAME": ccname} if ccname else None
    try:
        res = await sysutil.run_dropped(user, "klist", "-s", env=env)
    except (sysutil.CommandError, OSError) as exc:
        raise TgtError(f"klist: {exc}") from None
    if res.rc != 0:
        raise TgtError("authenticated, but no valid TGT in the user's credential cache "
                       "(sssd offline or cached authentication, or not a Kerberos account)")
