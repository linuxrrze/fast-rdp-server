# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""X11 desktops through xrdp + xorgxrdp.

xrdp listens on loopback only and its PAM stack (xrdp-sesman) accepts nothing
but one-time broker tokens (pam_fastrdp_token). xrdp itself handles session
reconnects; the broker only tells startwm.sh which desktop to start via
/run/fastrdp/desktop/<user>.
"""

from __future__ import annotations

import os

from .. import netcheck, sysutil
from ..identity import LocalUser
from ..state import Session
from .base import Backend, BackendError, LoginRequest, Target


class XrdpBackend(Backend):
    name = "xrdp"

    def _write_desktop_choice(self, user: LocalUser, xsession: str) -> None:
        ddir = os.path.join(self.cfg.broker.runtime_dir, "desktop")
        os.makedirs(ddir, exist_ok=True)
        os.chmod(ddir, 0o755)  # startwm.sh reads it as the user; the broker's umask is 077
        path = os.path.join(ddir, user.name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(xsession + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)

    async def ensure(self, req: LoginRequest) -> Target:
        expected = self.expected_listener_uid(req.user)
        uids = netcheck.listener_uids(self.bcfg.port)
        if uids != {expected}:
            raise BackendError(
                f"xrdp listener on port {self.bcfg.port} not owned by uid {expected} (found {sorted(uids)})"
            )
        self._write_desktop_choice(req.user, req.desktop.xsession)
        token = self.tokens.issue(req.user.name, req.password)
        self.state.put(Session(user=req.user.name, backend=self.name, desktop=req.desktop.name))
        return Target(
            host=self.bcfg.host,
            port=self.bcfg.port,
            username=req.user.name,
            password=token,
            domain="",
            security=self.bcfg.security,
        )

    async def logout(self, user: LocalUser) -> None:
        # xrdp sessions are ordinary logind sessions of the user.
        await sysutil.run("loginctl", "terminate-user", user.name, check=False)
        self.state.drop(user.name, self.name)
