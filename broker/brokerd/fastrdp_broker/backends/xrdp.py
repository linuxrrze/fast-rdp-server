# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""X11 desktops through xrdp + xorgxrdp.

xrdp listens on loopback only and its PAM stack (xrdp-sesman) accepts nothing
but one-time broker tokens (pam_fastrdp_token). xrdp itself handles session
reconnects; the broker only tells startwm.sh which desktop to start via
/run/fastrdp/desktop/<user>.

xrdp sessions are the user's logind sessions opened through the xrdp-sesman PAM
service (pam_systemd type=x11). Only those are touched: a logout must not end the
user's SSH or other desktop sessions, and a reconnect keeps the desktop that is
actually running.
"""

from __future__ import annotations

import logging
import os
import time

from .. import netcheck, sysutil
from ..identity import LocalUser
from ..state import Session
from .base import Backend, BackendError, LoginRequest, Target

log = logging.getLogger("fastrdp.xrdp")


PAM_SERVICE = "xrdp-sesman"


class XrdpBackend(Backend):
    name = "xrdp"
    obtains_tgt = True  # the token carries the password to pam_sss in xrdp-sesman

    async def live_sessions(self, user_name: str) -> list[str]:
        """logind session ids of the user's running xrdp sessions."""
        res = await sysutil.run("loginctl", "list-sessions", "--no-legend", check=False)
        ids = []
        for line in res.stdout.splitlines():
            cols = line.split()
            if len(cols) < 3 or cols[2] != user_name:
                continue
            info = await sysutil.run(
                "loginctl", "show-session", cols[0], "-p", "Service", "-p", "State", check=False
            )
            props = dict(kv.split("=", 1) for kv in info.stdout.splitlines() if "=" in kv)
            if props.get("Service") == PAM_SERVICE and props.get("State") != "closing":
                ids.append(cols[0])
        return ids

    async def alive(self, session: Session) -> bool:
        return bool(await self.live_sessions(session.user))

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
        existing = self.state.get(req.user.name, self.name)
        if existing and await self.live_sessions(req.user.name):
            # xrdp reconnects to the running session; startwm.sh does not run again, so
            # the recorded desktop stays the one that is actually running.
            if existing.desktop != req.desktop.name:
                log.info("%s: reconnecting to running %s session (requested %s)",
                         req.user.name, existing.desktop, req.desktop.name)
            existing.last_login = time.time()
            self.state.put(existing)
        else:
            self._write_desktop_choice(req.user, req.desktop.xsession)
            self.state.put(Session(user=req.user.name, backend=self.name, desktop=req.desktop.name))
        token = self.tokens.issue(req.user.name, req.password)
        return Target(
            host=self.bcfg.host,
            port=self.bcfg.port,
            username=req.user.name,
            password=token,
            domain="",
            security=self.bcfg.security,
        )

    async def logout(self, user: LocalUser) -> None:
        # Only the xrdp sessions; terminate-user would also end SSH and other logins.
        for sid in await self.live_sessions(user.name):
            await sysutil.run("loginctl", "terminate-session", sid, check=False)
        self.state.drop(user.name, self.name)
