# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""GNOME 50+ (Wayland only) via GDM headless sessions + gnome-remote-desktop.

Per user:
  1. configure g-r-d *headless* mode inside the user's systemd manager
     (port, per-user TLS cert, random per-session RDP credentials),
  2. enable gnome-remote-desktop-headless.service (WantedBy=gnome-session.target)
     for the runtime of the user manager (/run/user/<uid>, not $HOME),
  3. start GDM's gnome-headless-session@<user>.service, which creates a real
     logind session running gnome-shell headless,
  4. wait until g-r-d listens on the port as that user.
The proxy then connects with the random credentials (NLA). The user never sees
a GDM greeter: authentication and MFA already happened at the proxy.
"""

from __future__ import annotations

import time

from .. import netcheck, sysutil
from ..identity import LocalUser
from ..state import Session
from .base import Backend, BackendError, LoginRequest, Target

GRD_USER_UNIT = "gnome-remote-desktop-headless.service"
RDP_USER = "fastrdp"


class GnomeBackend(Backend):
    name = "gnome"

    def unit(self, user: LocalUser) -> str:
        return self.bcfg.unit.format(user=user.name)

    async def _running(self, user: LocalUser, session: Session | None) -> bool:
        return (
            session is not None
            and await sysutil.unit_active(self.unit(user))
            and netcheck.listener_uids(session.port) == {user.uid}
        )

    async def ensure(self, req: LoginRequest) -> Target:
        user = req.user
        session = self.state.get(user.name, self.name)
        if await self._running(user, session):
            session.last_login = time.time()
            self.state.put(session)
            return self.target_for(session)

        port = self.allocate_port()
        try:
            return await self._start(req, port)
        except sysutil.CommandError as exc:  # e.g. back-end certificate creation
            raise BackendError(f"GNOME session for {user.name}: {exc}") from None
        finally:
            self.release_port(port)

    async def _start(self, req: LoginRequest, port: int) -> Target:
        user = req.user
        secret = self.new_secret()
        crt, key = await sysutil.ensure_backend_cert(user, self.cfg.broker.state_dir)
        grdctl = ("grdctl", "--headless", "rdp")
        try:
            await sysutil.run_as_user(user, *grdctl, "set-tls-cert", crt)
            await sysutil.run_as_user(user, *grdctl, "set-tls-key", key)
            await sysutil.run_as_user(user, *grdctl, "set-port", str(port))
            await sysutil.run_as_user(user, *grdctl, "disable-port-negotiation")
            await sysutil.run_as_user(user, *grdctl, "set-credentials", RDP_USER, input=secret + "\n")
            await sysutil.run_as_user(user, *grdctl, "enable")
            # --runtime: the link goes to $XDG_RUNTIME_DIR/systemd/user (tmpfs), part of the
            # user unit search path, not to ~/.config/systemd/user, which the user manager
            # cannot read when $HOME is Kerberized NFS and it starts without a TGT.
            await sysutil.run_as_user(user, "systemctl", "--user", "--runtime", "enable", GRD_USER_UNIT)
            if await sysutil.unit_active(self.unit(user)):
                # Session alive but g-r-d gone or on another port: restart only g-r-d.
                await sysutil.run_as_user(user, "systemctl", "--user", "restart", GRD_USER_UNIT)
            else:
                await sysutil.start_unit(self.unit(user))
            session = Session(
                user=user.name, backend=self.name, desktop=req.desktop.name,
                port=port, rdp_user=RDP_USER, rdp_password=secret,
            )
            self.state.put(session)
            await sysutil.wait_for_listener(port, user.uid, self.cfg.broker.session_start_timeout)
        except sysutil.CommandError as exc:
            raise BackendError(f"GNOME session for {user.name}: {exc}") from None
        return self.target_for(session)

    async def logout(self, user: LocalUser) -> None:
        await sysutil.stop_unit(self.unit(user))
        self.state.drop(user.name, self.name)
