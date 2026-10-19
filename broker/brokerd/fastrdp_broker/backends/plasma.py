"""Plasma 6 (Wayland) via a headless kwin_wayland --virtual session + KRdp.

The system unit fastrdp-plasma@<user>.service (shipped in broker/session/)
opens a logind session through PAM (service fastrdp-session) and runs
/usr/libexec/fastrdp/session-plasma, which starts Plasma on KWin's virtual
backend and krdpserver on the allocated loopback port. Settings come from a
root-only EnvironmentFile written here.

Headless KRdp is not an officially supported Plasma mode yet; see
docs/desktop-matrix.md for the validation status.
"""

from __future__ import annotations

import os
import time

from .. import netcheck, sysutil
from ..identity import LocalUser
from ..state import Session
from .base import Backend, BackendError, LoginRequest, Target

RDP_USER = "fastrdp"


class PlasmaBackend(Backend):
    name = "plasma"

    def unit(self, user: LocalUser) -> str:
        return self.bcfg.unit.format(user=user.name)

    def env_path(self, user: LocalUser) -> str:
        return os.path.join(self.cfg.broker.runtime_dir, "sessions", f"{user.name}.plasma.env")

    def _write_env(self, user: LocalUser, values: dict[str, str]) -> None:
        path = self.env_path(user)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for k, v in values.items():
                fh.write(f"{k}={v}\n")
        os.replace(path + ".tmp", path)

    async def ensure(self, req: LoginRequest) -> Target:
        user = req.user
        session = self.state.get(user.name, self.name)
        if (
            session is not None
            and await sysutil.unit_active(self.unit(user))
            and netcheck.listener_uids(session.port) == {user.uid}
        ):
            session.last_login = time.time()
            self.state.put(session)
            return self.target_for(session)

        port = self.allocate_port()
        try:
            return await self._start(req, port)
        finally:
            self.release_port(port)

    async def _start(self, req: LoginRequest, port: int) -> Target:
        user = req.user
        secret = self.new_secret()
        crt, key = await sysutil.ensure_backend_cert(user, self.cfg.broker.state_dir)
        self._write_env(
            user,
            {
                "FASTRDP_PORT": str(port),
                "FASTRDP_RDP_USER": RDP_USER,
                "FASTRDP_RDP_PASSWORD": secret,
                "FASTRDP_WIDTH": str(req.width),
                "FASTRDP_HEIGHT": str(req.height),
                "FASTRDP_TLS_CERT": crt,
                "FASTRDP_TLS_KEY": key,
            },
        )
        session = Session(
            user=user.name, backend=self.name, desktop=req.desktop.name,
            port=port, rdp_user=RDP_USER, rdp_password=secret,
        )
        self.state.put(session)
        try:
            # A stale unit (e.g. KRdp crashed) is restarted with the new settings.
            await sysutil.run("systemctl", "restart", "--no-block", self.unit(user))
            await sysutil.wait_for_listener(port, user.uid, self.cfg.broker.session_start_timeout)
        except sysutil.CommandError as exc:
            raise BackendError(f"Plasma session for {user.name}: {exc}") from None
        return self.target_for(session)

    async def logout(self, user: LocalUser) -> None:
        await sysutil.stop_unit(self.unit(user))
        self.state.drop(user.name, self.name)
