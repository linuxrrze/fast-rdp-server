# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
from __future__ import annotations

import os
import pwd
import secrets
from dataclasses import asdict, dataclass

from .. import netcheck, sysutil
from ..config import BackendSection, Config, Desktop
from ..identity import LocalUser
from ..state import Session, StateStore
from ..tokens import TokenStore


class BackendError(Exception):
    pass


@dataclass
class Target:
    host: str
    port: int
    username: str
    password: str
    domain: str
    security: str
    # SHA-256 (hex) of the back-end's TLS certificate: the proxy refuses any other one,
    # so whoever binds the port while the back-end is down cannot pose as it
    cert_sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class LoginRequest:
    user: LocalUser
    desktop: Desktop
    password: str | None  # the user's real password, if the proxy learned it
    width: int
    height: int


class Backend:
    name = ""
    # True when the back-end's own PAM stack receives the user's password and so gets
    # the Kerberos TGT itself (xrdp: pam_fastrdp_token -> pam_sss). Otherwise the broker
    # obtains it before the session starts ([broker] session_tgt, Broker.session_tgt).
    obtains_tgt = False

    def __init__(self, cfg: Config, state: StateStore, tokens: TokenStore):
        self.cfg = cfg
        self.bcfg: BackendSection = cfg.backends[self.name]
        self.state = state
        self.tokens = tokens

    async def ensure(self, req: LoginRequest) -> Target:
        raise NotImplementedError

    async def alive(self, session: Session) -> bool:
        """Whether a recorded session still exists. Default: trust the record."""
        return True

    async def logout(self, user: LocalUser) -> None:
        raise NotImplementedError

    async def blocked_by(self, user: LocalUser) -> str | None:
        """What keeps a new session of this back-end from starting for the user now (for
        the log and the desktop picker), None if nothing does. Default: nothing."""
        return None

    # helpers for per-user loopback back-ends
    def allocate_port(self) -> int:
        lo, hi = self.cfg.broker.port_range
        taken = self.state.ports_in_use() | {p for p, _ in netcheck.listeners()}
        for port in range(lo, hi + 1):
            if port not in taken and not netcheck.port_in_use(port):
                # Reserved synchronously (no await in between), released by release_port().
                self.state.reserved_ports.add(port)
                return port
        raise BackendError("no free back-end port")

    def release_port(self, port: int) -> None:
        self.state.reserved_ports.discard(port)

    @staticmethod
    def new_secret() -> str:
        return secrets.token_urlsafe(24)

    def certificate_for(self, user_name: str) -> str:
        """The certificate the back-end presents: configured, or the per-user one
        (sysutil.ensure_backend_cert)."""
        return self.bcfg.certificate or os.path.join(
            self.cfg.broker.state_dir, "users", user_name, "tls.crt")

    def cert_sha256(self, user_name: str) -> str:
        try:
            return sysutil.cert_sha256(self.certificate_for(user_name))
        except sysutil.CommandError as exc:
            raise BackendError(str(exc)) from None

    def target_for(self, session: Session) -> Target:
        return Target(
            host=self.bcfg.host,
            port=session.port,
            username=session.rdp_user,
            password=session.rdp_password,
            domain="",
            security=self.bcfg.security,
            cert_sha256=self.cert_sha256(session.user),
        )

    def expected_listener_uid(self, user: LocalUser) -> int:
        if not self.bcfg.listener_user:
            return user.uid
        try:
            return pwd.getpwnam(self.bcfg.listener_user).pw_uid
        except KeyError:
            raise BackendError(f"listener user {self.bcfg.listener_user!r} does not exist") from None
