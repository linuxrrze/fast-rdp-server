# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""fastrdp-brokerd: authorises proxy logins and starts/reuses per-user sessions."""

from __future__ import annotations

import asyncio
import grp
import logging
import os
import pwd
from collections import defaultdict

from . import identity, pamauth
from .backends import BACKENDS, Backend, BackendError, LoginRequest
from .config import Config
from .identity import IdentityError, LocalUser
from .mfa import MfaDenied, SecondFactor, split_otp
from .protocol import ProtocolError, int_field, peer_uid, read_message, str_field, write_message
from .state import StateStore
from .tokens import WEB_TOKEN_PREFIX, TokenStore

log = logging.getLogger("fastrdp.broker")


class Denied(Exception):
    """Login refused. The message is logged; the client only sees a generic error."""


class Broker:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = StateStore(cfg.broker.state_dir)
        self.tokens = TokenStore(cfg.broker.token_ttl)
        # One-time tokens for browser logins (fastrdp-webgate -> Guacamole -> proxy).
        self.web_tokens = TokenStore(cfg.web.token_ttl, WEB_TOKEN_PREFIX)
        self.web_uid = None
        if cfg.web.enabled:
            self.web_uid = pwd.getpwnam(cfg.web.gateway_user).pw_uid
        self.mfa = SecondFactor(cfg.mfa)
        self.backends: dict[str, Backend] = {
            name: cls(cfg, self.state, self.tokens) for name, cls in BACKENDS.items()
        }
        self.user_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.proxy_uid = pwd.getpwnam(cfg.broker.proxy_user).pw_uid
        self.active: dict[str, str] = {}  # proxy session id -> user

    # ---------------------------------------------------------------- login
    async def first_factor(
        self, msg: dict
    ) -> tuple[LocalUser, str | None, str | None, str | None]:
        """Returns (user, real password or None, OTP or None, MFA already done by)."""
        method = str_field(msg, "method", required=True)
        rhost = str_field(msg, "client_address")
        rdp_user = identity.normalize_rdp_user(str_field(msg, "user", required=True))
        secret = str_field(msg, "password")

        if method == "nla":
            # The proxy module already compared the CredSSP user with the Kerberos
            # principal; check again here so neither side can be bypassed alone.
            principal = str_field(msg, "principal", required=True)
            name, realm = identity.split_principal(principal)
            if self.cfg.auth.realms and realm not in self.cfg.auth.realms:
                raise Denied(f"realm {realm} not accepted")
            if name.lower() != rdp_user.lower():
                raise Denied(f"principal {principal} does not match user {rdp_user}")
            user = identity.resolve(name, realm, self.cfg.auth)
            try:
                await asyncio.to_thread(pamauth.account_ok, self.cfg.auth.pam_service, user.name, rhost)
            except pamauth.PamError as exc:
                raise Denied(f"account check failed for {user.name}: {exc}") from None
            if msg.get("smartcard") is True:
                # Smartcard logon (PKINIT): whatever came as "password" is the card PIN and must
                # never reach pam_sss or the MFA server. The flag itself is client-supplied, so
                # it does not replace MFA; exempt groups whose accounts *require* smartcards.
                log.info("smartcard logon for %s", user.name)
                secret = None
            return user, secret, None, None

        if method == "tls" and secret and secret.startswith(WEB_TOKEN_PREFIX):
            # Browser login: the webgate authenticated the user (incl. MFA) at the IdP.
            if not self.cfg.web.enabled:
                raise Denied("web token presented but [web] is disabled")
            if rhost not in self.cfg.web.allowed_clients:
                raise Denied(f"web token from unexpected client address {rhost}")
            user = identity.resolve(rdp_user, None, self.cfg.auth)
            ok, _ = self.web_tokens.redeem(user.name, secret)
            if not ok:
                raise Denied(f"invalid or reused web token for {user.name}")
            try:
                await asyncio.to_thread(pamauth.account_ok, self.cfg.auth.pam_service, user.name, rhost)
            except pamauth.PamError as exc:
                raise Denied(f"account check failed for {user.name}: {exc}") from None
            return user, None, None, "idp"

        if method == "tls":
            if not self.cfg.auth.allow_tls_password_login:
                raise Denied("password logins without NLA are disabled")
            if not secret:
                raise Denied("no password supplied")
            user = identity.resolve(rdp_user, None, self.cfg.auth)
            otp = None
            if self.mfa.wants_otp_in_password and not self.mfa.exempt(user.groups):
                split = split_otp(secret, self.cfg.mfa)
                if split:
                    secret, otp = split
                elif self.cfg.mfa.mode == "otp":
                    raise Denied(f"{user.name}: no OTP appended to password")
            try:
                await asyncio.to_thread(
                    pamauth.authenticate, self.cfg.auth.pam_service, user.name, secret, rhost
                )
            except pamauth.PamError as exc:
                raise Denied(f"password check failed for {user.name}: {exc}") from None
            return user, secret, otp, None

        raise Denied(f"unknown method {method!r}")

    async def login(self, msg: dict) -> dict:
        session_id = str_field(msg, "session_id", required=True, max_len=64)
        user, password, otp, mfa_done = await self.first_factor(msg)

        if not identity.user_allowed(user, self.cfg.auth):
            raise Denied(f"{user.name} is not in an allowed group")

        if mfa_done:
            log.info("second factor for %s already verified by %s", user.name, mfa_done)
        elif not self.mfa.exempt(user.groups):
            try:
                factor = await self.mfa.verify(user.name, otp, password)
            except MfaDenied as exc:
                raise Denied(f"MFA failed for {user.name}: {exc}") from None
            log.info("second factor ok for %s via %s", user.name, factor)

        try:
            desktop_name = identity.choose_desktop(self.cfg, user, str_field(msg, "desktop_hint"))
        except IdentityError as exc:
            raise Denied(str(exc)) from None
        desktop = self.cfg.desktops[desktop_name]
        width = int_field(msg, "width", 320, 8192)
        height = int_field(msg, "height", 200, 8192)
        if not (width and height):
            w, h = self.cfg.default_geometry.split("x")
            width, height = int(w), int(h)

        backend = self.backends[desktop.backend]
        async with self.user_locks[user.name]:
            target = await backend.ensure(LoginRequest(user, desktop, password, width, height))
        self.active[session_id] = user.name
        log.info(
            "login %s session=%s desktop=%s -> %s:%d (%s)",
            user.name, session_id, desktop.name, target.host, target.port, target.security,
        )
        return {"ok": True, "user": user.name, "desktop": desktop.name, "target": target.as_dict()}

    async def issue_web_token(self, msg: dict) -> dict:
        """fastrdp-webgate asks for a one-time login token after OIDC login."""
        name = identity.normalize_rdp_user(str_field(msg, "user", required=True))
        user = identity.resolve(name, None, self.cfg.auth)
        if not identity.user_allowed(user, self.cfg.auth):
            raise Denied(f"{user.name} is not in an allowed group")
        try:
            await asyncio.to_thread(pamauth.account_ok, self.cfg.auth.pam_service, user.name, None)
        except pamauth.PamError as exc:
            raise Denied(f"account check failed for {user.name}: {exc}") from None
        desktops = [d for d in self.cfg.desktops if identity.desktop_allowed(self.cfg, d, user)]
        log.info("web token issued for %s", user.name)
        return {
            "ok": True,
            "user": user.name,
            "token": self.web_tokens.issue(user.name, None),
            "desktops": desktops,
        }

    # ---------------------------------------------------------------- admin
    async def status(self) -> dict:
        return {
            "ok": True,
            "sessions": [s.public() for s in self.state.sessions.values()],
            "connected": len(self.active),
            "pending_tokens": len(self.tokens),
            "pending_web_tokens": len(self.web_tokens),
        }

    async def logout(self, msg: dict) -> dict:
        name = str_field(msg, "user", required=True)
        user = identity.resolve(name, None, self.cfg.auth)
        for backend in self.backends.values():
            if self.state.get(user.name, backend.name):
                await backend.logout(user)
        return {"ok": True}

    # ------------------------------------------------------------- sockets
    async def handle_broker_client(self, reader, writer) -> None:
        uid = peer_uid(writer)
        try:
            while (msg := await read_message(reader)) is not None:
                op = msg["op"]
                try:
                    if op == "login" and uid == self.proxy_uid:
                        reply = await self.login(msg)
                    elif op == "end" and uid == self.proxy_uid:
                        user = self.active.pop(str(msg.get("session_id")), None)
                        log.info("session end %s user=%s", msg.get("session_id"), user)
                        reply = {"ok": True}
                    elif op == "web_token" and self.web_uid is not None and uid == self.web_uid:
                        reply = await self.issue_web_token(msg)
                    elif op == "status" and uid == 0:
                        reply = await self.status()
                    elif op == "logout" and uid == 0:
                        reply = await self.logout(msg)
                    else:
                        log.warning("op %r not permitted for uid %d", op, uid)
                        reply = {"ok": False, "error": "not permitted"}
                except (Denied, IdentityError) as exc:
                    log.warning("denied: %s", exc)
                    reply = {"ok": False, "error": "access denied"}
                except BackendError as exc:
                    log.error("backend error: %s", exc)
                    reply = {"ok": False, "error": "session could not be started"}
                await write_message(writer, reply)
        except ProtocolError as exc:
            log.warning("protocol error from uid %d: %s", uid, exc)
        except Exception:
            log.exception("unexpected error")
        finally:
            writer.close()

    async def handle_token_client(self, reader, writer) -> None:
        uid = peer_uid(writer)
        try:
            if uid != 0:
                log.warning("token socket: rejected uid %d", uid)
                return
            msg = await read_message(reader)
            if msg is None or msg["op"] != "redeem":
                return
            user = str_field(msg, "user", required=True)
            token = str_field(msg, "token", required=True)
            ok, password = self.tokens.redeem(user, token)
            if not ok:
                log.warning("token redemption failed for %s", user)
            await write_message(writer, {"ok": ok, "password": password if ok else None})
        except ProtocolError as exc:
            log.warning("token socket protocol error: %s", exc)
        finally:
            writer.close()

    async def serve(self) -> None:
        servers = []
        for path, handler, mode in (
            (self.cfg.broker.socket, self.handle_broker_client, 0o660),
            (self.cfg.broker.token_socket, self.handle_token_client, 0o600),
        ):
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            srv = await asyncio.start_unix_server(handler, path, limit=64 * 1024)
            os.chmod(path, mode)
            servers.append(srv)
        # Clients reach broker.sock through its group; every operation re-checks the peer uid.
        if self.cfg.broker.socket_group:
            gid = grp.getgrnam(self.cfg.broker.socket_group).gr_gid
        else:
            gid = pwd.getpwnam(self.cfg.broker.proxy_user).pw_gid
        os.chown(self.cfg.broker.socket, -1, gid)
        log.info("listening on %s and %s", self.cfg.broker.socket, self.cfg.broker.token_socket)
        await asyncio.gather(*(s.serve_forever() for s in servers))
