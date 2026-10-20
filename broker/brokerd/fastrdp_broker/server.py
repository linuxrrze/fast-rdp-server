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
from concurrent.futures import ThreadPoolExecutor

from . import conntype, identity, pamauth, tgt
from .backends import BACKENDS, Backend, BackendError, LoginRequest, Target
from .config import Config
from .identity import IdentityError, LocalUser
from .mfa import MfaDenied, SecondFactor, split_otp
from .protocol import ProtocolError, int_field, peer_uid, read_message, str_field, write_message
from .state import StateStore
from .tokens import WEB_TOKEN_PREFIX, TokenStore

log = logging.getLogger("fastrdp.broker")


class Denied(Exception):
    """Login refused. The message is logged; the client only sees a generic error and
    `reason`, one of the refusal reasons in protocol.py."""

    def __init__(self, message: str, reason: str = "denied"):
        super().__init__(message)
        self.reason = reason


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
        if cfg.mfa.nla_kdc_enforced and cfg.mfa.mode != "none":
            log.warning(
                "[mfa] nla_kdc_enforced: Kerberos NLA logins from %s skip the %s second factor; "
                "the KDC must require passkey/PKINIT pre-authentication for TERMSRV tickets "
                "(FreeIPA: ipa service-mod TERMSRV/<host> --auth-ind=passkey --auth-ind=pkinit)",
                ", ".join(cfg.auth.realms), cfg.mfa.mode,
            )
        self.backends: dict[str, Backend] = {
            name: cls(cfg, self.state, self.tokens) for name, cls in BACKENDS.items()
        }
        self.user_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.proxy_uid = pwd.getpwnam(cfg.broker.proxy_user).pw_uid
        self.active: dict[str, str] = {}  # proxy session id -> user
        # Reads of users' home directories run here, never in the event loop and never in
        # the default executor (PAM checks): a hung NFS mount may block a thread forever.
        self.home_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fastrdp-home")

    # ---------------------------------------------------------------- desktop
    async def read_desktop_pref(self, user: LocalUser) -> str | None:
        """~/.config/fastrdp/desktop with a time limit; None if unreadable or too slow."""
        timeout = self.cfg.broker.home_read_timeout
        if timeout <= 0:
            return None
        fut = asyncio.get_running_loop().run_in_executor(self.home_pool, identity.read_desktop_pref, user)
        try:
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            log.warning(
                "%s: no answer from %s within %.1fs (home on a hung network filesystem?); "
                "using the default desktop", user.name, user.home, timeout,
            )
            return None

    async def choose_desktop(self, user: LocalUser, hint: str | None) -> str:
        """identity.choose_desktop, reading the user's preference file off the event loop."""
        hinted = identity.hinted_desktop(self.cfg, user, hint)
        if hinted:
            return hinted
        pref = await self.read_desktop_pref(user)
        return identity.choose_desktop(self.cfg, user, None, pref=pref)

    def authz_reason(self, user: LocalUser, proven: bool) -> str:
        """Reason for refusing a user whose first factor checked out (allowed groups,
        account check). "not_allowed" confirms the credentials, so it is given only if the
        client knows that already (NLA: CredSSP succeeded; web: the IdP signed the user in)
        or no second factor is due. A TLS password login that still owes its second factor
        gets "denied": the refusal must not confirm a password to somebody without it."""
        return "not_allowed" if proven or self.mfa.exempt(user.groups) else "denied"

    # ---------------------------------------------------------------- kerberos
    def require_credential(self, user: LocalUser, password: str | None) -> None:
        """[broker] session_tgt = required: refuse, before MFA, logins that cannot give
        the session a TGT (no password: Kerberos SSO without delegation, smartcard, web)."""
        if self.cfg.broker.session_tgt == "required" and not password:
            raise Denied(
                f"{user.name}: login without a password, but [broker] session_tgt = required "
                "(Kerberized home?); log in with NLA and a typed/delegated password, or TLS"
            )

    async def session_tgt(self, user: LocalUser, password: str | None, backend: Backend) -> None:
        """TGT for back-ends that never see the password (GNOME, Plasma), before they
        start, on every login: a reconnect with a password refreshes an expiring TGT."""
        mode = self.cfg.broker.session_tgt
        if mode == "off" or backend.obtains_tgt or not password:
            return  # without a password "required" already refused the login
        try:
            await tgt.obtain(user, password)
        except tgt.TgtError as exc:
            if mode == "required":
                raise Denied(f"{user.name}: no Kerberos TGT for the {backend.name} session: {exc}") from None
            log.warning("%s: no Kerberos TGT for the %s session (Kerberos/NFS access will fail): %s",
                        user.name, backend.name, exc)
            return
        log.info("%s: Kerberos TGT stored for the %s session", user.name, backend.name)

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
            # The Kerberos principal (from the KDC's ticket, via the proxy module) is the
            # identity. The CredSSP user name is informational: a UPN or DOMAIN\user may
            # differ from the account name (docs/windows-clients.md §3.6).
            principal = str_field(msg, "principal", required=True)
            name, realm = identity.split_principal(principal)
            if self.cfg.auth.realms and realm not in self.cfg.auth.realms:
                raise Denied(f"realm {realm} not accepted")
            user = identity.resolve_principal(name, realm, self.cfg.auth)
            raw_user = str_field(msg, "user", required=True)
            if secret and identity.names_other_account(raw_user, user):
                # A password delegated for somebody else must not reach pam_sss or MFA.
                log.warning("principal %s: CredSSP user %r is another account; "
                            "delegated password not used", principal, raw_user)
                secret = None
            try:
                await asyncio.to_thread(pamauth.account_ok, self.cfg.auth.pam_service, user.name, rhost)
            except pamauth.PamError as exc:
                raise Denied(f"account check failed for {user.name}: {exc}", "not_allowed") from None
            if msg.get("smartcard") is True:
                # Smartcard logon (PKINIT): whatever came as "password" is the card PIN and must
                # never reach pam_sss or the MFA server. The flag itself is client-supplied, so
                # it does not replace MFA; exempt groups whose accounts *require* smartcards.
                log.info("smartcard logon for %s", user.name)
                secret = None
            if self.cfg.mfa.nla_kdc_enforced and self.cfg.mfa.mode != "none" and realm in self.cfg.auth.realms:
                # The ticket for TERMSRV came from this realm's KDC, which (operator
                # assertion, checked by preflight for FreeIPA) only issues it after
                # passkey/PKINIT pre-authentication. Only this branch: TLS and web never.
                log.info("%s: Kerberos NLA login (principal %s); second factor skipped: "
                         "[mfa] nla_kdc_enforced (KDC-enforced strong pre-authentication)",
                         user.name, principal)
                return user, secret, None, "kdc"
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
                raise Denied(f"account check failed for {user.name}: {exc}", "not_allowed") from None
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
                    raise Denied(f"{user.name}: no OTP appended to password", "mfa_failed")
            try:
                await asyncio.to_thread(
                    pamauth.authenticate, self.cfg.auth.pam_service, user.name, secret, rhost
                )
            except pamauth.PamError as exc:
                # A failed account check (expired, locked) follows a correct password.
                reason = self.authz_reason(user, False) if exc.step == "account" else "denied"
                raise Denied(f"password check failed for {user.name}: {exc}", reason) from None
            return user, secret, otp, None

        raise Denied(f"unknown method {method!r}")

    async def login(self, msg: dict) -> dict:
        session_id = str_field(msg, "session_id", required=True, max_len=64)
        user, password, otp, mfa_done = await self.first_factor(msg)

        if not identity.user_allowed(user, self.cfg.auth):
            proven = msg.get("method") == "nla" or mfa_done is not None
            raise Denied(f"{user.name} is not in an allowed group", self.authz_reason(user, proven))
        self.require_credential(user, password)

        if mfa_done:
            log.info("second factor for %s already verified by %s", user.name, mfa_done)
        elif not self.mfa.exempt(user.groups):
            try:
                factor = await self.mfa.verify(user.name, otp, password)
            except MfaDenied as exc:
                raise Denied(f"MFA failed for {user.name}: {exc}", exc.reason) from None
            log.info("second factor ok for %s via %s", user.name, factor)

        try:
            desktop_name = await self.choose_desktop(user, str_field(msg, "desktop_hint"))
        except IdentityError as exc:
            raise Denied(str(exc), exc.reason) from None
        desktop = self.cfg.desktops[desktop_name]
        width = int_field(msg, "width", 320, 8192)
        height = int_field(msg, "height", 200, 8192)
        if not (width and height):
            w, h = self.cfg.default_geometry.split("x")
            width, height = int(w), int(h)

        backend = self.backends[desktop.backend]

        async def start() -> Target:
            async with self.user_locks[user.name]:
                await self.session_tgt(user, password, backend)
                return await backend.ensure(LoginRequest(user, desktop, password, width, height))

        # A session start that is under way completes even if the proxy gives up on this
        # login (handle_broker_client): stopping it halfway could leave a half-started
        # session behind, a finished one is simply there at the next login.
        starting = asyncio.ensure_future(start())
        try:
            target = await asyncio.shield(starting)
        except asyncio.CancelledError:
            starting.add_done_callback(lambda t: self._abandoned_start_done(t, user.name))
            raise
        self.active[session_id] = user.name
        log.info(
            "login %s session=%s desktop=%s -> %s:%d (%s)",
            user.name, session_id, desktop.name, target.host, target.port, target.security,
        )
        reply = {"ok": True, "user": user.name, "desktop": desktop.name, "target": target.as_dict()}
        self.add_connection_type(reply["target"], msg, backend, user)
        return reply

    @staticmethod
    def _abandoned_start_done(task: asyncio.Future, name: str) -> None:
        if task.cancelled():
            return
        if (exc := task.exception()) is not None:
            log.warning("%s: session start for an abandoned login failed: %s", name, exc)
        else:
            log.info("%s: session started for an abandoned login; it is reused at the next login", name)

    async def login_unless_abandoned(self, msg: dict, reader: asyncio.StreamReader) -> dict | None:
        """login(), cancelled when the proxy closes the connection first: the user gave up
        (closed the client during an MFA push) and the proxy dropped the request
        (fastrdp_plugin.c broker_call). Returns None then. Cancelling stops a push wait
        (mfa.py); a session start already under way completes (login()). The proxy sends
        nothing else while it waits, so data instead of EOF is a protocol error."""
        login = asyncio.ensure_future(self.login(msg))
        peer = asyncio.ensure_future(reader.read(1))
        try:
            await asyncio.wait({login, peer}, return_when=asyncio.FIRST_COMPLETED)
            finished = login.done()
        finally:
            for task in (login, peer):
                if not task.done():
                    task.cancel()
            # let the cancellations run: the reader must be free for the next message
            await asyncio.gather(login, peer, return_exceptions=True)
        if finished:
            return login.result()  # Denied etc. propagate as before
        if peer.exception() is None and peer.result():  # a reset counts as closed
            raise ProtocolError("data received while a login was pending")
        log.info("login of session %s abandoned: the proxy closed the connection (client gone)",
                 msg.get("session_id"))
        return None

    # ---------------------------------------------------------------- network
    def add_connection_type(self, target: dict, msg: dict, backend: Backend, user: LocalUser) -> None:
        """xrdp only: the connection type the module sends to the back-end instead of the
        client's AUTODETECT/unset one (conntype.py). gnome-remote-desktop and KRdp never
        read connectionType (they measure the link with their own auto-detection)."""
        if backend.name != "xrdp":
            return
        client_type = msg.get("connection_type")
        ct = conntype.for_backend(
            client_type, str_field(msg, "client_address"),
            self.cfg.network.lan, self.cfg.network.xrdp_autodetect_profile,
        )
        if ct:
            target["connection_type"] = ct
            log.info("%s: connection type %s towards xrdp (client sent %r)", user.name, ct, client_type)

    async def _web_user(self, msg: dict) -> tuple[identity.LocalUser, list[dict]]:
        """User named by fastrdp-webgate (OIDC-authenticated) and the desktops it may use."""
        name = identity.normalize_rdp_user(str_field(msg, "user", required=True))
        user = identity.resolve(name, None, self.cfg.auth)
        if not identity.user_allowed(user, self.cfg.auth):
            raise Denied(f"{user.name} is not in an allowed group", "not_allowed")
        self.require_credential(user, None)  # web logins never carry a password
        try:
            await asyncio.to_thread(pamauth.account_ok, self.cfg.auth.pam_service, user.name, None)
        except pamauth.PamError as exc:
            raise Denied(f"account check failed for {user.name}: {exc}", "not_allowed") from None
        desktops = [
            {"name": d.name, "label": d.label or d.name}
            for d in self.cfg.desktops.values()
            if identity.desktop_allowed(self.cfg, d.name, user)
        ]
        return user, desktops

    async def web_desktops(self, msg: dict) -> dict:
        """fastrdp-webgate lists the desktops for its chooser (no token issued)."""
        user, desktops = await self._web_user(msg)
        default = await self.choose_desktop(user, None)
        return {"ok": True, "user": user.name, "desktops": desktops, "default": default}

    async def issue_web_token(self, msg: dict) -> dict:
        """fastrdp-webgate asks for a one-time login token after OIDC login."""
        user, desktops = await self._web_user(msg)
        log.info("web token issued for %s", user.name)
        return {
            "ok": True,
            "user": user.name,
            "token": self.web_tokens.issue(user.name, None),
            "desktops": [d["name"] for d in desktops],
        }

    # ---------------------------------------------------------------- admin
    async def reap(self) -> None:
        """Drop records of sessions that no longer exist (e.g. xrdp sessions ended in-session)."""
        for s in list(self.state.sessions.values()):
            backend = self.backends.get(s.backend)
            if backend is not None and not await backend.alive(s):
                log.info("%s: %s session gone, dropping its record", s.user, s.backend)
                self.state.drop(s.user, s.backend)

    async def status(self) -> dict:
        await self.reap()
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
                        reply = await self.login_unless_abandoned(msg, reader)
                        if reply is None:
                            break
                    elif op == "end" and uid == self.proxy_uid:
                        user = self.active.pop(str(msg.get("session_id")), None)
                        log.info("session end %s user=%s", msg.get("session_id"), user)
                        reply = {"ok": True}
                    elif op == "web_token" and self.web_uid is not None and uid == self.web_uid:
                        reply = await self.issue_web_token(msg)
                    elif op == "web_desktops" and self.web_uid is not None and uid == self.web_uid:
                        reply = await self.web_desktops(msg)
                    elif op == "status" and uid == 0:
                        reply = await self.status()
                    elif op == "logout" and uid == 0:
                        reply = await self.logout(msg)
                    else:
                        log.warning("op %r not permitted for uid %d", op, uid)
                        reply = {"ok": False, "error": "not permitted", "reason": "denied"}
                except (Denied, IdentityError) as exc:
                    # The error text stays generic; `reason` lets the proxy pick the RDP
                    # error info (protocol.py).
                    log.warning("denied (%s): %s", exc.reason, exc)
                    reply = {"ok": False, "error": "access denied", "reason": exc.reason}
                except BackendError as exc:
                    log.error("backend error: %s", exc)
                    reply = {"ok": False, "error": "session could not be started", "reason": "backend"}
                try:
                    await write_message(writer, reply)
                except ConnectionError:
                    # The peer went away just before the reply (e.g. the proxy's client
                    # closed as the login completed). The proxy never routed this session
                    # and will not report its end.
                    if op == "login" and reply.get("ok"):
                        self.active.pop(str(msg.get("session_id")), None)
                    log.info("uid %d closed the connection before the %r reply", uid, op)
                    break
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
