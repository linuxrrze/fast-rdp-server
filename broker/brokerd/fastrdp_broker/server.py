# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""fastrdp-brokerd: authorises proxy logins and starts/reuses per-user sessions."""

from __future__ import annotations

import asyncio
import grp
import json
import logging
import os
import pwd
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Awaitable, Callable

from . import conntype, home, identity, pamauth, tgt, tickets
from .backends import BACKENDS, Backend, BackendError, LoginRequest, Target
from .config import WEB_APPROVAL_MODES, Config
from .desktopprefs import DesktopPrefs, PrefsError
from .grace import GraceKey, ReconnectGrace
from .identity import IdentityError, LocalUser
from .mfa import ApprovalError, ApprovalEvents, CodeEntry, MfaDenied, SecondFactor, split_otp
from .protocol import ProtocolError, int_field, peer_uid, read_message, str_field, write_message
from .state import StateStore
from .tokens import WEB_TOKEN_PREFIX, TokenStore
from .ui import CODE_DIGITS, WaitingTexts

log = logging.getLogger("fastrdp.broker")

# Sends one progress message to the proxy module (protocol.py "progress"); never blocks.
Progress = Callable[[dict], None]
# Sends the desktop picker's prompt and waits up to the given seconds for the module's
# answer (login_unless_abandoned): (answered, desktop name or None for the default).
AskDesktop = Callable[[dict, float], Awaitable[tuple[bool, str | None]]]
# The broker waits this much longer than the picker's countdown for the answer.
PICKER_GRACE = 5
# {"op": "code"} lines per login ([mfa] code_or_web): attempts at most 10, plus codes
# typed while Keycloak was unreachable or after the field closed (dropped)
MAX_CODE_LINES = 32
# A missing [web] gateway_user (fastrdp-webgate installed later) is looked up again at most
# this often (seconds); until it exists, the webgate's operations are refused.
WEB_UID_RETRY = 30


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
        # Desktops chosen for RDP logins on the webgate's chooser page (web_set_desktop).
        self.desktop_prefs = DesktopPrefs(cfg.broker.state_dir)
        self.tokens = TokenStore(cfg.broker.token_ttl)
        # One-time tokens for browser logins (fastrdp-webgate -> Guacamole -> proxy).
        self.web_tokens = TokenStore(cfg.web.token_ttl, WEB_TOKEN_PREFIX)
        # uid of [web] gateway_user, the only peer of the webgate's operations (web_gateway_uid)
        self.web_uid: int | None = None
        self.web_uid_missing_since: float | None = None  # monotonic time of the last failed lookup
        if cfg.web.enabled and self.web_gateway_uid() is None:
            # Not fatal: RDP logins do not need the webgate.
            log.error("[web] gateway_user %r does not exist: web logins, the desktop chooser and the "
                      "approval page are refused until it does (looked up again every %ds); RDP logins "
                      "are not affected. Install fastrdp-webgate (creates %s), re-run the deployment, or "
                      "set [web] gateway_user to the webgate's account", cfg.web.gateway_user,
                      WEB_UID_RETRY, cfg.web.gateway_user)
            if cfg.mfa.mode == "web":
                log.error("[mfa] web: RDP logins that owe a second factor are refused while the "
                          "webgate's account is missing (nobody can approve them)")
            elif cfg.mfa.mode == "push_or_web":
                log.warning("[mfa] push_or_web: only push can approve RDP logins while the webgate's "
                            "account is missing")
        self.mfa = SecondFactor(cfg.mfa)
        # Texts for the proxy's waiting screen (ui.py)
        self.waiting = WaitingTexts(cfg.ui)
        if cfg.mfa.mode in WEB_APPROVAL_MODES and not cfg.ui.approve_url:
            log.info("[ui] approve_url is not set: the proxy's waiting screen cannot name the "
                     "approval page (no URL, no QR code)")
        if cfg.mfa.nla_kdc_enforced and cfg.mfa.mode != "none":
            log.warning(
                "[mfa] nla_kdc_enforced: Kerberos NLA logins from %s skip the %s second factor; "
                "the KDC must require passkey/PKINIT pre-authentication for TERMSRV tickets "
                "(FreeIPA: ipa service-mod TERMSRV/<host> --auth-ind=passkey --auth-ind=pkinit)",
                ", ".join(cfg.auth.realms), cfg.mfa.mode,
            )
        if cfg.mfa.mode in WEB_APPROVAL_MODES:
            log.info("[mfa] %s: logins wait up to %ds for approval on the webgate's approval page "
                     "(sign-in at most %ds older than the login%s)", cfg.mfa.mode,
                     cfg.mfa.web_approval_timeout, cfg.mfa.web_approval_max_auth_age,
                     "; one pending login per user" if cfg.mfa.web_approval_single_pending else "")
        if cfg.mfa.mode == "code_or_web":
            log.info("[mfa] code_or_web: codes typed on the waiting screen are checked by Keycloak "
                     "(%s, client %s); %d attempt(s) per login, at most %d wrong codes per user in %ds",
                     cfg.mfa.keycloak.issuer, cfg.mfa.keycloak.client_id, cfg.mfa.code_attempts,
                     cfg.mfa.code_user_failures, cfg.mfa.code_failure_window)
        if cfg.mfa.kdc_evidence_as_mfa and cfg.mfa.mode != "none":
            log.info(
                "[mfa] kdc_evidence_as_mfa: Kerberos NLA logins from %s whose ticket carries %s "
                "skip the %s second factor",
                ", ".join(cfg.auth.realms), " or ".join(cfg.mfa.kdc_evidence_as_mfa), cfg.mfa.mode,
            )
        # [mfa] reconnect_grace (grace.py): reconnects skip a recently passed second factor.
        self.grace = ReconnectGrace(cfg.mfa.reconnect_grace, cfg.mfa.reconnect_grace_same_address)
        if self.grace.enabled and cfg.mfa.mode != "none":
            log.info(
                "[mfa] reconnect_grace: reconnects within %ds of a passed %s second factor skip it "
                "(same account, login method, principal%s)",
                cfg.mfa.reconnect_grace, cfg.mfa.mode,
                " and client address" if cfg.mfa.reconnect_grace_same_address else "; any client address",
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

    # ------------------------------------------------------------------ web
    def web_gateway_uid(self) -> int | None:
        """uid of [web] gateway_user; None while [web] is disabled or the account does not
        exist. Once found it is kept; a missing account is looked up again at most every
        WEB_UID_RETRY seconds, so a webgate installed later is picked up without a restart."""
        if not self.cfg.web.enabled:
            return None
        if self.web_uid is not None:
            return self.web_uid
        now = time.monotonic()
        if self.web_uid_missing_since is not None and now - self.web_uid_missing_since < WEB_UID_RETRY:
            return None
        try:
            uid = pwd.getpwnam(self.cfg.web.gateway_user).pw_uid
        except KeyError:
            self.web_uid_missing_since = now
            return None
        if self.web_uid_missing_since is not None:
            log.info("[web] gateway_user %r now exists (uid %d): web gateway operations enabled",
                     self.cfg.web.gateway_user, uid)
        self.web_uid = uid
        return uid

    def from_webgate(self, uid: int) -> bool:
        """Peer `uid` is the webgate's. Never true while its account is unknown."""
        web_uid = self.web_gateway_uid()
        return web_uid is not None and uid == web_uid

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

    def web_desktop_pref(self, user: LocalUser) -> tuple[str | None, bool]:
        """(desktop the user chose on the webgate for RDP logins or None, allowed now)."""
        try:
            pref = self.desktop_prefs.get(user.name)
        except (PrefsError, OSError) as exc:
            log.warning("%s: desktop preference not read: %s", user.name, exc)
            return None, False
        return pref, bool(pref) and identity.desktop_allowed(self.cfg, pref, user)

    async def choose_desktop(self, user: LocalUser, hint: str | None) -> str:
        """identity.choose_desktop: the desktop chosen on the webgate (desktopprefs.py),
        else the user's preference file, read off the event loop."""
        return (await self.desktop_choice(user, hint))[0]

    async def desktop_choice(self, user: LocalUser, hint: str | None) -> tuple[str, str]:
        """choose_desktop() and why: (desktop, source), source as identity.desktop_choice."""
        hinted = identity.hinted_desktop(self.cfg, user, hint)
        if hinted:
            return hinted, "hint"
        web_pref, allowed = self.web_desktop_pref(user)
        if web_pref and allowed:
            return web_pref, "web_pref"
        if web_pref:
            log.info("%s: desktop %s chosen on the web gateway is not allowed (any more); ignored",
                     user.name, web_pref)
        pref = await self.read_desktop_pref(user)
        name, source, _ = identity.desktop_choice(self.cfg, user, None, pref=pref)
        return name, source

    async def running_desktops(self, user: LocalUser) -> dict[str, str]:
        """back-end -> desktop of the user's sessions that still run (state records the
        back-end confirms; a back-end that cannot tell in 5 s counts as not running)."""
        running = {}
        for name, backend in self.backends.items():
            session = self.state.get(user.name, name)
            if session is None or session.desktop not in self.cfg.desktops:
                continue
            try:
                if await asyncio.wait_for(backend.alive(session), 5):
                    running[name] = session.desktop
            except Exception as exc:  # noqa: BLE001 - only a hint for the picker
                log.debug("%s: %s session state unknown: %s", user.name, name, exc)
        return running

    async def pick_desktop(self, user: LocalUser, msg: dict, chosen: str, source: str, lang: str,
                           ask: AskDesktop) -> str:
        """[broker] desktop_picker: the user picks the desktop on the proxy's waiting screen
        (protocol.py "choose_desktop"), `chosen` (from `source`, desktop_choice()) or the
        running session's desktop preselected. Not for a login with a client hint, a user
        with one permitted desktop, or with "if_multiple" a desktop chosen before (web
        gateway, fastrdpctl, ~/.config/fastrdp/desktop). Returns the desktop to start."""
        mode = self.cfg.broker.desktop_picker
        if mode == "never":
            return chosen
        if str_field(msg, "desktop_hint") is not None:
            log.debug("%s: no desktop picker: the client named a desktop", user.name)
            return chosen
        allowed = [d for d in self.cfg.desktops.values() if identity.desktop_allowed(self.cfg, d.name, user)]
        if len(allowed) < 2:
            return chosen
        if mode == "if_multiple" and source not in ("group_default", "default"):
            log.info("%s: no desktop picker: %s chosen before (%s)", user.name, chosen, source)
            return chosen
        running = await self.running_desktops(user)
        names = {d.name for d in allowed}
        live = [d for d in allowed if running.get(d.backend) == d.name]
        default = chosen
        if live:
            # the running session of the chosen desktop's back-end (xrdp: any X11 desktop
            # reconnects to the one that runs), else the first running one
            backend = self.cfg.desktops[chosen].backend
            default = next((d.name for d in live if d.backend == backend), live[0].name)
            if self.cfg.broker.desktop_picker_when_running == "skip":
                log.info("%s: no desktop picker: reconnecting to the running %s session (%s)",
                         user.name, default, self.cfg.desktops[default].backend)
                return default
        # at most 9 rows (keys 1-9), the preselected one among them
        rows = allowed[:9]
        if default not in {d.name for d in rows}:
            rows[-1] = self.cfg.desktops[default]
        options = []
        for d in rows:
            other = running.get(d.backend)
            options.append({
                "name": d.name, "label": d.label or d.name, "running": other == d.name,
                "reconnects": (self.cfg.desktops[other].label or other) if other and other != d.name else None,
            })
        timeout = self.cfg.broker.desktop_picker_timeout
        log.info("%s: desktop picker: %s, %s preselected, %ds", user.name,
                 ", ".join(o["name"] for o in options), default, timeout)
        answered, desktop = await ask(self.waiting.picker(lang, user.name, options, default, timeout),
                                      timeout + PICKER_GRACE)
        if not answered:
            log.warning("%s: desktop picker: no answer from the proxy within %ds; %s", user.name,
                        timeout + PICKER_GRACE, default)
            return default
        if desktop is None:
            log.info("%s: desktop picker: %s (preselected; timeout or Esc)", user.name, default)
            return default
        if desktop not in {o["name"] for o in options} or desktop not in names \
                or not identity.desktop_allowed(self.cfg, desktop, user):
            log.warning("%s: desktop picker answer %r was not offered; %s", user.name, desktop, default)
            return default
        log.info("%s: desktop %s chosen in the desktop picker", user.name, desktop)
        return desktop

    def authz_reason(self, user: LocalUser, proven: bool) -> str:
        """Reason for refusing a user whose first factor checked out (allowed groups,
        account check). "not_allowed" confirms the credentials, so it is given only if the
        client knows that already (NLA: CredSSP succeeded; web: the IdP signed the user in)
        or no second factor is due. A TLS password login that still owes its second factor
        gets "denied": the refusal must not confirm a password to somebody without it."""
        return "not_allowed" if proven or self.mfa.exempt(user.groups) else "denied"

    # ---------------------------------------------------------------- kerberos
    def tgt_mode(self, user: LocalUser) -> tuple[str, str | None]:
        """The user's [broker] session_tgt mode and the session_tgt_groups group it comes
        from (None: the global session_tgt)."""
        return identity.session_tgt_mode(self.cfg, user)

    def require_credential(self, user: LocalUser, password: str | None) -> None:
        """session_tgt = required (globally or for one of the user's groups): refuse,
        before MFA, logins that cannot give the session a TGT (no password: Kerberos SSO
        without delegation, Remote Credential Guard, smartcard, web)."""
        mode, group = self.tgt_mode(user)
        if group is not None and mode != self.cfg.broker.session_tgt:
            log.info("%s: session_tgt = %s (group %s; default %s)",
                     user.name, mode, group, self.cfg.broker.session_tgt)
        if mode == "required" and not password:
            source = f"[broker.session_tgt_groups] {group}" if group else "[broker] session_tgt"
            raise Denied(
                f"{user.name}: login without a password, but {source} = required "
                "(Kerberized home?); log in with NLA and a typed/delegated password, or TLS"
            )

    async def session_tgt(self, user: LocalUser, password: str | None, backend: Backend) -> None:
        """TGT for back-ends that never see the password (GNOME, Plasma), before they
        start, on every login: a reconnect with a password refreshes an expiring TGT."""
        mode, _ = self.tgt_mode(user)
        if mode == "off" or backend.obtains_tgt or not password:
            return  # without a password "required" already refused the login
        try:
            await tgt.obtain(user, password, self.cfg.auth)
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
        # As typed ('alice', 'DOMAIN\alice', 'alice@example.com'): the account of TLS and
        # web logins; for NLA only checked against the principal's account.
        rdp_user = str_field(msg, "user", required=True)
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
            if secret and identity.names_other_account(rdp_user, user, self.cfg.auth):
                # A password delegated for somebody else must not reach pam_sss or MFA.
                log.warning("principal %s: CredSSP user %r is another account; "
                            "delegated password not used", principal, rdp_user)
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
            if msg.get("remote_guard") is True:
                # Remote Credential Guard (mstsc /remoteGuard, proxy.ini AcceptRemoteGuard): the
                # client sent Kerberos tickets instead of a password and the proxy module
                # discarded them. The identity is the principal as for any NLA login; like
                # Restricted Admin or SSO without delegation there is no password, so no
                # session TGT ([broker] session_tgt = required refuses the login). MFA as for
                # SSO: the flag is client-driven and never replaces a second factor.
                log.info("%s: remote credential guard: identity only, credentials discarded "
                         "(principal %s)", user.name, principal)
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
            user = identity.resolve_login(rdp_user, self.cfg.auth)
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
            user = identity.resolve_login(rdp_user, self.cfg.auth)
            otp = None
            if self.mfa.wants_otp_in_password and not self.mfa.exempt(user.groups):
                split = split_otp(secret, self.cfg.mfa)
                if split:
                    secret, otp = split
                elif self.cfg.mfa.mode == "otp" and not self.grace.lookup(self.grace_key(user, msg)):
                    # Without a grace entry the login fails anyway: refuse before PAM.
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

    def grace_key(self, user: LocalUser, msg: dict) -> GraceKey | None:
        """Reconnect-grace binding of a login whose first factor checked out (grace.py).
        Called only for NLA (Kerberos principal from the ticket) and TLS password logins;
        the principal field of a TLS login is client-supplied and ignored."""
        method = str_field(msg, "method", required=True)
        principal = None
        if method == "nla":
            name, realm = identity.split_principal(str_field(msg, "principal", required=True))
            principal = f"{name}@{realm}"
        return self.grace.key(user.name, method, principal, str_field(msg, "client_address"))

    def kdc_evidence(self, user: LocalUser, msg: dict) -> str | None:
        """The first [mfa] kdc_evidence_as_mfa item that the KDC asserted in the ticket of
        this Kerberos NLA login ("kdc_evidence" from the proxy module, verified with the
        service key there), or None. Only principals of [auth] realms: another realm's KDC
        does not apply this realm's policy, and AD filters foreign SIDs only at the trust."""
        wanted = self.cfg.mfa.kdc_evidence_as_mfa
        evidence = msg.get("kdc_evidence")
        if not wanted or msg.get("method") != "nla" or evidence is None:
            return None
        if not isinstance(evidence, list) or len(evidence) > 1024 or not all(
            isinstance(e, str) and len(e) <= 256 for e in evidence
        ):
            raise ProtocolError("invalid field 'kdc_evidence'")
        _, realm = identity.split_principal(str_field(msg, "principal", required=True))
        if realm not in self.cfg.auth.realms:
            return None
        have = set(evidence)
        if match := next((w for w in wanted if w in have), None):
            return match
        log.info("%s: KDC evidence in the ticket: %s; none of [mfa] kdc_evidence_as_mfa", user.name,
                 ", ".join(e for e in evidence if e.startswith("ind:")) or "no indicators")
        log.debug("%s: KDC evidence %s", user.name, evidence)
        return None

    async def login(self, msg: dict, progress: Progress | None = None,
                    ask: AskDesktop | None = None, codes: CodeEntry | None = None) -> dict:
        """`progress`: the module asked for progress messages ("progress": 1) and shows
        them on its waiting screen: "mfa" once the login waits for a push or web approval
        (not for an exempt group, nla_kdc_enforced, KDC evidence or reconnect grace),
        "choose_desktop" for the desktop picker (with `ask`: the module also announced
        "picker": 1; pick_desktop()), "session_start" before the back-end is started or
        reused. `codes`: the module announced "code_entry": 1, so [mfa] code_or_web can
        read a code on its waiting screen (login_unless_abandoned() fills it)."""
        session_id = str_field(msg, "session_id", required=True, max_len=64)
        user, password, otp, mfa_done = await self.first_factor(msg)
        lang = self.waiting.language(int_field(msg, "keyboard_layout", 0, 0xFFFFFFFF)) if progress else ""
        lengths = self.cfg.mfa.otp_lengths
        digits = lengths[0] if len(lengths) == 1 else 0

        def notify(method: str, timeout: int, code: str | None = None, request_id: str | None = None,
                   entry: dict | None = None) -> None:
            assert progress is not None
            progress(self.waiting.mfa(lang, method, timeout, user.name, code, request_id, entry, digits))

        if not identity.user_allowed(user, self.cfg.auth):
            proven = msg.get("method") == "nla" or mfa_done is not None
            raise Denied(f"{user.name} is not in an allowed group", self.authz_reason(user, proven))
        self.require_credential(user, password)

        passed = None  # (grace key, time, factor) of a real second factor
        if mfa_done:
            log.info("second factor for %s already verified by %s", user.name, mfa_done)
        elif not self.mfa.exempt(user.groups):
            grace_key = self.grace_key(user, msg)
            if evidence := self.kdc_evidence(user, msg):
                # The KDC vouches for this login's pre-authentication (PKINIT, passkey,
                # Windows Hello for Business, ...): a real second factor, so it earns grace.
                log.info("%s: Kerberos NLA login (principal %s); second factor from KDC evidence %s",
                         user.name, str_field(msg, "principal"), evidence)
                passed = (grace_key, self.grace.clock(), f"kdc {evidence}")
            elif hit := self.grace.lookup(grace_key):
                entry, age = hit
                log.info("%s: %s login from %s; second factor skipped: reconnect grace "
                         "(%s passed %ds ago from %s)%s", user.name, msg.get("method"),
                         str_field(msg, "client_address"), entry.factor, age, entry.address,
                         "; appended OTP not checked" if otp else "")
            else:
                try:
                    # privacyIDEA knows directory users by their short name, also
                    # with fully qualified SSSD names ('alice@example.com' -> 'alice').
                    mfa_user = identity.short_name(user.name, self.cfg.auth)
                    if self.cfg.mfa.mode == "web" and self.web_gateway_uid() is None:
                        # Fail now instead of waiting web_approval_timeout for nobody.
                        raise MfaDenied(f"web approval unavailable: [web] gateway_user "
                                        f"{self.cfg.web.gateway_user!r} does not exist")
                    # Web approval: the webgate names the local account (mfa_pending).
                    factor = await self.mfa.verify(mfa_user, otp, password, account=user.name,
                                                   method=str_field(msg, "method", required=True),
                                                   client_address=str_field(msg, "client_address"),
                                                   notify=notify if progress else None,
                                                   codes=codes if progress else None)
                except MfaDenied as exc:
                    raise Denied(f"MFA failed for {user.name}: {exc}", exc.reason) from None
                log.info("second factor ok for %s via %s", user.name, factor)
                passed = (grace_key, self.grace.clock(), factor)

        try:
            desktop_name, source = await self.desktop_choice(user, str_field(msg, "desktop_hint"))
        except IdentityError as exc:
            raise Denied(str(exc), exc.reason) from None
        if progress and ask and mfa_done != "idp":  # web logins chose on the web gateway
            desktop_name = await self.pick_desktop(user, msg, desktop_name, source, lang, ask)
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
                # Before any back-end: a missing home must not surface as a grdctl
                # assertion (GNOME has no pam_mkhomedir) or be created below a missing
                # automount root (pam_mkhomedir in xrdp-sesman would). home.py
                await home.prepare(user, self.cfg.broker.home_check, self.home_pool,
                                   self.cfg.broker.home_read_timeout, self.cfg.broker.home_create_roots)
                return await backend.ensure(LoginRequest(user, desktop, password, width, height))

        if progress:
            try:
                progress(self.waiting.session_start(lang, user.name, desktop.label or desktop.name))
            except Exception as exc:
                log.debug("progress message not sent: %s", exc)
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
        if passed and passed[0]:
            # Only now: refusals, MFA failures and back-end errors never earn grace.
            self.grace.record(*passed, str_field(msg, "client_address"))
            log.info("%s: reconnect grace for %s logins%s for %ds", user.name, passed[0].method,
                     f" from {passed[0].address}" if passed[0].address else "", self.grace.seconds)
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

    async def login_unless_abandoned(self, msg: dict, reader: asyncio.StreamReader,
                                     progress: Progress | None = None) -> dict | None:
        """login(), cancelled when the proxy closes the connection first: the user gave up
        (closed the client during an MFA push or the desktop picker) and the proxy dropped
        the request (fastrdp_plugin.c broker_call). Returns None then. Cancelling stops a
        push wait (mfa.py); a session start already under way completes (login()). While
        a login is pending the proxy sends only these lines: the desktop picker's answer
        {"op": "choice", "desktop": str|null}, once, after a "choose_desktop" prompt and
        only with "picker": 1 in the request; codes from the waiting screen
        {"op": "code", "code": "<digits>"}, only with "code_entry": 1, at most
        MAX_CODE_LINES (one that comes when no code field is open is dropped). Anything
        else is a protocol error."""
        prompted: asyncio.Future | None = None
        answers = 0
        code_lines = 0
        codes = CodeEntry() if progress is not None and msg.get("code_entry") == 1 else None

        async def ask(prompt: dict, timeout: float) -> tuple[bool, str | None]:
            nonlocal prompted
            assert progress is not None and prompted is None
            prompted = asyncio.get_running_loop().create_future()
            progress(prompt)
            try:
                return True, await asyncio.wait_for(asyncio.shield(prompted), timeout)
            except TimeoutError:
                prompted.cancel()  # an answer after this is too late
                return False, None

        picker = ask if progress is not None and msg.get("picker") == 1 else None
        login = asyncio.ensure_future(self.login(msg, progress, picker, codes))
        peer = asyncio.ensure_future(reader.readline())
        try:
            while True:
                await asyncio.wait({login, peer}, return_when=asyncio.FIRST_COMPLETED)
                if login.done() or peer.exception() is not None or not peer.result():
                    break  # a reset counts as closed
                line = peer.result()
                answer = self.parse_answer(line)
                if answer["op"] == "code":
                    code_lines += 1
                    if codes is None or code_lines > MAX_CODE_LINES:
                        raise ProtocolError("data received while a login was pending")
                    code = self.parse_code(answer)
                    if not codes.put(code):
                        log.info("session %s: code from the waiting screen came while no code field "
                                 "was open; ignored", msg.get("session_id"))
                    peer = asyncio.ensure_future(reader.readline())
                    continue
                if prompted is None or answers:
                    raise ProtocolError("data received while a login was pending")
                answers += 1
                desktop = self.parse_choice(answer)
                if prompted.done():
                    log.info("session %s: desktop picker answer %r came too late; ignored",
                             msg.get("session_id"), desktop)
                else:
                    prompted.set_result(desktop)
                peer = asyncio.ensure_future(reader.readline())
            finished = login.done()
        finally:
            for task in (login, peer):
                if not task.done():
                    task.cancel()
            # let the cancellations run: the reader must be free for the next message
            await asyncio.gather(login, peer, return_exceptions=True)
        if finished:
            return login.result()  # Denied etc. propagate as before
        if isinstance(peer.exception(), ValueError):  # longer than the reader's limit
            raise ProtocolError("data received while a login was pending")
        log.info("login of session %s abandoned: the proxy closed the connection (client gone)",
                 msg.get("session_id"))
        return None

    @staticmethod
    def parse_answer(line: bytes) -> dict:
        """A line the module sent while its login is pending (protocol.py): an object
        with "op" "choice" or "code"."""
        if not line.endswith(b"\n"):
            raise ProtocolError("data received while a login was pending")
        try:
            answer = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ProtocolError("invalid answer while a login was pending") from None
        if not isinstance(answer, dict) or answer.get("op") not in ("choice", "code"):
            raise ProtocolError("data received while a login was pending")
        return answer

    @staticmethod
    def parse_choice(choice: dict) -> str | None:
        """The desktop picker's answer (protocol.py): the desktop or None (default)."""
        if "desktop" not in choice:
            raise ProtocolError("data received while a login was pending")
        return str_field(choice, "desktop", max_len=64)

    @staticmethod
    def parse_code(answer: dict) -> str:
        """A code typed on the waiting screen: digits only, ui.CODE_DIGITS long."""
        code = answer.get("code")
        lo, hi = CODE_DIGITS
        if not isinstance(code, str) or not lo <= len(code) <= hi or not code.isascii() or not code.isdigit():
            raise ProtocolError("invalid code from the waiting screen")
        return code

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
        user = identity.resolve_login(str_field(msg, "user", required=True), self.cfg.auth)
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
        web_pref, allowed = self.web_desktop_pref(user)
        return {"ok": True, "user": user.name, "desktops": desktops, "default": default,
                "rdp_desktop": web_pref if allowed else None}

    async def web_set_desktop(self, msg: dict) -> dict:
        """fastrdp-webgate stores the desktop the user chose for RDP logins (null: none)."""
        user, desktops = await self._web_user(msg)
        if "desktop" not in msg:
            raise ProtocolError("web_set_desktop needs 'desktop' (str or null)")
        desktop = str_field(msg, "desktop", max_len=64)
        if desktop is not None and desktop not in {d["name"] for d in desktops}:
            raise Denied(f"{user.name} chose desktop {desktop!r} for RDP logins, which is not allowed",
                         "not_allowed")
        try:
            self.desktop_prefs.set(user.name, desktop)
        except (PrefsError, OSError) as exc:
            log.error("%s: desktop preference not stored: %s", user.name, exc)
            return {"ok": False, "error": "not stored", "reason": "unavailable"}
        log.info("%s: desktop for RDP logins %s on the web gateway", user.name,
                 f"set to {desktop}" if desktop else "reset to the default")
        return {"ok": True, "user": user.name, "rdp_desktop": desktop}

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

    # ------------------------------------------------------------ web approval
    def mfa_pending(self, msg: dict) -> dict:
        """fastrdp-webgate lists the user's logins waiting for web approval (mfa.WebApprovals)."""
        user = identity.resolve_login(str_field(msg, "user", required=True), self.cfg.auth)
        return {"ok": True, "user": user.name, "pending": self.mfa.approvals.list(user.name)}

    def mfa_decide(self, msg: dict) -> dict:
        """fastrdp-webgate approves or denies one of them for the user it signed in;
        `auth_time` is that sign-in (ID token), `bound` says the user came with this
        login's id (the waiting screen's QR code). Refusals carry an approval_* reason."""
        user = identity.resolve_login(str_field(msg, "user", required=True), self.cfg.auth)
        request_id = str_field(msg, "id", required=True, max_len=64)
        approve = msg.get("approve")
        auth_time = int_field(msg, "auth_time", 0, 2**40)
        bound = msg.get("bound", False)
        if not isinstance(approve, bool) or auth_time is None or not isinstance(bound, bool):
            raise ProtocolError("mfa_decide needs 'approve' (bool) and 'auth_time' (int); 'bound' is a bool")
        try:
            entry = self.mfa.approvals.decide(user.name, request_id, approve, auth_time, bound)
        except ApprovalError as exc:
            log.warning("web approval decision by %s refused (%s): %s", user.name, exc.reason, exc)
            reply = {"ok": False, "error": "not decided", "reason": exc.reason}
            if exc.outcome:
                reply["outcome"] = exc.outcome
            return reply
        log.info("web approval for %s from %s (%s login): %s on the approval page", user.name,
                 entry.client_address, entry.method,
                 ("approved via the login-bound link" if bound else "approved") if approve else "DENIED")
        # the user's own logins still waiting (never ids or other users'): a bound approval
        # while others wait may be an attacker's link to the attacker's login
        others = self.mfa.approvals.count(user.name)
        if approve and bound and others:
            log.warning("web approval for %s via the login-bound link while %d other login(s) of the "
                        "account waited: somebody else may have the password", user.name, others)
        return {"ok": True, "approved": approve, "others_pending": others}

    async def mfa_events(self, msg: dict) -> dict:
        """fastrdp-webgate's notifier: events of web approvals (mfa.ApprovalEvents), waiting
        up to `wait_s` seconds for the first. One consumer expected."""
        wait_s = int_field(msg, "wait_s", 0, ApprovalEvents.MAX_WAIT)
        approvals = self.mfa.approvals
        events = await approvals.events.get(wait_s or 0, approvals.still_news)
        return {"ok": True, "events": events}

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
            "mfa_grace_entries": len(self.grace),
            "mfa_pending_approvals": len(self.mfa.approvals),
            "mfa_events": self.mfa.approvals.events.status(),
            "tickets": await self.session_tickets(),
        }

    async def _tickets_of(self, names: list[str]) -> dict[str, dict]:
        """TGT metadata (tickets.py) of local accounts; unresolvable names say so."""
        users, out = [], {}
        for name in names:
            try:
                users.append(await asyncio.to_thread(identity.resolve, name, None, self.cfg.auth))
            except (IdentityError, OSError) as exc:
                out[name] = {"state": "unknown", "error": f"user lookup: {exc}"}
        out.update(await tickets.query_all(users))
        return out

    async def session_tickets(self) -> dict[str, dict]:
        """The TGT of every account with a session (once per account, not per back-end)."""
        return await self._tickets_of(sorted({s.user for s in self.state.sessions.values()}))

    async def list_tickets(self, msg: dict) -> dict:
        """fastrdpctl tickets [USER]: one account (session or not), or every session user."""
        name = str_field(msg, "user")
        if name is None:
            await self.reap()
            return {"ok": True, "tickets": await self.session_tickets()}
        return {"ok": True, "tickets": await self._tickets_of([name])}

    async def logout(self, msg: dict) -> dict:
        name = str_field(msg, "user", required=True)
        user = identity.resolve(name, None, self.cfg.auth)
        for backend in self.backends.values():
            if self.state.get(user.name, backend.name):
                await backend.logout(user)
        return {"ok": True}

    async def clear_grace(self, msg: dict) -> dict:
        """fastrdpctl clear-grace [USER]: forget reconnect grace (suspected compromise)."""
        user = str_field(msg, "user")  # local account name; None = everybody
        n = self.grace.clear(user)
        log.warning("reconnect grace cleared for %s (%d entries)", user or "all users", n)
        return {"ok": True, "cleared": n}

    async def desktop_pref(self, msg: dict) -> dict:
        """fastrdpctl desktop USER [DESKTOP | --clear]: the desktop stored for the user's
        RDP logins (as web_set_desktop stores it), and what an RDP login without a
        client hint gets now and why. "set" stores a desktop the user may use, "clear"
        removes the stored one."""
        user = identity.resolve_login(str_field(msg, "user", required=True), self.cfg.auth)
        desktop = str_field(msg, "set", max_len=64)
        clear = msg.get("clear", False)
        if not isinstance(clear, bool) or (clear and desktop is not None):
            raise ProtocolError("desktop_pref takes 'set' (str) or 'clear' (true), not both")
        allowed = [d for d in self.cfg.desktops if identity.desktop_allowed(self.cfg, d, user)]
        if desktop is not None and desktop not in allowed:
            log.warning("fastrdpctl: desktop %r not stored for %s: not allowed for the user",
                        desktop, user.name)
            return {"ok": False, "error": f"desktop {desktop!r} is not allowed for {user.name}",
                    "reason": "not_allowed", "user": user.name, "allowed": allowed}
        if desktop is not None or clear:
            try:
                self.desktop_prefs.set(user.name, desktop)
            except (PrefsError, OSError) as exc:
                log.error("%s: desktop preference not stored: %s", user.name, exc)
                return {"ok": False, "error": "not stored", "reason": "unavailable"}
            log.warning("%s: desktop for RDP logins %s by fastrdpctl", user.name,
                        f"set to {desktop}" if desktop else "cleared")
        stored, stored_allowed = self.web_desktop_pref(user)
        home = await self.read_desktop_pref(user)
        try:
            chosen, source, group = identity.desktop_choice(self.cfg, user, None, pref=home, web_pref=stored)
        except IdentityError:
            chosen, source, group = None, "none", None
        return {"ok": True, "user": user.name, "rdp_desktop": stored,
                "rdp_desktop_allowed": stored_allowed, "home_desktop": home, "desktop": chosen,
                "source": source, "group": group, "allowed": allowed,
                "login_allowed": identity.user_allowed(user, self.cfg.auth)}

    # ------------------------------------------------------------- sockets
    @staticmethod
    def progress_writer(writer: asyncio.StreamWriter) -> Progress:
        """Progress messages before the login reply. Queued without waiting for the
        proxy to read them (no drain): a slow or gone proxy never delays or fails the
        login, which notices a gone proxy on its own (login_unless_abandoned)."""
        def send(msg: dict) -> None:
            try:
                if not writer.is_closing():
                    writer.write(json.dumps(msg, separators=(",", ":")).encode() + b"\n")
            except Exception as exc:
                log.debug("progress message not sent: %s", exc)
        return send

    async def handle_broker_client(self, reader, writer) -> None:
        uid = peer_uid(writer)
        try:
            while (msg := await read_message(reader)) is not None:
                op = msg["op"]
                try:
                    if op == "login" and uid == self.proxy_uid:
                        progress = self.progress_writer(writer) if msg.get("progress") == 1 else None
                        reply = await self.login_unless_abandoned(msg, reader, progress)
                        if reply is None:
                            break
                    elif op == "end" and uid == self.proxy_uid:
                        user = self.active.pop(str(msg.get("session_id")), None)
                        log.info("session end %s user=%s", msg.get("session_id"), user)
                        reply = {"ok": True}
                    elif op == "web_token" and self.from_webgate(uid):
                        reply = await self.issue_web_token(msg)
                    elif op == "web_desktops" and self.from_webgate(uid):
                        reply = await self.web_desktops(msg)
                    elif op == "web_set_desktop" and self.from_webgate(uid):
                        reply = await self.web_set_desktop(msg)
                    elif op == "mfa_pending" and self.from_webgate(uid):
                        reply = self.mfa_pending(msg)
                    elif op == "mfa_decide" and self.from_webgate(uid):
                        reply = self.mfa_decide(msg)
                    elif op == "mfa_events" and self.from_webgate(uid):
                        reply = await self.mfa_events(msg)
                    elif op == "status" and uid == 0:
                        reply = await self.status()
                    elif op == "tickets" and uid == 0:
                        reply = await self.list_tickets(msg)
                    elif op == "logout" and uid == 0:
                        reply = await self.logout(msg)
                    elif op == "clear_grace" and uid == 0:
                        reply = await self.clear_grace(msg)
                    elif op == "desktop_pref" and uid == 0:
                        reply = await self.desktop_pref(msg)
                    else:
                        missing = (op.startswith(("web_", "mfa_")) and self.cfg.web.enabled
                                   and self.web_uid is None)
                        log.warning("op %r not permitted for uid %d%s", op, uid,
                                    f" ([web] gateway_user {self.cfg.web.gateway_user!r} does not exist)"
                                    if missing else "")
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
