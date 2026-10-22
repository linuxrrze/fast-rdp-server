# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Second factor: privacyIDEA (OTP appended to the password, or push), or approval of
the pending login on fastrdp-webgate's approval page (web)."""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .config import PRIVACYIDEA_MODES, MfaSection
from .privacyidea import PrivacyIdea, PrivacyIdeaError

log = logging.getLogger(__name__)

YUBIKEY_OTP = re.compile(r"[cbdefghijklnrtuv]{44}$")


class MfaDenied(Exception):
    """`reason`: "mfa_failed", or "mfa_timeout" for a push or web approval not given in time."""

    def __init__(self, message: str, reason: str = "mfa_failed"):
        super().__init__(message)
        self.reason = reason


def split_otp(secret: str, cfg: MfaSection) -> tuple[str, str] | None:
    """Split 'password+OTP' typed into one field. Returns (password, otp) or None.

    YubiKey OTPs (44 modhex chars) are recognised first, then numeric OTPs of the
    configured lengths in the configured order. Deployments should configure one
    TOTP length so a password ending in digits is not split ambiguously.
    """
    if cfg.yubikey_otp and len(secret) > 44 and YUBIKEY_OTP.search(secret):
        return secret[:-44], secret[-44:]
    for length in cfg.otp_lengths:
        if len(secret) > length and secret[-length:].isdigit():
            return secret[:-length], secret[-length:]
    return None


class ApprovalError(Exception):
    """A web approval decision the broker refuses. `reason` (protocol.py): approval_unknown,
    approval_finished (`outcome` says how it ended), approval_conflict, approval_stale."""

    def __init__(self, message: str, reason: str, outcome: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.outcome = outcome


@dataclass
class PendingApproval:
    id: str                     # random, names the login in the webgate's forms
    user: str                   # local account
    method: str                 # "nla" | "tls"
    client_address: str | None  # socket peer the proxy saw
    created: float              # monotonic (age, expiry)
    created_wall: float         # time.time() (compared with the IdP's auth_time)
    future: asyncio.Future      # True = approved, False = denied


class WebApprovals:
    """Logins waiting in the broker for their user's decision on the webgate's approval
    page ([mfa] mode web / push_or_web). An entry exists while its login waits: removed
    on the decision, on the timeout and when the proxy abandons the login (cancelled).
    Decided, expired and abandoned ids are remembered for FINISHED_KEEP seconds so that
    a late click gets a clear answer. Memory only; the broker's event loop only, so no
    locking."""

    FINISHED_KEEP = 300

    def __init__(self, cfg: MfaSection, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time):
        self.cfg = cfg
        self.clock = clock
        self.wall = wall
        self.pending: dict[str, PendingApproval] = {}
        self.finished: dict[str, tuple[str, str, float]] = {}  # id -> (user, outcome, when)

    def prune(self) -> None:
        now = self.clock()
        for k in [k for k, (_u, _o, t) in self.finished.items() if now - t >= self.FINISHED_KEEP]:
            del self.finished[k]

    def _finish(self, entry: PendingApproval, outcome: str) -> None:
        if self.pending.pop(entry.id, None) is not None:
            self.finished[entry.id] = (entry.user, outcome, self.clock())

    def count(self, user: str) -> int:
        return sum(1 for e in self.pending.values() if e.user == user)

    async def wait(self, user: str, method: str, client_address: str | None) -> str:
        """Register the login and wait for its decision. Returns "web"; raises MfaDenied
        (denied: mfa_failed, no decision in time: mfa_timeout). Cancelling (the proxy
        dropped the login) removes the entry."""
        self.prune()
        entry = PendingApproval(secrets.token_urlsafe(16), user, method, client_address,
                                self.clock(), self.wall(), asyncio.get_running_loop().create_future())
        self.pending[entry.id] = entry
        timeout = self.cfg.web_approval_timeout
        log.info("web approval pending for %s from %s (%s login, %ds)", user, client_address, method, timeout)
        try:
            approved = await asyncio.wait_for(entry.future, timeout)
        except TimeoutError:
            self._finish(entry, "expired")
            raise MfaDenied("web approval not given in time", "mfa_timeout") from None
        except asyncio.CancelledError:
            self._finish(entry, "abandoned")
            log.info("web approval wait for %s cancelled", user)
            raise
        if not approved:
            raise MfaDenied("web approval denied")
        return "web"

    def list(self, user: str) -> list[dict]:
        """The pending logins of `user` (local account), oldest first."""
        conflict = self.cfg.web_approval_single_pending and self.count(user) > 1
        now = self.clock()
        return [
            {"id": e.id, "method": e.method, "client_address": e.client_address,
             "age_s": int(now - e.created), "single_pending_conflict": conflict}
            for e in sorted(self.pending.values(), key=lambda e: e.created) if e.user == user
        ]

    def decide(self, user: str, request_id: str, approve: bool, auth_time: int) -> PendingApproval:
        """Resolve a pending login of `user`. `auth_time`: when the IdP last authenticated
        the user who decides (ID token). Approving needs a sign-in no older than
        web_approval_max_auth_age before the login, and (web_approval_single_pending) no
        other pending login of the user; denying is always allowed. Raises ApprovalError."""
        self.prune()
        entry = self.pending.get(request_id)
        if entry is None or entry.user != user:
            # another user's id is answered like an unknown one
            done = self.finished.get(request_id)
            if done is not None and done[0] == user:
                raise ApprovalError(f"login {request_id} already {done[1]}", "approval_finished", done[1])
            raise ApprovalError(f"no pending login {request_id}", "approval_unknown")
        if approve:
            if self.cfg.web_approval_single_pending and self.count(user) > 1:
                raise ApprovalError(f"{self.count(user)} logins pending; approving none of them "
                                    "([mfa] web_approval_single_pending)", "approval_conflict")
            age = entry.created_wall - auth_time
            if age > self.cfg.web_approval_max_auth_age:
                raise ApprovalError(f"sign-in {age:.0f}s older than the login "
                                    f"(web_approval_max_auth_age = {self.cfg.web_approval_max_auth_age})",
                                    "approval_stale")
        self._finish(entry, "approved" if approve else "denied")
        if not entry.future.done():
            entry.future.set_result(approve)
        return entry

    def __len__(self) -> int:
        return len(self.pending)


class SecondFactor:
    def __init__(self, cfg: MfaSection):
        self.cfg = cfg
        self.pi = PrivacyIdea(cfg.privacyidea) if cfg.mode in PRIVACYIDEA_MODES else None
        self.approvals = WebApprovals(cfg)

    @property
    def wants_otp_in_password(self) -> bool:
        return self.cfg.mode in ("otp", "otp_or_push")

    def exempt(self, groups: set[str]) -> bool:
        return self.cfg.mode == "none" or bool(groups & set(self.cfg.exempt_groups))

    async def verify(self, user: str, otp: str | None, password: str | None, *,
                     account: str | None = None, method: str = "", client_address: str | None = None) -> str:
        """Run the configured second factor. Returns the factor used; raises MfaDenied.
        `user`: privacyIDEA's name; `account` (default `user`), `method` and
        `client_address`: the local account and the login shown on the approval page."""
        try:
            if otp is not None and self.wants_otp_in_password:
                assert self.pi is not None
                if await asyncio.to_thread(self.pi.check_otp, user, otp):
                    return "otp"
                raise MfaDenied("OTP rejected")
            if self.cfg.mode == "web":
                return await self.approvals.wait(account or user, method, client_address)
            if self.cfg.mode == "push_or_web":
                return await self.push_or_web(user, password, account or user, method, client_address)
            if self.cfg.mode in ("push", "otp_or_push"):
                if await self.push(user, password):
                    return "push"
                raise MfaDenied("push not confirmed in time", "mfa_timeout")
            raise MfaDenied("OTP required: append it to the password")
        except PrivacyIdeaError as exc:
            log.error("privacyIDEA error for %s: %s", user, exc)
            raise MfaDenied("MFA service unavailable") from None

    async def push(self, user: str, password: str | None) -> bool:
        """Push challenge: True once approved, False if push_timeout passed (or the final
        check refused it). Raises MfaDenied without a push-capable token."""
        assert self.pi is not None
        txid = await asyncio.to_thread(self.pi.trigger_challenge, user, password)
        if not txid:
            raise MfaDenied("no challenge-capable token for user")
        log.info("push challenge sent to %s (transaction %s)", user, txid)
        cancel = threading.Event()
        try:
            return await asyncio.to_thread(self.pi.wait_for_push, user, txid, cancel)
        except asyncio.CancelledError:
            # The proxy gave up on the login (user closed the client), or the web
            # approval answered first (push_or_web): stop polling.
            cancel.set()
            log.info("push wait for %s cancelled (transaction %s)", user, txid)
            raise

    async def push_or_web(self, user: str, password: str | None, account: str, method: str,
                          client_address: str | None) -> str:
        """Push and web approval at once; the first answer wins and the other is cancelled.
        A Deny or a refused push fails the login. A push that cannot start (no push-capable
        token, privacyIDEA unreachable) or runs out of push_timeout leaves the web approval
        waiting, whose web_approval_timeout bounds the whole wait."""
        started = time.monotonic()
        push = asyncio.ensure_future(self.push(user, password))
        web = asyncio.ensure_future(self.approvals.wait(account, method, client_address))
        try:
            await asyncio.wait({push, web}, return_when=asyncio.FIRST_COMPLETED)
            if not web.done():
                exc = push.exception()
                if exc is None and push.result():
                    return "push"
                if exc is None and time.monotonic() - started < self.cfg.privacyidea.push_timeout:
                    # wait_for_push gives up early only when the final check refused it
                    raise MfaDenied("push refused")
                if exc is not None and not isinstance(exc, (MfaDenied, PrivacyIdeaError)):
                    raise exc
                log.log(logging.WARNING if exc else logging.INFO, "push for %s: %s; waiting for web approval only",
                        user, exc or "not confirmed in time")
            return await web
        finally:
            for task in (push, web):
                if not task.done():
                    task.cancel()
            await asyncio.gather(push, web, return_exceptions=True)
