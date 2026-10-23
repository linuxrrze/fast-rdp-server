# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Second factor: privacyIDEA (OTP appended to the password, or push), approval of the
pending login on fastrdp-webgate's approval page (web), or a code typed on the proxy's
waiting screen and checked by Keycloak, racing the approval page (code_or_web)."""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from .config import KEYCLOAK_OTP_MODES, PRIVACYIDEA_MODES, MfaSection
from . import keycloak_otp
from .keycloak_otp import KeycloakError, KeycloakOtp
from .privacyidea import PrivacyIdea, PrivacyIdeaError

log = logging.getLogger(__name__)

YUBIKEY_OTP = re.compile(r"[cbdefghijklnrtuv]{44}\Z")   # \Z: not before a trailing newline


# Called once a login waits for the user: (method "push" | "web" | "push_or_web" |
# "code_or_web", seconds the wait may take, the web approval's correlation code or None,
# the web approval's id or None), for code_or_web also entry= (the code field's state,
# ui.WaitingTexts.mfa()). The broker turns it into a progress message for the proxy's
# waiting screen (ui.py: the QR code names the id); it must not block.
Notify = Callable[..., None]


def notify_safely(notify: Notify | None, method: str, timeout: float, code: str | None = None,
                  request_id: str | None = None, entry: dict | None = None) -> None:
    """The waiting screen is a courtesy: its errors never touch the login."""
    if notify is None:
        return
    try:
        if entry is None:
            notify(method, max(0, int(timeout)), code, request_id)
        else:
            notify(method, max(0, int(timeout)), code, request_id, entry=entry)
    except Exception as exc:
        log.debug("progress message not sent: %s", exc)


class CodeEntry:
    """Codes the proxy module reads on the waiting screen for one login ({"op": "code"},
    protocol.py; Broker.login_unless_abandoned puts them here). Accepted only while the
    code field is open; a code that comes after it closed (the approval page answered
    first) is dropped."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.open = False

    def put(self, code: str) -> bool:
        if not self.open:
            return False
        self.queue.put_nowait(code)
        return True

    async def get(self) -> str:
        return await self.queue.get()


class CodeFailures:
    """Wrong codes per account within [mfa] code_failure_window seconds. At
    code_user_failures the account's code field stays closed (the approval page still
    works) until older failures leave the window. Memory only; the event loop only."""

    def __init__(self, cfg: MfaSection, clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self.clock = clock
        self.failures: dict[str, deque[float]] = {}

    def _recent(self, account: str) -> deque[float]:
        times = self.failures.get(account, deque())
        while times and self.clock() - times[0] >= self.cfg.code_failure_window:
            times.popleft()
        if not times:
            self.failures.pop(account, None)
        return times

    def blocked(self, account: str) -> bool:
        return len(self._recent(account)) >= self.cfg.code_user_failures

    def record(self, account: str) -> None:
        times = self._recent(account)
        times.append(self.clock())
        self.failures[account] = times


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
    id: str                     # random (new_id()), names the login in the webgate's forms
                                # and in the waiting screen's QR code
    user: str                   # local account
    method: str                 # "nla" | "tls"
    client_address: str | None  # socket peer the proxy saw
    created: float              # monotonic (age, expiry)
    created_wall: float         # time.time() (compared with the IdP's auth_time)
    future: asyncio.Future      # True = approved, False = denied
    code: str = ""              # two digits: waiting screen, approval page, notification


class ApprovalEvents:
    """Events about web approvals for fastrdp-webgate's notifier (op mfa_events, protocol.py):
    {"event": "pending", ...} when a login starts waiting, {"event": "finished", ...} when
    it ends. A hint for the user's phone only: queued without waiting (put_nowait), dropped
    and counted when the queue is full, never awaited by a login.

    Events are kept only while a consumer polls: from its first mfa_events until
    CONSUMER_GONE seconds after its last one ended (a webgate without notification
    backends never polls, so nothing piles up). One consumer is expected; two would
    share the events between them. Memory only; the broker's event loop only."""

    MAX_QUEUED = 256
    MAX_BATCH = 100      # events per reply (well below the 256 KiB line the webgate reads)
    MAX_WAIT = 25        # seconds a poll may wait for the first event
    CONSUMER_GONE = 300

    def __init__(self, clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
                 maxsize: int = MAX_QUEUED):
        self.clock = clock
        self.wall = wall
        self.queue: asyncio.Queue = asyncio.Queue(maxsize)
        self.polling = 0
        self.last_poll: float | None = None       # monotonic, end of the last poll
        self.last_poll_wall: float | None = None  # time.time(), for status
        self.sent = 0
        self.dropped = 0

    def consumer(self) -> bool:
        return self.polling > 0 or (self.last_poll is not None
                                    and self.clock() - self.last_poll < self.CONSUMER_GONE)

    def put(self, event: dict) -> None:
        if not self.consumer():
            while not self.queue.empty():   # left over from a consumer that went away
                self.queue.get_nowait()
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("web approval notifications: queue full, %d event(s) dropped so far "
                            "(is fastrdp-webgate's notifier stuck?)", self.dropped)

    async def get(self, wait_s: float, keep: Callable[[dict], bool] = lambda e: True) -> list[dict]:
        """Queued events (oldest first, at most MAX_BATCH), waiting up to `wait_s` seconds
        for the first one; [] if none came. `keep` leaves out events no longer worth
        sending (a login that ended before anybody heard of it)."""
        self.polling += 1
        self.last_poll_wall = self.wall()
        try:
            events: list[dict] = []
            if self.queue.empty() and wait_s > 0:
                try:
                    events.append(await asyncio.wait_for(self.queue.get(), wait_s))
                except TimeoutError:
                    pass
            while len(events) < self.MAX_BATCH and not self.queue.empty():
                events.append(self.queue.get_nowait())
        finally:
            self.polling -= 1
            self.last_poll = self.clock()
            self.last_poll_wall = self.wall()
        events = [e for e in events if keep(e)]
        self.sent += len(events)
        return events

    def status(self) -> dict:
        return {"consumer": self.consumer(), "queued": self.queue.qsize(), "sent": self.sent,
                "dropped": self.dropped,
                "last_poll": int(self.last_poll_wall) if self.last_poll_wall is not None else None}


class WebApprovals:
    """Logins waiting in the broker for their user's decision on the webgate's approval
    page ([mfa] mode web / push_or_web). An entry exists while its login waits: removed
    on the decision, on the timeout and when the proxy abandons the login (cancelled).
    Decided, expired and abandoned ids are remembered for FINISHED_KEEP seconds so that
    a late click gets a clear answer. Every entry gets a two-digit correlation code that
    the waiting screen, the approval page and the notification show, so the user can
    match them. Registration and end are reported to `events` (the webgate's
    notifications). Memory only; the broker's event loop only, so no locking."""

    FINISHED_KEEP = 300
    ID_BYTES = 16   # new_id(): 22 characters (config.LOGIN_ID_CHARS)

    def __init__(self, cfg: MfaSection, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time):
        self.cfg = cfg
        self.clock = clock
        self.wall = wall
        self.pending: dict[str, PendingApproval] = {}
        self.finished: dict[str, tuple[str, str, float]] = {}  # id -> (user, outcome, when)
        self.events = ApprovalEvents(clock, wall)

    @classmethod
    def new_id(cls) -> str:
        """128 random bits, URL-safe: the waiting screen's QR code carries the id
        (<approve_url>?login=<id>) so that approving binds to this login. Not a
        credential (the approval page still wants the user's fresh MFA sign-in), but
        unguessable, so nobody can point another user's approval page at a login of
        theirs without having seen the id."""
        return secrets.token_urlsafe(cls.ID_BYTES)

    def new_code(self, user: str) -> str:
        """Two random digits, unlike the codes of the user's other pending logins (as far
        as 100 codes go)."""
        taken = {e.code for e in self.pending.values() if e.user == user}
        for _ in range(20):
            code = f"{secrets.randbelow(100):02d}"
            if code not in taken:
                break
        return code

    def still_news(self, event: dict) -> bool:
        """A "pending" event is sent only while its login still waits."""
        return event.get("event") != "pending" or event.get("id") in self.pending

    def prune(self) -> None:
        now = self.clock()
        for k in [k for k, (_u, _o, t) in self.finished.items() if now - t >= self.FINISHED_KEEP]:
            del self.finished[k]

    def _finish(self, entry: PendingApproval, outcome: str) -> None:
        if self.pending.pop(entry.id, None) is not None:
            self.finished[entry.id] = (entry.user, outcome, self.clock())
            self.events.put({"event": "finished", "id": entry.id, "user": entry.user, "outcome": outcome})

    def count(self, user: str) -> int:
        return sum(1 for e in self.pending.values() if e.user == user)

    async def wait(self, user: str, method: str, client_address: str | None,
                   notify: Notify | None = None, code: str | None = None,
                   request_id: str | None = None) -> str:
        """Register the login and wait for its decision. Returns "web"; raises MfaDenied
        (denied: mfa_failed, no decision in time: mfa_timeout). Cancelling (the proxy
        dropped the login) removes the entry. `notify`: told ("web", timeout, code, id)
        once the login is pending. `code`, `request_id`: the correlation code and the id
        (default: new ones)."""
        self.prune()
        entry = PendingApproval(request_id or self.new_id(), user, method, client_address,
                                self.clock(), self.wall(), asyncio.get_running_loop().create_future(),
                                code or self.new_code(user))
        self.pending[entry.id] = entry
        timeout = self.cfg.web_approval_timeout
        log.info("web approval pending for %s from %s (%s login, %ds, code %s)", user, client_address,
                 method, timeout, entry.code)
        self.events.put({"event": "pending", "id": entry.id, "user": user, "method": method,
                         "client_address": client_address, "created": int(entry.created_wall),
                         "timeout_s": int(timeout), "code": entry.code})
        notify_safely(notify, "web", timeout, entry.code, entry.id)
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

    def stale(self, entry: PendingApproval, auth_time: int) -> float | None:
        """Seconds by which a sign-in at `auth_time` (IdP clock) is older than the login,
        if that is more than web_approval_max_auth_age: such a sign-in cannot approve it
        (decide() refuses, list() marks it). None if it may."""
        age = entry.created_wall - auth_time
        return age if age > self.cfg.web_approval_max_auth_age else None

    def list(self, user: str, auth_time: int | None = None) -> list[dict]:
        """The pending logins of `user` (local account), oldest first. With `auth_time`
        (the webgate's sign-in), "needs_fresh_sign_in" says which of them that sign-in is
        too old to approve (the rule of decide())."""
        conflict = self.cfg.web_approval_single_pending and self.count(user) > 1
        now = self.clock()
        return [
            {"id": e.id, "method": e.method, "client_address": e.client_address,
             "age_s": int(now - e.created), "single_pending_conflict": conflict, "code": e.code,
             "needs_fresh_sign_in": auth_time is not None and self.stale(e, auth_time) is not None}
            for e in sorted(self.pending.values(), key=lambda e: e.created) if e.user == user
        ]

    def decide(self, user: str, request_id: str, approve: bool, auth_time: int,
               bound: bool = False) -> PendingApproval:
        """Resolve a pending login of `user`. `auth_time`: when the IdP last authenticated
        the user who decides (ID token). Approving needs a sign-in no older than
        web_approval_max_auth_age before the login, and (web_approval_single_pending) no
        other pending login of the user, unless `bound`: the user came to the approval
        page with this login's id (the QR code of its own waiting screen), so another
        pending login (perhaps somebody else's with the same password) cannot be the one
        approved by mistake. Denying is always allowed. Raises ApprovalError."""
        self.prune()
        entry = self.pending.get(request_id)
        if entry is None or entry.user != user:
            # another user's id is answered like an unknown one
            done = self.finished.get(request_id)
            if done is not None and done[0] == user:
                raise ApprovalError(f"login {request_id} already {done[1]}", "approval_finished", done[1])
            raise ApprovalError(f"no pending login {request_id}", "approval_unknown")
        if approve:
            if self.cfg.web_approval_single_pending and self.count(user) > 1 and not bound:
                raise ApprovalError(f"{self.count(user)} logins pending; approving none of them "
                                    "([mfa] web_approval_single_pending)", "approval_conflict")
            age = self.stale(entry, auth_time)
            if age is not None:
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
        self.kc = KeycloakOtp(cfg.keycloak) if cfg.mode in KEYCLOAK_OTP_MODES else None
        self.approvals = WebApprovals(cfg)
        self.code_failures = CodeFailures(cfg)

    @property
    def wants_otp_in_password(self) -> bool:
        return self.cfg.mode in ("otp", "otp_or_push")

    def exempt(self, groups: set[str]) -> bool:
        return self.cfg.mode == "none" or bool(groups & set(self.cfg.exempt_groups))

    async def verify(self, user: str, otp: str | None, password: str | None, *,
                     account: str | None = None, method: str = "", client_address: str | None = None,
                     notify: Notify | None = None, codes: CodeEntry | None = None) -> str:
        """Run the configured second factor. Returns the factor used; raises MfaDenied.
        `user`: privacyIDEA's and Keycloak's name; `account` (default `user`), `method` and
        `client_address`: the local account and the login shown on the approval page.
        `notify` hears when the login starts waiting for the user (push, web approval;
        not for an OTP check), for the proxy's waiting screen. `codes`: the module can
        read a code on its waiting screen (code_or_web; without it only the approval page)."""
        try:
            if otp is not None and self.wants_otp_in_password:
                assert self.pi is not None
                if await asyncio.to_thread(self.pi.check_otp, user, otp):
                    return "otp"
                raise MfaDenied("OTP rejected")
            if self.cfg.mode == "web" or (self.cfg.mode == "code_or_web" and codes is None):
                return await self.approvals.wait(account or user, method, client_address, notify)
            if self.cfg.mode == "code_or_web":
                assert codes is not None
                return await self.code_or_web(user, account or user, method, client_address, codes, notify)
            if self.cfg.mode == "push_or_web":
                return await self.push_or_web(user, password, account or user, method, client_address,
                                              notify)
            if self.cfg.mode in ("push", "otp_or_push"):
                if await self.push(user, password, notify):
                    return "push"
                raise MfaDenied("push not confirmed in time", "mfa_timeout")
            raise MfaDenied("OTP required: append it to the password")
        except PrivacyIdeaError as exc:
            log.error("privacyIDEA error for %s: %s", user, exc)
            raise MfaDenied("MFA service unavailable") from None

    async def push(self, user: str, password: str | None, notify: Notify | None = None) -> bool:
        """Push challenge: True once approved, False if push_timeout passed (or the final
        check refused it). Raises MfaDenied without a push-capable token. `notify` hears
        ("push", push_timeout) once the challenge is out."""
        assert self.pi is not None
        txid = await asyncio.to_thread(self.pi.trigger_challenge, user, password)
        if not txid:
            raise MfaDenied("no challenge-capable token for user")
        log.info("push challenge sent to %s (transaction %s)", user, txid)
        notify_safely(notify, "push", self.cfg.privacyidea.push_timeout)
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
                          client_address: str | None, notify: Notify | None = None) -> str:
        """Push and web approval at once; the first answer wins and the other is cancelled.
        A Deny or a refused push fails the login. A push that cannot start (no push-capable
        token, privacyIDEA unreachable) or runs out of push_timeout leaves the web approval
        waiting, whose web_approval_timeout bounds the whole wait. `notify` hears
        ("push_or_web", web_approval_timeout, code, id) at the start, and ("web", the time
        left, code, id) when only the web approval is left."""
        started = time.monotonic()
        code, request_id = self.approvals.new_code(account), self.approvals.new_id()
        notify_safely(notify, "push_or_web", self.cfg.web_approval_timeout, code, request_id)
        push = asyncio.ensure_future(self.push(user, password))
        web = asyncio.ensure_future(self.approvals.wait(account, method, client_address, code=code,
                                                        request_id=request_id))
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
                notify_safely(notify, "web", self.cfg.web_approval_timeout - (time.monotonic() - started), code,
                              request_id)
            return await web
        finally:
            for task in (push, web):
                if not task.done():
                    task.cancel()
            await asyncio.gather(push, web, return_exceptions=True)

    async def code_or_web(self, user: str, account: str, method: str, client_address: str | None,
                          codes: CodeEntry, notify: Notify | None = None) -> str:
        """A code typed on the waiting screen (checked by Keycloak) and the web approval at
        once; the first success wins and the other is cancelled. Returns "keycloak_otp" or
        "web"; raises MfaDenied: Deny or no decision in web_approval_timeout (as "web"; it
        bounds the whole wait, a code check under way included), or
        [mfa] code_attempts wrong codes for this login. A Keycloak that cannot be reached
        costs no attempt. With code_user_failures wrong codes of the account in the window
        the field stays closed and only the approval page is left; also for the rest of
        the login when the user has no OTP credential (NO_OTP) or Keycloak's answer shows
        a setup error (OFF, keycloak_otp.py), neither costing an attempt. `notify` hears
        ("code_or_web", the time left, code, id, entry={"state": ..., "attempts_left": n})
        at the start and after every code: state "ready", "wrong", "unavailable", or
        without a field "blocked", "no_otp", "off"."""
        assert self.kc is not None
        started = time.monotonic()
        timeout = self.cfg.web_approval_timeout
        code, request_id = self.approvals.new_code(account), self.approvals.new_id()
        attempts = self.cfg.code_attempts

        def prompt(state: str) -> None:
            notify_safely(notify, "code_or_web", timeout - (time.monotonic() - started), code, request_id,
                          entry={"state": state, "attempts_left": attempts})

        blocked = self.code_failures.blocked(account)
        if blocked:
            log.warning("%s: %d wrong codes within %ds: code entry closed, approval page only",
                        account, self.cfg.code_user_failures, self.cfg.code_failure_window)
        web = asyncio.ensure_future(self.approvals.wait(account, method, client_address, code=code,
                                                        request_id=request_id))
        codes.open = not blocked
        prompt("blocked" if blocked else "ready")
        typed: asyncio.Future | None = None
        try:
            while True:
                typed = asyncio.ensure_future(codes.get())
                await asyncio.wait({web, typed}, return_when=asyncio.FIRST_COMPLETED)
                if web.done():
                    return await web
                # The approval page's decision or timeout ends the wait also while Keycloak
                # checks: web_approval_timeout bounds the whole wait (the check's thread
                # finishes on its own; a right code then only ends its Keycloak session).
                check = asyncio.ensure_future(asyncio.to_thread(self.kc.check, user, typed.result()))
                await asyncio.wait({web, check}, return_when=asyncio.FIRST_COMPLETED)
                if web.done():  # decided on the approval page meanwhile: that counts (a Deny too)
                    return await web
                try:
                    result = check.result()
                except KeycloakError as exc:
                    log.error("code of %s not checked: %s", account, exc)
                    prompt("unavailable")
                    continue
                if result == keycloak_otp.OK:
                    log.info("%s: code from the waiting screen accepted by Keycloak", account)
                    return "keycloak_otp"
                if result in (keycloak_otp.NO_OTP, keycloak_otp.OFF):
                    # not the user's mistake: no attempt; the field stays closed, which
                    # also keeps odd answers from becoming unlimited guesses
                    log.info("%s: code entry closed for this login (%s), approval page only",
                             account, "no OTP credential" if result == keycloak_otp.NO_OTP else "code check unusable")
                    codes.open = False
                    prompt(result)
                    return await web
                attempts -= 1
                self.code_failures.record(account)
                log.warning("%s: wrong code on the waiting screen (%s login from %s); %d attempt(s) left",
                            account, method, client_address, attempts)
                if attempts <= 0:
                    raise MfaDenied("too many wrong codes")
                if self.code_failures.blocked(account):
                    log.warning("%s: %d wrong codes within %ds: code entry closed, approval page only",
                                account, self.cfg.code_user_failures, self.cfg.code_failure_window)
                    codes.open = False
                    prompt("blocked")
                else:
                    prompt("wrong")
        finally:
            codes.open = False
            for task in (web, typed):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(t for t in (web, typed) if t is not None), return_exceptions=True)
