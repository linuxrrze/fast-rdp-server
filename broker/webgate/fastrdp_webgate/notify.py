# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Approval notifications (docs/notifications.md): when an RDP login waits for web
approval, the user's phone gets "approve your RDP login from <address> (code NN)",
linking to the fixed approval page <public_url><path_prefix>/approve.

The notification is a hint only: approving still takes the fresh MFA sign-in on that
page, which lists the signed-in user's own pending logins. It carries no secret, no
login id and no other link.

A background thread long-polls the broker (op mfa_events, protocol.py) and hands each
message to a small thread pool, one task per subscription, with a short timeout. Every
error is logged and dropped: nothing here can delay or fail a login. Backends: ntfy
(POST to <ntfy_url>/<the user's topic>) and Web Push (webpush.py).
"""

from __future__ import annotations

import collections
import hashlib
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import webpush
from .config import Config
from .notifystore import StoreError, SubscriptionStore

log = logging.getLogger("fastrdp.webgate.notify")

TITLE = "fastrdp sign-in"
POLL_WAIT = 25           # seconds the broker may hold a poll (its maximum)
SEND_TIMEOUT = 5
FINISHED_TTL = 300
SENT_KEEP = 900          # seconds a notified login is remembered for its follow-up
METHODS = {"nla": "Kerberos (NLA)", "tls": "password"}
OUTCOMES = {
    "approved": "was approved",
    "denied": "was denied",
    "expired": "was not approved in time",
    "abandoned": "was cancelled by the RDP client",
}
ALERT = ("Several sign-in attempts with your account. If that wasn't you, change your password.")


@dataclass
class Message:
    title: str
    body: str
    url: str | None           # only ever the fixed approval page
    tag: str                  # replaces an earlier notification with the same tag (Web Push)
    ttl: int
    urgent: bool = True
    renotify: bool = True     # ntfy: send at all for a follow-up (Web Push always replaces)


def tag_of(login_id: str) -> str:
    """Web Push tag and Topic of a login: a hash, so that the push service never sees
    the broker's id (22 base64url characters, the Topic header allows 32)."""
    return webpush.b64u(hashlib.sha256(b"fastrdp-notify\0" + login_id.encode()).digest()[:16])


def broker_mfa_events(path: str, wait_s: int, timeout: float) -> list[dict]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps({"op": "mfa_events", "wait_s": wait_s}).encode() + b"\n")
        line = s.makefile("rb").readline(256 * 1024)
    try:
        reply = json.loads(line)
    except ValueError:
        raise OSError("no answer from broker") from None
    if not isinstance(reply, dict) or not reply.get("ok") or not isinstance(reply.get("events"), list):
        raise OSError(f"broker refused mfa_events: {reply.get('error') if isinstance(reply, dict) else reply}")
    return [e for e in reply["events"] if isinstance(e, dict)]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never carry the token elsewhere


def send_ntfy(base_url: str, topic: str, msg: Message, token: str | None, timeout: float = SEND_TIMEOUT,
              opener=None) -> int:
    """POST one message to <base_url>/<topic> (ntfy's publish API with headers); the
    HTTP status."""
    headers = {"Title": msg.title, "Priority": "high" if msg.urgent else "default",
               "Tags": "key" if msg.url else "warning"}
    if msg.url:
        headers["Click"] = msg.url
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{base_url}/{topic}", data=msg.body.encode(), headers=headers, method="POST")
    try:
        with (opener or urllib.request.build_opener(_NoRedirect)).open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code


class RateLimit:
    """At most `count` notifications per user within `window` seconds; above that one
    alert per window."""

    def __init__(self, count: int, window: int, clock=time.monotonic):
        self.count, self.window, self.clock = count, window, clock
        self.sent: dict[str, collections.deque] = {}
        self.alerted: dict[str, float] = {}

    def check(self, user: str) -> str:
        """"send", "alert" (the limit was just reached) or "drop"."""
        now = self.clock()
        q = self.sent.setdefault(user, collections.deque())
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) < self.count:
            q.append(now)
            return "send"
        if now - self.alerted.get(user, -self.window) >= self.window:
            self.alerted[user] = now
            return "alert"
        return "drop"


class Notifier:
    def __init__(self, cfg: Config, store: SubscriptionStore, *, vapid_key=None, ntfy_token: str | None = None,
                 clock=time.monotonic, workers: int = 4):
        self.cfg = cfg
        self.n = cfg.notify
        self.store = store
        self.vapid_key = vapid_key
        self.ntfy_token = ntfy_token
        self.clock = clock
        self.approve_url = cfg.webgate.public_url.rstrip("/") + cfg.webgate.path_prefix + "/approve"
        self.rate = RateLimit(*self.n.rate(), clock=clock)
        self.notified: dict[str, tuple[str, dict, float]] = {}   # login id -> (user, event, when)
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fastrdp-notify")
        self.stop = threading.Event()

    @property
    def vapid_public_key(self) -> str:
        return webpush.b64u(webpush.public_bytes(self.vapid_key)) if self.vapid_key else ""

    # ------------------------------------------------------------ messages
    def pending_message(self, event: dict) -> Message:
        address = str(event.get("client_address") or "an unknown address")
        when = time.strftime("%H:%M:%S UTC", time.gmtime(event.get("created") or time.time()))
        code = f" (code {event['code']})" if self.n.show_code and event.get("code") else ""
        method = METHODS.get(event.get("method"), "RDP")
        body = (f"fastrdp: approve your RDP login from {address}{code}? {event.get('user')}, "
                f"{method} login at {when}. Approve only a login you started yourself.")
        ttl = int(event.get("timeout_s") or 90)
        return Message(TITLE, body, self.approve_url, tag_of(str(event.get("id"))), ttl)

    def finished_message(self, event: dict, pending: dict) -> Message:
        outcome = str(event.get("outcome"))
        address = str(pending.get("client_address") or "an unknown address")
        body = f"The RDP login from {address} {OUTCOMES.get(outcome, 'has ended')}."
        bad = outcome in ("denied", "expired")
        if bad:
            body += " If you did not start it, change your password."
        return Message(TITLE, body, None, tag_of(str(event.get("id"))), FINISHED_TTL, urgent=False,
                       renotify=bad and self.n.alert_on_deny)

    def alert_message(self, user: str) -> Message:
        return Message(TITLE, ALERT, None, tag_of("alert:" + user), FINISHED_TTL)

    # ------------------------------------------------------------ events
    def handle(self, event: dict) -> None:
        """One broker event; never raises."""
        try:
            self._handle(event)
        except Exception:
            log.exception("approval notification for event %s failed", event.get("event"))

    def _handle(self, event: dict) -> None:
        now = self.clock()
        for k in [k for k, (_u, _e, t) in self.notified.items() if now - t >= SENT_KEEP]:
            del self.notified[k]
        user = event.get("user")
        if not isinstance(user, str) or not isinstance(event.get("id"), str):
            return
        if event.get("event") == "pending":
            subs = self.subscriptions(user)
            if not subs:
                return
            verdict = self.rate.check(user)
            if verdict == "drop":
                log.info("approval notification for %s not sent: rate limit %s", user, self.n.rate_limit)
                return
            if verdict == "alert":
                log.warning("approval notifications for %s: more than %s; sending one alert without a link",
                            user, self.n.rate_limit)
                self.deliver(user, subs, self.alert_message(user))
                return
            self.notified[event["id"]] = (user, event, now)
            self.deliver(user, subs, self.pending_message(event))
        elif event.get("event") == "finished":
            entry = self.notified.pop(event["id"], None)
            if entry is None or entry[0] != user:
                return   # never notified (no subscription, rate limit, ended before we heard)
            subs = self.subscriptions(user)
            if subs:
                self.deliver(user, subs, self.finished_message(event, entry[1]))

    def subscriptions(self, user: str) -> list[dict]:
        try:
            return [s for s in self.store.list(user) if s["type"] in self.n.backends]
        except (StoreError, OSError) as exc:
            log.warning("subscriptions of %s not read: %s", user, exc)
            return []

    def deliver(self, user: str, subs: list[dict], msg: Message) -> None:
        for sub in subs:
            if sub["type"] == "ntfy" and not msg.renotify:
                continue   # ntfy cannot replace a message: a follow-up only as an alert
            self.pool.submit(self.send_one, user, sub, msg)

    def send_one(self, user: str, sub: dict, msg: Message) -> bool:
        """Send to one subscription (in a pool thread); True if accepted. Never raises."""
        try:
            if sub["type"] == "ntfy":
                status = send_ntfy(self.n.ntfy_url, str(sub.get("topic")), msg, self.ntfy_token,
                                   timeout=SEND_TIMEOUT)
                if status == 200:
                    return True
                log.warning("ntfy refused the notification for %s: HTTP %d%s", user, status,
                            " (check ntfy_token_file and the token's write access)" if status in (401, 403) else "")
                return False
            payload = json.dumps({"title": msg.title, "body": msg.body, "tag": msg.tag, "url": msg.url},
                                 separators=(",", ":")).encode()
            status = webpush.send(sub, payload, self.vapid_key, self.n.vapid_subject, ttl=msg.ttl,
                                  urgency="high" if msg.urgent else "normal", topic=msg.tag,
                                  timeout=SEND_TIMEOUT)
            if status in (200, 201, 202):
                return True
            if status in (404, 410):
                log.info("web push subscription %r of %s has expired (HTTP %d); removed",
                         sub.get("label"), user, status)
                self.store.remove(user, sub["id"])
            else:
                log.warning("push service refused the notification for %s (%r): HTTP %d%s", user,
                            sub.get("label"), status, " (rate limited)" if status == 429 else
                            " (payload too large)" if status == 413 else "")
            return False
        except Exception as exc:  # timeouts, DNS, TLS, bad keys: logged, never raised
            log.warning("notification for %s (%s %r) not sent: %s", user, sub.get("type"), sub.get("label"), exc)
            return False

    def test(self, user: str) -> int:
        """Send a test message to all the user's subscriptions; their number."""
        subs = self.subscriptions(user)
        msg = Message(TITLE, "Test: notifications for RDP login approvals work on this device.",
                      self.approve_url, tag_of("test:" + user), 300, urgent=False)
        self.deliver(user, subs, msg)
        return len(subs)

    # ------------------------------------------------------------ loop
    def run(self) -> None:
        """Poll the broker until stop is set; backs off while the broker is away."""
        path = self.cfg.webgate.broker_socket
        backoff, failing = 1.0, False
        log.info("approval notifications via %s", ", ".join(self.n.backends))
        while not self.stop.is_set():
            try:
                events = broker_mfa_events(path, POLL_WAIT, POLL_WAIT + 10)
            except OSError as exc:
                if not failing:
                    log.warning("approval notifications: broker not reachable (%s); retrying", exc)
                failing = True
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            if failing:
                log.info("approval notifications: broker reachable again")
            backoff, failing = 1.0, False
            for event in events:
                self.handle(event)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="fastrdp-notifier", daemon=True)
        t.start()
        return t
