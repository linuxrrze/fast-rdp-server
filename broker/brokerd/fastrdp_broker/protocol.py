# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Wire protocol: one JSON object per line over a Unix stream socket.

Proxy module -> broker.sock:
  {"op": "login", "session_id": str, "method": "nla"|"tls", "user": str, "domain": str,
   "password": str|null, "principal": str|null, "smartcard": bool, "remote_guard": bool,
   "desktop_hint": str|null, "client_address": str|null, "width": int|null,
   "height": int|null, "connection_type": int, "kdc_evidence": [str] (NLA only),
   "progress": 1 (optional), "keyboard_layout": int (with "progress"),
   "picker": 1 (optional, with "progress")}
  -> 0..n progress messages (only if the request has "progress": 1), then
  -> {"ok": true, "user": str, "desktop": str,
      "target": {"host": str, "port": int, "username": str, "password": str,
                 "domain": str, "security": "tls"|"nla", "cert_sha256": str}}
  -> {"ok": false, "error": str, "reason": str}

  {"op": "end", "session_id": str}  -> {"ok": true}

  "smartcard": NLA with TSSmartCardCreds; "password" then holds the PIN and is ignored.
  "remote_guard": NLA with TSRemoteGuardCreds (Remote Credential Guard, mstsc /remoteGuard;
  proxy.ini [FastRDP] AcceptRemoteGuard). The module discarded the forwarded Kerberos
  tickets; "password" is null. Identity only: the principal is the identity, there is no
  session TGT. Both flags are false for TLS logins and are absent from older modules.
  "kdc_evidence": what the KDC asserted in the Kerberos service ticket, verified with the
  service key by the proxy's FreeRDP (patches/freerdp/0005): "ind:<authentication
  indicator>" (MIT/FreeIPA CAMMAC) and "sid:S-1-..." (enabled group SIDs from the PAC:
  ExtraSids, domain and resource groups), at most 512 items. Kerberos NLA logins only; []
  if the ticket carried none; absent for TLS logins, from older modules and when FreeRDP
  cannot tell. Compared with [mfa] kdc_evidence_as_mfa (Broker.kdc_evidence).

  "progress": 1: the module shows a waiting screen (proxy.ini [FastRDP] WaitingScreen,
  fastrdp_plugin.c waitingScreen) and takes progress messages before the reply: one JSON
  object per line with a "progress" field; the reply is the first line without one.
  Requests without "progress" (older modules, WaitingScreen off) get the reply alone; a
  module that asks gets none from an older broker and keeps its generic panel. The module
  accepts at most 32 progress messages, each within the 64 KiB line limit.
    {"progress": "mfa", "method": "push"|"web"|"push_or_web", "timeout_s": int,
     "lines": [str], "countdown": str, "approve_url": str, "qr": [str]}
      once the login waits for the user's second factor (mfa.SecondFactor notify): a
      privacyIDEA push, the approval page, or both; again with method "web" when only the
      approval page is left (push_or_web, push failed or timed out). Never for exempt
      groups, nla_kdc_enforced, kdc_evidence_as_mfa, reconnect grace or an appended OTP.
      "timeout_s": seconds the wait may take (countdown, labelled "countdown");
      "approve_url" and "qr" ([ui] approve_url, qr_code) only for web and push_or_web:
      "qr" is the QR code of approve_url as rows of "0"/"1" (qrcode.py, dark = "1",
      without the quiet zone).
    {"progress": "choose_desktop", "options": [{"name": str, "label": str, "running": bool}],
     "default": str, "timeout_s": int, "lines": [str], "countdown": str, "hint": str}
      the desktop picker ([broker] desktop_picker, Broker.pick_desktop): after the second
      factor, only if the request has "picker": 1 (the module can draw the rows and read
      the client's input: WaitingScreen, patches/freerdp/0007), names no desktop
      ("desktop_hint"), is no web login, the user may use more than one desktop and, with
      "if_multiple", has not chosen one before (desktop_choice() source). 2..9
      options in [desktops] order ("label" with the running/reconnects marks of [ui]
      picker_running, picker_reconnects; "running": the desktop of a running session),
      "default" preselected (one of them), "timeout_s" 3..60. The module answers once:
        {"op": "choice", "desktop": str|null}
      null (Esc, or the countdown ran out) = "default". The broker waits timeout_s + 5
      seconds; no answer, a name it did not offer, or one the user may no longer use gives
      "default" (logged). An answer after that is logged and ignored.
    {"progress": "session_start", "lines": [str]}
      before the back-end session is started or reused (GNOME/Plasma can take a while).
  "lines": texts from [ui] (ui.py) in [ui] language or the language of "keyboard_layout"
  (the client's keyboard layout, [MS-RDPBCGR] 2.2.1.3.2) with [ui] language_from_keyboard.
  Progress messages are queued without waiting for the module; failing to send one never
  fails or delays the login. ("mfa_pending" below is the webgate's, unrelated.)

  The module closes the connection without waiting for the "login" reply when its RDP
  client goes away (e.g. mstsc closed during an MFA push or the desktop picker). The
  broker then cancels the login (Broker.login_unless_abandoned): a push or web approval
  wait stops, a session start already under way completes, nothing is recorded as
  connected. While a login is pending the module sends nothing but the one "choice" line
  after a "choose_desktop" prompt; any other data (also a "choice" before the prompt, a
  second one, or one from a module without "picker": 1) is a protocol error and closes
  the connection without a reply.

fastrdp-webgate ([web] gateway_user) -> broker.sock:
  {"op": "web_token", "user": str}
  -> {"ok": true, "user": str, "token": "fastrdp-web1:...", "desktops": [str]}
  {"op": "web_desktops", "user": str}
  -> {"ok": true, "user": str, "default": str, "rdp_desktop": str|null,
      "desktops": [{"name": str, "label": str}]}
  {"op": "web_set_desktop", "user": str, "desktop": str|null}
  -> {"ok": true, "user": str, "rdp_desktop": str|null}
  Refusals as for "login".

  "default": the desktop an RDP login without a client hint gets now; "rdp_desktop":
  the desktop the user chose for RDP logins on the chooser page (desktopprefs.py; null:
  none, or no longer allowed). web_set_desktop stores it (null removes it); a desktop the
  user may not use is refused ("not_allowed"), a failed write gives "unavailable". The
  "desktop" field must be present.

  [mfa] mode web / push_or_web (mfa.WebApprovals): logins waiting for their user's
  approval on the webgate's approval page. "user" is the name the webgate signed in
  (resolved like a TLS login); only that account's logins are listed or decided.
  {"op": "mfa_pending", "user": str}
  -> {"ok": true, "user": str, "pending": [{"id": str, "method": "nla"|"tls",
      "client_address": str|null, "age_s": int, "single_pending_conflict": bool,
      "code": str}]}
  {"op": "mfa_decide", "user": str, "id": str, "approve": bool, "auth_time": int}
  -> {"ok": true, "approved": bool}
  -> {"ok": false, "error": "not decided", "reason": "approval_unknown"|"approval_finished"|
      "approval_conflict"|"approval_stale", "outcome": str (approval_finished only)}
  "auth_time": the ID token's auth_time (Unix time) of the sign-in that decides. Approve
  is refused for a sign-in more than [mfa] web_approval_max_auth_age seconds older than
  the login ("approval_stale") and, with web_approval_single_pending, while the user has
  more than one pending login ("approval_conflict"; every entry says so). Deny is always
  accepted. "approval_unknown": no such pending login of this user (another user's id
  looks the same); "approval_finished": it was already approved, denied, expired or
  abandoned ("outcome": approved|denied|expired|abandoned, kept for 5 minutes). A missing
  or malformed field is a protocol error.
  "code": two random digits per pending login, shown on the waiting screen ([ui] {code}),
  on the approval page and in notifications, so the user can tell which login is which.

  {"op": "mfa_events", "wait_s": int (0..25, absent: 0)}
  -> {"ok": true, "events": [
       {"event": "pending", "id": str, "user": str, "method": "nla"|"tls",
        "client_address": str|null, "created": int, "timeout_s": int, "code": str} |
       {"event": "finished", "id": str, "user": str,
        "outcome": "approved"|"denied"|"expired"|"abandoned"}]}
  Long poll of fastrdp-webgate's notifier (approval notifications, docs/notifications.md):
  the events since the last poll, oldest first, at most 100; with none queued it waits up
  to "wait_s" seconds for the first and may return []. "user" is the local account,
  "created" Unix time. A "pending" event whose login has ended by the time it is
  collected is left out (its "finished" event still comes). Events are queued only while
  a notifier polls (from its first poll until 5 minutes after its last), at most 256;
  more are dropped and counted ("status" "mfa_events"). Logins never wait for this. One
  consumer is expected: two would split the events between them. "user" in the request
  is ignored.

Refusals: "error" stays generic ("access denied", "session could not be started",
"not permitted"); details go to the broker log only. "reason" is machine-readable; the
proxy module maps it to an RDP Set Error Info code ([MS-RDPBCGR] 2.2.5.1.1):
  "denied"       bad or unknown credentials (never told apart), invalid web token, realm,
                 policy (session_tgt = required), anything else              -> 0x7
  "not_allowed"  identity proven, but not in allow_groups, account check failed
                 (expired, locked, pam_access) or no permitted desktop        -> 0x9
  "mfa_failed"   second factor rejected (also Deny on the approval page),
                 missing or MFA service unavailable                          -> 0x7
  "mfa_timeout"  push or web approval not given in time                      -> 0x409
  "backend"      session could not be started                                -> 0x400
"not_allowed" confirms the credentials, so a TLS password login that still owes its
second factor gets "denied" instead (Broker.authz_reason). Receivers treat unknown
reasons like "denied".

PAM module -> token.sock (root only):
  {"op": "redeem", "user": str, "token": str} -> {"ok": true, "password": str|null}

Admin (root) -> broker.sock:
  {"op": "status"} -> {"ok": true, "sessions": [...], "mfa_grace_entries": int,
                       "mfa_pending_approvals": int, "mfa_events": {"consumer": bool,
                       "queued": int, "sent": int, "dropped": int, "last_poll": int|null},
                       ..., "tickets": {account: {...}}}
      "mfa_events": the approval notification queue (mfa_events above); "last_poll"
      Unix time of the notifier's last poll (null: none since the broker started).
  {"op": "tickets", "user": str|absent} -> {"ok": true, "tickets": {account: {...}}}
      TGT metadata of each session user's (or one account's) default credential cache:
      state ok|expiring|not_renewable_soon|expired|none|unknown, principal, cache,
      cache_type, expires (UTC ISO), expires_in (s), renewable, renew_until, renew_in,
      caches (number in the collection), error (tickets.py)
  {"op": "logout", "user": str} -> {"ok": true}
  {"op": "clear_grace", "user": str|absent} -> {"ok": true, "cleared": int}
      forget [mfa] reconnect_grace entries of one local account (absent: all)
  {"op": "desktop_pref", "user": str, "set": str|absent, "clear": bool|absent}
  -> {"ok": true, "user": str, "rdp_desktop": str|null, "rdp_desktop_allowed": bool,
      "home_desktop": str|null, "desktop": str|null, "source": str, "group": str|null,
      "allowed": [str], "login_allowed": bool}
  -> {"ok": false, "error": str, "reason": "not_allowed", "user": str, "allowed": [str]}
      fastrdpctl desktop: the desktop stored for the account's RDP logins (the one
      web_set_desktop stores; "user" resolved like a TLS login). "set" stores a desktop
      the account may use (else "not_allowed", with the desktops it may use), "clear":
      true removes it (both at once: protocol error); a failed write gives
      "unavailable". The reply then shows the state afterwards: "rdp_desktop" the stored
      desktop (also one no longer allowed: "rdp_desktop_allowed" false, ignored),
      "home_desktop" ~/.config/fastrdp/desktop (null: none, unreadable or
      home_read_timeout), "desktop" what an RDP login without a client hint gets now
      (null: no permitted desktop) and "source" why: web_pref (the stored desktop),
      home_file, group_default ("group" names the group, [defaults.groups]) or default
      ([defaults] desktop); "none" if no desktop is permitted. "login_allowed": the
      account is in [auth] allow_groups (or no groups are configured).
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct

MAX_LINE = 64 * 1024


class ProtocolError(Exception):
    pass


def peer_uid(writer: asyncio.StreamWriter) -> int:
    sock: socket.socket = writer.get_extra_info("socket")
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


async def read_message(reader: asyncio.StreamReader) -> dict | None:
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise ProtocolError("truncated message") from None
    except asyncio.LimitOverrunError:
        raise ProtocolError("message too large") from None
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from None
    if not isinstance(msg, dict) or not isinstance(msg.get("op"), str):
        raise ProtocolError("message must be an object with an 'op' field")
    return msg


async def write_message(writer: asyncio.StreamWriter, msg: dict) -> None:
    writer.write(json.dumps(msg, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


def str_field(msg: dict, key: str, *, required: bool = False, max_len: int = 1024) -> str | None:
    value = msg.get(key)
    if value is None or value == "":
        if required:
            raise ProtocolError(f"missing field {key!r}")
        return None
    if not isinstance(value, str) or len(value) > max_len:
        raise ProtocolError(f"invalid field {key!r}")
    return value


def int_field(msg: dict, key: str, lo: int, hi: int) -> int | None:
    value = msg.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise ProtocolError(f"invalid field {key!r}")
    return value
