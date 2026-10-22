# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Wire protocol: one JSON object per line over a Unix stream socket.

Proxy module -> broker.sock:
  {"op": "login", "session_id": str, "method": "nla"|"tls", "user": str, "domain": str,
   "password": str|null, "principal": str|null, "smartcard": bool, "remote_guard": bool,
   "desktop_hint": str|null, "client_address": str|null, "width": int|null,
   "height": int|null, "connection_type": int}
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

  The module closes the connection without waiting for the "login" reply when its RDP
  client goes away (e.g. mstsc closed during an MFA push). The broker then cancels the
  login (Broker.login_unless_abandoned): a push or web approval wait stops, a session
  start already under way completes, nothing is recorded as connected. The module sends
  nothing else while a login is pending; data instead of EOF is a protocol error.

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
      "client_address": str|null, "age_s": int, "single_pending_conflict": bool}]}
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
                       "mfa_pending_approvals": int, ...,
                       "tickets": {account: {...}}}
  {"op": "tickets", "user": str|absent} -> {"ok": true, "tickets": {account: {...}}}
      TGT metadata of each session user's (or one account's) default credential cache:
      state ok|expiring|not_renewable_soon|expired|none|unknown, principal, cache,
      cache_type, expires (UTC ISO), expires_in (s), renewable, renew_until, renew_in,
      caches (number in the collection), error (tickets.py)
  {"op": "logout", "user": str} -> {"ok": true}
  {"op": "clear_grace", "user": str|absent} -> {"ok": true, "cleared": int}
      forget [mfa] reconnect_grace entries of one local account (absent: all)
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
