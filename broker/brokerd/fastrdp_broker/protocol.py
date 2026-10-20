# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Wire protocol: one JSON object per line over a Unix stream socket.

Proxy module -> broker.sock:
  {"op": "login", "session_id": str, "method": "nla"|"tls", "user": str, "domain": str,
   "password": str|null, "principal": str|null, "smartcard": bool, "desktop_hint": str|null,
   "client_address": str|null, "width": int|null, "height": int|null}
  -> {"ok": true, "user": str, "desktop": str,
      "target": {"host": str, "port": int, "username": str, "password": str,
                 "domain": str, "security": "tls"|"nla"}}
  -> {"ok": false, "error": str, "reason": str}

  {"op": "end", "session_id": str}  -> {"ok": true}

fastrdp-webgate ([web] gateway_user) -> broker.sock:
  {"op": "web_token", "user": str}
  -> {"ok": true, "user": str, "token": "fastrdp-web1:...", "desktops": [str]}
  {"op": "web_desktops", "user": str}
  -> {"ok": true, "user": str, "default": str, "desktops": [{"name": str, "label": str}]}
  Refusals as for "login".

Refusals: "error" stays generic ("access denied", "session could not be started",
"not permitted"); details go to the broker log only. "reason" is machine-readable; the
proxy module maps it to an RDP Set Error Info code ([MS-RDPBCGR] 2.2.5.1.1):
  "denied"       bad or unknown credentials (never told apart), invalid web token, realm,
                 policy (session_tgt = required), anything else              -> 0x7
  "not_allowed"  identity proven, but not in allow_groups, account check failed
                 (expired, locked, pam_access) or no permitted desktop        -> 0x9
  "mfa_failed"   second factor rejected, missing or MFA service unavailable  -> 0x7
  "mfa_timeout"  push not approved in time                                   -> 0x409
  "backend"      session could not be started                                -> 0x400
"not_allowed" confirms the credentials, so a TLS password login that still owes its
second factor gets "denied" instead (Broker.authz_reason). Receivers treat unknown
reasons like "denied".

PAM module -> token.sock (root only):
  {"op": "redeem", "user": str, "token": str} -> {"ok": true, "password": str|null}

Admin (root) -> broker.sock:
  {"op": "status"} -> {"ok": true, "sessions": [...]}
  {"op": "logout", "user": str} -> {"ok": true}
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
