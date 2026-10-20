# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Virtual FIDO authenticator for ONE Linux session: CTAPHID reports from the session's
browser in, [MS-RDPEWA] requests to that session's RDP client out.

Transport-free: the caller moves bytes (uhid <-> Bridge <-> DVC). What happens here:

  CTAPHID_INIT/PING/WINK/CANCEL   answered locally (CANCEL -> RDPEWA CANCEL_CUR_OP)
  CTAPHID_CBOR authenticatorGetInfo (0x04)
                                  answered locally: CTAP2.1, rk, up, uv=true (the CLIENT
                                  verifies the user), no clientPin, so the browser never
                                  runs the PIN protocol against the bridge
  CTAPHID_CBOR MakeCredential/GetAssertion
                                  policy (RP ID allow-list, one operation at a time, rate
                                  limit, optional local consent), then forwarded as an
                                  RDPEWA WEB_AUTHN request; the client's answer goes back
                                  as the CTAP response, byte for byte
  anything else                   CTAP1_ERR_INVALID_COMMAND

The bridge never sees the origin: browsers give authenticators only clientDataHash.
Origin binding therefore still comes from the browser in the session, and the RP ID
allow-list is what keeps a compromised session from using the user's keys for sites
the deployment did not intend (docs/webauthn-redirection.md, security model).
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from . import cbor, ctaphid, rdpewa

# CTAP2 authenticator commands
AUTHN_MAKE_CREDENTIAL = 0x01
AUTHN_GET_ASSERTION = 0x02
AUTHN_GET_INFO = 0x04
AUTHN_CLIENT_PIN = 0x06
AUTHN_GET_NEXT_ASSERTION = 0x08

# CTAP status codes (CTAP 2.1, 8.2)
CTAP1_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_CHANNEL_BUSY = 0x06
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D
CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F
CTAP2_ERR_NOT_ALLOWED = 0x30

# CTAP map keys
MC_RP, MC_OPTIONS, MC_PIN_AUTH, MC_PIN_PROTO = 2, 7, 8, 9
GA_RP_ID, GA_OPTIONS, GA_PIN_AUTH, GA_PIN_PROTO = 1, 5, 6, 7


@dataclass
class Policy:
    # RP IDs this session may use the client's authenticators for: exact names, or
    # ".example.com" for the domain and its subdomains. Empty = nothing is forwarded.
    allowed_rp_ids: list[str] = field(default_factory=list)
    max_per_minute: int = 10
    timeout_ms: int = 60000
    # Called before forwarding (e.g. a desktop notification in the session the user
    # must accept): (rp_id, "create" | "get") -> bool. None = no extra prompt; the
    # client-side touch/UV remains the user's consent.
    confirm: Callable[[str, str], bool] | None = None

    def rp_allowed(self, rp_id: str) -> bool:
        rp_id = rp_id.lower().rstrip(".")
        for a in self.allowed_rp_ids:
            a = a.lower()
            if a.startswith("."):
                if rp_id == a[1:] or rp_id.endswith(a):
                    return True
            elif rp_id == a:
                return True
        return False


@dataclass
class Pending:
    cid: int
    request: rdpewa.Request
    started: float


class Bridge:
    """One per session. handle_report() returns (reports for the browser, RDPEWA
    request bytes for the client or None); handle_client() takes the client's answer."""

    def __init__(self, session_id: str, policy: Policy, aaguid: bytes = b"\0" * 16,
                 clock: Callable[[], float] = time.monotonic):
        self.session_id = session_id
        self.policy = policy
        self.aaguid = aaguid
        self.clock = clock
        self.assembler = ctaphid.Assembler()
        self.channels: set[int] = set()
        self.pending: Pending | None = None
        self.recent: deque[float] = deque()
        self.log: list[str] = []

    # ---------------------------------------------------------------- browser side
    def handle_report(self, report: bytes) -> tuple[list[bytes], bytes | None]:
        try:
            msg = self.assembler.feed(report)
        except ctaphid.CtapHidError as exc:
            return ctaphid.error(exc.cid, exc.code), None
        if msg is None:
            return [], None
        if msg.cid != ctaphid.BROADCAST_CID and msg.cid not in self.channels:
            return ctaphid.error(msg.cid, ctaphid.ERR_INVALID_CHANNEL), None
        if msg.cmd == ctaphid.INIT:
            return self._init(msg), None
        if self.pending and msg.cid != self.pending.cid and msg.cmd != ctaphid.CANCEL:
            return ctaphid.error(msg.cid, ctaphid.ERR_CHANNEL_BUSY), None
        if msg.cmd == ctaphid.PING:
            return ctaphid.fragment(msg), None
        if msg.cmd == ctaphid.WINK:
            return ctaphid.fragment(ctaphid.Message(msg.cid, ctaphid.WINK, b"")), None
        if msg.cmd == ctaphid.CANCEL:
            return self._cancel(msg.cid)
        if msg.cmd == ctaphid.CBOR:
            return self._cbor(msg)
        return ctaphid.error(msg.cid, ctaphid.ERR_INVALID_CMD), None

    def _init(self, msg: ctaphid.Message) -> list[bytes]:
        if len(msg.payload) != 8:
            return ctaphid.error(msg.cid, ctaphid.ERR_INVALID_LEN)
        if msg.cid == ctaphid.BROADCAST_CID:
            cid = ctaphid.new_cid(self.channels)
            self.channels.add(cid)
        else:
            cid = msg.cid           # re-INIT of an existing channel: abort its transaction
            if self.pending and self.pending.cid == cid:
                self.pending = None
        return ctaphid.fragment(ctaphid.Message(msg.cid, ctaphid.INIT, ctaphid.init_response(msg.payload, cid)))

    def _reply(self, cid: int, status: int, body: dict | None = None) -> list[bytes]:
        payload = bytes([status]) + (cbor.encode(body, canonical=True) if body is not None else b"")
        return ctaphid.fragment(ctaphid.Message(cid, ctaphid.CBOR, payload))

    def get_info(self) -> dict:
        return {
            1: ["FIDO_2_0", "FIDO_2_1"],
            2: [],
            3: self.aaguid,
            4: {"rk": True, "up": True, "uv": True, "plat": False},
            5: 1200,
            9: ["usb"],
        }

    def _cbor(self, msg: ctaphid.Message) -> tuple[list[bytes], bytes | None]:
        if not msg.payload:
            return ctaphid.error(msg.cid, ctaphid.ERR_INVALID_LEN), None
        command, body = msg.payload[0], msg.payload[1:]
        if command == AUTHN_GET_INFO:
            return self._reply(msg.cid, 0, self.get_info()), None
        if command not in (AUTHN_MAKE_CREDENTIAL, AUTHN_GET_ASSERTION):
            return self._reply(msg.cid, CTAP1_ERR_INVALID_COMMAND), None
        if self.pending:
            return self._reply(msg.cid, CTAP2_ERR_CHANNEL_BUSY), None
        try:
            ctap = cbor.decode(body)
            if not isinstance(ctap, dict):
                raise cbor.CborError("not a map")
        except cbor.CborError:
            return self._reply(msg.cid, CTAP2_ERR_INVALID_CBOR), None
        create = command == AUTHN_MAKE_CREDENTIAL
        rp = ctap.get(MC_RP) if create else ctap.get(GA_RP_ID)
        rp_id = rp.get("id") if create and isinstance(rp, dict) else rp
        if not isinstance(rp_id, str) or not rp_id:
            return self._reply(msg.cid, CTAP2_ERR_INVALID_CBOR), None
        denied = self._policy(rp_id, "create" if create else "get")
        if denied:
            self.log.append(f"{self.session_id}: denied {rp_id}: {denied}")
            return self._reply(msg.cid, CTAP2_ERR_OPERATION_DENIED), None
        # The client verifies the user itself (it advertised uv, no clientPin): drop any
        # PIN/UV auth parameters, ask for UV when the browser asked for it.
        for key in ((MC_PIN_AUTH, MC_PIN_PROTO) if create else (GA_PIN_AUTH, GA_PIN_PROTO)):
            ctap.pop(key, None)
        options = ctap.get(MC_OPTIONS if create else GA_OPTIONS) or {}
        uv = bool(options.get("uv"))
        para = {
            "attachment": rdpewa.ATTACHMENT_ANY,
            "requireResident": bool(options.get("rk")) if create else False,
            "preferResident": False,
            "userVerification": rdpewa.UV_REQUIRED if uv else rdpewa.UV_PREFERRED,
            "attestationPreference": rdpewa.ATTESTATION_NONE,
            "enterpriseAttestation": 0,
        }
        req = rdpewa.make_webauthn_request(
            rdpewa.CMD_MAKE_CREDENTIAL if create else rdpewa.CMD_GET_ASSERTION, ctap,
            flags=rdpewa.FLAG_UV_REQUIRED if uv else rdpewa.FLAG_UV_PREFERRED,
            timeout=self.policy.timeout_ms, webauthn_para=para)
        self.pending = Pending(msg.cid, req, self.clock())
        self.recent.append(self.clock())
        self.log.append(f"{self.session_id}: forwarded {'create' if create else 'get'} for {rp_id}")
        return ctaphid.keepalive(msg.cid), req.encode()

    def _policy(self, rp_id: str, op: str) -> str | None:
        if not self.policy.rp_allowed(rp_id):
            return "RP ID not allowed"
        now = self.clock()
        while self.recent and now - self.recent[0] > 60:
            self.recent.popleft()
        if len(self.recent) >= self.policy.max_per_minute:
            return "rate limit"
        if self.policy.confirm is not None and not self.policy.confirm(rp_id, op):
            return "not confirmed by the user"
        return None

    def _cancel(self, cid: int) -> tuple[list[bytes], bytes | None]:
        if not self.pending or self.pending.cid != cid:
            return [], None             # CANCEL has no response of its own (11.2.9.1.5)
        tid = self.pending.request.transaction_id
        self.pending = None
        cancel = rdpewa.Request(rdpewa.CANCEL_CUR_OP, request=tid, transaction_id=tid)
        return self._reply(cid, CTAP2_ERR_KEEPALIVE_CANCEL), cancel.encode()

    def tick(self) -> list[bytes]:
        """Call every ~100 ms: keepalives while the client works, timeout afterwards."""
        if not self.pending:
            return []
        if (self.clock() - self.pending.started) * 1000 > self.policy.timeout_ms + 5000:
            cid, self.pending = self.pending.cid, None
            return self._reply(cid, CTAP2_ERR_USER_ACTION_TIMEOUT)
        return ctaphid.keepalive(self.pending.cid, ctaphid.STATUS_UPNEEDED)

    # ---------------------------------------------------------------- client side
    def handle_client(self, data: bytes) -> list[bytes]:
        """The client's WebAuthN_Channel response -> reports for the browser."""
        if not self.pending:
            return []                   # late answer for a cancelled/timed-out request
        cid, self.pending = self.pending.cid, None
        try:
            resp = rdpewa.Response.decode(data)
            if not resp.ok:
                code = (CTAP2_ERR_KEEPALIVE_CANCEL if resp.hresult == rdpewa.NTE_USER_CANCELLED
                        else CTAP2_ERR_OPERATION_DENIED)
                return self._reply(cid, code)
            result = resp.as_webauthn()
        except (rdpewa.RdpewaError, cbor.CborError):
            return self._reply(cid, CTAP2_ERR_OPERATION_DENIED)
        return ctaphid.fragment(ctaphid.Message(cid, ctaphid.CBOR, result.ctaphid_payload))
