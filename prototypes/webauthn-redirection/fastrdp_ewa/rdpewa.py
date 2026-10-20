# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[MS-RDPEWA] WebAuthN_Channel messages (revision 3.0, section 2.2).

Direction: the RDP *server* (here: a Linux session) sends requests, the *client* (mstsc,
FreeRDP with rdpewa) answers. One request is one DVC message:

  request   CBOR map with text keys (2.2.1): command, flags, timeout, transactionId,
            request (byte string: CTAP command byte + CTAP CBOR map, 2.2.1.2/2.2.1.3),
            webAuthNPara (map, 2.2.1.1), clientDataJSON, rpId, ...
  response  32-bit HRESULT (little endian, as FreeRDP sends it) + payload (2.2.2):
            WEB_AUTHN -> CBOR map {deviceInfo, status, response}; response = CTAP status
            byte + CTAP response map (2.2.2.1.1/2.2.2.1.2); IUVPAA/API_VERSION -> 4-byte
            little-endian integer; CANCEL -> nothing; GET_CREDENTIALS/
            GET_AUTHENTICATOR_LIST -> CBOR array.

Unknown keys are kept (Request.extra) so messages round-trip; key lookups on decode
are case-insensitive because the specification spells some keys differently in the
field lists and in the examples (transactionid/transactionId, Manufacturer/manufacturer).
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from . import cbor

# 2.2.1 command
WEB_AUTHN = 5
IUVPAA = 6
CANCEL_CUR_OP = 7
API_VERSION = 8
GET_CREDENTIALS = 9
GET_AUTHENTICATOR_LIST = 12
COMMANDS = {WEB_AUTHN: "WEB_AUTHN", IUVPAA: "IUVPAA", CANCEL_CUR_OP: "CANCEL_CUR_OP",
            API_VERSION: "API_VERSION", GET_CREDENTIALS: "GET_CREDENTIALS",
            GET_AUTHENTICATOR_LIST: "GET_AUTHENTICATOR_LIST"}

# first byte of "request" for WEB_AUTHN (CTAP2 command codes)
CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02

# 2.2.1 flags
FLAG_SELECT_CREDENTIAL_ALLOW_UV = 0x00008000
FLAG_U2F = 0x00020000
FLAG_DUAL = 0x00040000
FLAG_CLIENT_PIN_REQUIRED = 0x00100000
FLAG_UV_REQUIRED = 0x00400000
FLAG_UV_PREFERRED = 0x00800000
FLAG_UV_NOT_REQUIRED = 0x01000000
FLAG_HMAC_SECRET_EXTENSION = 0x04000000
FLAG_FORCE_U2F_V2 = 0x08000000

# 2.2.1.1 webAuthNPara values
ATTACHMENT_ANY, ATTACHMENT_PLATFORM, ATTACHMENT_CROSS_PLATFORM = 0, 1, 2
UV_ANY, UV_REQUIRED, UV_PREFERRED, UV_DISCOURAGED = 0, 1, 2, 3
ATTESTATION_ANY, ATTESTATION_NONE, ATTESTATION_INDIRECT, ATTESTATION_DIRECT = 0, 1, 2, 3

S_OK = 0
E_NOTIMPL = 0x80004001
E_INVALIDARG = 0x80070057
NTE_USER_CANCELLED = 0x80090036     # what Windows' webauthn.dll reports on cancel
CTAP2_OK = 0x00

KNOWN_KEYS = ("command", "flags", "timeout", "transactionId", "request", "webAuthNPara",
              "rpId", "clientDataJSON")


class RdpewaError(ValueError):
    pass


def _get(m: dict, key: str):
    """Case-insensitive text-key lookup."""
    if key in m:
        return m[key]
    low = key.lower()
    for k, v in m.items():
        if isinstance(k, str) and k.lower() == low:
            return v
    return None


def _uint(v, name: str, bits: int = 32) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < 1 << bits:
        raise RdpewaError(f"{name} must be an unsigned {bits}-bit integer")
    return v


@dataclass
class Request:
    command: int
    flags: int = 0
    timeout: int = 0                       # milliseconds
    transaction_id: bytes = b"\0" * 16     # GUID bytes
    request: bytes | None = None           # WEB_AUTHN: CTAP command byte + CTAP map; CANCEL: GUID
    webauthn_para: dict | None = None
    rp_id: str | None = None
    client_data_json: bytes | None = None
    extra: dict = field(default_factory=dict)   # other keys
    key_order: list = field(default_factory=list)   # wire order of a decoded message

    # ---------------------------------------------------------------- CTAP payload
    @property
    def ctap_command(self) -> int | None:
        return self.request[0] if self.command == WEB_AUTHN and self.request else None

    def ctap_map(self) -> dict:
        if self.command != WEB_AUTHN or not self.request:
            raise RdpewaError("only WEB_AUTHN requests carry a CTAP map")
        m = cbor.decode(self.request[1:])
        if not isinstance(m, dict):
            raise RdpewaError("CTAP request is not a map")
        return m

    def rp_id_of_request(self) -> str | None:
        """The RP ID the client's authenticator will sign for (MakeCredential: rp.id,
        GetAssertion: rpId). This, not clientDataJSON, is what the key binds to."""
        if self.command == GET_CREDENTIALS:
            return self.rp_id
        if self.command != WEB_AUTHN:
            return None
        m = self.ctap_map()
        if self.ctap_command == CMD_MAKE_CREDENTIAL:
            rp = m.get(2)
            return rp.get("id") if isinstance(rp, dict) else None
        if self.ctap_command == CMD_GET_ASSERTION:
            return m.get(1) if isinstance(m.get(1), str) else None
        return None

    # ---------------------------------------------------------------- wire
    def encode(self) -> bytes:
        m: dict = {"command": self.command, "flags": self.flags, "timeout": self.timeout,
                   "transactionId": bytes(self.transaction_id)}
        if self.request is not None:
            m["request"] = bytes(self.request)
        if self.webauthn_para is not None:
            m["webAuthNPara"] = self.webauthn_para
        if self.rp_id is not None:
            m["rpId"] = self.rp_id
        if self.client_data_json is not None:
            m["clientDataJSON"] = bytes(self.client_data_json)
        m.update(self.extra)
        if self.key_order:   # a decoded message re-encodes byte for byte
            by_lower = {k.lower() if isinstance(k, str) else k: k for k in m}
            ordered = {}
            for k in self.key_order:
                name = by_lower.get(k.lower() if isinstance(k, str) else k)
                if name is not None and name not in ordered:
                    ordered[k] = m[name]
            ordered.update({k: v for k, v in m.items() if k not in ordered and
                            (k.lower() if isinstance(k, str) else k) not in
                            {(o.lower() if isinstance(o, str) else o) for o in ordered}})
            m = ordered
        return cbor.encode(m)

    @classmethod
    def decode(cls, data: bytes) -> Request:
        m = cbor.decode(data)
        if not isinstance(m, dict):
            raise RdpewaError("request is not a CBOR map")
        command = _uint(_get(m, "command"), "command")
        if command == 0:
            raise RdpewaError("missing command")
        tid = _get(m, "transactionId")
        if tid is not None and (not isinstance(tid, bytes) or len(tid) != 16):
            raise RdpewaError("transactionId must be a 16-byte GUID")
        req = _get(m, "request")
        if req is not None and not isinstance(req, bytes):
            raise RdpewaError("request must be a byte string")
        # (no "request" on WEB_AUTHN is tolerated here: the specification's own example
        # 4.1.1 has one; ctap_map() refuses it when the message is used)
        if command == WEB_AUTHN and req is not None and (not req or req[0] not in (CMD_MAKE_CREDENTIAL,
                                                                                    CMD_GET_ASSERTION)):
            raise RdpewaError("WEB_AUTHN request needs a MakeCredential/GetAssertion command byte")
        if command == CANCEL_CUR_OP and (req is None or len(req) != 16):
            raise RdpewaError("CANCEL_CUR_OP request must be the operation GUID")
        para = _get(m, "webAuthNPara")
        if para is not None and not isinstance(para, dict):
            raise RdpewaError("webAuthNPara must be a map")
        cdj = _get(m, "clientDataJSON")
        if cdj is not None and not isinstance(cdj, bytes):
            raise RdpewaError("clientDataJSON must be a byte string")
        rp_id = _get(m, "rpId")
        if rp_id is not None and not isinstance(rp_id, str):
            raise RdpewaError("rpId must be a text string")
        known = {k.lower() for k in KNOWN_KEYS}
        return cls(
            command=command,
            flags=_uint(_get(m, "flags") or 0, "flags"),
            timeout=_uint(_get(m, "timeout") or 0, "timeout"),
            transaction_id=tid if tid is not None else b"\0" * 16,
            request=req, webauthn_para=para, rp_id=rp_id, client_data_json=cdj,
            extra={k: v for k, v in m.items() if not (isinstance(k, str) and k.lower() in known)},
            key_order=list(m),
        )


def new_transaction_id() -> bytes:
    return uuid.uuid4().bytes_le


def make_webauthn_request(ctap_command: int, ctap_map: dict, *, flags: int = 0, timeout: int = 60000,
                          webauthn_para: dict | None = None, client_data_json: bytes | None = None,
                          transaction_id: bytes | None = None) -> Request:
    """WEB_AUTHN request around a CTAP2 MakeCredential/GetAssertion map (encoded
    CTAP2-canonically, as an authenticator expects it)."""
    if ctap_command not in (CMD_MAKE_CREDENTIAL, CMD_GET_ASSERTION):
        raise RdpewaError("only MakeCredential and GetAssertion can be redirected")
    return Request(WEB_AUTHN, flags=flags, timeout=timeout,
                   transaction_id=transaction_id or new_transaction_id(),
                   request=bytes([ctap_command]) + cbor.encode(ctap_map, canonical=True),
                   webauthn_para=webauthn_para, client_data_json=client_data_json)


# ---------------------------------------------------------------- responses
@dataclass
class WebAuthnResult:
    """Payload of a WEB_AUTHN response (2.2.2.1)."""
    device_info: dict
    status: int
    ctap_status: int
    ctap_response: dict | None      # MakeCredential: {1: fmt, 2: authData, 3: attStmt, ...}
    extra: dict = field(default_factory=dict)

    def encode(self) -> bytes:
        body = bytes([self.ctap_status])
        if self.ctap_response is not None:
            body += cbor.encode(self.ctap_response, canonical=True)
        return cbor.encode({"deviceInfo": self.device_info, "status": self.status, "response": body,
                            **self.extra})

    @classmethod
    def decode(cls, data: bytes) -> WebAuthnResult:
        m = cbor.decode(data)
        if not isinstance(m, dict):
            raise RdpewaError("WEB_AUTHN response is not a map")
        body = _get(m, "response")
        if not isinstance(body, bytes) or not body:
            raise RdpewaError("WEB_AUTHN response lacks the CTAP response bytes")
        ctap = None
        if len(body) > 1:
            ctap = cbor.decode(body[1:])
            if not isinstance(ctap, dict):
                raise RdpewaError("CTAP response is not a map")
        info = _get(m, "deviceInfo")
        return cls(device_info=info if isinstance(info, dict) else {},
                   status=_get(m, "status") or 0, ctap_status=body[0], ctap_response=ctap,
                   extra={k: v for k, v in m.items() if str(k).lower() not in ("deviceinfo", "status", "response")})

    @property
    def ctaphid_payload(self) -> bytes:
        """What a CTAPHID_CBOR response to the browser carries: status byte + map."""
        return bytes([self.ctap_status]) + (cbor.encode(self.ctap_response, canonical=True)
                                            if self.ctap_response is not None else b"")


@dataclass
class Response:
    hresult: int
    payload: bytes = b""

    def encode(self) -> bytes:
        return struct.pack("<I", self.hresult) + self.payload

    @classmethod
    def decode(cls, data: bytes) -> Response:
        if len(data) < 4:
            raise RdpewaError("response shorter than its HRESULT")
        return cls(struct.unpack("<I", data[:4])[0], bytes(data[4:]))

    @property
    def ok(self) -> bool:
        return self.hresult & 0x80000000 == 0

    def as_webauthn(self) -> WebAuthnResult:
        return WebAuthnResult.decode(self.payload)

    def as_uint32(self) -> int:       # IUVPAA (0/1), API_VERSION
        if len(self.payload) != 4:
            raise RdpewaError("expected a 4-byte value")
        return struct.unpack("<I", self.payload)[0]

    def as_array(self) -> list:       # GET_CREDENTIALS, GET_AUTHENTICATOR_LIST
        a = cbor.decode(self.payload)
        if not isinstance(a, list):
            raise RdpewaError("expected a CBOR array")
        return a

    @classmethod
    def webauthn(cls, result: WebAuthnResult, hresult: int = S_OK) -> Response:
        return cls(hresult, result.encode())

    @classmethod
    def uint32(cls, value: int, hresult: int = S_OK) -> Response:
        return cls(hresult, struct.pack("<I", value))
