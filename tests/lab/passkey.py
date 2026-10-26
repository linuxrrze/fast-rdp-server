# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (a software passkey is a full second factor for its lab user; never enrol it for
# a real account). Used by tests/lab/approve.py --passkey-file.
#
# A WebAuthn discoverable credential (ES256, P-256) without a browser or an authenticator,
# standard library only: what navigator.credentials.create() / .get() hand to Keycloak's
# webauthn forms.
#   registration: clientDataJSON, attestationObject ("none", flags UP|UV|AT, AAGUID zero),
#                 publicKeyCredentialId
#   assertion:    clientDataJSON, authenticatorData (UP|UV, sign count + 1), signature (DER,
#                 low S), credentialId, userHandle (Keycloak: the UTF-8 bytes of the user id)
# UV is asserted by this code, not checked by anything: lab only.
#
# Key file: JSON (rp_id, credential_id, private_key, user_handle, sign_count, user_name),
# mode 0600, refused if group or others may read it. KeyFile holds an flock while a count
# is taken and written back before the assertion is sent: Keycloak refuses a count that
# does not grow (a cloned authenticator), so parallel runs with one file must not reuse it.
# P-256 in Python integers (RFC 6979 nonces): not constant time, fine for a lab credential.
"""LAB ONLY: a software passkey (WebAuthn, ES256) for Keycloak sign-ins (see header)."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import struct

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40
AAGUID = bytes(16)
LABEL = "lab soft passkey"


class PasskeyError(Exception):
    pass


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def point_mul(k: int, pt=G):
    acc = None
    while k:
        if k & 1:
            acc = point_add(acc, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return acc


def i2b(i: int) -> bytes:
    return i.to_bytes(32, "big")


def rfc6979_k(d: int, h: bytes) -> int:
    x, h1 = i2b(d), i2b(int.from_bytes(h, "big") % N)
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_rs(d: int, msg: bytes) -> tuple[int, int]:
    """ECDSA P-256 / SHA-256, deterministic (RFC 6979), low S."""
    h = hashlib.sha256(msg).digest()
    k = rfc6979_k(d, h)
    r = point_mul(k)[0] % N
    s = pow(k, -1, N) * (int.from_bytes(h, "big") + r * d) % N
    return r, min(s, N - s)


def der_signature(r: int, s: int) -> bytes:
    def der_int(i: int) -> bytes:
        b = i.to_bytes(i.bit_length() // 8 + 1, "big")   # a leading 0 keeps it positive
        return b"\x02" + bytes([len(b)]) + b
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)
    raise ValueError("CBOR: too large")


def cbor(obj) -> bytes:
    """The CBOR subset of attestation objects and COSE keys; maps in the order given
    (callers give CTAP2 canonical order)."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode()
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, dict):
        return _cbor_head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    raise TypeError(type(obj).__name__)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def client_data(kind: str, challenge: str, origin: str) -> bytes:
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False},
                      separators=(",", ":")).encode()


@dataclasses.dataclass
class Passkey:
    rp_id: str
    credential_id: bytes
    private_key: int
    user_handle: bytes
    sign_count: int = 0
    user_name: str = ""

    def __repr__(self) -> str:   # never the private key
        return f"Passkey(rp_id={self.rp_id!r}, user_name={self.user_name!r}, sign_count={self.sign_count})"

    @classmethod
    def new(cls, rp_id: str, user_handle: bytes, user_name: str = "") -> Passkey:
        return cls(rp_id, secrets.token_bytes(32), secrets.randbelow(N - 1) + 1, user_handle, 0, user_name)

    def cose_key(self) -> bytes:
        x, y = point_mul(self.private_key)
        return cbor({1: 2, 3: -7, -1: 1, -2: i2b(x), -3: i2b(y)})   # EC2, ES256, P-256

    def to_json(self) -> str:
        return json.dumps({"rp_id": self.rp_id, "credential_id": b64u(self.credential_id),
                           "private_key": b64u(i2b(self.private_key)), "user_handle": b64u(self.user_handle),
                           "sign_count": self.sign_count, "user_name": self.user_name}) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Passkey:
        try:
            d = json.loads(text)
            return cls(d["rp_id"], unb64u(d["credential_id"]), int.from_bytes(unb64u(d["private_key"]), "big"),
                       unb64u(d["user_handle"]), int(d["sign_count"]), d.get("user_name", ""))
        except (ValueError, KeyError, TypeError):
            raise PasskeyError("not a passkey file (JSON with rp_id, credential_id, private_key, "
                               "user_handle, sign_count)") from None

    def _auth_data(self, flags: int, attested: bytes = b"") -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + \
            struct.pack(">I", self.sign_count) + attested

    def register(self, challenge: str, origin: str) -> dict[str, str]:
        """Keycloak's register form fields (webauthn-register.ftl), base64url."""
        cdj = client_data("webauthn.create", challenge, origin)
        attested = AAGUID + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose_key()
        att = cbor({"fmt": "none", "attStmt": {}, "authData": self._auth_data(FLAG_UP | FLAG_UV | FLAG_AT, attested)})
        return {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att),
                "publicKeyCredentialId": b64u(self.credential_id), "authenticatorLabel": LABEL,
                "transports": "internal", "authenticatorAttachment": "platform", "error": ""}

    def assertion(self, challenge: str, origin: str) -> dict[str, str]:
        """Keycloak's webauth form fields (webauthn-authenticate.ftl and the username page),
        base64url; signed with the current sign_count (KeyFile.next_count() raises it)."""
        cdj = client_data("webauthn.get", challenge, origin)
        auth = self._auth_data(FLAG_UP | FLAG_UV)
        sig = der_signature(*sign_rs(self.private_key, auth + hashlib.sha256(cdj).digest()))
        return {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(auth), "signature": b64u(sig),
                "credentialId": b64u(self.credential_id), "userHandle": b64u(self.user_handle), "error": ""}


class KeyFile:
    """The key file, flock'ed while open (see header)."""

    def __init__(self, path: str, create: Passkey | None = None):
        import fcntl
        self.path = path
        if create is not None:
            self.fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)   # never another key
        else:
            self.fd = os.open(path, os.O_RDWR)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        if os.fstat(self.fd).st_mode & 0o077:
            os.close(self.fd)
            raise PasskeyError(f"{path}: readable by group or others (chmod 600)")
        if create is not None:
            self.key = create
            self.write()
        else:
            self.key = Passkey.from_json(os.read(self.fd, 1 << 16).decode("utf-8", "replace"))

    def write(self) -> None:
        os.ftruncate(self.fd, 0)
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.write(self.fd, self.key.to_json().encode())
        os.fsync(self.fd)

    def next_count(self) -> Passkey:
        """Raise the sign count and store it before anything is signed with it."""
        self.key.sign_count += 1
        self.write()
        return self.key

    def close(self) -> None:
        os.close(self.fd)   # releases the lock

    def __enter__(self) -> KeyFile:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
