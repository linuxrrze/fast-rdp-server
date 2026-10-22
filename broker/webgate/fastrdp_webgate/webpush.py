# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Web Push for approval notifications (docs/notifications.md), python3-cryptography only.

  - Message encryption, RFC 8291 with the aes128gcm content coding of RFC 8188: ECDH
    (P-256) between a fresh key pair and the subscription's "p256dh" key, HKDF-SHA-256
    with the subscription's "auth" secret, one record of at most 4096 bytes.
  - VAPID, RFC 8292: an ES256 JWT (aud = the push service's origin, exp at most 24 h
    ahead, sub = [notify] vapid_subject) signed with the webgate's P-256 key, sent as
    "Authorization: vapid t=<JWT>, k=<public key>". The public key is derived from the
    private key ([notify] vapid_private_key_file); browsers get it as the
    applicationServerKey of their subscription.
  - Delivery, RFC 8030: POST to the subscription's endpoint with TTL, Urgency and Topic.
    201/202: accepted; 404/410: the subscription is gone (the caller deletes it).

The push service only sees the endpoint, the sizes, the timing and these headers; the
payload is encrypted for the browser.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RECORD_SIZE = 4096
TAG_LENGTH = 16
# One record: header (86 bytes) + ciphertext + tag must fit in what push services
# accept (4096); the plaintext gets one delimiter byte.
MAX_PAYLOAD = RECORD_SIZE - TAG_LENGTH - 1 - 86
JWT_LIFETIME = 12 * 3600   # RFC 8292: at most 24 h


class WebPushError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_bytes(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed point (65 bytes, 0x04 || X || Y)."""
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_vapid_key(pem: bytes) -> ec.EllipticCurvePrivateKey:
    """The webgate's VAPID key: a PEM EC private key on P-256 (SEC1 or PKCS#8)."""
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise WebPushError(f"VAPID key: {exc}") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise WebPushError("VAPID key must be an EC key on P-256 (prime256v1)")
    return key


def check_subscription_keys(p256dh: str, auth: str) -> None:
    """Raises WebPushError unless the browser's keys have the right form."""
    try:
        point, secret = unb64u(p256dh), unb64u(auth)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except (ValueError, TypeError):
        raise WebPushError("p256dh is not a P-256 public key") from None
    if len(point) != 65 or len(secret) != 16:
        raise WebPushError("p256dh must be an uncompressed P-256 point, auth 16 bytes")


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)


def encrypt(plaintext: bytes, ua_public: bytes, auth_secret: bytes, *,
            as_private: ec.EllipticCurvePrivateKey | None = None, salt: bytes | None = None) -> bytes:
    """aes128gcm body for one push message (RFC 8291 section 3.4, RFC 8188 section 2).
    `as_private` and `salt` are fresh unless given (tests: RFC 8291 Appendix A)."""
    if len(plaintext) > MAX_PAYLOAD:
        raise WebPushError(f"payload of {len(plaintext)} bytes is larger than {MAX_PAYLOAD}")
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    salt = salt or os.urandom(16)
    as_public = public_bytes(as_private)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    ikm = _hkdf(auth_secret, ecdh_secret, b"WebPush: info\0" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\0", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\0", 12)
    # a single record, so the last one: delimiter 0x02, no padding
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public
    return header + ciphertext


def origin(endpoint: str) -> str:
    parts = urllib.parse.urlsplit(endpoint)
    return f"{parts.scheme}://{parts.netloc}"


def vapid_jwt(key: ec.EllipticCurvePrivateKey, audience: str, subject: str, now: float | None = None) -> str:
    """ES256 JWT for the push service at `audience` (an origin)."""
    now = time.time() if now is None else now
    header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64u(json.dumps({"aud": audience, "exp": int(now) + JWT_LIFETIME, "sub": subject},
                             separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return f"{header}.{claims}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def endpoint_allowed(endpoint: str, hosts: list[str]) -> bool:
    """https:// to one of the push services' hosts (or a subdomain), default port."""
    try:
        parts = urllib.parse.urlsplit(endpoint)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or port not in (None, 443) or parts.username or parts.password:
        return False
    return any(host == h or host.endswith("." + h) for h in hosts)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def send(subscription: dict, payload: bytes, key: ec.EllipticCurvePrivateKey, subject: str, *,
         ttl: int, urgency: str = "high", topic: str | None = None, timeout: float = 5,
         opener=None) -> int:
    """Encrypt and POST one message; returns the push service's HTTP status (201/202 ok,
    404/410 subscription gone, 413 too large, 429 rate limited, ...). Raises OSError and
    WebPushError (bad subscription keys)."""
    try:
        body = encrypt(payload, unb64u(subscription["p256dh"]), unb64u(subscription["auth"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise WebPushError(f"subscription keys: {exc}") from None
    endpoint = subscription["endpoint"]
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "aes128gcm",
        "TTL": str(max(0, int(ttl))),
        "Urgency": urgency,
        "Authorization": f"vapid t={vapid_jwt(key, origin(endpoint), subject)}, k={b64u(public_bytes(key))}",
    }
    if topic:
        headers["Topic"] = topic
    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with (opener or _opener).open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code
