"""Encrypted connection data for Guacamole's JSON auth extension (guacamole-auth-json).

Format (identical to guacamole-client doc/encrypt-json.sh):
  base64( AES-128-CBC(key, IV=0, PKCS#7)( HMAC-SHA256(key, json) || json ) )
The same 128-bit key (32 hex digits, json-secret-key / JSON_SECRET_KEY) is used for both.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NULL_IV = bytes(16)


def parse_key(hex_key: str) -> bytes:
    key = bytes.fromhex(hex_key.strip())
    if len(key) != 16:
        raise ValueError("Guacamole JSON secret key must be 32 hex digits (128 bits)")
    return key


def encrypt(key: bytes, payload: dict) -> str:
    plain = json.dumps(payload, separators=(",", ":")).encode()
    signed = hmac.new(key, plain, hashlib.sha256).digest() + plain
    padder = padding.PKCS7(128).padder()
    data = padder.update(signed) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(NULL_IV)).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode()


def decrypt(key: bytes, blob: str) -> dict:
    """Inverse of encrypt() with signature check (used by tests and for debugging)."""
    dec = Cipher(algorithms.AES(key), modes.CBC(NULL_IV)).decryptor()
    data = dec.update(base64.b64decode(blob)) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    signed = unpadder.update(data) + unpadder.finalize()
    sig, plain = signed[:32], signed[32:]
    if not hmac.compare_digest(sig, hmac.new(key, plain, hashlib.sha256).digest()):
        raise ValueError("bad signature")
    return json.loads(plain)
