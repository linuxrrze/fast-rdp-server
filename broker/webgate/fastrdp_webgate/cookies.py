"""HMAC-signed, expiring cookie values (no server-side session store)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class Signer:
    def __init__(self, secret: str):
        self.key = hashlib.sha256(("fastrdp-webgate:" + secret).encode()).digest()

    def _mac(self, purpose: str, body: bytes) -> bytes:
        return hmac.new(self.key, purpose.encode() + b"\0" + body, hashlib.sha256).digest()

    def dumps(self, purpose: str, data: dict, ttl: int) -> str:
        body = json.dumps({**data, "_exp": int(time.time()) + ttl}, separators=(",", ":")).encode()
        b = base64.urlsafe_b64encode(body).rstrip(b"=")
        m = base64.urlsafe_b64encode(self._mac(purpose, body)).rstrip(b"=")
        return (b + b"." + m).decode()

    def loads(self, purpose: str, value: str | None) -> dict | None:
        if not value or value.count(".") != 1:
            return None
        b, m = value.split(".")
        try:
            body = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
            mac = base64.urlsafe_b64decode(m + "=" * (-len(m) % 4))
        except ValueError:
            return None
        if not hmac.compare_digest(mac, self._mac(purpose, body)):
            return None
        data = json.loads(body)
        if data.pop("_exp", 0) < time.time():
            return None
        return data

    def csrf(self, session_value: str) -> str:
        return hmac.new(self.key, b"csrf\0" + session_value.encode(), hashlib.sha256).hexdigest()
