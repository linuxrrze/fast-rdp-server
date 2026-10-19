"""One-time login tokens handed to xrdp in place of the user's password.

pam_fastrdp_token redeems them via token.sock. A token is bound to one user,
valid for a short time and usable once. If the proxy knew the user's real
password, the PAM module receives it on redemption and stores it as
PAM_AUTHTOK, so pam_sss can still obtain a Kerberos TGT for the session.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

TOKEN_PREFIX = "fastrdp1:"


@dataclass
class _Entry:
    user: str
    expires: float
    password: str | None


class TokenStore:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._tokens: dict[str, _Entry] = {}

    def _purge(self) -> None:
        now = time.monotonic()
        for tok in [t for t, e in self._tokens.items() if e.expires < now]:
            del self._tokens[tok]

    def issue(self, user: str, password: str | None) -> str:
        self._purge()
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        self._tokens[token] = _Entry(user, time.monotonic() + self.ttl, password)
        return token

    def redeem(self, user: str, token: str) -> tuple[bool, str | None]:
        self._purge()
        entry = self._tokens.get(token)
        if entry is None or not secrets.compare_digest(entry.user, user):
            return False, None
        del self._tokens[token]
        return True, entry.password

    def __len__(self) -> int:
        self._purge()
        return len(self._tokens)
