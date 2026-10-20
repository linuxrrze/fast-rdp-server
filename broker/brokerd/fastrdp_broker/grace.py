# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] reconnect_grace: skip the second factor for a reconnect of a user who passed it
recently (docs/auth-matrix.md#reconnect-grace).

Neither the proxy nor xrdp supports RDP auto-reconnect cookies, so mstsc reconnects after
a network drop with a full login: NLA (silent with Kerberos) and a new push. An entry is
recorded only after a login whose second factor privacyIDEA confirmed *and* whose session
was started; it expires a fixed time after that second factor (absolute, never extended
by the logins it lets through). Lookups match the local account, the login method (the
first factor's class), the Kerberos principal (NLA) and, by default, the client address.

Memory only: a broker restart forgets every entry. Used from the broker's event loop
only (asyncio, one thread), so no locking.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, NamedTuple


class GraceKey(NamedTuple):
    user: str               # local account
    method: str             # "nla" (Kerberos ticket) | "tls" (password checked by PAM)
    principal: str | None   # NLA: Kerberos principal from the KDC's ticket; TLS: None
    address: str | None     # client address, or None if not bound ([mfa] reconnect_grace_same_address = false)


@dataclass(frozen=True)
class GraceEntry:
    passed_at: float        # monotonic time of the real second factor
    address: str | None     # where it was passed (for the log)
    factor: str             # "otp" | "push"


class ReconnectGrace:
    def __init__(self, seconds: int, same_address: bool, clock: Callable[[], float] = time.monotonic):
        self.seconds = seconds
        self.same_address = same_address
        self.clock = clock
        self.entries: dict[GraceKey, GraceEntry] = {}
        # clear() times per user ("" = all users): a login whose second factor was
        # passed before them (still waiting for its session) must not record afterwards.
        self.cleared: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return self.seconds > 0

    def key(self, user: str, method: str, principal: str | None, address: str | None) -> GraceKey | None:
        """The binding of a login, or None if it can never use (or earn) grace."""
        if not self.enabled or method not in ("nla", "tls"):
            return None
        if method == "nla" and not principal:
            return None
        if self.same_address and not address:
            return None  # nothing to bind to
        return GraceKey(user, method, principal if method == "nla" else None,
                        address if self.same_address else None)

    def prune(self) -> None:
        now = self.clock()
        for k in [k for k, e in self.entries.items() if now - e.passed_at >= self.seconds]:
            del self.entries[k]
        for u in [u for u, t in self.cleared.items() if now - t >= self.seconds]:
            del self.cleared[u]

    def lookup(self, key: GraceKey | None) -> tuple[GraceEntry, float] | None:
        """(entry, seconds since its second factor) while the grace period runs."""
        if key is None:
            return None
        self.prune()
        entry = self.entries.get(key)
        if entry is None:
            return None
        return entry, self.clock() - entry.passed_at

    def record(self, key: GraceKey | None, passed_at: float, factor: str, address: str | None) -> None:
        """After a login with a real second factor (passed at `passed_at`, self.clock())
        whose session started. The period counts from the second factor, not the start."""
        if key is None:
            return
        self.prune()
        if passed_at <= max(self.cleared.get(key.user, -1e18), self.cleared.get("", -1e18)):
            return
        old = self.entries.get(key)
        if old is None or old.passed_at < passed_at:
            self.entries[key] = GraceEntry(passed_at, address, factor)

    def clear(self, user: str | None = None) -> int:
        """Forget the entries of `user` (all users: None). Returns how many."""
        self.cleared[user or ""] = self.clock()
        doomed = [k for k in self.entries if user is None or k.user == user]
        for k in doomed:
            del self.entries[k]
        return len(doomed)

    def __len__(self) -> int:
        self.prune()
        return len(self.entries)
