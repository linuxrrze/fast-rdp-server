# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""TGT metadata of session users for `fastrdpctl status` / `fastrdpctl tickets` (backlog K2).

Operators see who is about to lose Kerberos access (Kerberized NFS/SMB homes, SSO):
the principal, expiry and renewal limit of the TGT in the user's default credential
cache, i.e. the cache the session's processes use (no KRB5CCNAME, default_ccache_name
= KCM:; docs/nfs-kerberos-homes.md). `klist` runs with the user's ids
(sysutil.run_dropped), so sssd-kcm answers for that uid only, never with root's
view. Only metadata leaves this module: no ticket, key or session-key data.

MIT klist has no machine-readable output; with LC_ALL=C and TZ=UTC it prints times
as `%x %X` of the C locale ("10/21/26 08:00:00", UTC). Other layouts that
krb5_timestamp_to_sfstring may fall back to are accepted too.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import sysutil
from .identity import LocalUser

log = logging.getLogger("fastrdp.tickets")

# A TGT that expires within EXPIRING_S is "expiring" (sssd renews well before that:
# krb5_renew_interval); a TGT whose renewal ends within RENEW_ENDING_S (or that is not
# renewable) is "not_renewable_soon": the user must log in again with a password (K4).
EXPIRING_S = 3600
RENEW_ENDING_S = 86400
KLIST_TIMEOUT_S = 5
# klist output independent of the broker's and the host's locale and time zone.
KLIST_ENV = {"LC_ALL": "C", "TZ": "UTC"}

STATES = ("ok", "expiring", "not_renewable_soon", "expired", "none", "unknown")

_TIME = (r"(?:\d{1,2}/\d{1,2}/\d{2,4} \d{1,2}:\d\d(?::\d\d)?"     # %x %X / %x %R (C, en_US)
         r"|\d{1,2} [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d"           # %d %b %Y %T
         r"|[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4}"  # %c (C)
         r"|\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?"                  # ISO 8601
         r"|\d{12}(?:\d\d)?)")                                    # ISO 8601 basic
_TIME_FORMATS = ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M", "%m/%d/%Y %H:%M",
                 "%d %b %Y %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S",
                 "%Y-%m-%dT%H:%M", "%Y%m%d%H%M%S", "%Y%m%d%H%M")
_TICKET = re.compile(rf"^({_TIME})\s+({_TIME})\s+(\S+)\s*$")
_RENEW = re.compile(rf"renew until ({_TIME})")
_FLAGS = re.compile(r"Flags: (\S+)")
_CACHE = re.compile(r"^Ticket cache: (\S+)\s*$")
_PRINCIPAL = re.compile(r"^Default principal: (\S+)\s*$")
_LIST_ROW = re.compile(r"^(\S+)\s+(\S+:\S*|/\S+)(\s+\(Expired\))?\s*$")


@dataclass
class Ticket:
    service: str
    starts: float
    expires: float
    renew_until: float | None = None
    flags: str = ""


@dataclass
class Cache:
    name: str
    principal: str
    tickets: list[Ticket] = field(default_factory=list)


def parse_time(text: str) -> float:
    """klist time (printed with TZ=UTC) -> epoch seconds. Raises ValueError."""
    text = " ".join(text.split())
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"unknown klist time format: {text!r}")


def parse_klist(out: str) -> list[Cache]:
    """Every cache block of MIT `klist [-f]` / `klist -A [-f]` output (LC_ALL=C)."""
    caches: list[Cache] = []
    cur: Cache | None = None
    pending_cache: str | None = None
    for line in out.splitlines():
        if m := _CACHE.match(line):
            pending_cache, cur = m.group(1), None
            continue
        if m := _PRINCIPAL.match(line):
            if pending_cache is not None:
                cur = Cache(pending_cache, m.group(1))
                caches.append(cur)
                pending_cache = None
            continue
        if cur is None:
            continue
        if m := _TICKET.match(line.strip()):
            cur.tickets.append(Ticket(m.group(3), parse_time(m.group(1)), parse_time(m.group(2))))
            continue
        if cur.tickets and line[:1] in ("\t", " "):
            # "\trenew until T, Flags: FRIA" (one line, or flags on the next)
            if m := _RENEW.search(line):
                cur.tickets[-1].renew_until = parse_time(m.group(1))
            if m := _FLAGS.search(line):
                cur.tickets[-1].flags = m.group(1)
    return caches


def parse_list(out: str) -> list[tuple[str, str, bool]]:
    """(principal, cache, expired) rows of `klist -l`."""
    rows = []
    for line in out.splitlines():
        if line.startswith(("Principal name", "-")):
            continue
        if m := _LIST_ROW.match(line):
            rows.append((m.group(1), m.group(2), bool(m.group(3))))
    return rows


def _realm(principal: str) -> str:
    return principal.rsplit("@", 1)[1] if "@" in principal else ""


def find_tgt(cache: Cache) -> Ticket | None:
    """The TGT for the client's realm (krbtgt/REALM@REALM), else any krbtgt ticket."""
    realm = _realm(cache.principal)
    tgts = [t for t in cache.tickets if t.service.startswith("krbtgt/")]
    for t in tgts:
        if t.service == f"krbtgt/{realm}@{realm}":
            return t
    return tgts[0] if tgts else None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cache_type(name: str) -> str:
    if ":" not in name or name.startswith("/"):
        return "FILE"
    return name.split(":", 1)[0].upper()


def describe(cache: Cache | None, now: float | None = None) -> dict:
    """Metadata and state of the TGT in `cache` (the user's primary cache)."""
    now = time.time() if now is None else now
    if cache is None:
        return {"state": "none", "error": "no credential cache"}
    info: dict = {"principal": cache.principal, "cache": cache.name, "cache_type": cache_type(cache.name)}
    tgt = find_tgt(cache)
    if tgt is None:
        return {**info, "state": "none", "error": "no TGT in the default cache"}
    renewable = ("R" in tgt.flags) if tgt.flags else tgt.renew_until is not None
    if tgt.renew_until is not None and tgt.renew_until <= tgt.expires:
        renewable = False  # nothing left to renew into
    info.update(expires=_iso(tgt.expires), expires_in=int(tgt.expires - now), renewable=renewable)
    if tgt.renew_until is not None:
        info.update(renew_until=_iso(tgt.renew_until), renew_in=int(tgt.renew_until - now))
    if tgt.expires <= now:
        state = "expired"
    elif tgt.expires - now < EXPIRING_S:
        state = "expiring"
    elif not renewable or tgt.renew_until is None or tgt.renew_until - now < RENEW_ENDING_S:
        state = "not_renewable_soon"
    else:
        state = "ok"
    info["state"] = state
    return info


async def _klist(user: LocalUser, *args: str) -> sysutil.Result:
    return await sysutil.run_dropped(user, "klist", *args, env=KLIST_ENV, timeout=KLIST_TIMEOUT_S)


async def query(user: LocalUser, now: float | None = None) -> dict:
    """TGT metadata of the user's default credential cache, as the user sees it."""
    try:
        res = await _klist(user, "-f")
        if res.rc != 0:
            err = sysutil.summarize(res.stderr or res.stdout, max_lines=1)
            return {"state": "none", "error": err}
        caches = parse_klist(res.stdout)
        info = describe(caches[0] if caches else None, now)
        listing = await _klist(user, "-l")
        if listing.rc == 0:
            info["caches"] = len(parse_list(listing.stdout))
        return info
    except (sysutil.CommandError, OSError, ValueError) as exc:
        log.warning("%s: klist: %s", user.name, exc)
        return {"state": "unknown", "error": f"klist: {exc}"}


async def query_all(users: list[LocalUser]) -> dict[str, dict]:
    """query() for each user, concurrently (each klist has its own timeout)."""
    results = await asyncio.gather(*(query(u) for u in users))
    return {u.name: r for u, r in zip(users, results)}


# ------------------------------------------------------------------ fastrdpctl output
def _left(seconds: int | None) -> str:
    if seconds is None:
        return ""
    if seconds <= 0:
        return "past"
    d, rest = divmod(seconds, 86400)
    h, rest = divmod(rest, 3600)
    m = rest // 60
    return f"{d}d{h}h" if d else f"{h}h{m:02d}m" if h else f"{m}m"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    return ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in [header, *rows]]


def format_tickets(tickets: dict[str, dict]) -> list[str]:
    if not tickets:
        return ["no session users"]
    rows = []
    for name in sorted(tickets):
        t = tickets[name]
        expires = f"{t['expires']} ({_left(t.get('expires_in'))})" if "expires" in t else "-"
        if "renew_until" in t:
            renew = f"{t['renew_until']} ({_left(t.get('renew_in'))})"
        else:
            renew = "-" if "expires" not in t else "not renewable"
        rows.append([name, t.get("state", "?"), t.get("principal", "-"), expires, renew,
                     t.get("cache", t.get("error", "-"))])
    return _table(["USER", "TGT", "PRINCIPAL", "EXPIRES (UTC)", "RENEW UNTIL (UTC)", "CACHE"], rows)


def _when(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def format_status(reply: dict) -> list[str]:
    sessions = reply.get("sessions", [])
    lines = ["Sessions:"]
    if sessions:
        rows = [[s.get("user", ""), s.get("backend", ""), s.get("desktop", ""), str(s.get("port") or "-"),
                 _when(s.get("started")), _when(s.get("last_login"))] for s in sessions]
        lines += ["  " + ln for ln in _table(["USER", "BACKEND", "DESKTOP", "PORT", "STARTED (UTC)",
                                              "LAST LOGIN (UTC)"], rows)]
    else:
        lines.append("  none")
    lines.append("Kerberos TGT (default cache of each session user):")
    lines += ["  " + ln for ln in format_tickets(reply.get("tickets", {}))]
    lines.append(f"connected: {reply.get('connected', 0)}  pending tokens: {reply.get('pending_tokens', 0)}"
                 f"  pending web tokens: {reply.get('pending_web_tokens', 0)}"
                 f"  MFA grace entries: {reply.get('mfa_grace_entries', 0)}"
                 f"  MFA web approvals pending: {reply.get('mfa_pending_approvals', 0)}")
    return lines
