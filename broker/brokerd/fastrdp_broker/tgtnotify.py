# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Desktop notification before the session's Kerberos TGT can no longer be renewed (backlog K4).

sssd (and sssd-kcm) renew the session's TGT until its renew-until time (default 7 days,
`krb5_renewable_lifetime`); after that nothing can get a new one without the password,
and the session silently loses Kerberized NFS/SMB homes and shares
(docs/nfs-kerberos-homes.md, Q4). This checker runs inside each desktop session
(/usr/libexec/fastrdp/tgt-notify, started through XDG autostart or by wlroots-in-x), as
the user, and warns once per threshold (default 24 h and 2 h before) and once when the
TGT has expired: reconnect with the password, or run `kinit`.

- It reads the user's default cache like `fastrdpctl tickets` does (tickets.py):
  `klist -f` without KRB5CCNAME, LC_ALL=C, TZ=UTC. That is the cache rpc.gssd and the
  session's processes use.
- No TGT at all (SSO logins without a password, no Kerberos): nothing is shown.
- It talks to the session's notification daemon on the session bus it inherited
  (notify-send, else gdbus). A failed notification is retried at the next check.
- Once per threshold and TGT: the state (renewal deadline + thresholds shown) is kept
  per session bus in $XDG_RUNTIME_DIR/fastrdp-tgt-notify/; a new TGT (reconnect with a
  password, kinit) has a new deadline and starts over.
- One checker per session bus (flock); it ends when its parent (the session) ends.

Settings: /etc/fastrdp/tgt-notify.conf (TOML; Ansible fastrdp_tgt_notify*).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import tickets

DEFAULT_CONFIG = Path("/etc/fastrdp/tgt-notify.conf")
KLIST_TIMEOUT_S = 10
NOTIFY_TIMEOUT_S = 10
MIN_INTERVAL_S = 60
# How often the loop looks whether its session (parent process) is still there.
PARENT_POLL_S = 30
EXPIRED = "expired"

SUMMARY = "Kerberos login ends in {left}"
BODY = ("From {deadline} this session can no longer access your Kerberos-protected home "
        "directory and network drives (NFS/SMB): the login cannot be renewed without your "
        "password.\nTo renew it, disconnect and reconnect with your password, or run kinit in "
        "a terminal.")
EXPIRED_SUMMARY = "Kerberos login expired"
EXPIRED_BODY = ("This session can no longer access your Kerberos-protected home directory and "
                "network drives (NFS/SMB); saving files there fails.\nTo renew the login, "
                "disconnect and reconnect with your password, or run kinit in a terminal.")
TEXT_KEYS = ("summary", "body", "expired_summary", "expired_body")
PLACEHOLDERS = {"left": "2 h", "deadline": "Mon 01 Jan 00:00", "principal": "user@REALM"}

_DURATION = re.compile(r"^([0-9]+)([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    enabled: bool = True
    thresholds: tuple[int, ...] = (86400, 7200)   # seconds before the deadline, descending
    interval: int = 600
    notify_expired: bool = True
    texts: dict[str, str] = field(default_factory=lambda: {
        "summary": SUMMARY, "body": BODY, "expired_summary": EXPIRED_SUMMARY, "expired_body": EXPIRED_BODY})


def parse_duration(value, name: str) -> int:
    """'24h', '90m', '7d', '30s' or a number of seconds -> seconds (> 0)."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ConfigError(f"{name}: duration expected (e.g. 24h, 90m), got {value!r}")
    m = _DURATION.match(str(value).strip())
    if not m or int(m.group(1)) <= 0:
        raise ConfigError(f"{name}: duration expected (e.g. 24h, 90m), got {value!r}")
    return int(m.group(1)) * _UNITS[m.group(2)]


def parse_settings(raw: dict) -> Settings:
    s = Settings()
    unknown = set(raw) - {"enabled", "thresholds", "interval", "notify_expired", *TEXT_KEYS}
    if unknown:
        raise ConfigError(f"unknown settings: {', '.join(sorted(unknown))}")
    for key in ("enabled", "notify_expired"):
        if key in raw:
            if not isinstance(raw[key], bool):
                raise ConfigError(f"{key}: true or false")
            setattr(s, key, raw[key])
    if "thresholds" in raw:
        if not isinstance(raw["thresholds"], list):
            raise ConfigError("thresholds: list of durations, e.g. [\"24h\", \"2h\"]")
        s.thresholds = tuple(sorted({parse_duration(v, "thresholds") for v in raw["thresholds"]}, reverse=True))
    if "interval" in raw:
        s.interval = max(MIN_INTERVAL_S, parse_duration(raw["interval"], "interval"))
    for key in TEXT_KEYS:
        if key in raw:
            text = raw[key]
            if not isinstance(text, str) or not text.strip():
                raise ConfigError(f"{key}: non-empty text")
            try:
                text.format_map(PLACEHOLDERS)
            except (KeyError, ValueError, IndexError, AttributeError) as exc:
                raise ConfigError(f"{key}: only the placeholders {{left}}, {{deadline}} and "
                                  f"{{principal}} (and {{{{ }}}} for braces): {exc}") from None
            s.texts[key] = text
    return s


def load(path: Path = DEFAULT_CONFIG) -> Settings:
    """Settings from `path`; a missing file means the defaults."""
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        return Settings()
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    try:
        return parse_settings(raw)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from None


# ------------------------------------------------------------------ TGT state
@dataclass
class TgtStatus:
    principal: str
    expires: float
    renewable: bool
    deadline: float      # when the session loses access: renew-until, or expiry if not renewable

    def expired(self, now: float) -> bool:
        return self.expires <= now or self.deadline <= now


def tgt_status(klist_out: str) -> TgtStatus | None:
    """The TGT of the default (first) cache in `klist -f` output; None without one."""
    caches = tickets.parse_klist(klist_out)
    if not caches:
        return None
    tgt = tickets.find_tgt(caches[0])
    if tgt is None:
        return None
    # same rule as tickets.describe()
    renewable = ("R" in tgt.flags) if tgt.flags else tgt.renew_until is not None
    if tgt.renew_until is None or tgt.renew_until <= tgt.expires:
        renewable = False
    deadline = tgt.renew_until if renewable and tgt.renew_until is not None else tgt.expires
    return TgtStatus(caches[0].principal, tgt.expires, renewable, deadline)


def read_tgt() -> TgtStatus | None:
    """`klist -f` on the default cache, as the session's processes and rpc.gssd see it."""
    if not shutil.which("klist"):
        return None
    env = {k: v for k, v in os.environ.items() if k != "KRB5CCNAME"}
    env.update(tickets.KLIST_ENV)
    try:
        res = subprocess.run(["klist", "-f"], env=env, capture_output=True, text=True,
                             timeout=KLIST_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"fastrdp-tgt-notify: klist: {exc}", file=sys.stderr)
        return None
    if res.returncode != 0:
        return None          # no cache: nothing to warn about
    try:
        return tgt_status(res.stdout)
    except ValueError as exc:
        print(f"fastrdp-tgt-notify: klist output: {exc}", file=sys.stderr)
        return None


def due(settings: Settings, status: TgtStatus | None, shown: set[str], now: float) -> tuple[str, list[str]] | None:
    """(stage to show now, stages it covers) or None.

    Stages: one per threshold ("86400", "7200") and EXPIRED. Only the most urgent stage
    that applies is shown; the less urgent ones it covers are marked as shown too, so a
    checker that starts 1 h before the deadline does not also send the 24 h warning."""
    if status is None:
        return None
    if status.expired(now):
        if not settings.notify_expired:
            return None
        stages = [EXPIRED, *(str(t) for t in settings.thresholds)]
        return (EXPIRED, stages) if EXPIRED not in shown else None
    left = status.deadline - now
    applicable = [str(t) for t in settings.thresholds if left <= t]
    if not applicable:
        return None
    stage = applicable[-1]          # thresholds are descending: the last is the smallest
    return (stage, applicable) if stage not in shown else None


def human_left(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= 2 * 86400:
        return f"{seconds // 86400} days"
    if seconds >= 2 * 3600:
        return f"{seconds // 3600} hours"
    if seconds >= 3600:
        return f"1 hour {seconds % 3600 // 60} minutes"
    minutes = max(1, seconds // 60)
    return f"{minutes} minute{'' if minutes == 1 else 's'}"


def message(settings: Settings, stage: str, status: TgtStatus, now: float) -> tuple[str, str, str]:
    """(summary, body, urgency)."""
    values = {"left": human_left(status.deadline - now),
              "deadline": time.strftime("%a %d %b %H:%M", time.localtime(status.deadline)),
              "principal": status.principal}
    if stage == EXPIRED:
        return (settings.texts["expired_summary"].format_map(values),
                settings.texts["expired_body"].format_map(values), "critical")
    # the last warning stays on screen until dismissed (critical), earlier ones do not
    urgency = "critical" if stage == str(min(settings.thresholds)) else "normal"
    return settings.texts["summary"].format_map(values), settings.texts["body"].format_map(values), urgency


# ------------------------------------------------------------------ notification
def _gvariant_str(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def send(summary: str, body: str, urgency: str) -> bool:
    """Notification on the session bus: notify-send (libnotify-bin), else gdbus."""
    if shutil.which("notify-send"):
        cmd = ["notify-send", "--app-name=fastrdp", f"--urgency={urgency}", "--icon=dialog-warning",
               "--", summary, body]
    elif shutil.which("gdbus"):
        level = {"low": 0, "normal": 1, "critical": 2}[urgency]
        cmd = ["gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications",
               "--object-path", "/org/freedesktop/Notifications",
               "--method", "org.freedesktop.Notifications.Notify",
               _gvariant_str("fastrdp"), "0", _gvariant_str("dialog-warning"), _gvariant_str(summary),
               _gvariant_str(body), "[]", f"{{'urgency': <byte {level}>}}", "-1"]
    else:
        print("fastrdp-tgt-notify: neither notify-send (libnotify-bin) nor gdbus found", file=sys.stderr)
        return False
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=NOTIFY_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"fastrdp-tgt-notify: {cmd[0]}: {exc}", file=sys.stderr)
        return False
    if res.returncode != 0:
        print(f"fastrdp-tgt-notify: {cmd[0]} failed (no notification daemon on the session bus?): "
              f"{(res.stderr or res.stdout).strip()[:300]}", file=sys.stderr)
        return False
    return True


# ------------------------------------------------------------------ state
def runtime_dir() -> Path:
    return Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")


def session_key() -> str:
    """One checker per session bus: notifications go to the daemon on that bus."""
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"unix:path={runtime_dir()}/bus"
    # dbus-run-session addresses carry a guid; the path/abstract name identifies the bus
    bus = ",".join(p for p in bus.split(",") if not p.startswith("guid="))
    return hashlib.sha256(bus.encode()).hexdigest()[:16]


class State:
    """Stages already shown for the current TGT deadline, kept across checker restarts."""

    def __init__(self, path: Path):
        self.path = path
        self.deadline: float | None = None
        self.shown: set[str] = set()
        try:
            data = json.loads(path.read_text())
            self.deadline = float(data["deadline"])
            self.shown = {str(s) for s in data["shown"]}
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def for_deadline(self, deadline: float) -> set[str]:
        # a new TGT (reconnect with a password, kinit) has a new deadline: start over
        if self.deadline is None or abs(self.deadline - deadline) > 1:
            self.deadline, self.shown = deadline, set()
        return self.shown

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps({"deadline": self.deadline, "shown": sorted(self.shown)}))
            os.replace(tmp, self.path)
        except OSError as exc:
            print(f"fastrdp-tgt-notify: {self.path}: {exc}", file=sys.stderr)


def check_once(settings: Settings, state: State, now: float | None = None,
               reader=read_tgt, sender=send) -> str | None:
    """One check; returns the stage shown (None: nothing to show or sending failed)."""
    now = time.time() if now is None else now
    status = reader()
    if status is None:
        return None
    shown = state.for_deadline(status.deadline)
    todo = due(settings, status, shown, now)
    if todo is None:
        return None
    stage, covered = todo
    if not sender(*message(settings, stage, status, now)):
        return None          # retried at the next check
    shown.update(covered)
    state.save()
    return stage


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fastrdp-tgt-notify",
                                 description="Warn the desktop user before the Kerberos TGT can no longer be renewed.")
    ap.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--once", action="store_true", help="check once and exit")
    ap.add_argument("--status", action="store_true",
                    help="print the TGT deadline and the stage due now (JSON) and exit; no notification")
    args = ap.parse_args(argv)
    try:
        settings = load(args.config)
    except (ConfigError, OSError) as exc:
        print(f"fastrdp-tgt-notify: {exc}", file=sys.stderr)
        return 2
    if args.status:
        status, now = read_tgt(), time.time()
        todo = due(settings, status, set(), now)
        print(json.dumps({"enabled": settings.enabled, "principal": status and status.principal,
                          "deadline": status and int(status.deadline),
                          "renewable": status and status.renewable,
                          "due": todo and todo[0]}))
        return 0
    if not settings.enabled:
        return 0
    base = runtime_dir() / "fastrdp-tgt-notify"
    try:
        base.mkdir(mode=0o700, exist_ok=True)
        lock = open(base / f"{session_key()}.lock", "w")  # noqa: SIM115 - held while the loop runs
    except OSError as exc:
        print(f"fastrdp-tgt-notify: {base}: {exc}", file=sys.stderr)
        return 1
    with lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0         # this session already has a checker
        return _loop(settings, State(base / f"{session_key()}.json"), args.once)


def _loop(settings: Settings, state: State, once: bool) -> int:
    parent = os.getppid()
    while True:
        check_once(settings, state)
        if once:
            return 0
        waited = 0
        while waited < settings.interval:
            time.sleep(min(PARENT_POLL_S, settings.interval - waited))
            waited += PARENT_POLL_S
            if os.getppid() != parent:   # the session (our parent) ended
                return 0


if __name__ == "__main__":
    sys.exit(main())
