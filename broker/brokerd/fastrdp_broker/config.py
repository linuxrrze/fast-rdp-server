"""Broker configuration (/etc/fastrdp/broker.toml)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/fastrdp/broker.toml")


class ConfigError(Exception):
    pass


@dataclass
class BrokerSection:
    socket: str = "/run/fastrdp/broker.sock"
    token_socket: str = "/run/fastrdp/token.sock"
    proxy_user: str = "_fastrdp-proxy"
    state_dir: str = "/var/lib/fastrdp"
    runtime_dir: str = "/run/fastrdp"
    port_range: tuple[int, int] = (33900, 34899)
    token_ttl: int = 60
    session_start_timeout: int = 90


@dataclass
class AuthSection:
    realms: list[str] = field(default_factory=list)
    strip_realm: bool = True
    pam_service: str = "fastrdp"
    allow_groups: list[str] = field(default_factory=list)
    allow_tls_password_login: bool = True


@dataclass
class PrivacyIdeaSection:
    url: str = ""
    realm: str = ""
    ca_file: str = ""
    verify_tls: bool = True
    timeout: int = 10
    push_timeout: int = 60
    poll_interval: float = 1.5
    service_user: str = ""
    service_password_file: str = ""


@dataclass
class MfaSection:
    # none | otp | push | otp_or_push
    mode: str = "none"
    exempt_groups: list[str] = field(default_factory=list)
    otp_lengths: list[int] = field(default_factory=lambda: [6])
    yubikey_otp: bool = True
    privacyidea: PrivacyIdeaSection = field(default_factory=PrivacyIdeaSection)


@dataclass
class Desktop:
    name: str
    backend: str  # xrdp | gnome | plasma
    label: str = ""
    xsession: str = ""  # xrdp only: name of /usr/share/xsessions/<xsession>.desktop
    groups: list[str] = field(default_factory=list)


@dataclass
class BackendSection:
    name: str
    host: str = "127.0.0.1"
    port: int = 0  # fixed port (xrdp); 0 = allocate per session
    security: str = "tls"  # tls | nla : how the proxy talks to this backend
    listener_user: str = ""  # expected owner of the listening socket ("" = session user)
    unit: str = ""  # systemd unit template for per-user sessions


@dataclass
class Config:
    broker: BrokerSection
    auth: AuthSection
    mfa: MfaSection
    desktops: dict[str, Desktop]
    backends: dict[str, BackendSection]
    default_desktop: str
    default_geometry: str
    group_defaults: dict[str, str]


VALID_BACKENDS = ("xrdp", "gnome", "plasma")
VALID_MFA_MODES = ("none", "otp", "push", "otp_or_push")


def _section(cls, data: dict, where: str):
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{where}]: unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def _parse_geometry(value: str) -> str:
    try:
        w, h = value.lower().split("x")
        if not (320 <= int(w) <= 8192 and 200 <= int(h) <= 8192):
            raise ValueError
    except ValueError:
        raise ConfigError(f"invalid geometry {value!r}, expected WIDTHxHEIGHT") from None
    return value.lower()


def load(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    with open(path, "rb") as fh:
        return parse(tomllib.load(fh))


def parse(raw: dict) -> Config:
    raw = dict(raw)
    broker_raw = dict(raw.pop("broker", {}))
    if "port_range" in broker_raw:
        lo, hi = broker_raw["port_range"]
        if not (1024 < lo < hi < 65536):
            raise ConfigError("[broker] port_range must be [low, high] within 1025..65535")
        broker_raw["port_range"] = (lo, hi)
    broker = _section(BrokerSection, broker_raw, "broker")

    auth = _section(AuthSection, dict(raw.pop("auth", {})), "auth")
    auth.realms = [r.upper() for r in auth.realms]

    mfa_raw = dict(raw.pop("mfa", {}))
    pi = _section(PrivacyIdeaSection, dict(mfa_raw.pop("privacyidea", {})), "mfa.privacyidea")
    mfa = _section(MfaSection, mfa_raw, "mfa")
    mfa.privacyidea = pi
    if mfa.mode not in VALID_MFA_MODES:
        raise ConfigError(f"[mfa] mode must be one of {VALID_MFA_MODES}")
    if mfa.mode != "none" and not pi.url:
        raise ConfigError("[mfa.privacyidea] url is required when MFA is enabled")

    desktops: dict[str, Desktop] = {}
    for name, d in raw.pop("desktops", {}).items():
        desk = _section(Desktop, {"name": name, **d}, f"desktops.{name}")
        if desk.backend not in VALID_BACKENDS:
            raise ConfigError(f"[desktops.{name}] backend must be one of {VALID_BACKENDS}")
        if desk.backend == "xrdp" and not desk.xsession:
            raise ConfigError(f"[desktops.{name}] xrdp desktops need 'xsession'")
        desktops[name] = desk
    if not desktops:
        raise ConfigError("at least one [desktops.<name>] section is required")

    backend_defaults = {
        # xrdp binds its socket as root, then drops to runtime_user: the listener is uid 0.
        "xrdp": {"port": 3390, "security": "tls", "listener_user": "root"},
        "gnome": {"security": "nla", "unit": "gnome-headless-session@{user}.service"},
        "plasma": {"security": "nla", "unit": "fastrdp-plasma@{user}.service"},
    }
    backends_raw = raw.pop("backends", {})
    backends: dict[str, BackendSection] = {}
    for name in VALID_BACKENDS:
        merged = {"name": name, **backend_defaults[name], **backends_raw.pop(name, {})}
        b = _section(BackendSection, merged, f"backends.{name}")
        if b.security not in ("tls", "nla"):
            raise ConfigError(f"[backends.{name}] security must be 'tls' or 'nla'")
        backends[name] = b
    if backends_raw:
        raise ConfigError(f"unknown backends: {', '.join(backends_raw)}")

    defaults = dict(raw.pop("defaults", {}))
    default_desktop = defaults.pop("desktop", next(iter(desktops)))
    default_geometry = _parse_geometry(defaults.pop("geometry", "1920x1080"))
    group_defaults = dict(defaults.pop("groups", {}))
    if defaults:
        raise ConfigError(f"[defaults]: unknown keys: {', '.join(defaults)}")
    for desk_name in [default_desktop, *group_defaults.values()]:
        if desk_name not in desktops:
            raise ConfigError(f"[defaults] refers to unknown desktop {desk_name!r}")

    if raw:
        raise ConfigError(f"unknown top-level sections: {', '.join(raw)}")

    return Config(
        broker=broker,
        auth=auth,
        mfa=mfa,
        desktops=desktops,
        backends=backends,
        default_desktop=default_desktop,
        default_geometry=default_geometry,
        group_defaults=group_defaults,
    )
