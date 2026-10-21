# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Broker configuration (/etc/fastrdp/broker.toml)."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

from . import conntype

DEFAULT_CONFIG_PATH = Path("/etc/fastrdp/broker.toml")


class ConfigError(Exception):
    pass


@dataclass
class BrokerSection:
    socket: str = "/run/fastrdp/broker.sock"
    token_socket: str = "/run/fastrdp/token.sock"
    proxy_user: str = "_fastrdp-proxy"
    # Group owning broker.sock (proxy + webgate join it); "" = the proxy user's group.
    # Keep it separate from the proxy's own group, which can read the keytab and TLS key.
    socket_group: str = ""
    state_dir: str = "/var/lib/fastrdp"
    runtime_dir: str = "/run/fastrdp"
    port_range: tuple[int, int] = (33900, 34899)
    token_ttl: int = 60
    session_start_timeout: int = 90
    # Seconds the broker waits for ~/.config/fastrdp/desktop (read as root). Home
    # directories on NFS can hang (server down) or refuse root (sec=krb5*); the login
    # then falls back to the group/global default. 0 = never read users' homes.
    home_read_timeout: float = 3.0
    # Kerberos TGT for back-ends that never see the user's password (GNOME, Plasma):
    # "auto" = with a known password (NLA delegated, TLS), get one through PAM service
    # fastrdp-tgt (pam_sss) before the session starts; failure is only logged.
    # "required" = refuse logins without a password, and logins whose TGT step fails.
    # "off" = never. See docs/nfs-kerberos-homes.md.
    session_tgt: str = "auto"
    # Home directory of the user before any back-end starts (home.py): "create" = refuse
    # with a clear log line if it is unusable, create it (mkhomedir_helper, mode 0700)
    # if only its last component is missing; "check" = never create; "off" = no check.
    home_check: str = "create"
    # home_check = "create" only creates homes whose parent directory is one of these
    # roots or below one (also after resolving symlinks); the roots themselves and
    # missing parents never. [] = never create.
    home_create_roots: list[str] = field(default_factory=lambda: ["/home"])


@dataclass
class AuthSection:
    realms: list[str] = field(default_factory=list)
    # true: SSSD has short names (use_fully_qualified_names = false), 'alice' is tried
    # before 'alice@example.com'; false: fully qualified names, the other way round.
    strip_realm: bool = True
    # SSSD domain names qualifying account and group names besides the realms (lower
    # case), e.g. a FreeIPA domain that differs from its realm.
    domains: list[str] = field(default_factory=list)
    pam_service: str = "fastrdp"
    allow_groups: list[str] = field(default_factory=list)
    allow_tls_password_login: bool = True


@dataclass
class WebSection:
    """Browser access through fastrdp-webgate + Guacamole (MFA happens at the IdP)."""
    enabled: bool = False
    gateway_user: str = "_fastrdp-web"   # uid allowed to request web tokens
    # Web tokens are only accepted on logins coming from guacd (client address seen by the proxy).
    allowed_clients: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    token_ttl: int = 60


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
    # Kerberos NLA logins skip privacyIDEA: the operator asserts that the KDC issues
    # TERMSRV tickets only after strong pre-authentication (FreeIPA: auth indicators
    # passkey/pkinit on the TERMSRV service; docs/passkeys.md). Only for principals of
    # [auth] realms; TLS and web logins are unaffected. Never for AD without a policy
    # that guarantees it (AD has no authentication indicators).
    nla_kdc_enforced: bool = False
    # Seconds after a login with a real second factor (OTP/push) during which reconnects
    # of the same account, login method (nla/tls), Kerberos principal and, with
    # reconnect_grace_same_address, client address skip it. Counted from that second
    # factor, never extended; memory only. 0 = off. docs/auth-matrix.md#reconnect-grace
    reconnect_grace: int = 0
    reconnect_grace_same_address: bool = True
    privacyidea: PrivacyIdeaSection = field(default_factory=PrivacyIdeaSection)


@dataclass
class NetworkSection:
    """Connection type for the xrdp hop (conntype.py, docs/performance.md)."""
    # Clients whose socket address is in one of these CIDRs get `lan` towards xrdp,
    # unless they chose a connection type themselves.
    lan_networks: list[str] = field(default_factory=list)
    # Profile for all other clients that ask for auto-detection (mstsc's default):
    # modem | broadband_low | satellite | broadband_high | wan | lan | default (unchanged).
    xrdp_autodetect_profile: str = "wan"
    # lan_networks parsed (set by parse(), not a config key)
    lan: tuple = field(default=(), init=False)


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
    web: WebSection
    network: NetworkSection
    desktops: dict[str, Desktop]
    backends: dict[str, BackendSection]
    default_desktop: str
    default_geometry: str
    group_defaults: dict[str, str]


VALID_BACKENDS = ("xrdp", "gnome", "plasma")
VALID_MFA_MODES = ("none", "otp", "push", "otp_or_push")
VALID_SESSION_TGT = ("auto", "off", "required")
DOMAIN_NAME = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")
VALID_HOME_CHECK = ("create", "check", "off")
MAX_RECONNECT_GRACE = 3600  # seconds; longer is "MFA once per shift", not a reconnect aid


def _section(cls, data: dict, where: str):
    known = {f.name for f in fields(cls) if f.init}
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
    if (
        isinstance(broker.home_read_timeout, bool)
        or not isinstance(broker.home_read_timeout, (int, float))
        or not 0 <= broker.home_read_timeout <= 60
    ):
        raise ConfigError("[broker] home_read_timeout must be a number of seconds in 0..60")
    if broker.session_tgt not in VALID_SESSION_TGT:
        raise ConfigError(f"[broker] session_tgt must be one of {VALID_SESSION_TGT}")
    if broker.home_check not in VALID_HOME_CHECK:
        raise ConfigError(f"[broker] home_check must be one of {VALID_HOME_CHECK}")
    if not isinstance(broker.home_create_roots, list) or not all(
        isinstance(r, str) and r.startswith("/") and not r.startswith("//") and r != "/"
        and os.path.normpath(r) == r and "\n" not in r
        for r in broker.home_create_roots
    ):
        raise ConfigError("[broker] home_create_roots must be a list of absolute, normalised "
                          "directories other than / (e.g. [\"/home\"])")

    auth = _section(AuthSection, dict(raw.pop("auth", {})), "auth")
    if not isinstance(auth.strip_realm, bool):
        raise ConfigError("[auth] strip_realm must be true or false")
    if not isinstance(auth.domains, list) or not all(
        isinstance(d, str) and DOMAIN_NAME.fullmatch(d) for d in auth.domains
    ):
        raise ConfigError("[auth] domains must be a list of DNS domain names")
    auth.realms = [r.upper() for r in auth.realms]
    auth.domains = [d.lower() for d in auth.domains]

    mfa_raw = dict(raw.pop("mfa", {}))
    pi = _section(PrivacyIdeaSection, dict(mfa_raw.pop("privacyidea", {})), "mfa.privacyidea")
    mfa = _section(MfaSection, mfa_raw, "mfa")
    web = _section(WebSection, dict(raw.pop("web", {})), "web")
    mfa.privacyidea = pi
    if mfa.mode not in VALID_MFA_MODES:
        raise ConfigError(f"[mfa] mode must be one of {VALID_MFA_MODES}")
    if mfa.mode != "none" and not pi.url:
        raise ConfigError("[mfa.privacyidea] url is required when MFA is enabled")
    if not isinstance(mfa.nla_kdc_enforced, bool):
        raise ConfigError("[mfa] nla_kdc_enforced must be true or false")
    if mfa.nla_kdc_enforced and not auth.realms:
        # Only tickets from KDCs whose TERMSRV policy is known may skip MFA; a trusted
        # foreign realm's KDC does not apply this realm's authentication indicators.
        raise ConfigError("[mfa] nla_kdc_enforced needs [auth] realms (the realms whose KDC enforces it)")
    if (
        isinstance(mfa.reconnect_grace, bool)
        or not isinstance(mfa.reconnect_grace, int)
        or not 0 <= mfa.reconnect_grace <= MAX_RECONNECT_GRACE
    ):
        raise ConfigError(f"[mfa] reconnect_grace must be whole seconds in 0..{MAX_RECONNECT_GRACE}")
    if not isinstance(mfa.reconnect_grace_same_address, bool):
        raise ConfigError("[mfa] reconnect_grace_same_address must be true or false")

    network = _section(NetworkSection, dict(raw.pop("network", {})), "network")
    try:
        network.lan = conntype.parse_networks(network.lan_networks)
    except ValueError as exc:
        raise ConfigError(f"[network] lan_networks: {exc}") from None
    if network.xrdp_autodetect_profile not in conntype.PROFILES:
        raise ConfigError(f"[network] xrdp_autodetect_profile must be one of {conntype.PROFILES}")

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
        web=web,
        network=network,
        desktops=desktops,
        backends=backends,
        default_desktop=default_desktop,
        default_geometry=default_geometry,
        group_defaults=group_defaults,
    )
