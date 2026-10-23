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
    # session_tgt per group: {group: mode}. A member of listed groups gets the strictest
    # of their modes (required > auto > off), whatever session_tgt says; everybody else
    # gets session_tgt. Names as in allow_groups (short or "group@domain").
    session_tgt_groups: dict[str, str] = field(default_factory=dict)
    # Home directory of the user before any back-end starts (home.py): "create" = refuse
    # with a clear log line if it is unusable, create it (mkhomedir_helper, mode 0700)
    # if only its last component is missing; "check" = never create; "off" = no check.
    home_check: str = "create"
    # home_check = "create" only creates homes whose parent directory is one of these
    # roots or below one (also after resolving symlinks); the roots themselves and
    # missing parents never. [] = never create.
    home_create_roots: list[str] = field(default_factory=lambda: ["/home"])
    # Desktop picker on the proxy's waiting screen after the second factor (server.py
    # Broker.pick_desktop, docs/desktop-matrix.md#choosing-a-desktop): "never";
    # "if_multiple" = users who may use more than one desktop and have chosen none yet
    # (no desktop stored on the web gateway or with fastrdpctl, no ~/.config/fastrdp/desktop);
    # "always" = also when they have, that desktop preselected. Never with a client hint
    # (AlternateShell, the web gateway, downloaded .rdp files) or a single permitted desktop,
    # and only with proxy.ini [FastRDP] WaitingScreen and patches/freerdp/0007.
    desktop_picker: str = "never"
    # Seconds the picker waits for the user (3..60); then the preselected desktop.
    desktop_picker_timeout: int = 10
    # The user has a running session: "preselect" its desktop in the picker, or "skip"
    # the picker and reconnect to it.
    desktop_picker_when_running: str = "preselect"


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
class KeycloakOtpSection:
    """[mfa.keycloak] (mode code_or_web): Keycloak checks the code typed on the waiting
    screen through a direct grant (username + code, no password) of a confidential client
    whose direct grant flow has only Username Validation and OTP (keycloak_otp.py)."""
    # The realm's issuer, https://<host>/realms/<realm> (as [oidc] issuer of the webgate)
    issuer: str = ""
    client_id: str = ""
    client_secret_file: str = ""   # root-only; the client's secret
    ca_file: str = ""              # "" = system trust store
    timeout: int = 10
    # A token counts only with this value in its amr claim: the reference value of the
    # flow's OTP step (fastrdp_keycloak_passkeys.py), absent if a broken flow skipped it
    required_amr: str = "otp"


@dataclass
class MfaSection:
    # none | otp | push | otp_or_push | web | push_or_web | code_or_web
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
    # Per login: a Kerberos NLA login whose ticket carries one of these items skips
    # privacyIDEA. The proxy module reports what the KDC asserted in the ticket, verified
    # with the service key (patches/freerdp/0005): "ind:<authentication indicator>"
    # (MIT/FreeIPA, e.g. ind:pkinit, ind:passkey) and "sid:<group SID>" from the PAC
    # (AD, e.g. sid:S-1-18-4 for Windows Hello for Business key trust or an Authentication
    # Mechanism Assurance group). Only principals of [auth] realms; logins without a
    # matching item keep their second factor. docs/passkeys.md#kdc-evidence-per-login
    kdc_evidence_as_mfa: list[str] = field(default_factory=list)
    # Seconds after a login with a real second factor (OTP/push) during which reconnects
    # of the same account, login method (nla/tls), Kerberos principal and, with
    # reconnect_grace_same_address, client address skip it. Counted from that second
    # factor, never extended; memory only. 0 = off. docs/auth-matrix.md#reconnect-grace
    reconnect_grace: int = 0
    reconnect_grace_same_address: bool = True
    # mode web / push_or_web: the user approves a pending RDP login on fastrdp-webgate's
    # <prefix>/approve page after a fresh MFA sign-in at the IdP (mfa.WebApprovals).
    # Seconds a login waits for the decision; plus session_start_timeout at most
    # proxy.ini [FastRDP] Timeout.
    web_approval_timeout: int = 90
    # The approving sign-in (ID token auth_time) must be newer than the pending login,
    # or at most this many seconds older.
    web_approval_max_auth_age: int = 30
    # More than one pending login of a user: approving is refused for all of them (an
    # attacker with the password may have started one alongside the user's own).
    web_approval_single_pending: bool = True
    # mode code_or_web: wrong codes per login before it fails (mfa_failed), and wrong
    # codes per user within code_failure_window seconds before code entry is refused for
    # that user (the approval page still works). Keycloak's brute-force detection counts
    # on top.
    code_attempts: int = 3
    code_user_failures: int = 10
    code_failure_window: int = 900
    privacyidea: PrivacyIdeaSection = field(default_factory=PrivacyIdeaSection)
    keycloak: KeycloakOtpSection = field(default_factory=KeycloakOtpSection)


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
class UiSection:
    """Texts of the proxy's waiting screen (proxy.ini [FastRDP] WaitingScreen; ui.py)."""
    # Language of the texts: a built-in one (ui.BUILTIN_TEXTS: en, de) or one with its own
    # [ui.<language>] table.
    language: str = "en"
    # Take the language from the client's keyboard layout (0x0407 German -> "de") when
    # there are texts in that language; else `language`.
    language_from_keyboard: bool = True
    # The webgate's approval page as users reach it, e.g. https://rdp.example.com/web/approve:
    # shown with web approval, and as QR code with the login's id (<url>?login=<id>, so
    # that approving binds to the login on the screen). "" = not shown.
    approve_url: str = ""
    # QR code of approve_url (with the login's id) next to the text, for signing in on a phone.
    qr_code: bool = True
    # [ui.<language>] tables: {language: {text key: template}} (set by parse())
    texts: dict[str, dict[str, str]] = field(default_factory=dict)


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
    # TLS certificate the back-end presents; the proxy accepts only this one (its SHA-256
    # goes to the module with the target). "" = the per-user certificate the broker
    # creates (<state_dir>/users/<name>/tls.crt, gnome and plasma).
    certificate: str = ""
    unit: str = ""  # systemd unit template for per-user sessions


@dataclass
class Config:
    broker: BrokerSection
    auth: AuthSection
    mfa: MfaSection
    web: WebSection
    network: NetworkSection
    ui: UiSection
    desktops: dict[str, Desktop]
    backends: dict[str, BackendSection]
    default_desktop: str
    default_geometry: str
    group_defaults: dict[str, str]


VALID_BACKENDS = ("xrdp", "gnome", "plasma")
VALID_MFA_MODES = ("none", "otp", "push", "otp_or_push", "web", "push_or_web", "code_or_web")
PRIVACYIDEA_MODES = ("otp", "push", "otp_or_push", "push_or_web")
WEB_APPROVAL_MODES = ("web", "push_or_web", "code_or_web")
KEYCLOAK_OTP_MODES = ("code_or_web",)
AMR_VALUE = re.compile(r"[A-Za-z0-9._-]{1,64}")
# [mfa.keycloak] issuer: https://<host>[:port][/prefix]/realms/<realm> (plain http only on loopback)
KEYCLOAK_ISSUER = re.compile(r"(https://[A-Za-z0-9.-]+|http://(localhost|127\.0\.0\.1|\[::1\]))"
                             r"(:[0-9]{1,5})?(/[\x21-\x7e]*)?/realms/[^/\s]+")
CODE_ATTEMPTS = (1, 10)
CODE_USER_FAILURES = (1, 100)
CODE_FAILURE_WINDOW = (60, 86400)
VALID_SESSION_TGT = ("auto", "off", "required")
DOMAIN_NAME = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")
VALID_HOME_CHECK = ("create", "check", "off")
VALID_DESKTOP_PICKER = ("never", "if_multiple", "always")
VALID_DESKTOP_PICKER_WHEN_RUNNING = ("preselect", "skip")
DESKTOP_PICKER_TIMEOUT = (3, 60)  # seconds; the module accepts at most 60
MAX_RECONNECT_GRACE = 3600  # seconds; longer is "MFA once per shift", not a reconnect aid
# seconds; the proxy module caps [FastRDP] Timeout at 600, which also has to cover the
# session start after the approval (session_start_timeout, 90): 600 - 90
WEB_APPROVAL_TIMEOUT = (10, 510)
MAX_WEB_APPROVAL_AUTH_AGE = 300
# [ui.<language>] tables
LANGUAGE = re.compile(r"[a-z]{2,3}")
# [ui] approve_url: printable ASCII. The waiting screen's QR code names the login,
# <approve_url>?login=<id> (ui.login_url(); the id from mfa.WebApprovals.new_id()), and
# must fit into a version 10 QR code (ui.QR_MAX_VERSION: 213 bytes at level M).
LOGIN_ID_CHARS = 22  # token_urlsafe(16)
MAX_APPROVE_URL = 213 - len("?login=") - LOGIN_ID_CHARS  # 184
APPROVE_URL = re.compile(r"https://[\x21-\x7e]{1,%d}" % (MAX_APPROVE_URL - len("https://")))
# [mfa] kdc_evidence_as_mfa items (what fastrdp_plugin.c kdc_evidence() reports)
KDC_EVIDENCE_ITEM = re.compile(r"ind:[\x21-\x7e]{1,64}|sid:S-1-[0-9]{1,15}(-[0-9]{1,10}){1,15}")
# Present after a password logon too, so never a second factor: "hardened" is a password
# with FAST/SPAKE (MIT, FreeIPA); S-1-18-1 "authentication authority asserted identity"
# is in every AD/Samba AS logon, S-1-18-2 marks S4U2Self; Everyone, Authenticated Users,
# Users. Domain Users (RID 513) is refused below.
KDC_EVIDENCE_NOT_MFA = {"ind:hardened", "sid:S-1-18-1", "sid:S-1-18-2", "sid:S-1-1-0",
                        "sid:S-1-5-11", "sid:S-1-5-32-545"}


def _section(cls, data: dict, where: str):
    known = {f.name for f in fields(cls) if f.init}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{where}]: unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def parse_ui(raw: dict) -> UiSection:
    from . import ui as uitexts  # ui.py imports this module

    texts = {k: raw.pop(k) for k in [k for k, v in raw.items() if isinstance(v, dict)]}
    ui = _section(UiSection, raw, "ui")
    for key in ("language_from_keyboard", "qr_code"):
        if not isinstance(getattr(ui, key), bool):
            raise ConfigError(f"[ui] {key} must be true or false")
    for lang, table in texts.items():
        if not LANGUAGE.fullmatch(lang):
            raise ConfigError(f"[ui.{lang}]: not a language code (two or three lower-case letters)")
        unknown = set(table) - set(uitexts.TEXT_KEYS)
        if unknown:
            raise ConfigError(f"[ui.{lang}]: unknown keys: {', '.join(sorted(unknown))}")
        for key, template in table.items():
            try:
                uitexts.check_template(template)
            except ValueError as exc:
                raise ConfigError(f"[ui.{lang}] {key}: {exc}") from None
    ui.texts = texts
    if not isinstance(ui.language, str) or ui.language not in {*uitexts.BUILTIN_TEXTS, *texts}:
        raise ConfigError(f"[ui] language must be one of {sorted({*uitexts.BUILTIN_TEXTS, *texts})} "
                          "(built in, or with an [ui.<language>] table)")
    if not isinstance(ui.approve_url, str) or (ui.approve_url and not APPROVE_URL.fullmatch(ui.approve_url)):
        raise ConfigError(f"[ui] approve_url must be an https:// URL of at most {MAX_APPROVE_URL} "
                          "printable characters (or \"\")")
    return ui


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
    if not isinstance(broker.session_tgt_groups, dict):
        raise ConfigError("[broker] session_tgt_groups must be a table of group = mode")
    for group, mode in broker.session_tgt_groups.items():
        if not group.strip() or group != group.strip() or any(ord(c) < 32 for c in group):
            raise ConfigError(f"[broker.session_tgt_groups] invalid group name {group!r}")
        if mode not in VALID_SESSION_TGT:
            raise ConfigError(f"[broker.session_tgt_groups] {group}: mode must be one of {VALID_SESSION_TGT}")
    if broker.home_check not in VALID_HOME_CHECK:
        raise ConfigError(f"[broker] home_check must be one of {VALID_HOME_CHECK}")
    if broker.desktop_picker not in VALID_DESKTOP_PICKER:
        raise ConfigError(f"[broker] desktop_picker must be one of {VALID_DESKTOP_PICKER}")
    lo, hi = DESKTOP_PICKER_TIMEOUT
    if (
        isinstance(broker.desktop_picker_timeout, bool)
        or not isinstance(broker.desktop_picker_timeout, int)
        or not lo <= broker.desktop_picker_timeout <= hi
    ):
        raise ConfigError(f"[broker] desktop_picker_timeout must be whole seconds in {lo}..{hi}")
    if broker.desktop_picker_when_running not in VALID_DESKTOP_PICKER_WHEN_RUNNING:
        raise ConfigError("[broker] desktop_picker_when_running must be one of "
                          f"{VALID_DESKTOP_PICKER_WHEN_RUNNING}")
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
    kc = _section(KeycloakOtpSection, dict(mfa_raw.pop("keycloak", {})), "mfa.keycloak")
    mfa = _section(MfaSection, mfa_raw, "mfa")
    web = _section(WebSection, dict(raw.pop("web", {})), "web")
    mfa.privacyidea = pi
    mfa.keycloak = kc
    if mfa.mode not in VALID_MFA_MODES:
        raise ConfigError(f"[mfa] mode must be one of {VALID_MFA_MODES}")
    if mfa.mode in PRIVACYIDEA_MODES and not pi.url:
        raise ConfigError(f"[mfa.privacyidea] url is required for [mfa] mode = {mfa.mode!r}")
    if mfa.mode in WEB_APPROVAL_MODES and not web.enabled:
        raise ConfigError(f"[mfa] mode = {mfa.mode!r} needs [web] enabled (fastrdp-webgate's approval page)")
    if not isinstance(mfa.nla_kdc_enforced, bool):
        raise ConfigError("[mfa] nla_kdc_enforced must be true or false")
    if mfa.nla_kdc_enforced and not auth.realms:
        # Only tickets from KDCs whose TERMSRV policy is known may skip MFA; a trusted
        # foreign realm's KDC does not apply this realm's authentication indicators.
        raise ConfigError("[mfa] nla_kdc_enforced needs [auth] realms (the realms whose KDC enforces it)")
    if not isinstance(mfa.kdc_evidence_as_mfa, list) or not all(
        isinstance(i, str) and KDC_EVIDENCE_ITEM.fullmatch(i) for i in mfa.kdc_evidence_as_mfa
    ):
        raise ConfigError('[mfa] kdc_evidence_as_mfa must be a list of "ind:<indicator>" '
                          'and "sid:S-1-..." items (e.g. ["ind:pkinit", "sid:S-1-18-4"])')
    for item in mfa.kdc_evidence_as_mfa:
        if item in KDC_EVIDENCE_NOT_MFA or (item.startswith("sid:S-1-5-21-") and item.endswith("-513")):
            raise ConfigError(f"[mfa] kdc_evidence_as_mfa: {item} is in the tickets of password "
                              "logons too, it is no second factor")
    if mfa.kdc_evidence_as_mfa and not auth.realms:
        raise ConfigError("[mfa] kdc_evidence_as_mfa needs [auth] realms (the realms whose KDC is trusted for it)")
    if (
        isinstance(mfa.reconnect_grace, bool)
        or not isinstance(mfa.reconnect_grace, int)
        or not 0 <= mfa.reconnect_grace <= MAX_RECONNECT_GRACE
    ):
        raise ConfigError(f"[mfa] reconnect_grace must be whole seconds in 0..{MAX_RECONNECT_GRACE}")
    if not isinstance(mfa.reconnect_grace_same_address, bool):
        raise ConfigError("[mfa] reconnect_grace_same_address must be true or false")
    lo, hi = WEB_APPROVAL_TIMEOUT
    if (
        isinstance(mfa.web_approval_timeout, bool)
        or not isinstance(mfa.web_approval_timeout, int)
        or not lo <= mfa.web_approval_timeout <= hi
    ):
        raise ConfigError(f"[mfa] web_approval_timeout must be whole seconds in {lo}..{hi}")
    if (
        isinstance(mfa.web_approval_max_auth_age, bool)
        or not isinstance(mfa.web_approval_max_auth_age, int)
        or not 0 <= mfa.web_approval_max_auth_age <= MAX_WEB_APPROVAL_AUTH_AGE
    ):
        raise ConfigError(
            f"[mfa] web_approval_max_auth_age must be whole seconds in 0..{MAX_WEB_APPROVAL_AUTH_AGE}")
    if not isinstance(mfa.web_approval_single_pending, bool):
        raise ConfigError("[mfa] web_approval_single_pending must be true or false")
    for key, (lo, hi) in (("code_attempts", CODE_ATTEMPTS), ("code_user_failures", CODE_USER_FAILURES),
                          ("code_failure_window", CODE_FAILURE_WINDOW)):
        value = getattr(mfa, key)
        if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
            raise ConfigError(f"[mfa] {key} must be a whole number in {lo}..{hi}")
    if mfa.mode in KEYCLOAK_OTP_MODES:
        if not isinstance(kc.issuer, str) or not KEYCLOAK_ISSUER.fullmatch(kc.issuer.rstrip("/")):
            raise ConfigError(f"[mfa.keycloak] issuer must be https://<host>/realms/<realm> (http on loopback) for "
                              f"[mfa] mode = {mfa.mode!r}")
        kc.issuer = kc.issuer.rstrip("/")
        if not kc.client_id or not isinstance(kc.client_id, str):
            raise ConfigError(f"[mfa.keycloak] client_id is required for [mfa] mode = {mfa.mode!r}")
        if not kc.client_secret_file or not os.path.isabs(str(kc.client_secret_file)):
            raise ConfigError("[mfa.keycloak] client_secret_file must be an absolute path")
        if isinstance(kc.timeout, bool) or not isinstance(kc.timeout, int) or not 1 <= kc.timeout <= 60:
            raise ConfigError("[mfa.keycloak] timeout must be whole seconds in 1..60")
        if not isinstance(kc.required_amr, str) or not AMR_VALUE.fullmatch(kc.required_amr):
            raise ConfigError("[mfa.keycloak] required_amr must be an amr value such as \"otp\" "
                              "(letters, digits, . _ -; at most 64)")

    network = _section(NetworkSection, dict(raw.pop("network", {})), "network")
    try:
        network.lan = conntype.parse_networks(network.lan_networks)
    except ValueError as exc:
        raise ConfigError(f"[network] lan_networks: {exc}") from None
    if network.xrdp_autodetect_profile not in conntype.PROFILES:
        raise ConfigError(f"[network] xrdp_autodetect_profile must be one of {conntype.PROFILES}")

    ui = parse_ui(dict(raw.pop("ui", {})))

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
        "xrdp": {"port": 3390, "security": "tls", "listener_user": "root",
                 "certificate": "/etc/xrdp/cert.pem"},
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
        if b.certificate and not os.path.isabs(b.certificate):
            raise ConfigError(f"[backends.{name}] certificate must be an absolute path")
        if name == "xrdp" and not b.certificate:
            raise ConfigError("[backends.xrdp] certificate is required (the certificate in xrdp.ini)")
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
        ui=ui,
        desktops=desktops,
        backends=backends,
        default_desktop=default_desktop,
        default_geometry=default_geometry,
        group_defaults=group_defaults,
    )
