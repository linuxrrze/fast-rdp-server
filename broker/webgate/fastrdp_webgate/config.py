# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Configuration (/etc/fastrdp/webgate.toml)."""

from __future__ import annotations

import re
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/fastrdp/webgate.toml")
DNS_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*")


class ConfigError(Exception):
    pass


# RFC 8176 "amr" values that never prove a second factor on their own. required_amr_any
# accepts a token if *any* listed value is present, so listing one of these would let a
# password-only (or presence-only) login through. Passkeys: use "mfa", "hwk" or "swk"
# (see docs/passkeys.md), never "user" or "pin" alone.
SINGLE_FACTOR_AMR = frozenset({"pwd", "kba", "pin", "user", "wia", "rba", "geo"})
# OpenID Connect Core 2: acr "0" does not meet ISO/IEC 29115 level 1.
NO_ASSURANCE_ACR = frozenset({"0"})


@dataclass
class WebgateSection:
    listen: str = "127.0.0.1:8090"
    public_url: str = ""            # https://rdp.example.com (browser-facing origin)
    path_prefix: str = "/web"
    cookie_secret_file: str = "/etc/fastrdp/webgate-cookie.secret"
    session_lifetime: int = 900
    broker_socket: str = "/run/fastrdp/broker.sock"
    desktops: list[str] = field(default_factory=list)  # offered in the chooser; broker enforces access
    # The fastrdp proxy as RDP clients reach it, for the chooser's .rdp downloads (mstsc):
    # a DNS name (never an IP address: Windows then uses NTLM, which is refused).
    # "" = the host name of public_url.
    rdp_host: str = ""
    rdp_port: int = 3389
    # What the server offers (Ansible fastrdp_audio, fastrdp_audio_input), for the .rdp
    # downloads: audiomode:i:0 (play on this computer) or 2 (no sound), and
    # audiocapturemode:i:1 (microphone) only with rdp_audio_input (docs/audio.md).
    rdp_audio: bool = True
    rdp_audio_input: bool = True


@dataclass
class OidcSection:
    issuer: str = ""
    client_id: str = ""
    client_secret_file: str = ""
    scopes: str = "openid profile"
    username_claim: str = "preferred_username"
    # "user@domain" claims are accepted only for these domains (suffix removed); a claim
    # with any other domain is refused, so alice@gmail.com never becomes "alice".
    strip_domains: list[str] = field(default_factory=list)
    # MFA proof from the IdP: all required_acr values are alternatives (one must match);
    # required_amr_any: at least one of these methods must appear in the "amr" claim.
    required_acr: list[str] = field(default_factory=list)
    required_amr_any: list[str] = field(default_factory=list)
    ca_file: str = ""
    timeout: int = 10
    # The broker skips its own MFA for web logins, so the IdP must prove MFA. Only set
    # this if the IdP enforces MFA for this client in a way acr/amr cannot express.
    allow_without_mfa_proof: bool = False


@dataclass
class GuacamoleSection:
    url: str = "/guacamole/"         # browser-facing Guacamole URL
    json_secret_key_file: str = "/etc/fastrdp/guacamole-json.key"
    connection_host: str = "127.0.0.1"  # the fastrdp proxy as seen by guacd
    connection_port: int = 3389
    data_ttl: int = 30               # seconds the encrypted blob is accepted
    # "sha256:aa:bb:..." of the proxy's TLS certificate; guacd pins it instead of ignoring it.
    cert_fingerprint_file: str = ""
    rdp_parameters: dict[str, str] = field(default_factory=dict)


NOTIFY_BACKENDS = ("ntfy", "webpush")
# Push services of the browsers (subscription endpoints): Chrome/Edge on Android, Chrome,
# Opera, Samsung (FCM), Firefox (Mozilla autopush), Safari/iOS (Apple), Edge on Windows (WNS).
# The webgate POSTs to an endpoint the browser chose, so only these hosts and their
# subdomains are accepted; never internal addresses.
DEFAULT_PUSH_HOSTS = ["fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com",
                      "notify.windows.com"]
RATE_LIMIT = re.compile(r"([0-9]{1,3})/([0-9]{1,5})")


@dataclass
class NotifySection:
    """Approval notifications (docs/notifications.md): a hint on the user's phone when an
    RDP login waits for web approval, linking to <public_url><path_prefix>/approve."""
    backends: list[str] = field(default_factory=list)   # [] (off), "ntfy", "webpush"
    # Subscriptions: <state_dir>/notify/<account>.json (systemd StateDirectory)
    state_dir: str = "/var/lib/fastrdp-webgate"
    ntfy_url: str = ""               # https://ntfy.example.com (the server; topics per user)
    ntfy_token_file: str = ""        # access token with write access to the topics ("" = none)
    vapid_private_key_file: str = ""  # PEM, EC P-256 (openssl ecparam -name prime256v1 -genkey)
    vapid_subject: str = ""          # mailto:admin@example.com or https://... (RFC 8292)
    webpush_allowed_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_PUSH_HOSTS))
    # At most N notifications per user within the given seconds; above that one alert
    # without a link per window.
    rate_limit: str = "3/600"
    alert_on_deny: bool = True       # tell the user when a notified login is denied or times out
    show_code: bool = True           # the login's correlation code in the notification

    def rate(self) -> tuple[int, int]:
        m = RATE_LIMIT.fullmatch(self.rate_limit)
        assert m is not None  # parse() checked it
        return int(m.group(1)), int(m.group(2))


@dataclass
class Config:
    webgate: WebgateSection
    oidc: OidcSection
    guacamole: GuacamoleSection
    notify: NotifySection = field(default_factory=NotifySection)


def _section(cls, data: dict, where: str):
    unknown = set(data) - set(cls.__dataclass_fields__)
    if unknown:
        raise ConfigError(f"[{where}]: unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def parse(raw: dict) -> Config:
    raw = dict(raw)
    cfg = Config(
        webgate=_section(WebgateSection, raw.pop("webgate", {}), "webgate"),
        oidc=_section(OidcSection, raw.pop("oidc", {}), "oidc"),
        guacamole=_section(GuacamoleSection, raw.pop("guacamole", {}), "guacamole"),
        notify=_section(NotifySection, raw.pop("notify", {}), "notify"),
    )
    if raw:
        raise ConfigError(f"unknown sections: {', '.join(raw)}")
    for name, value in (("webgate.public_url", cfg.webgate.public_url),
                        ("oidc.issuer", cfg.oidc.issuer), ("oidc.client_id", cfg.oidc.client_id)):
        if not value:
            raise ConfigError(f"{name} is required")
    if not cfg.webgate.public_url.startswith("https://") and "localhost" not in cfg.webgate.public_url \
            and "127.0.0.1" not in cfg.webgate.public_url:
        raise ConfigError("webgate.public_url must be https://")
    if not (cfg.oidc.required_acr or cfg.oidc.required_amr_any or cfg.oidc.allow_without_mfa_proof):
        raise ConfigError("set oidc.required_acr or oidc.required_amr_any: web logins skip the "
                          "broker's MFA, so the IdP must prove it (or set allow_without_mfa_proof)")
    weak_amr = sorted(set(map(str, cfg.oidc.required_amr_any)) & SINGLE_FACTOR_AMR)
    if weak_amr:
        raise ConfigError(f"oidc.required_amr_any: {', '.join(weak_amr)} alone does not prove MFA "
                          "(any listed value is accepted); use e.g. otp, hwk, swk, mfa")
    weak_acr = sorted(set(map(str, cfg.oidc.required_acr)) & NO_ASSURANCE_ACR)
    if weak_acr:
        raise ConfigError(f"oidc.required_acr: {', '.join(weak_acr)} means no assurance")
    cfg.oidc.strip_domains = [d.lower() for d in cfg.oidc.strip_domains]
    cfg.webgate.path_prefix = "/" + cfg.webgate.path_prefix.strip("/")
    host = cfg.webgate.rdp_host
    if not isinstance(host, str) or (host and (not DNS_NAME.fullmatch(host)
                                               or host.replace(".", "").isdigit())):
        raise ConfigError("webgate.rdp_host must be the DNS name RDP clients connect to (no IP address)")
    if not host:
        # a lab's https://127.0.0.1 too; the name ends up in .rdp files, so no other characters
        cfg.webgate.rdp_host = urllib.parse.urlsplit(cfg.webgate.public_url).hostname or ""
        if not DNS_NAME.fullmatch(cfg.webgate.rdp_host):
            raise ConfigError("set webgate.rdp_host: public_url has no usable host name")
    port = cfg.webgate.rdp_port
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("webgate.rdp_port must be a port number 1..65535")
    for key in ("rdp_audio", "rdp_audio_input"):
        if not isinstance(getattr(cfg.webgate, key), bool):
            raise ConfigError(f"webgate.{key} must be true or false")
    cfg.guacamole.rdp_parameters = {str(k): str(v) for k, v in cfg.guacamole.rdp_parameters.items()}
    _check_notify(cfg)
    return cfg


def _local_http(url: str) -> bool:
    """http:// only to this host (tests, a lab without TLS); like public_url."""
    return urllib.parse.urlsplit(url).hostname in ("localhost", "127.0.0.1", "::1")


def _check_notify(cfg: Config) -> None:
    n = cfg.notify
    if not isinstance(n.backends, list) or any(b not in NOTIFY_BACKENDS for b in n.backends) \
            or len(set(n.backends)) != len(n.backends):
        raise ConfigError(f"notify.backends must be a list of {', '.join(NOTIFY_BACKENDS)} (each once)")
    for key in ("alert_on_deny", "show_code"):
        if not isinstance(getattr(n, key), bool):
            raise ConfigError(f"notify.{key} must be true or false")
    m = RATE_LIMIT.fullmatch(n.rate_limit) if isinstance(n.rate_limit, str) else None
    if not m or not 1 <= int(m.group(1)) <= 100 or not 60 <= int(m.group(2)) <= 86400:
        raise ConfigError('notify.rate_limit must be "N/SECONDS": 1..100 notifications per '
                          '60..86400 seconds, e.g. "3/600"')
    if not n.backends:
        return
    if not n.state_dir.startswith("/"):
        raise ConfigError("notify.state_dir must be an absolute path")
    if "ntfy" in n.backends:
        url = n.ntfy_url.rstrip("/")
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname or parts.query or parts.fragment or not (
                parts.scheme == "https" or (parts.scheme == "http" and _local_http(url))):
            raise ConfigError("notify.ntfy_url must be the ntfy server's https:// URL")
        n.ntfy_url = url
    if "webpush" in n.backends:
        if not n.vapid_private_key_file:
            raise ConfigError("notify.vapid_private_key_file is required for webpush")
        if not re.fullmatch(r"(mailto:[^\s@]+@[^\s@]+|https://\S+)", n.vapid_subject or ""):
            raise ConfigError("notify.vapid_subject must be mailto:<address> or an https:// URL (RFC 8292)")
        if not cfg.webgate.public_url.startswith("https://") and not _local_http(cfg.webgate.public_url):
            raise ConfigError("webpush needs an https:// webgate.public_url (service workers)")
        hosts = n.webpush_allowed_hosts
        if not isinstance(hosts, list) or not hosts or not all(
                isinstance(h, str) and DNS_NAME.fullmatch(h) and "." in h and not h.replace(".", "").isdigit()
                for h in hosts):
            raise ConfigError("notify.webpush_allowed_hosts must be a list of DNS names (push services)")
        n.webpush_allowed_hosts = [h.lower() for h in hosts]


def load(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    with open(path, "rb") as fh:
        return parse(tomllib.load(fh))


def read_secret(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        value = fh.read().strip()
    if not value:
        raise ConfigError(f"{path} is empty")
    return value
