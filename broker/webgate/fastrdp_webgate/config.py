# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Configuration (/etc/fastrdp/webgate.toml)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("/etc/fastrdp/webgate.toml")


class ConfigError(Exception):
    pass


@dataclass
class WebgateSection:
    listen: str = "127.0.0.1:8090"
    public_url: str = ""            # https://rdp.example.com (browser-facing origin)
    path_prefix: str = "/web"
    cookie_secret_file: str = "/etc/fastrdp/webgate-cookie.secret"
    session_lifetime: int = 900
    broker_socket: str = "/run/fastrdp/broker.sock"
    desktops: list[str] = field(default_factory=list)  # offered in the chooser; broker enforces access


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


@dataclass
class Config:
    webgate: WebgateSection
    oidc: OidcSection
    guacamole: GuacamoleSection


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
    cfg.oidc.strip_domains = [d.lower() for d in cfg.oidc.strip_domains]
    cfg.webgate.path_prefix = "/" + cfg.webgate.path_prefix.strip("/")
    cfg.guacamole.rdp_parameters = {str(k): str(v) for k, v in cfg.guacamole.rdp_parameters.items()}
    return cfg


def load(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    with open(path, "rb") as fh:
        return parse(tomllib.load(fh))


def read_secret(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        value = fh.read().strip()
    if not value:
        raise ConfigError(f"{path} is empty")
    return value
