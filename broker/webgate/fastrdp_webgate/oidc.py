# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Minimal OIDC relying party: authorization code flow with PKCE, confidential client.

The ID token is taken from the token endpoint response over TLS (server certificate
verified), which OpenID Connect Core 3.1.3.7 (6) allows in place of verifying the JWS
signature. All other ID token checks (iss, aud, azp, exp, iat, nonce) are performed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import OidcSection

CLOCK_SKEW = 60


class OidcError(Exception):
    pass


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class Provider:
    def __init__(self, cfg: OidcSection, client_secret: str):
        self.cfg = cfg
        self.client_secret = client_secret
        self.ssl = ssl.create_default_context(cafile=cfg.ca_file or None)
        self.meta: dict = {}

    def _open(self, req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout, context=self.ssl) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            body = exc.read(500).decode(errors="replace")
            raise OidcError(f"{req.full_url}: HTTP {exc.code} {body}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise OidcError(f"{req.full_url}: {exc}") from None

    def discover(self) -> None:
        url = self.cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
        meta = self._open(urllib.request.Request(url))
        if meta.get("issuer") != self.cfg.issuer:
            raise OidcError(f"discovery issuer {meta.get('issuer')!r} != configured {self.cfg.issuer!r}")
        for key in ("authorization_endpoint", "token_endpoint"):
            if not meta.get(key, "").startswith(("https://", "http://127.0.0.1", "http://localhost")):
                raise OidcError(f"discovery: bad {key}")
        self.meta = meta

    def authorize_url(self, redirect_uri: str, state: str, nonce: str, challenge: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self.cfg.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.cfg.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self.cfg.required_acr:
            params["acr_values"] = " ".join(self.cfg.required_acr)  # ask the IdP for step-up
        return self.meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)

    def logout_url(self, post_logout_redirect_uri: str) -> str | None:
        end = self.meta.get("end_session_endpoint")
        if not end:
            return None
        return end + "?" + urllib.parse.urlencode(
            {"client_id": self.cfg.client_id, "post_logout_redirect_uri": post_logout_redirect_uri})

    def exchange(self, code: str, redirect_uri: str, verifier: str) -> dict:
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.cfg.client_id,
            "client_secret": self.client_secret,
            "code_verifier": verifier,
        }).encode()
        req = urllib.request.Request(self.meta["token_endpoint"], data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Accept", "application/json")
        return self._open(req)

    def id_token_claims(self, token_response: dict, nonce: str, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        raw = token_response.get("id_token")
        if not isinstance(raw, str) or raw.count(".") != 2:
            raise OidcError("token response without a JWT id_token")
        try:
            claims = json.loads(b64url_decode(raw.split(".")[1]))
        except ValueError:
            raise OidcError("undecodable id_token") from None
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if claims.get("iss") != self.cfg.issuer:
            raise OidcError("id_token issuer mismatch")
        if self.cfg.client_id not in auds:
            raise OidcError("id_token audience mismatch")
        if len(auds) > 1 and claims.get("azp") != self.cfg.client_id:
            raise OidcError("id_token azp mismatch")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - CLOCK_SKEW:
            raise OidcError("id_token expired")
        if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + CLOCK_SKEW:
            raise OidcError("id_token issued in the future")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("id_token nonce mismatch")
        return claims

    def check_mfa(self, claims: dict) -> None:
        if self.cfg.required_acr and claims.get("acr") not in self.cfg.required_acr:
            raise OidcError(f"acr {claims.get('acr')!r} does not prove MFA")
        if self.cfg.required_amr_any:
            amr = claims.get("amr")
            if not isinstance(amr, list) or not set(map(str, amr)) & set(self.cfg.required_amr_any):
                raise OidcError(f"amr {amr!r} does not prove MFA")
