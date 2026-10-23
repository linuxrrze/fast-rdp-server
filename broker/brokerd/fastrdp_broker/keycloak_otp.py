# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Checks a TOTP code at Keycloak ([mfa] mode code_or_web; blocking, call via
asyncio.to_thread).

Keycloak has no API that only verifies a code. The broker therefore signs the user in
through a direct grant of its own confidential client ([mfa.keycloak] client_id): the
client's direct grant flow has Username Validation and OTP only, no password (the RDP
login checked the first factor already). A token means the code was right; the broker
ends that Keycloak session at once (logout with the refresh token) and throws the tokens
away. Only the holder of the client secret can use this flow; other clients keep the
realm's flows. docs/auth-matrix.md#code-on-the-waiting-screen

Users without an OTP credential: the flow's second sub-flow (Condition - sub-flow
executed, OTP sub-flow not executed) ends in Deny access, configured with the error text
NO_OTP_ERROR. A token is accepted only if its amr claim names the OTP step
([mfa.keycloak] required_amr, the reference value of the flow's OTP execution): a flow
that lost its Deny or OTP step and lets a name alone through issues tokens without it.
fastrdp_keycloak_passkeys.py sets up both and compares the flow exactly on every run.

Answers [tested: Keycloak 26.8.1] and what check() makes of them:
  200 with "otp" in amr                     -> OK
  400 invalid_grant (wrong or missing code, unknown user, pending required action,
      user locked by brute-force detection) -> WRONG (counts as a wrong code)
  401 {"error": NO_OTP_ERROR} (Deny access; JSON only with "Accept: application/json",
      which _post sends: without it Keycloak answers with an HTML page)
                                            -> NO_OTP (no attempt; approval page only)
  anything else: 200 without that amr or with a token that is not ours, 401/400
      unauthorized_client / invalid_client (wrong secret or client), 500, unknown errors
                                            -> OFF (a setup error: no attempt, logged as
      an error, no code field for the rest of the login; never "try again", so a
      Keycloak that answers oddly to wrong codes cannot be used to guess without limit)
Only a broker that cannot reach Keycloak at all raises KeycloakError (the field stays,
no attempt). The code never appears in a log."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import KeycloakOtpSection

log = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
# Deny access's error text in the code check's flow (fastrdp_keycloak_passkeys.py); Keycloak
# returns it as {"error": ...} with HTTP 401 for a user without an OTP credential.
NO_OTP_ERROR = "fastrdp_no_otp"
OK, WRONG, NO_OTP, OFF = "ok", "wrong", "no_otp", "off"
CLOCK_SKEW = 60


def token_claims(token: object) -> dict | None:
    """The payload of a JWT, unverified (see KeycloakOtp.token_problem); None if malformed."""
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    part = token.split(".")[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


class KeycloakError(Exception):
    """Keycloak not reachable (network, TLS, timeout): the code was not checked."""


class KeycloakOtp:
    def __init__(self, cfg: KeycloakOtpSection, secret: str | None = None):
        self.cfg = cfg
        base = cfg.issuer.rstrip("/") + "/protocol/openid-connect"
        self.token_url = base + "/token"
        self.logout_url = base + "/logout"
        self.ssl = ssl.create_default_context(cafile=cfg.ca_file or None)
        self._secret = secret

    def secret(self) -> str:
        """Read on every check, so a rotated secret needs no restart."""
        if self._secret is not None:
            return self._secret
        with open(self.cfg.client_secret_file, encoding="utf-8") as fh:
            return fh.read().strip()

    def _post(self, url: str, params: dict) -> tuple[int, dict]:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode(), method="POST")
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout, context=self.ssl) as resp:
                status, raw = resp.status, resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            with exc:
                status, raw = exc.code, exc.read(MAX_BODY)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise KeycloakError(f"{url}: {getattr(exc, 'reason', exc)}") from None
        try:
            body = json.loads(raw) if raw else {}
        except (ValueError, UnicodeDecodeError):
            body = {}
        return status, body if isinstance(body, dict) else {}

    def check(self, user: str, code: str) -> str:
        """OK, WRONG, NO_OTP or OFF (module docstring) for `code` of `user`. Raises
        KeycloakError only if Keycloak could not be asked."""
        try:
            secret = self.secret()
        except OSError as exc:
            raise KeycloakError(f"client secret not readable: {exc}") from None
        status, body = self._post(self.token_url, {
            "grant_type": "password", "client_id": self.cfg.client_id, "client_secret": secret,
            "username": user, "totp": code, "scope": "openid"})
        error = body.get("error")
        what = body.get("error_description") or error or "no details"
        if status == 400 and error == "invalid_grant":
            log.info("Keycloak refused the code of %s: %s", user, what)
            return WRONG
        if status == 401 and error == NO_OTP_ERROR:
            log.info("Keycloak: %s has no OTP credential (no authenticator app set up)", user)
            return NO_OTP
        if status != 200:
            hint = ""
            if error in ("unauthorized_client", "invalid_client"):
                hint = " (wrong [mfa.keycloak] client secret or client_id?)"
            elif status >= 500:
                hint = " (Keycloak error; or the direct grant flow lost its Deny access step: check it)"
            log.error("Keycloak cannot check codes of %s: HTTP %d, %s%s; approval page only for this login",
                      user, status, what, hint)
            return OFF
        refresh = body.get("refresh_token")
        if isinstance(refresh, str) and refresh:
            self.end_session(user, secret, refresh)
        else:
            log.warning("Keycloak accepted the code check of %s but sent no refresh token: its session "
                        "stays until the realm's SSO idle timeout (refresh tokens off for %s?)",
                        user, self.cfg.client_id)
        problem = self.token_problem(body)
        if problem:
            log.error("Keycloak flow issued a token without %s: check the direct grant flow of %s "
                      "(fastrdp_keycloak_passkeys.py, check mode); code of %s not accepted, approval page only",
                      problem, self.cfg.client_id, user)
            return OFF
        return OK

    def token_problem(self, body: dict) -> str | None:
        """What is wrong with the token of a 200, or None. The ID token (else the access
        token) must name this issuer and client, be unexpired and carry required_amr in
        amr. The signature is not checked: the token comes straight from the token
        endpoint over TLS (verified unless http on loopback), in answer to this client's
        authenticated request (OpenID Connect Core 3.1.3.7)."""
        claims = token_claims(body.get("id_token"))
        if claims is not None:
            aud = claims.get("aud")
            if claims.get("typ") not in (None, "ID") or (
                    aud != self.cfg.client_id and not (isinstance(aud, list) and self.cfg.client_id in aud)):
                return "this client as audience"
        else:
            claims = token_claims(body.get("access_token"))
            if claims is None:
                return "a readable token"
        if claims.get("iss") != self.cfg.issuer.rstrip("/"):
            return f"issuer {self.cfg.issuer}"
        if claims.get("azp") not in (None, self.cfg.client_id):
            return "this client as azp"
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp < time.time() - CLOCK_SKEW:
            return "a valid expiry"
        amr = claims.get("amr")
        if not isinstance(amr, list) or self.cfg.required_amr not in amr:
            return f"{self.cfg.required_amr!r} in amr (got {amr!r})"
        return None

    def end_session(self, user: str, secret: str, refresh_token: str) -> None:
        """Ends the session the check created (no cookie, but listed in Keycloak)."""
        try:
            status, body = self._post(self.logout_url, {
                "client_id": self.cfg.client_id, "client_secret": secret, "refresh_token": refresh_token})
        except KeycloakError as exc:
            log.warning("Keycloak session of the code check for %s not ended: %s", user, exc)
            return
        if status not in (200, 204):
            log.warning("Keycloak session of the code check for %s not ended: HTTP %d, %s", user, status,
                        body.get("error_description") or body.get("error") or "no details")
