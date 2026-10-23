# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline checks of the Keycloak sample docs/examples/keycloak-fastrdp-web-client.json
against what the webgate needs (broker/webgate/config/webgate.toml.example, oidc.py) and
what the passkey automation writes (fastrdp_keycloak_passkeys.py), so the sample cannot
drift. tests/keycloak/run.sh imports it into a real Keycloak. The code check's sample
client (keycloak-fastrdp-otp-check-client.json, [mfa] mode code_or_web) must pass the
automation's client checks."""

import importlib.util
import json
import re
import sys
import tomllib
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "docs/examples/keycloak-fastrdp-web-client.json"
WEBGATE_TOML = ROOT / "broker/webgate/config/webgate.toml.example"
SCRIPT = ROOT / "ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py"
ROLE_DEFAULTS = ROOT / "ansible/roles/web_gateway/defaults/main.yml"

sys.path.insert(0, str(ROOT / "broker/webgate"))
from fastrdp_webgate.config import OidcSection  # noqa: E402
from fastrdp_webgate.oidc import Provider  # noqa: E402

spec = importlib.util.spec_from_file_location("fastrdp_keycloak_passkeys", SCRIPT)
kp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp)

CLIENT = json.loads(SAMPLE.read_text())
GATE = tomllib.loads(WEBGATE_TOML.read_text())
BASE = GATE["webgate"]["public_url"].rstrip("/") + GATE["webgate"]["path_prefix"]


class WebClientSample(unittest.TestCase):
    def test_client_id(self):
        defaults = ROLE_DEFAULTS.read_text()
        role_id = re.search(r"^fastrdp_web_oidc_client_id:\s*(\S+)", defaults, re.M).group(1)
        self.assertEqual(CLIENT["clientId"], GATE["oidc"]["client_id"])
        self.assertEqual(CLIENT["clientId"], role_id)
        self.assertEqual(CLIENT["protocol"], "openid-connect")

    def test_confidential_without_secret(self):
        self.assertIs(CLIENT["publicClient"], False)
        self.assertIs(CLIENT["bearerOnly"], False)
        self.assertEqual(CLIENT["clientAuthenticatorType"], "client-secret")
        self.assertNotIn("secret", CLIENT, "admins generate the secret; never ship one")

    def test_standard_flow_only(self):
        self.assertIs(CLIENT["standardFlowEnabled"], True)
        for key in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled",
                    "consentRequired"):
            self.assertIs(CLIENT[key], False, key)
        attrs = CLIENT["attributes"]
        for key in ("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled"):
            self.assertEqual(attrs[key], "false", key)

    def test_redirect_and_logout_uris(self):
        # the webgate's redirect_uri is public_url + path_prefix + "/callback" (app.py)
        self.assertIn('self.prefix + "/callback"', (ROOT / "broker/webgate/fastrdp_webgate/app.py").read_text())
        self.assertEqual(CLIENT["redirectUris"], [BASE + "/callback"])
        self.assertEqual(CLIENT["attributes"]["post.logout.redirect.uris"], BASE + "/")
        self.assertEqual(CLIENT["baseUrl"], BASE + "/")
        self.assertEqual(CLIENT["webOrigins"], [])
        hosts = {urllib.parse.urlsplit(u).netloc for u in re.findall(r"https?://[^\"\s]+", SAMPLE.read_text())}
        self.assertEqual(hosts, {urllib.parse.urlsplit(GATE["webgate"]["public_url"]).netloc},
                         "one placeholder host, the one of webgate.toml.example")

    def test_pkce_matches_webgate(self):
        p = Provider(OidcSection(issuer="https://kc.example.com/realms/x", client_id="fastrdp-web"), "s")
        p.meta = {"authorization_endpoint": "https://kc.example.com/auth"}
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(p.authorize_url(BASE + "/callback", "st", "n", "c")).query))
        self.assertEqual(CLIENT["attributes"]["pkce.code.challenge.method"], q["code_challenge_method"])
        self.assertEqual(q["code_challenge_method"], "S256")

    def test_acr_loa_map(self):
        loa_map = json.loads(CLIENT["attributes"]["acr.loa.map"])   # Keycloak stores it as a JSON string
        s = kp.settings({"admin_url": "https://kc.example.com", "realm": "r", "admin_client_secret": "x"})
        self.assertEqual(loa_map, {s["acr"]: s["loa"]})
        for acr in GATE["oidc"]["required_acr"]:
            self.assertIn(acr, loa_map)

    def test_scopes_carry_the_claims(self):
        default = set(CLIENT["defaultClientScopes"])
        # acr: the acr claim; basic: sub and auth_time (web approval); profile: preferred_username
        self.assertLessEqual({"acr", "basic", "profile"}, default)
        requested = set(GATE["oidc"]["scopes"].split()) - {"openid"}
        self.assertLessEqual(requested, default | set(CLIENT["optionalClientScopes"]))
        self.assertIs(CLIENT["fullScopeAllowed"], False)

    def test_no_logout_channels(self):
        # the webgate has no front- or back-channel logout endpoint
        self.assertIs(CLIENT["frontchannelLogout"], False)
        self.assertFalse([k for k in CLIENT["attributes"] if k.startswith(("backchannel.", "frontchannel."))])

    def test_shipped(self):
        examples = (ROOT / "debian/fastrdp-webgate.examples").read_text().split()
        self.assertIn(str(SAMPLE.relative_to(ROOT)), examples)



OTP_SAMPLE = ROOT / "docs/examples/keycloak-fastrdp-otp-check-client.json"
OTP_CLIENT = json.loads(OTP_SAMPLE.read_text())


class OtpCheckClientSample(unittest.TestCase):
    def test_passes_the_automation(self):
        for key, want in kp.OTP_CHECK_CLIENT.items():
            self.assertEqual(bool(OTP_CLIENT.get(key)), want, key)
        for key in kp.OTP_CHECK_ATTRIBUTES_OFF:
            self.assertNotEqual(OTP_CLIENT["attributes"].get(key), "true", key)
        self.assertNotIn("protocolMappers", OTP_CLIENT)

    def test_refresh_tokens_for_the_logout(self):
        # keycloak_otp.py ends the check's session with the refresh token
        self.assertEqual(OTP_CLIENT["attributes"]["use.refresh.tokens"], "true")
        self.assertNotIn("secret", OTP_CLIENT)

    def test_names_match_the_defaults(self):
        self.assertEqual(OTP_CLIENT["clientId"], "fastrdp-otp-check")
        self.assertIn('#client_id = "fastrdp-otp-check"',
                      (ROOT / "broker/brokerd/config/broker.toml.example").read_text())
        self.assertIn("fastrdp_mfa_keycloak_client_id: fastrdp-otp-check",
                      (ROOT / "ansible/roles/common/defaults/main.yml").read_text())

    def test_shipped(self):
        examples = (ROOT / "debian/fastrdp-broker.examples").read_text().split()
        self.assertIn(str(OTP_SAMPLE.relative_to(ROOT)), examples)


if __name__ == "__main__":
    unittest.main()
