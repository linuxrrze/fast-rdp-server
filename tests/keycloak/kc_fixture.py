# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Test fixture for tests/keycloak/run.sh: a throwaway realm in a dev-mode Keycloak.

Creates realm REALM with
  - client fastrdp-web from docs/examples/keycloak-fastrdp-web-client.json (host replaced
    by the test webgate, a known secret, the probe's redirect URI) with another
    acr.loa.map entry instead of mfa -> 2, and an unrelated client profile/policy, so the
    run can prove that the role adds mfa and merges instead of replacing;
  - alice: password + TOTP (secret below), required action to register a passkey;
  - carol: password only;
  - a non-default passwordless RP entity name, which the role must keep.
check-sample imports the sample client unchanged into a realm of its own and compares
what Keycloak stores with the file (no field dropped or rewritten).
Standard library only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SAMPLE = Path(__file__).resolve().parents[2] / "docs" / "examples" / "keycloak-fastrdp-web-client.json"
SAMPLE_URL = "https://rdp1.lab.example.com"   # the sample's webgate public_url
SAMPLE_REALM = "fastrdp-sample"
REALM = "fastrdp-test"
CLIENT_ID = "fastrdp-web"
CLIENT_SECRET = "webgate-test-secret"
TOTP_SECRET = "fastrdp-totp-test-secret"   # raw HMAC key as Keycloak stores it
USERS = {"alice": "alice-Passw0rd!", "carol": "carol-Passw0rd!"}
OTHER_PROFILE = "unrelated-profile"
OTHER_POLICY = "unrelated-policy"


def totp(secret: str = TOTP_SECRET, at: float | None = None, step: int = 30) -> str:
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


class Admin:
    def __init__(self, base: str, user: str, password: str):
        self.base = base.rstrip("/")
        form = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                       "username": user, "password": password}).encode()
        with urllib.request.urlopen(f"{self.base}/realms/master/protocol/openid-connect/token", form) as r:
            self.token = json.load(r)["access_token"]

    def call(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.base + "/admin" + path, method=method,
                                     data=None if body is None else json.dumps(body).encode())
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"{method} {path}: HTTP {exc.code} {exc.read(300).decode(errors='replace')}")
        return json.loads(raw) if raw else None


def sample_client(webgate_url: str = SAMPLE_URL) -> dict:
    """The sample client with its host replaced by webgate_url (scheme://host[:port])."""
    raw = SAMPLE.read_text()
    if SAMPLE_URL not in raw:
        raise SystemExit(f"{SAMPLE}: {SAMPLE_URL} not found")
    return json.loads(raw.replace(SAMPLE_URL, webgate_url.rstrip("/")))


def sample_mismatches(want: dict, got: dict) -> list[str]:
    """Fields of the sample that Keycloak did not store as given (lists as sets)."""
    out = []
    for key, value in want.items():
        if key == "attributes":
            attrs = got.get("attributes") or {}
            out += [f"attributes.{k}: {attrs.get(k)!r} != {v!r}" for k, v in value.items() if attrs.get(k) != v]
        elif isinstance(value, list):
            if sorted(got.get(key) or []) != sorted(value):
                out.append(f"{key}: {got.get(key)!r} != {value!r}")
        elif got.get(key) != value:
            out.append(f"{key}: {got.get(key)!r} != {value!r}")
    return out


def check_sample(base: str, admin_user: str, admin_password: str) -> int:
    a = Admin(base, admin_user, admin_password)
    if any(r["realm"] == SAMPLE_REALM for r in a.call("GET", "/realms")):
        a.call("DELETE", f"/realms/{SAMPLE_REALM}")
    a.call("POST", "/realms", {"realm": SAMPLE_REALM, "enabled": True})
    try:
        want = sample_client()
        a.call("POST", f"/realms/{SAMPLE_REALM}/clients", want)
        got = a.call("GET", f"/realms/{SAMPLE_REALM}/clients?clientId={want['clientId']}")[0]
        bad = sample_mismatches(want, got)
        if not got.get("secret"):
            bad.append("no client secret generated")
    finally:
        a.call("DELETE", f"/realms/{SAMPLE_REALM}")
    for line in bad:
        print(line, file=sys.stderr)
    return 1 if bad else 0


def setup(base: str, webgate_url: str, probe_url: str, admin_user: str, admin_password: str) -> None:
    a = Admin(base, admin_user, admin_password)
    if any(r["realm"] == REALM for r in a.call("GET", "/realms")):
        a.call("DELETE", f"/realms/{REALM}")
    a.call("POST", "/realms", {"realm": REALM, "enabled": True})
    a.call("PUT", f"/realms/{REALM}", {
        # several logins within one TOTP period (Keycloak applies the OTP policy only as a whole)
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyInitialCounter": 0,
        "otpPolicyCodeReusable": True,
        "webAuthnPolicyPasswordlessRpEntityName": "fastrdp test",
        "bruteForceProtected": False,
    })
    client = sample_client(webgate_url)
    client["secret"] = CLIENT_SECRET
    client["redirectUris"].append(probe_url)   # a probe relying party without acr_values (e2e.py)
    client["attributes"]["acr.loa.map"] = json.dumps({"other": 5})   # the role adds mfa -> 2
    a.call("POST", f"/realms/{REALM}/clients", client)
    a.call("PUT", f"/realms/{REALM}/client-policies/profiles", {"profiles": [{
        "name": OTHER_PROFILE, "description": "must survive",
        "executors": [{"executor": "pkce-enforcer", "configuration": {"auto-configure": "false"}}]}]})
    a.call("PUT", f"/realms/{REALM}/client-policies/policies", {"policies": [{
        "name": OTHER_POLICY, "description": "must survive", "enabled": False,
        "conditions": [{"condition": "client-access-type", "configuration": {"type": ["public"]}}],
        "profiles": [OTHER_PROFILE]}]})
    for name, pw in USERS.items():
        creds = [{"type": "password", "value": pw, "temporary": False}]
        actions = []
        if name == "alice":
            creds.append({
                "type": "otp", "userLabel": "test TOTP",
                "secretData": json.dumps({"value": TOTP_SECRET}),
                "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0,
                                              "period": 30, "algorithm": "HmacSHA1"}),
            })
            actions = ["webauthn-register-passwordless"]
        a.call("POST", f"/realms/{REALM}/users", {
            "username": name, "enabled": True, "email": f"{name}@example.test", "emailVerified": True,
            "firstName": name.title(), "lastName": "Test", "credentials": creds,
            "requiredActions": actions,
        })


def state(base: str, admin_user: str, admin_password: str) -> dict:
    """What run.sh checks after the role: merged lists, kept settings."""
    a = Admin(base, admin_user, admin_password)
    realm = a.call("GET", f"/realms/{REALM}")
    client = a.call("GET", f"/realms/{REALM}/clients?clientId={CLIENT_ID}")[0]
    return {
        "profiles": [p["name"] for p in a.call("GET", f"/realms/{REALM}/client-policies/profiles")["profiles"]],
        "policies": [p["name"] for p in a.call("GET", f"/realms/{REALM}/client-policies/policies")["policies"]],
        "acr_loa_map": json.loads(client["attributes"].get("acr.loa.map", "{}")),
        "rp_entity_name": realm.get("webAuthnPolicyPasswordlessRpEntityName"),
        "passwordless": {k: v for k, v in realm.items() if k.startswith("webAuthnPolicyPasswordless")},
    }


def add_cookie_to_flow(base: str, admin_user: str, admin_password: str, flow: str) -> None:
    """Simulate a misconfiguration: an SSO Cookie step in the forced flow."""
    a = Admin(base, admin_user, admin_password)
    a.call("POST", f"/realms/{REALM}/authentication/flows/{urllib.parse.quote(flow)}/executions/execution",
           {"provider": "auth-cookie"})


def cookie_control_flow(a: Admin, profile: str = "fastrdp-mfa-flow") -> None:
    """Negative control for the SSO pitfall: flow "control-cookie" = Cookie OR (username,
    password, OTP), and point the role's client profile at it (the role restores it)."""
    base = f"/realms/{REALM}/authentication"
    if not any(f["alias"] == "control-cookie" for f in a.call("GET", f"{base}/flows")):
        a.call("POST", f"{base}/flows", {"alias": "control-cookie", "providerId": "basic-flow",
                                         "topLevel": True, "builtIn": False})
        a.call("POST", f"{base}/flows/control-cookie/executions/execution", {"provider": "auth-cookie"})
        a.call("POST", f"{base}/flows/control-cookie/executions/flow",
               {"alias": "control-forms", "type": "basic-flow", "provider": "registration-page-form"})
        for provider in ("auth-username-form", "auth-password-form", "auth-otp-form"):
            a.call("POST", f"{base}/flows/control-forms/executions/execution", {"provider": provider})
        for flow, req in (("control-cookie", "ALTERNATIVE"), ("control-forms", "REQUIRED")):
            for e in a.call("GET", f"{base}/flows/{flow}/executions"):
                if e["level"] == 0:
                    a.call("PUT", f"{base}/flows/{flow}/executions", {**e, "requirement": req})
    profiles = a.call("GET", f"/realms/{REALM}/client-policies/profiles")
    for p in profiles["profiles"]:
        if p["name"] == profile:
            p["executors"][0]["configuration"]["auth-flow-alias"] = "control-cookie"
    a.call("PUT", f"/realms/{REALM}/client-policies/profiles", profiles)


def main(argv: list[str]) -> int:
    cmd, base = argv[1], argv[2]
    if cmd == "setup":
        setup(base, argv[3], argv[4], argv[5], argv[6])
    elif cmd == "check-sample":
        return check_sample(base, argv[3], argv[4])
    elif cmd == "state":
        print(json.dumps(state(base, argv[3], argv[4])))
    elif cmd == "add-cookie":
        add_cookie_to_flow(base, argv[3], argv[4], argv[5])
    elif cmd == "totp":
        print(totp())
    else:
        print(f"unknown command {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
