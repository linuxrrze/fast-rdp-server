# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Test fixture for tests/keycloak/run.sh: a throwaway realm in a dev-mode Keycloak.

Creates realm REALM with
  - client fastrdp-web (confidential, redirect to the test webgate) with an existing
    acr.loa.map entry and an unrelated client profile/policy, so the run can prove that
    the role merges instead of replacing them;
  - alice: password + TOTP (secret below), required action to register a passkey;
  - carol: password only;
  - a non-default passwordless RP entity name, which the role must keep.
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
    a.call("POST", f"/realms/{REALM}/clients", {
        "clientId": CLIENT_ID, "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "secret": CLIENT_SECRET, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        # the webgate, and a probe relying party without acr_values (tests/keycloak/e2e.py)
        "redirectUris": [webgate_url.rstrip("/") + "/web/callback", probe_url],
        "attributes": {"acr.loa.map": json.dumps({"other": 5}),
                       "post.logout.redirect.uris": webgate_url.rstrip("/") + "/web/"},
    })
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
