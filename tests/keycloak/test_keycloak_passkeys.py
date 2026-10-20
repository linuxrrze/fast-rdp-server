# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py (no
Keycloak needed; run.sh tests it against a real one): settings validation, the
read-merge-write of client profiles/policies and the ACR map, the realm update keeping
other passwordless fields, check mode, and flow drift detection."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py"
spec = importlib.util.spec_from_file_location("fastrdp_keycloak_passkeys", SCRIPT)
kp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp)

BASE = {"admin_url": "https://kc.example.com", "realm": "lab", "admin_user": "admin", "admin_password": "pw"}


class FakeApi:
    """The endpoints the script uses, backed by dicts; records every write."""

    def __init__(self):
        self.realm = {"webAuthnPolicyPasswordlessRpEntityName": "Example", "webAuthnPolicyPasswordlessResidentKey": "required",
                      "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
                      "webAuthnPolicyPasswordlessSignatureAlgorithms": ["ES256"], "otpPolicyDigits": 6}
        self.required_actions = [{"alias": "webauthn-register-passwordless", "enabled": True}]
        self.flows = [{"alias": "browser", "builtIn": True}]
        self.executions: list[dict] = []
        self.configs: dict[str, dict] = {}
        self.profiles = {"profiles": [{"name": "other", "executors": []}]}
        self.policies = {"policies": [{"name": "other-policy", "enabled": False, "conditions": [], "profiles": ["other"]}]}
        self.client = {"id": "c1", "clientId": "fastrdp-web", "attributes": {"acr.loa.map": '{"gold":3}', "x": "y"}}
        self.writes: list[tuple[str, str, object]] = []

    def call(self, method, path, body=None):
        if method != "GET":
            self.writes.append((method, path, copy.deepcopy(body)))
        if path == "":
            if method == "PUT":
                self.realm.update(body)
            return copy.deepcopy(self.realm)
        if path == "/authentication/required-actions":
            return copy.deepcopy(self.required_actions)
        if path.startswith("/authentication/required-actions/") and method == "PUT":
            return None
        if path == "/authentication/flows":
            return copy.deepcopy(self.flows)
        if path.startswith("/authentication/flows/") and path.endswith("/executions"):
            return copy.deepcopy(self.executions)
        if path.startswith("/authentication/config/"):
            return {"config": self.configs[path.rsplit("/", 1)[1]]}
        if path == "/client-policies/profiles":
            if method == "PUT":
                self.profiles = body
            return copy.deepcopy(self.profiles)
        if path == "/client-policies/policies":
            if method == "PUT":
                self.policies = body
            return copy.deepcopy(self.policies)
        if path.startswith("/clients?clientId="):
            return [copy.deepcopy(self.client)] if path.endswith("fastrdp-web") else []
        if path == "/clients/c1" and method == "PUT":
            self.client = body
            return None
        raise AssertionError(f"unexpected {method} {path}")


def run(api, **over):
    s = kp.settings({**BASE, **over})
    r = kp.Run(api, s)
    r.realm()
    r.client_policies()
    r.client_acr_map()
    return r.changes


class Settings(unittest.TestCase):
    def test_defaults(self):
        s = kp.settings(dict(BASE))
        self.assertEqual((s["flow_alias"], s["acr"], s["loa"]), ("fastrdp-mfa", "mfa", 2))
        self.assertFalse(s["hardware_only"])

    def test_refused(self):
        cases = {
            "no credentials": {"admin_password": ""},
            "plain http": {"admin_url": "http://kc.example.com"},
            "hardware-only without AAGUIDs": {"hardware_only": True},
            "bad AAGUID": {"hardware_only": True, "aaguids": ["yubikey"]},
            "cookie as second factor": {"second_factors": ["auth-cookie"]},
            "password as second factor": {"second_factors": ["auth-password-form"]},
            "user-configured condition": {"second_factors": ["conditional-user-configured", "auth-otp-form"]},
            "no second factor": {"second_factors": []},
            "acr 1": {"acr": "1"},
            "bad mediation": {"mediation": "always"},
            "unknown key": {"flow": "x"},
            "loa 0": {"loa": 0},
            "bool as text": {"hardware_only": "maybe"},
        }
        for name, over in cases.items():
            with self.subTest(name), self.assertRaises(kp.KeycloakError):
                kp.settings({**BASE, **over})

    def test_ansible_strings_coerced(self):
        s = kp.settings({**BASE, "loa": "2", "check": "True", "hardware_only": "false"})
        self.assertEqual((s["loa"], s["check"], s["hardware_only"]), (2, True, False))

    def test_loopback_http_and_client_secret(self):
        s = kp.settings({"admin_url": "http://localhost:8080/", "realm": "lab", "admin_client_secret": "s"})
        self.assertEqual(s["admin_url"], "http://localhost:8080")


class Merge(unittest.TestCase):
    def test_first_run_merges_and_second_is_idempotent(self):
        api = FakeApi()
        changes = run(api)
        self.assertEqual(len(changes), 4, changes)
        self.assertEqual([p["name"] for p in api.profiles["profiles"]], ["other", "fastrdp-mfa-flow"])
        self.assertEqual([p["name"] for p in api.policies["policies"]], ["other-policy", "fastrdp-mfa"])
        self.assertEqual(api.policies["policies"][1]["conditions"],
                         [{"condition": "acr-condition", "configuration": {"acr-property": "mfa"}}])
        self.assertEqual(api.profiles["profiles"][1]["executors"][0]["configuration"],
                         {"auth-flow-alias": "fastrdp-mfa", "auth-flow-loa": 2})
        self.assertEqual(json.loads(api.client["attributes"]["acr.loa.map"]), {"gold": 3, "mfa": 2})
        self.assertEqual(api.client["attributes"]["x"], "y")
        self.assertEqual(api.realm["webAuthnPolicyPasswordlessPasskeysEnabled"], True)
        self.assertEqual(api.realm["webAuthnPolicyPasswordlessAttestationConveyancePreference"], "none")
        # Keycloak rebuilds the passwordless policy from the representation: the PUT
        # carries the unmanaged passwordless fields too, and nothing outside them
        realm_put = next(b for m, p, b in api.writes if p == "")
        self.assertEqual(realm_put["webAuthnPolicyPasswordlessRpEntityName"], "Example")
        self.assertEqual(realm_put["webAuthnPolicyPasswordlessSignatureAlgorithms"], ["ES256"])
        self.assertNotIn("otpPolicyDigits", realm_put)
        writes = len(api.writes)
        self.assertEqual(run(api), [])
        self.assertEqual(len(api.writes), writes)

    def test_check_mode_writes_nothing(self):
        api = FakeApi()
        changes = run(api, check=True)
        self.assertEqual(len(changes), 4)
        self.assertEqual(api.writes, [])

    def test_changed_profile_is_replaced_in_place(self):
        api = FakeApi()
        run(api)
        api.profiles["profiles"][1]["executors"][0]["configuration"]["auth-flow-alias"] = "browser"
        api.profiles["profiles"].append({"name": "later", "executors": []})
        changes = run(api)
        self.assertEqual(changes, ["update client profile fastrdp-mfa-flow (keeping 2 other)"])
        self.assertEqual([p["name"] for p in api.profiles["profiles"]], ["other", "fastrdp-mfa-flow", "later"])
        self.assertEqual(api.profiles["profiles"][1]["executors"][0]["configuration"]["auth-flow-alias"], "fastrdp-mfa")

    def test_hardware_only(self):
        api = FakeApi()
        run(api, hardware_only=True, aaguids=["CB69481E-8FF7-4039-93EC-0A2729A154A8"])
        self.assertEqual(api.realm["webAuthnPolicyPasswordlessAttestationConveyancePreference"], "direct")
        self.assertEqual(api.realm["webAuthnPolicyPasswordlessAcceptableAaguids"],
                         ["cb69481e-8ff7-4039-93ec-0a2729a154a8"])
        changes = run(api)   # switched off again: back to "none" and no allow-list
        self.assertIn("AttestationConveyancePreference", changes[0])
        self.assertEqual(api.realm["webAuthnPolicyPasswordlessAcceptableAaguids"], [])

    def test_missing_client(self):
        api = FakeApi()
        api.client["clientId"] = "other"
        with self.assertRaisesRegex(kp.KeycloakError, "not found"):
            kp.Run(api, kp.settings({**BASE, "client_id": "nope"})).client_acr_map()

    def test_disabled_required_action_enabled(self):
        api = FakeApi()
        api.required_actions[0]["enabled"] = False
        kp.Run(api, kp.settings(dict(BASE))).realm()
        self.assertTrue(any(p.endswith("webauthn-register-passwordless") and b["enabled"] for _, p, b in api.writes))


class Flow(unittest.TestCase):
    def executions(self, rows):
        out = []
        for i, (level, kind, name, req, cfg) in enumerate(rows):
            e = {"id": f"e{i}", "level": level, "requirement": req}
            if kind == "flow":
                e.update(authenticationFlow=True, displayName=name)
            else:
                e.update(providerId=name, displayName=name)
            if cfg:
                e["authenticationConfig"] = f"c{i}"
            out.append(e)
        return out

    def test_builtin_alias_refused(self):
        api = FakeApi()
        with self.assertRaisesRegex(kp.KeycloakError, "built-in"):
            kp.Run(api, kp.settings({**BASE, "flow_alias": "browser"})).flow()

    def test_matching_flow_untouched(self):
        api = FakeApi()
        s = kp.settings(dict(BASE))
        api.flows.append({"alias": "fastrdp-mfa", "builtIn": False})
        rows = kp.flow_wanted(s)
        api.executions = self.executions(rows)
        api.configs = {f"c{i}": r[4] for i, r in enumerate(rows) if r[4]}
        r = kp.Run(api, s)
        r.flow()
        self.assertEqual(r.changes, [])

    def test_cookie_step_detected(self):
        api = FakeApi()
        s = kp.settings({**BASE, "check": True})
        api.flows.append({"alias": "fastrdp-mfa", "builtIn": False})
        rows = [(0, "exec", "auth-cookie", "ALTERNATIVE", None)] + kp.flow_wanted(s)
        api.executions = self.executions(rows)
        api.configs = {f"c{i}": r[4] for i, r in enumerate(rows) if r[4]}
        r = kp.Run(api, s)
        r.flow()
        self.assertEqual(r.changes, ["rebuild flow fastrdp-mfa (removes auth-cookie)"])
        self.assertEqual(api.writes, [])

    def test_wanted_flow_shape(self):
        rows = kp.flow_wanted(kp.settings({**BASE, "second_factors": ["auth-otp-form", "privacyidea-authenticator"]}))
        providers = [r[2] for r in rows if r[1] == "exec"]
        self.assertNotIn("auth-cookie", providers)
        self.assertEqual(providers[:2], ["auth-username-form", "auth-password-form"])
        self.assertIn((1, "exec", "conditional-credential", "REQUIRED",
                       {"credentials": "webauthn-passwordless", "included": "false"}), rows)
        self.assertEqual([r[2] for r in rows if r[0] == 2], ["auth-otp-form", "privacyidea-authenticator"])


if __name__ == "__main__":
    unittest.main()
