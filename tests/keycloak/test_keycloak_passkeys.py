# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py (no
Keycloak needed; run.sh tests it against a real one): settings validation, the
read-merge-write of client profiles/policies and the ACR map, the realm update keeping
other passwordless fields, check mode, flow drift detection, and the code check's direct
grant flow and client checks ([mfa] mode code_or_web)."""

import copy
import importlib.util
import json
import re
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py"
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


class OtpCheckApi:
    """The endpoints of the code check's part (Run.otp_check): flows and sub-flows with
    their executions and configs (listed flattened with levels, as Keycloak does), the
    client fastrdp-otp-check and its mappers, the realm."""

    def __init__(self):
        self.realm = {"otpPolicyCodeReusable": False, "bruteForceProtected": True}
        self.flows = [{"alias": "browser", "builtIn": True, "id": "f-browser"}]
        self.execs: dict[str, list[dict]] = {}    # flow alias -> its own steps (sub-flows: "sub")
        self.configs: dict[str, dict] = {}
        self.client = {"id": "o1", "clientId": "fastrdp-otp-check", "publicClient": False,
                       "directAccessGrantsEnabled": True, "standardFlowEnabled": False,
                       "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "fullScopeAllowed": False,
                       "bearerOnly": False, "attributes": {}, "authenticationFlowBindingOverrides": {}}
        self.mappers: list[dict] = []
        self.writes: list[tuple[str, str, object]] = []
        self.n = 0

    def flat(self, alias, level=0):
        out = []
        for e in self.execs[alias]:
            out.append({k: v for k, v in e.items() if k != "sub"} | {"level": level})
            if e.get("sub"):
                out += self.flat(e["sub"], level + 1)
        return out

    def find(self, eid):
        for alias, rows in self.execs.items():
            for e in rows:
                if e["id"] == eid:
                    return alias, e
        raise AssertionError(f"no execution {eid}")

    def call(self, method, path, body=None):
        if method != "GET":
            self.writes.append((method, path, copy.deepcopy(body)))
        if path == "":
            return copy.deepcopy(self.realm)
        if path.startswith("/clients?clientId="):
            return [copy.deepcopy(self.client)] if path.endswith("fastrdp-otp-check") else []
        if path == "/clients/o1/protocol-mappers/models":
            if method == "POST":
                self.n += 1
                self.mappers.append({**copy.deepcopy(body), "id": f"m{self.n}"})
                return None
            return copy.deepcopy(self.mappers)
        if path.startswith("/clients/o1/protocol-mappers/models/") and method == "PUT":
            self.mappers = [copy.deepcopy(body) if m["id"] == body["id"] else m for m in self.mappers]
            return None
        if path == "/clients/o1" and method == "PUT":
            self.client = body
            return None
        if path == "/authentication/flows":
            if method == "POST":
                self.flows.append({**body, "id": f"f-{body['alias']}"})
                self.execs[body["alias"]] = []
                return None
            return copy.deepcopy(self.flows)
        if path.startswith("/authentication/flows/") and "/executions" in path:
            alias = urllib.parse.unquote(path.split("/")[3])
            self.n += 1
            if path.endswith("/executions/execution"):
                self.execs[alias].append({"id": f"x{self.n}", "providerId": body["provider"],
                                          "displayName": body["provider"], "requirement": "DISABLED",
                                          "requirementChoices": ["REQUIRED", "ALTERNATIVE", "DISABLED"]})
                return None
            if path.endswith("/executions/flow"):
                self.execs[body["alias"]] = []
                self.execs[alias].append({"id": f"x{self.n}", "authenticationFlow": True, "sub": body["alias"],
                                          "displayName": body["alias"], "requirement": "DISABLED",
                                          "requirementChoices": ["REQUIRED", "CONDITIONAL", "DISABLED"]})
                return None
            if method == "PUT":
                self.find(body["id"])[1]["requirement"] = body["requirement"]
                return None
            return copy.deepcopy(self.flat(alias))
        if path.startswith("/authentication/executions/") and path.endswith("/config"):
            eid = path.split("/")[3]
            self.n += 1
            self.configs[f"c{self.n}"] = dict(body["config"])
            self.find(eid)[1]["authenticationConfig"] = f"c{self.n}"
            return None
        if path.startswith("/authentication/config/"):
            return {"config": copy.deepcopy(self.configs[path.rsplit("/", 1)[1]])}
        if path.startswith("/authentication/executions/") and method == "DELETE":
            alias, e = self.find(path.rsplit("/", 1)[1])
            self.execs[alias].remove(e)
            if e.get("sub"):
                del self.execs[e["sub"]]
            return None
        raise AssertionError(f"unexpected {method} {path}")


WANTED_OTP_FLOW = [
    (0, "exec", "direct-grant-validate-username", "REQUIRED", None),
    (0, "flow", "fastrdp-otp-check - otp", "CONDITIONAL", None),
    (1, "exec", "conditional-user-configured", "REQUIRED", None),
    (1, "exec", "direct-grant-validate-otp", "REQUIRED",
     {"default.reference.value": "otp", "default.reference.maxAge": "60"}),
    (0, "flow", "fastrdp-otp-check - no otp", "CONDITIONAL", None),
    (1, "exec", "conditional-sub-flow-executed", "REQUIRED",
     {"flow_to_check": "fastrdp-otp-check - otp", "check_result": "not-executed"}),
    (1, "exec", "deny-access-authenticator", "REQUIRED", {"denyErrorMessage": "fastrdp_no_otp"}),
]


OTP = {**BASE, "otp_check_client_id": "fastrdp-otp-check"}


class OtpCheck(unittest.TestCase):
    def run_otp(self, api, **over):
        r = kp.Run(api, kp.settings({**OTP, **over}))
        r.otp_check()
        return r

    def test_settings_client(self):
        self.assertEqual(kp.settings(dict(BASE))["otp_check_client_id"], "")
        with self.assertRaisesRegex(kp.KeycloakError, "client of its own"):
            kp.settings({**BASE, "otp_check_client_id": "fastrdp-web"})
        with self.assertRaisesRegex(kp.KeycloakError, "flow of its own"):
            kp.settings({**OTP, "otp_check_flow_alias": "fastrdp-mfa"})

    def test_settings(self):
        self.assertEqual(kp.settings(dict(OTP))["otp_check_amr"], "otp")
        with self.assertRaisesRegex(kp.KeycloakError, "otp_check_amr"):
            kp.settings({**OTP, "otp_check_amr": "o t p"})

    def test_no_otp_error_matches_the_broker(self):
        sys.path.insert(0, str(ROOT / "broker/brokerd"))
        from fastrdp_broker import keycloak_otp
        self.assertEqual(kp.NO_OTP_ERROR, keycloak_otp.NO_OTP_ERROR)

    def test_creates_flow_mapper_and_binding_then_idempotent(self):
        api = OtpCheckApi()
        r = self.run_otp(api)
        self.assertEqual(r.changes, ["create direct grant flow fastrdp-otp-check",
                                     "client fastrdp-otp-check: amr mapper",
                                     "client fastrdp-otp-check: direct grant flow fastrdp-otp-check"])
        self.assertEqual(kp.flow_actual(api, "fastrdp-otp-check"), WANTED_OTP_FLOW)
        self.assertEqual([(m["protocolMapper"], m["config"]["id.token.claim"]) for m in api.mappers],
                         [("oidc-amr-mapper", "true")])
        self.assertEqual(api.client["authenticationFlowBindingOverrides"], {"direct_grant": "f-fastrdp-otp-check"})
        self.assertEqual(r.warnings, [])
        api.mappers[0]["config"]["userinfo.token.claim"] = "true"   # Keycloak adds it [tested]
        api.writes.clear()
        r = self.run_otp(api)
        self.assertEqual((r.changes, r.warnings, api.writes), ([], [], []))

    def test_amr_value_is_the_reference(self):
        api = OtpCheckApi()
        self.run_otp(api, otp_check_amr="totp")
        otp_step = kp.flow_actual(api, "fastrdp-otp-check")[3]
        self.assertEqual(otp_step[4]["default.reference.value"], "totp")

    def test_check_mode_writes_nothing(self):
        api = OtpCheckApi()
        r = self.run_otp(api, check=True)
        self.assertEqual(len(r.changes), 3)
        self.assertEqual(api.writes, [])

    def test_every_drift_is_reported_and_rebuilt(self):
        """Safeguard 1: any change by hand (a step disabled or removed, a config changed,
        the old two-step flow) is a warning naming the step, then rebuilt."""
        def disable(provider):
            def go(api):
                _, e = next((a, e) for a, rows in api.execs.items() for e in rows if e.get("providerId") == provider)
                e["requirement"] = "DISABLED"
            return go

        def drop_no_otp(api):
            top = api.execs["fastrdp-otp-check"]
            sub = next(e for e in top if e.get("sub") == "fastrdp-otp-check - no otp")
            top.remove(sub)
            del api.execs[sub["sub"]]

        def deny_message(api):
            _, e = next((a, e) for a, rows in api.execs.items() for e in rows
                        if e.get("providerId") == "deny-access-authenticator")
            api.configs[e["authenticationConfig"]]["denyErrorMessage"] = "denied"

        def no_reference(api):
            _, e = next((a, e) for a, rows in api.execs.items() for e in rows
                        if e.get("providerId") == "direct-grant-validate-otp")
            del e["authenticationConfig"]

        def old_flow(api):
            api.execs = {"fastrdp-otp-check": [
                {"id": "u", "providerId": "direct-grant-validate-username", "displayName": "u", "requirement": "REQUIRED"},
                {"id": "o", "providerId": "direct-grant-validate-otp", "displayName": "o", "requirement": "REQUIRED"}]}

        for name, tamper in (("deny disabled", disable("deny-access-authenticator")),
                             ("otp disabled", disable("direct-grant-validate-otp")),
                             ("no-otp sub-flow removed", drop_no_otp), ("deny message", deny_message),
                             ("otp reference removed", no_reference), ("older two-step flow", old_flow)):
            with self.subTest(name):
                api = OtpCheckApi()
                self.run_otp(api)
                tamper(api)
                checked = self.run_otp(api, check=True)
                self.assertEqual(checked.changes, ["rebuild direct grant flow fastrdp-otp-check"])
                self.assertIn("differs from the wanted structure", checked.warnings[0])
                self.assertIn("would be rebuilt", checked.warnings[0])
                r = self.run_otp(api)
                self.assertEqual(r.changes, ["rebuild direct grant flow fastrdp-otp-check"])
                self.assertIn("rebuilt", r.warnings[0])
                self.assertEqual(kp.flow_actual(api, "fastrdp-otp-check"), WANTED_OTP_FLOW)

    def test_changed_amr_mapper_reset(self):
        api = OtpCheckApi()
        self.run_otp(api)
        api.mappers[0]["config"]["id.token.claim"] = "false"
        r = self.run_otp(api)
        self.assertEqual(r.changes, ["client fastrdp-otp-check: reset amr mapper"])
        self.assertIn("changed by hand", r.warnings[0])
        self.assertEqual(api.mappers[0]["config"]["id.token.claim"], "true")

    def test_unsafe_client_refused(self):
        cases = {"publicClient=True": {"publicClient": True},
                 "standardFlowEnabled=True": {"standardFlowEnabled": True},
                 "serviceAccountsEnabled=True": {"serviceAccountsEnabled": True},
                 "fullScopeAllowed=True": {"fullScopeAllowed": True},
                 "directAccessGrantsEnabled=False": {"directAccessGrantsEnabled": False},
                 "standard.token.exchange.enabled=true": {"attributes": {"standard.token.exchange.enabled": "true"}},
                 "oauth2.device.authorization.grant.enabled=true":
                     {"attributes": {"oauth2.device.authorization.grant.enabled": "true"}}}
        for what, change in cases.items():
            with self.subTest(what):
                api = OtpCheckApi()
                api.client.update(change)
                with self.assertRaisesRegex(kp.KeycloakError, re.escape(what)):
                    self.run_otp(api)
                self.assertEqual(api.writes, [])
        api = OtpCheckApi()
        api.mappers = [{"name": "aud", "protocolMapper": "oidc-audience-mapper"}]
        with self.assertRaisesRegex(kp.KeycloakError, "audience mapper aud"):
            self.run_otp(api)

    def test_missing_client_and_builtin_flow(self):
        api = OtpCheckApi()
        with self.assertRaisesRegex(kp.KeycloakError, "not found"):
            self.run_otp(api, otp_check_client_id="other")
        with self.assertRaisesRegex(kp.KeycloakError, "built-in"):
            self.run_otp(api, otp_check_flow_alias="browser")

    def test_realm_warnings(self):
        api = OtpCheckApi()
        api.realm = {"otpPolicyCodeReusable": True, "bruteForceProtected": False}
        r = self.run_otp(api)
        self.assertEqual(len(r.warnings), 2)
        self.assertIn("used more than once", r.warnings[0])
        self.assertIn("brute-force detection is off", r.warnings[1])


if __name__ == "__main__":
    unittest.main()
