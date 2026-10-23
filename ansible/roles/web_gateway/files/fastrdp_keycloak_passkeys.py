#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Configure Keycloak for passkeys on the fastrdp web path (docs/passkeys.md, recipe A).

Reads a JSON settings object on stdin, talks to the Keycloak admin REST API and prints
one JSON object: {"changed": bool, "changes": [...], "check": bool}. Idempotent: a
second run with the same settings changes nothing. With "check": true nothing is
written; "changes" lists what would change.

What it manages, and nothing else:
  1. realm: WebAuthn *passwordless* policy (UV required, discoverable credential
     required, passkeys enabled, mediation), attestation + acceptable AAGUIDs
     (hardware-only mode), required action webauthn-register-passwordless enabled;
  2. the authentication flow <flow_alias> (default fastrdp-mfa), WITHOUT a Cookie step:
       Username Form, Password Form (skipped after a passkey), and a conditional
       sub-flow "second factor unless a passkey was used". The flow is rebuilt when
       its structure differs; a flow of that name that is built in is refused;
  3. client policies: profile <profile_name> (auth-flow-enforcer -> flow, LoA) and
     policy <policy_name> (acr-condition <acr>). Other profiles and policies are kept:
     the PUT endpoints replace the whole list, so the lists are read, merged and
     written back;
  4. the OIDC client's ACR-to-LoA map: <acr> -> <loa>, other entries kept;
  5. only with "otp_check_client_id" (broker [mfa] mode code_or_web): the direct grant
     flow <otp_check_flow_alias> (default fastrdp-otp-check: Username Validation, then
     OTP for users who have one and Deny access (error fastrdp_no_otp) for users who have
     none; no password; the OTP step's reference value <otp_check_amr> goes into amr
     through the client's mapper "fastrdp amr") bound as that client's direct grant flow
     override. A flow that differs in any step, requirement or config is reported in
     "warnings" and rebuilt (check mode: reported only). The client itself
     is created by hand (docs/examples/keycloak-fastrdp-otp-check-client.json); the
     script refuses it unless it is confidential, allows direct grants only (no browser
     flow, implicit flow, service account, device or CIBA grant, standard token
     exchange), has full scope off and no audience mapper. It warns ("warnings") when
     the realm lets an OTP code be used twice or has brute-force detection off.

Not managed (manual, docs/passkeys.md "Close the enrolment gap"): the browser flow
override of the client account-console. The realm update sends all current
webAuthnPolicyPasswordless* fields because Keycloak resets the ones missing from the
request; the AAGUID list is ours, though (empty unless hardware_only), so a list set by
hand in the realm is replaced (docs/backlog.md W3).

Standard library only; runs on the Ansible controller (or anywhere with Python 3.11+).
"""

from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PASSKEY_CREDENTIAL = "webauthn-passwordless"
SECOND_FACTOR_DEFAULT = ["auth-otp-form", "webauthn-authenticator"]
# Executions that must never be part of the forced flow: an SSO cookie would upgrade any
# existing session (also a password-only one) to the flow's LoA; the others skip factors.
FORBIDDEN_IN_FLOW = {"auth-cookie", "conditional-user-configured", "allow-access-authenticator",
                     "identity-provider-redirector", "auth-spnego"}
MEDIATIONS = ("conditional", "optional", "required", "silent", "none")


class KeycloakError(Exception):
    pass


# ------------------------------------------------------------------ settings
def settings(raw: dict) -> dict:
    s = {
        "admin_url": "", "realm": "", "client_id": "fastrdp-web",
        "admin_realm": "master", "admin_client_id": "admin-cli", "admin_client_secret": "",
        "admin_user": "", "admin_password": "",
        "ca_file": "", "verify_tls": True, "timeout": 20,
        "flow_alias": "fastrdp-mfa", "acr": "mfa", "loa": 2,
        "profile_name": "fastrdp-mfa-flow", "policy_name": "fastrdp-mfa",
        "second_factors": list(SECOND_FACTOR_DEFAULT),
        "mediation": "conditional",
        "hardware_only": False, "aaguids": [],
        "otp_check_client_id": "", "otp_check_flow_alias": "fastrdp-otp-check", "otp_check_amr": "otp",
        "check": False,
    }
    unknown = set(raw) - set(s)
    if unknown:
        raise KeycloakError(f"unknown settings: {', '.join(sorted(unknown))}")
    s.update(raw)
    for key in ("verify_tls", "hardware_only", "check"):  # Ansible may template them as strings
        if isinstance(s[key], str):
            if s[key].lower() not in ("true", "false"):
                raise KeycloakError(f"{key} must be true or false")
            s[key] = s[key].lower() == "true"
    if isinstance(s["loa"], str) and s["loa"].isdigit():
        s["loa"] = int(s["loa"])
    for key in ("admin_url", "realm", "client_id", "flow_alias", "acr", "profile_name", "policy_name"):
        if not isinstance(s[key], str) or not s[key].strip():
            raise KeycloakError(f"{key} is required")
    s["admin_url"] = s["admin_url"].rstrip("/")
    if not s["admin_url"].startswith(("https://", "http://127.0.0.1", "http://localhost", "http://[::1]")):
        raise KeycloakError("admin_url must be https:// (plain http only for loopback)")
    if not (s["admin_client_secret"] or (s["admin_user"] and s["admin_password"])):
        raise KeycloakError("admin credentials missing: admin_client_secret, or admin_user + admin_password")
    if s["acr"] in ("0", "1"):
        raise KeycloakError("acr must name the MFA level (e.g. mfa), not 0/1")
    if isinstance(s["loa"], bool) or not isinstance(s["loa"], int) or not 1 <= s["loa"] <= 100:
        raise KeycloakError("loa must be an integer >= 1")
    if s["mediation"] not in MEDIATIONS:
        raise KeycloakError(f"mediation must be one of {MEDIATIONS}")
    factors = s["second_factors"]
    if not isinstance(factors, list) or not factors or not all(isinstance(f, str) and f for f in factors):
        raise KeycloakError("second_factors must be a non-empty list of authenticator ids")
    bad = sorted(set(factors) & (FORBIDDEN_IN_FLOW | {"auth-password-form", "auth-username-form"}))
    if bad:
        raise KeycloakError(f"second_factors must not contain {', '.join(bad)}")
    if s["hardware_only"] and not s["aaguids"]:
        raise KeycloakError("hardware_only needs a non-empty aaguids allow-list")
    for a in s["aaguids"]:
        if not isinstance(a, str) or len(a) != 36 or a.count("-") != 4:
            raise KeycloakError(f"not an AAGUID: {a!r}")
    s["aaguids"] = [a.lower() for a in s["aaguids"]]
    if not isinstance(s["otp_check_client_id"], str):
        raise KeycloakError("otp_check_client_id must be a client id or empty")
    if s["otp_check_client_id"]:
        if s["otp_check_client_id"] == s["client_id"]:
            raise KeycloakError("otp_check_client_id must be a client of its own, not the webgate's")
        if not isinstance(s["otp_check_flow_alias"], str) or not s["otp_check_flow_alias"].strip() \
                or s["otp_check_flow_alias"] == s["flow_alias"]:
            raise KeycloakError("otp_check_flow_alias must name a flow of its own")
        if not isinstance(s["otp_check_amr"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", s["otp_check_amr"]):
            raise KeycloakError("otp_check_amr must be an amr value such as otp")
    return s


# ------------------------------------------------------------------ HTTP
class Api:
    def __init__(self, s: dict):
        self.s = s
        self.base = s["admin_url"]
        if s["verify_tls"]:
            self.ctx = ssl.create_default_context(cafile=s["ca_file"] or None)
        else:
            self.ctx = ssl._create_unverified_context()  # noqa: S323 (operator opted out)
        self.token = self._login()

    def _send(self, req: urllib.request.Request):
        try:
            with urllib.request.urlopen(req, timeout=self.s["timeout"], context=self.ctx) as resp:
                body = resp.read()
                return resp.status, resp.headers, body
        except urllib.error.HTTPError as exc:
            detail = exc.read(400).decode(errors="replace")
            raise KeycloakError(f"{req.get_method()} {req.full_url}: HTTP {exc.code} {detail}") from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise KeycloakError(f"{req.get_method()} {req.full_url}: {exc}") from None

    def _login(self) -> str:
        s = self.s
        form = {"client_id": s["admin_client_id"]}
        if s["admin_client_secret"]:
            form.update(grant_type="client_credentials", client_secret=s["admin_client_secret"])
        else:
            form.update(grant_type="password", username=s["admin_user"], password=s["admin_password"])
        url = f"{self.base}/realms/{urllib.parse.quote(s['admin_realm'], safe='')}/protocol/openid-connect/token"
        req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        _, _, body = self._send(req)
        try:
            return json.loads(body)["access_token"]
        except (ValueError, KeyError):
            raise KeycloakError("admin login: no access token in the response") from None

    def call(self, method: str, path: str, body=None):
        url = f"{self.base}/admin/realms/{urllib.parse.quote(self.s['realm'], safe='')}{path}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        _, headers, raw = self._send(req)
        if not raw:
            return headers.get("Location")
        return json.loads(raw)


def q(part: str) -> str:
    return urllib.parse.quote(part, safe="")


# ------------------------------------------------------------------ desired state
def realm_wanted(s: dict) -> dict:
    return {
        "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
        "webAuthnPolicyPasswordlessResidentKey": "required",
        "webAuthnPolicyPasswordlessPasskeysEnabled": True,
        "webAuthnPolicyPasswordlessMediation": s["mediation"],
        # direct: registrations without a verifiable attestation are refused; the
        # allow-list disables self-attestation. none: every passkey provider is accepted.
        "webAuthnPolicyPasswordlessAttestationConveyancePreference": "direct" if s["hardware_only"] else "none",
        "webAuthnPolicyPasswordlessAcceptableAaguids": s["aaguids"] if s["hardware_only"] else [],
    }


def sub_aliases(s: dict) -> tuple[str, str]:
    return f"{s['flow_alias']} - 2FA unless passkey", f"{s['flow_alias']} - second factor"


def flow_wanted(s: dict) -> list[tuple]:
    """Flattened tree: (level, kind, name, requirement, config)."""
    cond, second = sub_aliases(s)
    rows = [
        (0, "exec", "auth-username-form", "REQUIRED", None),
        (0, "exec", "auth-password-form", "REQUIRED", None),
        (0, "flow", cond, "CONDITIONAL", None),
        (1, "exec", "conditional-credential", "REQUIRED",
         {"credentials": PASSKEY_CREDENTIAL, "included": "false"}),
        (1, "flow", second, "REQUIRED", None),
    ]
    rows += [(2, "exec", f, "ALTERNATIVE", None) for f in s["second_factors"]]
    return rows


# The code check's direct grant flow: the username and the OTP, no password (the RDP
# login checked that). A user with an OTP credential must pass the OTP step (sub-flow 1);
# for one without, sub-flow 1 is skipped and sub-flow 2 denies with NO_OTP_ERROR, which
# the broker tells apart from a wrong code (keycloak_otp.py). The OTP step's reference
# value puts otp_check_amr into the token's amr (mapper OTP_CHECK_AMR_MAPPER): the broker
# accepts no token without it, so a flow that lost its Deny or OTP step and lets a name
# alone through still fails closed. Compared exactly on every run.
NO_OTP_ERROR = "fastrdp_no_otp"   # = broker/brokerd/fastrdp_broker/keycloak_otp.py NO_OTP_ERROR
OTP_REFERENCE_MAX_AGE = "60"      # seconds the reference counts after the step (AmrUtils)


def otp_check_flow(s: dict) -> list[tuple]:
    alias = s["otp_check_flow_alias"]
    with_otp, without_otp = f"{alias} - otp", f"{alias} - no otp"
    return [
        (0, "exec", "direct-grant-validate-username", "REQUIRED", None),
        (0, "flow", with_otp, "CONDITIONAL", None),
        (1, "exec", "conditional-user-configured", "REQUIRED", None),
        (1, "exec", "direct-grant-validate-otp", "REQUIRED",
         {"default.reference.value": s["otp_check_amr"], "default.reference.maxAge": OTP_REFERENCE_MAX_AGE}),
        (0, "flow", without_otp, "CONDITIONAL", None),
        (1, "exec", "conditional-sub-flow-executed", "REQUIRED",
         {"flow_to_check": with_otp, "check_result": "not-executed"}),
        (1, "exec", "deny-access-authenticator", "REQUIRED", {"denyErrorMessage": NO_OTP_ERROR}),
    ]


OTP_CHECK_AMR_MAPPER = {"name": "fastrdp amr", "protocol": "openid-connect", "protocolMapper": "oidc-amr-mapper",
                        "config": {"id.token.claim": "true", "access.token.claim": "true",
                                   "lightweight.claim": "true", "introspection.token.claim": "true"}}


def flow_diff(actual: list[tuple], wanted: list[tuple]) -> str:
    """The steps that differ, for the report (configs included: they are no secrets)."""
    lines = []
    for i in range(max(len(actual), len(wanted))):
        a = actual[i] if i < len(actual) else None
        w = wanted[i] if i < len(wanted) else None
        if a != w:
            lines.append(f"step {i + 1}: {a if a else 'missing'} instead of {w if w else 'nothing'}")
    return "; ".join(lines)


# Client settings that would make the code check's client more than a code check
OTP_CHECK_CLIENT = {"publicClient": False, "directAccessGrantsEnabled": True, "standardFlowEnabled": False,
                    "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "fullScopeAllowed": False,
                    "bearerOnly": False}
OTP_CHECK_ATTRIBUTES_OFF = ("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
                            "standard.token.exchange.enabled")


def flow_actual(api: Api, alias: str) -> list[tuple]:
    rows = []
    for e in api.call("GET", f"/authentication/flows/{q(alias)}/executions"):
        cfg = None
        if e.get("authenticationConfig"):
            cfg = api.call("GET", f"/authentication/config/{q(e['authenticationConfig'])}").get("config", {})
        if e.get("authenticationFlow"):
            rows.append((e["level"], "flow", e["displayName"], e["requirement"], cfg))
        else:
            rows.append((e["level"], "exec", e.get("providerId", ""), e["requirement"], cfg))
    return rows


# ------------------------------------------------------------------ steps
class Run:
    def __init__(self, api: Api, s: dict):
        self.api, self.s = api, s
        self.changes: list[str] = []
        self.warnings: list[str] = []

    def change(self, what: str) -> bool:
        """Record a change; True when it should be written (not in check mode)."""
        self.changes.append(what)
        return not self.s["check"]

    def realm(self) -> None:
        cur = self.api.call("GET", "")
        diff = {k: v for k, v in realm_wanted(self.s).items() if cur.get(k) != v}
        if diff and self.change("realm WebAuthn passwordless policy: " + ", ".join(sorted(diff))):
            # Keycloak rebuilds the whole policy from the representation (missing fields
            # fall back to defaults): send all passwordless fields, ours changed.
            body = {k: v for k, v in cur.items() if k.startswith("webAuthnPolicyPasswordless")}
            self.api.call("PUT", "", {**body, **diff})
        ra = self.api.call("GET", "/authentication/required-actions")
        wanted = next((a for a in ra if a.get("alias") == "webauthn-register-passwordless"), None)
        if wanted is None:
            if self.change("register required action webauthn-register-passwordless"):
                self.api.call("POST", "/authentication/register-required-action",
                              {"providerId": "webauthn-register-passwordless",
                               "name": "Webauthn Register Passwordless"})
                self.api.call("PUT", "/authentication/required-actions/webauthn-register-passwordless",
                              {"alias": "webauthn-register-passwordless", "enabled": True,
                               "providerId": "webauthn-register-passwordless",
                               "name": "Webauthn Register Passwordless"})
        elif not wanted.get("enabled") and self.change("enable required action webauthn-register-passwordless"):
            self.api.call("PUT", "/authentication/required-actions/webauthn-register-passwordless",
                          {**wanted, "enabled": True})

    def flow(self) -> None:
        s, alias = self.s, self.s["flow_alias"]
        flows = {f["alias"]: f for f in self.api.call("GET", "/authentication/flows")}
        if alias in flows and flows[alias].get("builtIn"):
            raise KeycloakError(f"flow {alias!r} is a built-in flow; choose another flow_alias")
        if alias not in flows:
            if not self.change(f"create flow {alias}"):
                return
            self.api.call("POST", "/authentication/flows", {
                "alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                "description": "fastrdp: MFA for acr=mfa (passkey, or password + second factor); "
                               "no Cookie step. Managed by Ansible (keycloak_passkeys)."})
        else:
            actual = flow_actual(self.api, alias)
            if actual == flow_wanted(s):
                return
            forbidden = sorted({r[2] for r in actual if r[1] == "exec"} & FORBIDDEN_IN_FLOW)
            note = f" (removes {', '.join(forbidden)})" if forbidden else ""
            if not self.change(f"rebuild flow {alias}{note}"):
                return
            for e in self.api.call("GET", f"/authentication/flows/{q(alias)}/executions"):
                if e["level"] == 0:  # removing a sub-flow execution removes its sub-flow
                    self.api.call("DELETE", f"/authentication/executions/{q(e['id'])}")
        self._build_flow()

    def _add_exec(self, parent: str, provider: str, requirement: str, config: dict | None = None,
                  config_alias: str | None = None) -> None:
        self.api.call("POST", f"/authentication/flows/{q(parent)}/executions/execution", {"provider": provider})
        self._set_requirement(parent, lambda e: e.get("providerId") == provider, requirement, config, config_alias)

    def _add_flow(self, parent: str, alias: str, requirement: str) -> None:
        self.api.call("POST", f"/authentication/flows/{q(parent)}/executions/flow",
                      {"alias": alias, "type": "basic-flow", "provider": "registration-page-form",
                       "description": "fastrdp (keycloak_passkeys)"})
        self._set_requirement(parent, lambda e: e.get("authenticationFlow") and e.get("displayName") == alias,
                              requirement, None)

    def _set_requirement(self, parent, match, requirement, config, config_alias=None) -> None:
        execs = [e for e in self.api.call("GET", f"/authentication/flows/{q(parent)}/executions")
                 if e["level"] == 0 and match(e)]
        if not execs:
            raise KeycloakError(f"execution just added to {parent!r} not found")
        e = execs[-1]
        if e["requirement"] != requirement:
            if requirement not in e.get("requirementChoices", [requirement]):
                raise KeycloakError(f"{e.get('displayName')}: requirement {requirement} not allowed "
                                    f"(choices {e.get('requirementChoices')})")
            self.api.call("PUT", f"/authentication/flows/{q(parent)}/executions",
                          {**e, "requirement": requirement})
        if config is not None:
            self.api.call("POST", f"/authentication/executions/{q(e['id'])}/config",
                          {"alias": config_alias or f"{self.s['flow_alias']}-{e['providerId']}", "config": config})

    def _build_flow(self) -> None:
        s, top = self.s, self.s["flow_alias"]
        cond, second = sub_aliases(s)
        self._add_exec(top, "auth-username-form", "REQUIRED")
        self._add_exec(top, "auth-password-form", "REQUIRED")
        self._add_flow(top, cond, "CONDITIONAL")
        self._add_exec(cond, "conditional-credential", "REQUIRED",
                       {"credentials": PASSKEY_CREDENTIAL, "included": "false"})
        self._add_flow(cond, second, "REQUIRED")
        for factor in s["second_factors"]:
            self._add_exec(second, factor, "ALTERNATIVE")
        built = flow_actual(self.api, top)
        if built != flow_wanted(s):
            raise KeycloakError(f"flow {top!r} differs after building it: {built}")

    def client_policies(self) -> None:
        s = self.s
        profile = {
            "name": s["profile_name"],
            "description": "fastrdp: force the MFA flow (managed by Ansible, keycloak_passkeys)",
            "executors": [{"executor": "auth-flow-enforcer",
                           "configuration": {"auth-flow-alias": s["flow_alias"], "auth-flow-loa": s["loa"]}}],
        }
        policy = {
            "name": s["policy_name"],
            "description": f"fastrdp: acr_values={s['acr']} -> flow {s['flow_alias']} "
                           "(managed by Ansible, keycloak_passkeys)",
            "enabled": True,
            "conditions": [{"condition": "acr-condition", "configuration": {"acr-property": s["acr"]}}],
            "profiles": [s["profile_name"]],
        }
        # The PUTs replace the realm's whole list: merge ours into what is there.
        for kind, noun, item in (("profiles", "profile", profile), ("policies", "policy", policy)):
            cur = self.api.call("GET", f"/client-policies/{kind}") or {}
            items = list(cur.get(kind) or [])
            idx = next((i for i, x in enumerate(items) if x.get("name") == item["name"]), None)
            if idx is not None and canon(items[idx]) == canon(item):
                continue
            verb = "update" if idx is not None else "add"
            if idx is None:
                items.append(item)
            else:
                items[idx] = item
            if self.change(f"{verb} client {noun} {item['name']} (keeping {len(items) - 1} other)"):
                self.api.call("PUT", f"/client-policies/{kind}", {**cur, kind: items})

    def client_acr_map(self) -> None:
        s = self.s
        found = self.api.call("GET", f"/clients?clientId={q(s['client_id'])}")
        if not found:
            raise KeycloakError(f"client {s['client_id']!r} not found in realm {s['realm']!r}")
        client = found[0]
        attrs = dict(client.get("attributes") or {})
        try:
            loa_map = json.loads(attrs.get("acr.loa.map") or "{}")
        except ValueError:
            raise KeycloakError(f"client {s['client_id']}: acr.loa.map is not JSON") from None
        if str(loa_map.get(s["acr"])) == str(s["loa"]):
            return
        loa_map[s["acr"]] = s["loa"]
        if self.change(f"client {s['client_id']}: ACR-to-LoA {s['acr']} -> {s['loa']}"):
            attrs["acr.loa.map"] = json.dumps(loa_map, separators=(",", ":"))
            self.api.call("PUT", f"/clients/{q(client['id'])}", {**client, "attributes": attrs})

    # -------------------------------------------------------------- code check
    def otp_check(self) -> None:
        """Direct grant flow of the broker's code check and its binding (settings
        otp_check_client_id); refuses an unsafe client, warns about the realm."""
        s = self.s
        client_id, alias = s["otp_check_client_id"], s["otp_check_flow_alias"]
        found = self.api.call("GET", f"/clients?clientId={q(client_id)}")
        if not found:
            raise KeycloakError(f"client {client_id!r} (code check) not found in realm {s['realm']!r}: "
                                "create it first (docs/examples/keycloak-fastrdp-otp-check-client.json)")
        client = found[0]
        attrs = client.get("attributes") or {}
        bad = [f"{k}={client.get(k)}" for k, v in OTP_CHECK_CLIENT.items() if bool(client.get(k)) != v]
        bad += [f"{k}=true" for k in OTP_CHECK_ATTRIBUTES_OFF if str(attrs.get(k, "")).lower() == "true"]
        mappers = self.api.call("GET", f"/clients/{q(client['id'])}/protocol-mappers/models") or []
        bad += [f"audience mapper {m.get('name')}" for m in mappers
                if m.get("protocolMapper") == "oidc-audience-mapper"]
        if bad:
            raise KeycloakError(f"client {client_id} (code check) must be confidential, direct grants only, "
                                f"full scope off, no token exchange or audience mapper; found: {', '.join(bad)}")

        flows = {f["alias"]: f for f in self.api.call("GET", "/authentication/flows")}
        if alias in flows and flows[alias].get("builtIn"):
            raise KeycloakError(f"flow {alias!r} is a built-in flow; choose another otp_check_flow_alias")
        wanted = otp_check_flow(s)
        if alias not in flows:
            if self.change(f"create direct grant flow {alias}"):
                self.api.call("POST", "/authentication/flows", {
                    "alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                    "description": "fastrdp: code check of the broker (username + OTP, no password; "
                                   "users without OTP are denied), direct grants of one client only. "
                                   "Managed by Ansible (keycloak_passkeys); do not edit."})
                self._build_otp_check_flow()
        else:
            actual = flow_actual(self.api, alias)
            if actual != wanted:
                # a hand-made change (or the older two-step flow): never accept it silently
                self.warnings.append(f"direct grant flow {alias} of the code check differs from the "
                                     f"wanted structure ({flow_diff(actual, wanted)}); "
                                     + ("would be rebuilt" if s["check"] else "rebuilt"))
                if self.change(f"rebuild direct grant flow {alias}"):
                    for e in self.api.call("GET", f"/authentication/flows/{q(alias)}/executions"):
                        if e["level"] == 0:   # removing a sub-flow execution removes its sub-flow
                            self.api.call("DELETE", f"/authentication/executions/{q(e['id'])}")
                    self._build_otp_check_flow()
        if not s["check"]:
            built = flow_actual(self.api, alias)
            if built != wanted:
                raise KeycloakError(f"flow {alias!r} differs after building it: {flow_diff(built, wanted)}")
            flows = {f["alias"]: f for f in self.api.call("GET", "/authentication/flows")}
        self._otp_check_mapper(client)
        flow_id = flows.get(alias, {}).get("id")
        overrides = dict(client.get("authenticationFlowBindingOverrides") or {})
        if flow_id is None or overrides.get("direct_grant") != flow_id:
            if self.change(f"client {client_id}: direct grant flow {alias}"):
                overrides["direct_grant"] = flow_id
                self.api.call("PUT", f"/clients/{q(client['id'])}",
                              {**client, "authenticationFlowBindingOverrides": overrides})

        realm = self.api.call("GET", "")
        if realm.get("otpPolicyCodeReusable"):
            self.warnings.append("realm: OTP codes may be used more than once (otpPolicyCodeReusable): "
                                 "a code typed on the RDP waiting screen can be replayed; turn it off")
        if not realm.get("bruteForceProtected"):
            self.warnings.append("realm: brute-force detection is off; wrong codes of the code check are "
                                 "then limited only by the broker ([mfa] code_attempts, code_user_failures)")


    def _build_otp_check_flow(self) -> None:
        s, top = self.s, self.s["otp_check_flow_alias"]
        _, with_otp, _, otp, without_otp, cond, deny = otp_check_flow(s)
        self._add_exec(top, "direct-grant-validate-username", "REQUIRED")
        self._add_flow(top, with_otp[2], "CONDITIONAL")
        self._add_exec(with_otp[2], "conditional-user-configured", "REQUIRED")
        self._add_exec(with_otp[2], "direct-grant-validate-otp", "REQUIRED", otp[4], f"{top}-otp-reference")
        self._add_flow(top, without_otp[2], "CONDITIONAL")
        self._add_exec(without_otp[2], "conditional-sub-flow-executed", "REQUIRED", cond[4], f"{top}-no-otp-condition")
        self._add_exec(without_otp[2], "deny-access-authenticator", "REQUIRED", deny[4], f"{top}-no-otp-deny")

    def _otp_check_mapper(self, client: dict) -> None:
        """The amr mapper on the code check's client (the broker requires amr)."""
        path = f"/clients/{q(client['id'])}/protocol-mappers/models"
        mappers = self.api.call("GET", path) or []
        want = OTP_CHECK_AMR_MAPPER
        mine = next((m for m in mappers if m.get("name") == want["name"]), None)
        if mine is None:
            if self.change(f"client {self.s['otp_check_client_id']}: amr mapper"):
                self.api.call("POST", path, want)
        elif mine.get("protocolMapper") != want["protocolMapper"] or any(
                str((mine.get("config") or {}).get(k)).lower() != v for k, v in want["config"].items()):
            # our keys must match; Keycloak adds others (userinfo.token.claim) by itself
            self.warnings.append(f"client {self.s['otp_check_client_id']}: amr mapper {want['name']!r} was changed by hand")
            if self.change(f"client {self.s['otp_check_client_id']}: reset amr mapper"):
                self.api.call("PUT", f"{path}/{q(mine['id'])}",
                              {**want, "id": mine["id"], "config": {**(mine.get("config") or {}), **want["config"]}})


def canon(obj):
    """Compare Keycloak JSON loosely: numbers and booleans as strings, key order ignored."""
    if isinstance(obj, dict):
        return {k: canon(v) for k, v in obj.items() if v not in (None, [], {}, "")}
    if isinstance(obj, list):
        return [canon(v) for v in obj]
    if isinstance(obj, bool):
        return str(obj).lower()
    return str(obj)


def main() -> int:
    try:
        s = settings(json.load(sys.stdin))
        run = Run(Api(s), s)
        run.realm()
        run.flow()
        run.client_policies()
        run.client_acr_map()
        if s["otp_check_client_id"]:
            run.otp_check()
    except (KeycloakError, ValueError) as exc:
        print(json.dumps({"failed": True, "msg": str(exc)}))
        return 1
    out = {"changed": bool(run.changes), "changes": run.changes, "check": s["check"]}
    if run.warnings:
        out["warnings"] = run.warnings
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
