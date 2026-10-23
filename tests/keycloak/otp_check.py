# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""The broker's code check ([mfa] mode code_or_web, broker/brokerd/fastrdp_broker/
keycloak_otp.py) against the real Keycloak of tests/keycloak/run.sh, after the role set up
the direct grant flow of the client fastrdp-otp-check (kc_fixture.py otp-client):
  - alice's right code is accepted without a password, the ID token's amr is ["otp"]
    (the flow's OTP reference), and no Keycloak session is left;
  - a wrong code and a pending required action are wrong codes; carol (no OTP
    credential) gets the flow's Deny access (HTTP 401 fastrdp_no_otp), not a wrong code;
    a wrong client secret makes the check unusable (OFF), not a wrong code;
  - username + code through another client (the webgate's) is refused;
  - safeguard 2: with the flow's Deny access step disabled by hand, Keycloak issues carol
    a token on her name alone; it has no "otp" in amr and the broker refuses it, and the
    setup script's check mode reports the flow; applying it restores the flow;
  - with otpPolicyCodeReusable off, the same code is refused the second time.
Prints "ok  ..." / "FAIL ..." lines like e2e.py; exit 1 on a failure.

  python3 otp_check.py <keycloak base URL> <admin password>"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "broker/brokerd"))
from fastrdp_broker import keycloak_otp  # noqa: E402
from fastrdp_broker.config import KeycloakOtpSection  # noqa: E402
from fastrdp_broker.keycloak_otp import KeycloakOtp  # noqa: E402
from kc_fixture import CLIENT_SECRET, OTP_CLIENT_SECRET, REALM, Admin, totp  # noqa: E402

failures = 0
SCRIPT = HERE.parents[1] / "ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py"
spec = importlib.util.spec_from_file_location("fastrdp_keycloak_passkeys", SCRIPT)
kp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kp)


def post(url: str, form: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, urllib.parse.urlencode(form).encode())
    req.add_header("Accept", "application/json")   # as keycloak_otp.py (Deny access: else HTML)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        with exc:
            raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {}


def amr(token: str) -> object:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("amr")


def check(desc: str, cond: bool, detail: str = "") -> None:
    global failures
    if cond:
        print(f"ok   {desc}")
    else:
        failures += 1
        print(f"FAIL {desc}" + (f": {detail}" if detail else ""))


def main() -> int:
    base, admin_pw = sys.argv[1], sys.argv[2]
    a = Admin(base, "admin", admin_pw)
    r = f"/realms/{REALM}"
    issuer = f"{base}/realms/{REALM}"
    kc = KeycloakOtp(KeycloakOtpSection(issuer=issuer, client_id="fastrdp-otp-check",
                                        client_secret_file="/nonexistent", timeout=10), secret=OTP_CLIENT_SECRET)

    def uid(name: str) -> str:
        return a.call("GET", f"{r}/users?username={name}&exact=true")[0]["id"]

    def set_actions(name: str, actions: list[str]) -> None:
        u = a.call("GET", f"{r}/users/{uid(name)}")
        u["requiredActions"] = actions
        a.call("PUT", f"{r}/users/{uid(name)}", u)

    def sessions(name: str) -> list:
        """The user's sessions of the code check's client (e2e.py leaves webgate ones)."""
        return [x for x in a.call("GET", f"{r}/users/{uid(name)}/sessions")
                if "fastrdp-otp-check" in (x.get("clients") or {}).values()]

    def realm_set(**fields) -> None:
        realm = a.call("GET", r)   # the whole realm: a partial PUT may reset policies
        a.call("PUT", r, {**realm, **fields})

    def grant(user: str, code: str, secret: str = OTP_CLIENT_SECRET) -> tuple[int, dict]:
        return post(f"{issuer}/protocol/openid-connect/token", {
            "grant_type": "password", "client_id": "fastrdp-otp-check", "client_secret": secret,
            "username": user, "totp": code, "scope": "openid"})

    def setup_script(check: bool):
        s = kp.settings({"admin_url": base, "realm": REALM, "client_id": "fastrdp-web", "admin_user": "admin",
                         "admin_password": admin_pw, "otp_check_client_id": "fastrdp-otp-check", "check": check})
        run = kp.Run(kp.Api(s), s)
        run.otp_check()
        return run

    def set_requirement(flow: str, match, requirement: str) -> None:
        flow = urllib.parse.quote(flow)
        for e in a.call("GET", f"{r}/authentication/flows/{flow}/executions"):
            if e["level"] == 0 and match(e):
                a.call("PUT", f"{r}/authentication/flows/{flow}/executions", {**e, "requirement": requirement})

    old_actions = a.call("GET", f"{r}/users/{uid('alice')}").get("requiredActions", [])
    set_actions("alice", [])
    try:
        check("code check: alice's right code accepted without a password",
              kc.check("alice", totp()) == keycloak_otp.OK)
        left = sessions("alice")
        check("code check: no Keycloak session left after the check", left == [], json.dumps(left))
        status, body = grant("alice", totp())
        got = amr(body["id_token"]) if status == 200 else None
        check("code check: the ID token's amr is [\"otp\"] (the OTP step's reference)", got == ["otp"],
              f"HTTP {status}, amr {got!r}")
        if status == 200:
            post(f"{issuer}/protocol/openid-connect/logout", {"client_id": "fastrdp-otp-check",
                 "client_secret": OTP_CLIENT_SECRET, "refresh_token": body["refresh_token"]})
        check("code check: wrong code is a wrong code", kc.check("alice", "000000") == keycloak_otp.WRONG)
        status, body = grant("carol", "123456")
        check("code check: carol (no OTP credential) gets Deny access, HTTP 401 fastrdp_no_otp",
              (status, body.get("error")) == (401, "fastrdp_no_otp"), f"HTTP {status} {body}")
        check("code check: carol is no wrong code but NO_OTP", kc.check("carol", "123456") == keycloak_otp.NO_OTP)
        status, body = grant("alice", totp(), secret="wrong")
        check("code check: a wrong client secret is HTTP 401 unauthorized_client",
              (status, body.get("error")) == (401, "unauthorized_client"), f"HTTP {status} {body}")
        bad = KeycloakOtp(KeycloakOtpSection(issuer=issuer, client_id="fastrdp-otp-check",
                                             client_secret_file="/nonexistent", timeout=10), secret="wrong")
        check("code check: a wrong client secret makes the check unusable (OFF), no wrong code",
              bad.check("alice", totp()) == keycloak_otp.OFF)

        # safeguards: flows changed by hand. Without the "no otp" sub-flow a name alone
        # gets a token (amr []); with only its Deny step disabled Keycloak answers 500.
        tampers = (("no-otp sub-flow disabled", "fastrdp-otp-check",
                    lambda e: e.get("displayName") == "fastrdp-otp-check - no otp", "CONDITIONAL", 200),
                   ("Deny access step disabled", "fastrdp-otp-check - no otp",
                    lambda e: e.get("providerId") == "deny-access-authenticator", "REQUIRED", 500))
        for what, flow, match, restore, expect in tampers:
            set_requirement(flow, match, "DISABLED")
            try:
                status, body = grant("carol", "123456")
                got = amr(body["id_token"]) if status == 200 else None
                if expect == 200:
                    check(f"tampered flow ({what}): Keycloak issues carol a token on her name alone, "
                          "without otp in amr", status == 200 and "otp" not in (got or []), f"HTTP {status}, amr {got!r}")
                    post(f"{issuer}/protocol/openid-connect/logout", {"client_id": "fastrdp-otp-check",
                         "client_secret": OTP_CLIENT_SECRET, "refresh_token": body.get("refresh_token", "")})
                else:
                    check(f"tampered flow ({what}): Keycloak answers HTTP {expect}", status == expect,
                          f"HTTP {status} {body}")
                check(f"tampered flow ({what}): the broker refuses (OFF, no wrong code)",
                      kc.check("carol", "123456") == keycloak_otp.OFF)
                run = setup_script(check=True)
                check(f"tampered flow ({what}): the setup script's check mode reports it",
                      run.changes == ["rebuild direct grant flow fastrdp-otp-check"]
                      and any("DISABLED" in w and "differs" in w for w in run.warnings),
                      f"changes {run.changes}, warnings {run.warnings}")
                setup_script(check=False)
                check(f"tampered flow ({what}): the setup script rebuilds it, carol gets Deny access again",
                      kc.check("carol", "123456") == keycloak_otp.NO_OTP and setup_script(check=True).changes == [])
            finally:
                set_requirement(flow, match, restore)   # a no-op after the rebuild
        check("code check: no Keycloak session of carol left", sessions("carol") == [], json.dumps(sessions("carol")))

        # the webgate's client: the realm's direct grant flow (or none) wants more than a code
        form = {"grant_type": "password", "client_id": "fastrdp-web", "client_secret": CLIENT_SECRET,
                "username": "alice", "totp": totp()}
        req = urllib.request.Request(f"{issuer}/protocol/openid-connect/token",
                                     urllib.parse.urlencode(form).encode())
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
        check("code check: username + code through another client refused", status != 200, f"HTTP {status}")

        set_actions("alice", ["UPDATE_PASSWORD"])
        check("code check: alice with a pending required action is a wrong code (nothing enrolled)",
              kc.check("alice", totp()) == keycloak_otp.WRONG)
        set_actions("alice", [])

        realm_set(otpPolicyCodeReusable=False)
        code = totp(at=time.time() + 30)   # unused so far: the look-ahead window takes it
        first, second = kc.check("alice", code), kc.check("alice", code)
        check("code check: with otpPolicyCodeReusable off a code counts once",
              (first, second) == (keycloak_otp.OK, keycloak_otp.WRONG),
              f"first {first}, second {second}")
    finally:
        realm_set(otpPolicyCodeReusable=True)
        set_actions("alice", old_actions)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
