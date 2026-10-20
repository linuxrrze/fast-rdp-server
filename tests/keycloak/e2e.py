# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""End-to-end passkey checks: Keycloak (configured by the keycloak_passkeys role) ->
the real fastrdp-webgate (in this process) <- headless Chromium with a CDP virtual
authenticator (CTAP2, resident keys, user verification).

Called by tests/keycloak/run.sh, which starts Keycloak, creates the fixture realm
(kc_fixture.py) and applies the role. --apply CMD re-applies the role with
"hardware-only" or "default" settings for the hardware-only checks.

Every check prints "ok   ..." or "FAIL ...". The ID token claims the webgate saw
(acr, amr, accepted or refused) are written to --report as JSON.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import secrets
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "broker" / "webgate"))

import kc_fixture as fx  # noqa: E402
from cdp import Browser, CdpError  # noqa: E402
from fastrdp_webgate import app as webgate_app  # noqa: E402
from fastrdp_webgate import config as webgate_config  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import OidcError, Provider, pkce_pair  # noqa: E402

DEBUG = bool(os.environ.get("FASTRDP_KC_DEBUG"))
PASSES: list[str] = []
FAILS: list[str] = []


def ok(desc: str) -> None:
    PASSES.append(desc)
    print(f"ok   {desc}", flush=True)


def fail(desc: str, detail: str = "") -> None:
    FAILS.append(desc)
    print(f"FAIL {desc}", flush=True)
    for line in detail.splitlines()[-8:]:
        print(f"     | {line}", flush=True)


def check(desc: str, cond: bool, detail: str = "") -> bool:
    (ok(desc) if cond else fail(desc, detail))
    return cond


# ------------------------------------------------------------------ fake broker
class FakeBroker(socketserver.ThreadingUnixStreamServer):
    """Answers the webgate's web_desktops/web_token requests like a permissive broker."""

    def __init__(self, path: str):
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                msg = json.loads(self.rfile.readline())
                reply = {"ok": True, "user": msg["user"], "desktops": [{"name": "xfce", "label": "XFCE"}],
                         "default": "xfce"}
                if msg["op"] == "web_token":
                    reply = {"ok": True, "user": msg["user"], "token": "FRWT-test", "desktops": ["xfce"]}
                self.wfile.write(json.dumps(reply).encode() + b"\n")

        super().__init__(path, Handler)


# ------------------------------------------------------------------ webgate
class Gate:
    """The real webgate (config parser, OIDC provider, HTTP handler), with check_mfa
    wrapped to record what it decided."""

    def __init__(self, keycloak: str, port: int, tmp: str):
        self.public = f"http://localhost:{port}"
        self.records: list[dict] = []
        cfg = webgate_config.parse({
            "webgate": {"public_url": self.public, "listen": f"127.0.0.1:{port}",
                        "broker_socket": os.path.join(tmp, "broker.sock")},
            "oidc": {"issuer": f"{keycloak}/realms/{fx.REALM}", "client_id": fx.CLIENT_ID,
                     "required_acr": ["mfa"]},     # the role default fastrdp_web_required_acr
            "guacamole": {},
        })
        self.cfg = cfg
        self.provider = Provider(cfg.oidc, fx.CLIENT_SECRET)
        self.provider.discover()
        real_check = self.provider.check_mfa

        def recording_check(claims: dict) -> None:
            entry = {"user": claims.get("preferred_username"), "acr": claims.get("acr"),
                     "amr": claims.get("amr"), "accepted": False}
            try:
                real_check(claims)
                entry["accepted"] = True
            except OidcError as exc:
                entry["error"] = str(exc)
                raise
            finally:
                self.records.append(entry)

        self.provider.check_mfa = recording_check
        self.broker = FakeBroker(cfg.webgate.broker_socket)
        threading.Thread(target=self.broker.serve_forever, daemon=True).start()
        app = webgate_app.Webgate(cfg, self.provider, Signer(secrets.token_hex(32)), os.urandom(16))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), webgate_app.make_handler(app))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def last(self) -> dict | None:
        return self.records[-1] if self.records else None

    def stop(self) -> None:
        self.httpd.shutdown()
        self.broker.shutdown()


class Probe:
    """A second relying party for the same client WITHOUT acr_values (an ordinary login,
    e.g. another application in the realm). Its ID tokens go through the webgate's own
    id_token_claims + check_mfa."""

    def __init__(self, gate: Gate, port: int):
        self.gate = gate
        self.redirect = f"http://localhost:{port}/cb"
        self.result: dict = {}
        cfg = dataclasses.replace(gate.cfg.oidc, required_acr=[])
        self.provider = Provider(cfg, fx.CLIENT_SECRET)
        self.provider.discover()
        probe = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                probe.result = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
                body = b"<html><body>probe callback</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def start(self) -> tuple[str, str, str, str]:
        state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
        verifier, challenge = pkce_pair()
        return self.provider.authorize_url(self.redirect, state, nonce, challenge), state, nonce, verifier

    def finish(self, state: str, nonce: str, verifier: str) -> dict:
        if self.result.get("state") != state or "code" not in self.result:
            raise OidcError(f"probe: no code ({self.result})")
        tokens = self.provider.exchange(self.result["code"], self.redirect, verifier)
        return self.gate.provider.id_token_claims(tokens, nonce)

    def stop(self) -> None:
        self.httpd.shutdown()


# ------------------------------------------------------------------ browser driving
PAGE_JS = r"""(() => {
  const t = document.body ? document.body.innerText : '';
  const vis = id => { const e = document.getElementById(id); return !!e && e.type !== 'hidden' && e.offsetParent !== null; };
  if (location.href.startsWith(%(gate)s)) {
    if (t.includes('Signed in as')) return 'chooser';
    if (t.includes('was not accepted')) return 'refused';
    return 'gate-other';
  }
  if (location.href.startsWith(%(probe)s)) return 'probe';
  if (t.includes('We are sorry')) return 'kc-error';
  if (document.getElementById('registerWebAuthn')) return 'register-passkey';
  if (vis('otp')) return 'otp';
  if (document.getElementById('totp') || t.includes('Mobile Authenticator Setup')) return 'otp-setup';
  if (vis('username') && vis('password')) return 'username-password';
  if (vis('username')) return 'username';
  if (vis('password')) return 'password';
  return 'other';
})()"""


class Driver:
    def __init__(self, browser: Browser, gate: Gate, probe: Probe):
        self.b, self.gate, self.probe = browser, gate, probe
        self.js_page = PAGE_JS % {"gate": json.dumps(gate.public), "probe": json.dumps(probe.redirect.rsplit("/", 1)[0])}

    def page(self) -> str:
        return self.b.js(self.js_page)

    def fill_submit(self, fields: dict) -> None:
        self.b.js("""((f) => {
            let form = null;
            for (const [k, v] of Object.entries(f)) { const e = document.getElementById(k); e.value = v; form = e.form; }
            const btn = form.querySelector('[type=submit]');
            if (btn) btn.click(); else form.submit();
            return true; })(%s)""" % json.dumps(fields))
        time.sleep(0.5)
        self.b.settle()

    def click_text(self, needle: str) -> None:
        found = self.b.js("""((n) => {
            for (const e of document.querySelectorAll('button, a, input[type=button], input[type=submit]')) {
              const label = (e.innerText || e.value || '');
              if (label.toLowerCase().includes(n)) { e.click(); return true; } }
            return false; })(%s)""" % json.dumps(needle.lower()))
        if not found:
            raise CdpError(f"no button with {needle!r} on {self.b.url()}")
        time.sleep(1.0)
        self.b.settle()

    def run(self, start_url: str, user: str, password: str | None = None, otp: bool = False,
            passkey: bool = False, register: bool = False, stop_at: tuple[str, ...] = (),
            max_steps: int = 12) -> str:
        """Drive the login until a final page; returns the page kind it ended on."""
        self.b.goto(start_url)
        seen = []
        for _ in range(max_steps):
            kind = self.page()
            seen.append(kind)
            if DEBUG:
                print(f"     . {user}: {kind} {self.b.url()[:100]} | {' '.join(self.b.text().split())[:160]}",
                      file=sys.stderr, flush=True)
            if kind in stop_at or kind in ("chooser", "refused", "probe", "gate-other", "otp-setup", "kc-error",
                                           "other"):
                return kind
            if kind == "username":
                if passkey:
                    self.click_text("passkey")
                else:
                    self.fill_submit({"username": user})
            elif kind == "username-password":
                if passkey:
                    self.click_text("passkey")
                elif password is None:
                    return kind
                else:
                    self.fill_submit({"username": user, "password": password})
            elif kind == "password":
                if password is None:
                    return kind
                self.fill_submit({"password": password})
            elif kind == "otp":
                if not otp:
                    return kind
                self.fill_submit({"otp": fx.totp()})
            elif kind == "register-passkey":
                if not register:
                    return kind
                self.b.js("document.getElementById('registerWebAuthn').click(); true")
                time.sleep(1.5)
                self.b.settle()
        raise CdpError(f"login did not finish: {seen}")


def keycloak_error(b: Browser) -> str:
    return " ".join(b.text().split())[:200]


# ------------------------------------------------------------------ scenarios
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keycloak", required=True)          # http://localhost:PORT
    ap.add_argument("--chrome", required=True)
    ap.add_argument("--gate-port", type=int, default=18090)
    ap.add_argument("--probe-port", type=int, default=18091)
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--apply", required=True, help="command: <cmd> hardware-only|default re-applies the role")
    ap.add_argument("--report", required=True)
    ap.add_argument("--chrome-log")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="fastrdp-kc-e2e.")
    gate = Gate(args.keycloak, args.gate_port, tmp)
    probe = Probe(gate, args.probe_port)
    log = open(args.chrome_log, "ab") if args.chrome_log else None  # noqa: SIM115
    browser = Browser(args.chrome, log=log)
    report: dict = {"cases": {}}
    try:
        auth = browser.add_authenticator()
        d = Driver(browser, gate, probe)
        start = gate.public + "/web/"
        admin = fx.Admin(args.keycloak, args.admin_user, args.admin_password)
        alice_id = admin.call("GET", f"/realms/{fx.REALM}/users?username=alice&exact=true")[0]["id"]

        def passkeys_in_keycloak() -> int:
            creds = admin.call("GET", f"/realms/{fx.REALM}/users/{alice_id}/credentials")
            return sum(1 for c in creds if c["type"] == "webauthn-passwordless")

        # 1. password + TOTP -> acr=mfa; then the required action registers a passkey
        #    on the virtual authenticator (attestation "none" policy)
        n = len(gate.records)
        end = d.run(start, "alice", fx.USERS["alice"], otp=True, register=True)
        rec = gate.last() if len(gate.records) > n else None
        report["cases"]["password+otp"] = rec
        check("password + TOTP: webgate accepts, acr=mfa",
              end == "chooser" and rec and rec["accepted"] and rec["acr"] == "mfa", f"{end} {rec}")
        check("passkey registered during that login (Keycloak + virtual authenticator)",
              passkeys_in_keycloak() == 1 and len(browser.credentials(auth)) == 1,
              f"keycloak={passkeys_in_keycloak()} authenticator={len(browser.credentials(auth))}")

        # 2. passkey only (discoverable credential, UV) -> acr=mfa, no password typed
        browser.clear_cookies()
        n = len(gate.records)
        end = d.run(start, "alice", passkey=True)
        rec = gate.last() if len(gate.records) > n else None
        report["cases"]["passkey"] = rec
        check("passkey login: webgate accepts, acr=mfa, no password or OTP",
              end == "chooser" and rec and rec["accepted"] and rec["acr"] == "mfa"
              and rec["user"] == "alice", f"{end} {rec}")

        # 3a. password only, user WITH a second factor: the forced flow stops at the OTP form
        browser.clear_cookies()
        n = len(gate.records)
        end = d.run(start, "alice", fx.USERS["alice"], otp=False)
        check("password only (alice): flow stops at the OTP step, no token",
              end == "otp" and len(gate.records) == n, end)
        # 3b. password only, user WITHOUT a second factor: Keycloak 26.8 fails the flow
        #     (the second-factor ALTERNATIVEs are not configured; no setup is offered), no token
        browser.clear_cookies()
        n = len(gate.records)
        end = d.run(start, "carol", fx.USERS["carol"])
        check("password only (carol, no 2nd factor): login refused, no token",
              end in ("kc-error", "otp-setup") and len(gate.records) == n, end)
        # 3c. a password-only token from an ordinary login (no acr_values) is refused by the webgate
        browser.clear_cookies()
        url, state, nonce, verifier = probe.start()
        end = d.run(url, "carol", fx.USERS["carol"])
        claims = probe.finish(state, nonce, verifier) if end == "probe" else {}
        try:
            gate.provider.check_mfa(claims)
            accepted = True
        except OidcError:
            accepted = False
        report["cases"]["password-only-token"] = gate.last()
        check("password-only ID token (acr=1, other client request): webgate refuses it",
              end == "probe" and not accepted and claims.get("acr") == "1", f"{end} acr={claims.get('acr')}")

        # 4. SSO pitfall: carol's password-only SSO session (from 3c, cookies kept) must not
        #    turn into acr=mfa at the webgate: the forced flow has no Cookie step
        n = len(gate.records)
        browser.goto(start)
        kind = d.page()
        check("existing password-only SSO session: webgate login asks again (no Cookie step)",
              kind in ("username", "username-password", "password") and len(gate.records) == n,
              f"{kind} {gate.last()}")
        end = d.run(start, "carol", fx.USERS["carol"])
        check("... and finishing it with the password only still gives no token",
              end in ("kc-error", "otp-setup") and len(gate.records) == n, end)
        # 4b. alice: SSO session from a password+OTP login elsewhere does not skip the
        #     forced flow either (every web login re-authenticates)
        browser.clear_cookies()
        url, state, nonce, verifier = probe.start()
        d.run(url, "alice", fx.USERS["alice"], otp=True)
        browser.goto(start)
        check("existing alice SSO session: webgate login asks again", d.page() != "chooser", d.page())

        # 4c. control: the same password-only SSO session against a forced flow that DOES
        #     have a Cookie step (Cookie OR username+password+OTP). Keycloak 26.8.1's
        #     CookieAuthenticator refuses step-up (requested LoA 2 > session LoA 1), so the
        #     session is still asked again. The role's flow has no Cookie step regardless.
        browser.clear_cookies()
        url, state, nonce, verifier = probe.start()
        d.run(url, "carol", fx.USERS["carol"])
        fx.cookie_control_flow(admin)
        n = len(gate.records)
        browser.goto(start)
        kind = d.page()
        report["cases"]["control-cookie-flow"] = {"page": kind, "token": gate.last() if len(gate.records) > n else None}
        check("control: forced flow WITH Cookie: password-only SSO session still not upgraded (LoA step-up check)",
              kind in ("username", "username-password", "password") and len(gate.records) == n, kind)
        subprocess.run([args.apply, "default"], check=True, stdout=subprocess.DEVNULL)
        check("... role re-applied: client profile points at fastrdp-mfa again",
              admin.call("GET", f"/realms/{fx.REALM}/client-policies/profiles")["profiles"][-1]["executors"][0]
              ["configuration"]["auth-flow-alias"] == "fastrdp-mfa")

        # 5. hardware-only: attestation "direct" + AAGUID allow-list. The virtual
        #    authenticator's attestation is not accepted -> registration refused.
        subprocess.run([args.apply, "hardware-only"], check=True, stdout=subprocess.DEVNULL)
        admin = fx.Admin(args.keycloak, args.admin_user, args.admin_password)
        admin.call("PUT", f"/realms/{fx.REALM}/users/{alice_id}",
                   {"requiredActions": ["webauthn-register-passwordless"]})
        browser.clear_cookies()
        before_kc, saved = passkeys_in_keycloak(), browser.credentials(auth)
        n = len(gate.records)
        end = d.run(start, "alice", fx.USERS["alice"], otp=True, register=True, max_steps=8)
        page_text = keycloak_error(browser)
        report["cases"]["hardware-only-registration"] = {"end": end, "page": page_text}
        check("hardware-only: virtual authenticator's passkey registration refused by Keycloak",
              passkeys_in_keycloak() == before_kc and len(gate.records) == n,
              f"end={end} keycloak {before_kc}->{passkeys_in_keycloak()} page={page_text}")
        # The refused registration still overwrote alice's discoverable credential on the
        # authenticator (same RP ID + user handle; Keycloak sends no excludeCredentials by
        # default). Put the old one back for the next check.
        browser.call("WebAuthn.clearCredentials", {"authenticatorId": auth})
        for cred in saved:
            browser.call("WebAuthn.addCredential", {"authenticatorId": auth, "credential": cred})
        # documented caveat: the allow-list is checked at registration only
        browser.clear_cookies()
        admin.call("PUT", f"/realms/{fx.REALM}/users/{alice_id}", {"requiredActions": []})
        n = len(gate.records)
        end = d.run(start, "alice", passkey=True)
        rec = gate.last() if len(gate.records) > n else None
        report["cases"]["hardware-only-old-passkey"] = rec
        check("hardware-only: a passkey registered BEFORE still logs in (delete old credentials)",
              end == "chooser" and rec and rec["accepted"], f"{end} {rec}")
        subprocess.run([args.apply, "default"], check=True, stdout=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001 - report and fail the run
        fail(f"unexpected error: {exc.__class__.__name__}", f"{exc}\nat {browser.url() if browser else ''}")
    finally:
        browser.close()
        gate.stop()
        probe.stop()
        if log:
            log.close()
        report["webgate_decisions"] = gate.records
        Path(args.report).write_text(json.dumps(report, indent=2))
    print(f"\n{len(PASSES)} passed, {len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
