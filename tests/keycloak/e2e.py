# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""End-to-end passkey checks: Keycloak (configured by the keycloak_passkeys role) ->
the real fastrdp-webgate (in this process) <- headless Chromium with a CDP virtual
authenticator (CTAP2, resident keys, user verification).

Called by tests/keycloak/run.sh, which starts Keycloak, creates the fixture realm
(kc_fixture.py) and applies the role. --apply CMD re-applies the role with
"hardware-only", "account-console" or "default" settings.

The approval page (/web/approve, backlog W2) runs against a fake broker that holds
pending RDP logins in the broker's real mfa.WebApprovals (decide(), stale(), list()),
with web_approval_max_auth_age shortened to APPROVAL_MAX_AUTH_AGE so that the
"sign-in too old" cases (W6) need only a few seconds.

Every check prints "ok   ..." or "FAIL ...". The ID token claims the webgate saw
(acr, amr, accepted or refused) are written to --report as JSON.
"""

from __future__ import annotations

import argparse
import asyncio
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
sys.path.insert(0, str(HERE.parent.parent / "broker" / "brokerd"))

import kc_fixture as fx  # noqa: E402
from cdp import Browser, CdpError  # noqa: E402
from fastrdp_webgate import app as webgate_app  # noqa: E402
from fastrdp_webgate import config as webgate_config  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import OidcError, Provider, pkce_pair  # noqa: E402
from fastrdp_broker.config import MfaSection  # noqa: E402
from fastrdp_broker.mfa import ApprovalError, MfaDenied, WebApprovals  # noqa: E402

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
APPROVAL_MAX_AUTH_AGE = 5   # seconds; the broker's default is 30


class FakeBroker(socketserver.ThreadingUnixStreamServer):
    """Answers the webgate's web_desktops/web_token requests like a permissive broker,
    and mfa_pending/mfa_decide like server.py, from the broker's own WebApprovals on an
    event loop of its own; the test adds pending logins with start_login()."""

    def __init__(self, path: str):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

        async def make() -> WebApprovals:
            return WebApprovals(MfaSection(mode="web", web_approval_timeout=600,
                                           web_approval_max_auth_age=APPROVAL_MAX_AUTH_AGE))

        self.approvals = self.in_loop(make())
        broker = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                msg = json.loads(self.rfile.readline())
                reply = {"ok": True, "user": msg["user"], "desktops": [{"name": "xfce", "label": "XFCE"}],
                         "default": "xfce"}
                if msg["op"] == "web_token":
                    reply = {"ok": True, "user": msg["user"], "token": "FRWT-test", "desktops": ["xfce"]}
                elif msg["op"] in ("mfa_pending", "mfa_decide"):
                    reply = broker.in_loop(broker.approval_op(msg))
                self.wfile.write(json.dumps(reply).encode() + b"\n")

        super().__init__(path, Handler)

    def in_loop(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    async def approval_op(self, msg: dict) -> dict:
        """mfa_pending / mfa_decide with server.py's replies (the user names are local)."""
        user = msg["user"]
        if msg["op"] == "mfa_pending":
            return {"ok": True, "user": user, "pending": self.approvals.list(user, msg.get("auth_time"))}
        try:
            self.approvals.decide(user, msg["id"], msg["approve"], msg["auth_time"], msg.get("bound", False))
        except ApprovalError as exc:
            reply = {"ok": False, "error": "not decided", "reason": exc.reason}
            if exc.outcome:
                reply["outcome"] = exc.outcome
            return reply
        return {"ok": True, "approved": msg["approve"], "others_pending": self.approvals.count(user)}

    def start_login(self, user: str):
        """An RDP login of `user` waiting for web approval: (id, future of wait())."""
        rid = WebApprovals.new_id()
        fut = asyncio.run_coroutine_threadsafe(
            self.approvals.wait(user, "nla", "192.0.2.10", request_id=rid), self.loop)
        deadline = time.time() + 5
        while rid not in self.approvals.pending and time.time() < deadline:
            time.sleep(0.05)
        return rid, fut

    def stop(self) -> None:
        self.shutdown()
        self.loop.call_soon_threadsafe(self.loop.stop)


def outcome(fut) -> str:
    """How a pending login ended: approved, denied, waiting or the error."""
    if not fut.done():
        return "waiting"
    try:
        return "approved" if fut.result() == "web" else repr(fut.result())
    except MfaDenied as exc:
        return "denied" if exc.reason == "mfa_failed" else exc.reason
    except BaseException as exc:  # noqa: BLE001 - cancelled or anything else: name it
        return exc.__class__.__name__


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
        self.broker.stop()


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
    if (t.includes('was not accepted') || t.includes('Second factor required')) return 'refused';
    if (location.pathname.startsWith('/web/approve')) return 'approve';
    if (t.includes('Signed in as')) return 'chooser';
    return 'gate-other';
  }
  if (location.href.startsWith(%(probe)s)) return 'probe';
  if (location.pathname.startsWith('/realms/' + %(realm)s + '/account'))
    return (t.includes('Personal info') || t.includes('Account security')) ? 'account' : 'account-loading';
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
        self.js_page = PAGE_JS % {"gate": json.dumps(gate.public), "probe": json.dumps(probe.redirect.rsplit("/", 1)[0]),
                                  "realm": json.dumps(fx.REALM)}

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

    def run(self, start_url: str | None, user: str, password: str | None = None, otp: bool = False,
            passkey: bool = False, register: bool = False, stop_at: tuple[str, ...] = (),
            max_steps: int = 12) -> str:
        """Drive the login until a final page; returns the page kind it ended on. Without
        `start_url` it continues on the current page."""
        if start_url:
            self.b.goto(start_url)
        seen = []
        for _ in range(max_steps):
            kind = self.page()
            seen.append(kind)
            if DEBUG:
                print(f"     . {user}: {kind} {self.b.url()[:100]} | {' '.join(self.b.text().split())[:160]}",
                      file=sys.stderr, flush=True)
            if kind in stop_at or kind in ("chooser", "refused", "probe", "gate-other", "otp-setup", "kc-error",
                                           "approve", "account", "other"):
                return kind
            if kind == "account-loading":   # the account console's script still redirects or renders
                time.sleep(1.0)
                self.b.settle()
            elif kind == "username":
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

    # ---------------------------------------------------------- approval page
    def buttons(self) -> list[list[str]]:
        """The approval page's forms: [id, decision] each."""
        return self.b.js("""[...document.querySelectorAll('form')].map(f => {
            const id = f.querySelector('input[name=id]'), d = f.querySelector('input[name=decision]');
            return id && d ? [id.value, d.value] : null; }).filter(x => x)""") or []

    def decide(self, rid: str, decision: str) -> str:
        """Submit the Approve or Deny form of login `rid`; returns the page text after it."""
        found = self.b.js("""((rid, dec) => {
            for (const f of document.querySelectorAll('form')) {
              const id = f.querySelector('input[name=id]'), d = f.querySelector('input[name=decision]');
              if (id && d && id.value === rid && d.value === dec) { f.submit(); return true; } }
            return false; })(%s, %s)""" % (json.dumps(rid), json.dumps(decision)))
        if not found:
            raise CdpError(f"no {decision} form for {rid} on {self.b.url()}")
        time.sleep(0.5)
        self.b.settle()
        return " ".join(self.b.text().split())


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

        # 5b. W3: switching hardware-only off leaves attestation and the AAGUID list as
        #     they are (an allow-list set by hand survives the role); clear them by hand,
        #     sending all passwordless fields (Keycloak resets the ones left out)
        admin = fx.Admin(args.keycloak, args.admin_user, args.admin_password)   # its token lives 60 s
        realm = admin.call("GET", f"/realms/{fx.REALM}")
        check("hardware-only switched off: the role keeps attestation direct and the AAGUID list (W3)",
              realm.get("webAuthnPolicyPasswordlessAttestationConveyancePreference") == "direct"
              and len(realm.get("webAuthnPolicyPasswordlessAcceptableAaguids") or []) == 2,
              str({k: v for k, v in realm.items() if "Attestation" in k or "Aaguids" in k}))
        policy = {k: v for k, v in realm.items() if k.startswith("webAuthnPolicyPasswordless")}
        admin.call("PUT", f"/realms/{fx.REALM}", {**policy, "webAuthnPolicyPasswordlessAttestationConveyancePreference":
                                                  "not specified", "webAuthnPolicyPasswordlessAcceptableAaguids": []})
        realm = admin.call("GET", f"/realms/{fx.REALM}")
        check("... cleared by hand (all passwordless fields sent), RP name kept",
              realm.get("webAuthnPolicyPasswordlessAcceptableAaguids") in ([], None)
              and realm.get("webAuthnPolicyPasswordlessRpEntityName") == "fastrdp test",
              str({k: v for k, v in realm.items() if k.startswith("webAuthnPolicyPasswordless")}))

        # 6. W2: the approval page (/web/approve) against Keycloak, pending logins in the
        #    broker's WebApprovals (fake broker)
        approve = gate.public + "/web/approve"
        broker = gate.broker
        # 6a. an existing SSO session (alice, password + OTP at another application) does
        #     not count: the approval sign-in sends prompt=login + max_age=0
        browser.clear_cookies()
        url, state, nonce, verifier = probe.start()
        d.run(url, "alice", fx.USERS["alice"], otp=True)
        sso_claims = probe.finish(state, nonce, verifier)
        l1, f1 = broker.start_login("alice")
        browser.goto(approve)
        kind = d.page()
        check("approval with an existing Keycloak session: Keycloak asks again (prompt=login, max_age=0)",
              kind in ("username", "username-password", "password"), f"{kind} {browser.url()[:120]}")
        n = len(gate.records)
        end = d.run(approve, "alice", passkey=True)
        rec = gate.last() if len(gate.records) > n else None
        report["cases"]["approve-passkey"] = rec
        check("approval sign-in with a passkey: acr=mfa, the page lists the pending login with Approve",
              end == "approve" and rec and rec["accepted"] and [l1, "approve"] in d.buttons(),
              f"{end} {rec} {d.buttons()}")
        text = d.decide(l1, "approve")
        time.sleep(0.3)
        check("... Approve: the broker's login continues (approved)",
              "Login approved" in text and outcome(f1) == "approved", f"{text[:120]} {outcome(f1)}")
        # 6b. a real ID token of the SSO session: its auth_time is no approval sign-in for a
        #     request started later than the clock-skew allowance (oidc.CLOCK_SKEW) after it;
        #     within the allowance the broker's web_approval_max_auth_age decides
        from fastrdp_webgate.oidc import CLOCK_SKEW
        auth_time = sso_claims.get("auth_time")
        try:
            gate.provider.check_fresh(sso_claims, auth_time + CLOCK_SKEW + 1)
            fresh_refused = False
        except OidcError:
            fresh_refused = True
        check("an ID token of an earlier SSO session (old auth_time) is no approval sign-in", fresh_refused,
              f"auth_time={auth_time}")
        # 6c. password + OTP approves too
        browser.clear_cookies()
        l2, f2 = broker.start_login("alice")
        end = d.run(approve, "alice", fx.USERS["alice"], otp=True)
        ok_page = end == "approve" and [l2, "approve"] in d.buttons()
        text = d.decide(l2, "approve") if ok_page else ""
        time.sleep(0.3)
        check("approval sign-in with password + TOTP: approved", ok_page and outcome(f2) == "approved",
              f"{end} {text[:100]} {outcome(f2)}")
        # 6d. password only: alice (has a second factor) stops at the OTP form, carol (none)
        #     gets Keycloak's error page; neither reaches the approval page
        browser.clear_cookies()
        l3, f3 = broker.start_login("alice")
        n = len(gate.records)
        end = d.run(approve, "alice", fx.USERS["alice"], otp=False)
        check("approval sign-in with the password only (alice): stops at the OTP step, login still waits",
              end == "otp" and len(gate.records) == n and outcome(f3) == "waiting", f"{end} {outcome(f3)}")
        browser.clear_cookies()
        lc, fc = broker.start_login("carol")
        end = d.run(approve, "carol", fx.USERS["carol"])
        check("approval sign-in with the password only (carol, no 2nd factor): refused, login still waits",
              end in ("kc-error", "otp-setup") and len(gate.records) == n and outcome(fc) == "waiting",
              f"{end} {outcome(fc)}")
        fc.cancel()
        # 6e. the login-bound link (?login=<id>, the QR code) survives the round trip and
        #     approves exactly that login while another of the user's logins waits (l3)
        browser.clear_cookies()
        l4, f4 = broker.start_login("alice")
        end = d.run(f"{approve}?login={l4}", "alice", passkey=True)
        page_text = " ".join(browser.text().split())
        check("login-bound link: after the Keycloak sign-in the page shows that login and the warning",
              end == "approve" and "This RDP login" in page_text and "2 logins with your account" in page_text
              and [l4, "approve"] in d.buttons() and [l3, "approve"] not in d.buttons(),
              f"{end} {page_text[:160]} {d.buttons()}")
        text = d.decide(l4, "approve")
        time.sleep(0.3)
        check("... Approve approves that login only (bound), the other keeps waiting",
              outcome(f4) == "approved" and outcome(f3) == "waiting", f"{text[:100]} {outcome(f4)} {outcome(f3)}")
        # 6f. Deny always works
        browser.goto(approve)
        text = d.decide(l3, "deny")
        time.sleep(0.3)
        check("Deny on the list: the login is denied", "Login denied" in text and outcome(f3) == "denied",
              f"{text[:100]} {outcome(f3)}")

        # 7. W6: a sign-in older than the login (by more than web_approval_max_auth_age)
        time.sleep(APPROVAL_MAX_AUTH_AGE + 2)
        l5, f5 = broker.start_login("alice")
        browser.goto(approve)
        page_text = " ".join(browser.text().split())
        check("stale sign-in: the list offers 'Sign in again to approve' instead of Approve (W6)",
              d.page() == "approve" and "Sign in again to approve" in page_text
              and [l5, "approve"] not in d.buttons() and [l5, "deny"] in d.buttons(),
              f"{page_text[:160]} {d.buttons()}")
        d.click_text("sign in again")
        end = d.run(None, "alice", passkey=True)
        ok_page = end == "approve" and [l5, "approve"] in d.buttons()
        text = d.decide(l5, "approve") if ok_page else ""
        time.sleep(0.3)
        check("... the link signs in afresh, then Approve works", ok_page and outcome(f5) == "approved",
              f"{end} {d.buttons()} {text[:80]} {outcome(f5)}")
        time.sleep(APPROVAL_MAX_AUTH_AGE + 2)
        l6, f6 = broker.start_login("alice")
        browser.goto(f"{approve}?login={l6}")
        kind = d.page()
        check("stale sign-in on the login-bound page: straight to a fresh Keycloak sign-in",
              kind in ("username", "username-password", "password"), f"{kind} {browser.url()[:120]}")
        end = d.run(None, "alice", passkey=True)
        page_text = " ".join(browser.text().split())
        ok_page = end == "approve" and [l6, "approve"] in d.buttons() and "clocks" not in page_text
        text = d.decide(l6, "approve") if ok_page else ""
        time.sleep(0.3)
        check("... back on that login's page (no loop, no clock hint), Approve works",
              ok_page and outcome(f6) == "approved", f"{end} {page_text[:120]} {outcome(f6)}")
        time.sleep(APPROVAL_MAX_AUTH_AGE + 2)
        l7, f7 = broker.start_login("alice")
        browser.goto(approve)
        text = d.decide(l7, "deny")
        time.sleep(0.3)
        check("Deny works with a stale sign-in too", "Login denied" in text and outcome(f7) == "denied",
              f"{text[:100]} {outcome(f7)}")

        # 8. W4: the account console. Default: the realm's browser flow, a password alone is
        #    enough (the enrolment gap); with fastrdp_keycloak_account_console_mfa it signs
        #    in through fastrdp-mfa
        account = f"{args.keycloak}/realms/{fx.REALM}/account/"
        browser.clear_cookies()
        end = d.run(account, "carol", fx.USERS["carol"])
        check("account console by default: carol's password alone signs in (the enrolment gap)",
              end == "account", end)
        subprocess.run([args.apply, "account-console"], check=True, stdout=subprocess.DEVNULL)
        admin = fx.Admin(args.keycloak, args.admin_user, args.admin_password)
        mfa_id = next(f["id"] for f in admin.call("GET", f"/realms/{fx.REALM}/authentication/flows")
                      if f["alias"] == "fastrdp-mfa")
        acc = admin.call("GET", f"/realms/{fx.REALM}/clients?clientId=account-console")[0]
        check("fastrdp_keycloak_account_console_mfa: the role binds fastrdp-mfa (by id) to account-console",
              (acc.get("authenticationFlowBindingOverrides") or {}).get("browser") == mfa_id,
              str(acc.get("authenticationFlowBindingOverrides")))
        browser.clear_cookies()
        end = d.run(account, "carol", fx.USERS["carol"])
        check("... carol (password only) can no longer sign in to the account console",
              end in ("kc-error", "otp-setup"), end)
        browser.clear_cookies()
        end = d.run(account, "alice", fx.USERS["alice"], otp=False)
        check("... alice with the password alone stops at the OTP step", end == "otp", end)
        browser.clear_cookies()
        end = d.run(account, "alice", passkey=True)
        check("... alice with her passkey signs in to the account console", end == "account", end)
        subprocess.run([args.apply, "default"], check=True, stdout=subprocess.DEVNULL)
        admin = fx.Admin(args.keycloak, args.admin_user, args.admin_password)
        acc = admin.call("GET", f"/realms/{fx.REALM}/clients?clientId=account-console")[0]
        check("option off again: the role leaves the override in place",
              (acc.get("authenticationFlowBindingOverrides") or {}).get("browser") == mfa_id,
              str(acc.get("authenticationFlowBindingOverrides")))
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
