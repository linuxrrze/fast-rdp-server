# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of tests/lab/approve.py: the QR code flow against the real webgate
(broker/webgate, its approval page) with a fake broker on a Unix socket and a fake
Keycloak that serves the login and OTP forms like its v2 login theme and checks the
TOTP (no step twice: otpPolicyCodeReusable false). Without python3-cryptography the
webgate's guacjson/webpush (not on the approval path) are stubbed."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import html
import http.server
import importlib.util
import io
import json
import logging
import os
import secrets
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("fastrdp_lab_approve", HERE / "approve.py")
ap = importlib.util.module_from_spec(_spec)
sys.modules["fastrdp_lab_approve"] = ap   # dataclasses look the module up
_spec.loader.exec_module(ap)

sys.path.insert(0, str(HERE.parents[1] / "broker" / "webgate"))
try:
    import cryptography  # noqa: F401
except ImportError:
    for _name in ("guacjson", "webpush"):   # AES / ECDH helpers of other pages
        sys.modules[f"fastrdp_webgate.{_name}"] = types.ModuleType(f"fastrdp_webgate.{_name}")
from fastrdp_webgate import config as wg_config  # noqa: E402
from fastrdp_webgate.app import Webgate, make_handler  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import Provider  # noqa: E402

logging.getLogger("fastrdp.webgate").addHandler(logging.NullHandler())
logging.getLogger("fastrdp.webgate").propagate = False

USER, PASSWORD = "labuser1", "pw: not in any output"
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
MINE, OTHER = "QRcodeOnMyScreen_0123A", "SomebodyElsesLogin-987"


class FakeKeycloak(http.server.BaseHTTPRequestHandler):
    """Discovery, authorize (login form), login-actions (password, then OTP), token."""
    issuer = ""
    secret = b""
    sessions: dict = {}      # AUTH_SESSION_ID -> {"q": authorize query, "step", "code": session_code}
    codes: dict = {}         # OIDC code -> (query, auth_time)
    used: set = set()        # TOTP steps used (otpPolicyCodeReusable false)
    posts: list = []         # (step, form) of every login-actions POST
    tamper_state = False

    def log_message(self, *a):
        pass

    def reply(self, status, body="", headers=()):
        data = body.encode()
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def form_page(self, sid, error="", headers=()):
        s = self.sessions[sid]
        s["code"] = secrets.token_urlsafe(8)   # Keycloak renews the session code per page
        action = html.escape(f"{self.issuer}/login-actions/authenticate?session_code={s['code']}"
                             f"&execution=e-{s['step']}&client_id=fastrdp-web&tab_id=t1")
        if s["step"] == "password":
            err = (f'<div class="pf-v5-c-alert pf-m-danger"><span class="pf-v5-c-alert__title kc-feedback-text">'
                   f"{error}</span></div>" if error else "")
            body = (f'{err}<form id="webauth" action="{action}" method="post">'   # passkey autofill
                    '<input type="hidden" id="clientDataJSON" name="clientDataJSON">'
                    '<input type="hidden" id="username" name="username"></form>'
                    f'<form id="kc-form-login" onsubmit="login.disabled = true; return true;" '
                    f'action="{action}" method="post" novalidate="novalidate">'
                    '<input type="hidden" id="id-hidden-input" name="credentialId">'
                    '<input id="username" name="username" value="" type="text" autocomplete="username" autofocus>'
                    '<input id="password" name="password" value="" type="password">'
                    '<input type="checkbox" id="rememberMe" name="rememberMe">'
                    '<button class="pf-v5-c-button pf-m-primary" name="login" id="kc-login" type="submit">'
                    "Sign In</button></form>")
        else:
            err = (f'<span id="input-error-otp-code" class="pf-v5-c-helper-text__item-text" aria-live="polite">'
                   f"{error}</span>" if error else "")
            body = (f'<form id="kc-select-try-another-way-form" action="{action}" method="post">'
                    '<input type="hidden" name="tryAnotherWay" value="on"></form>'
                    f'<form id="kc-otp-login-form" action="{action}" method="post" novalidate="novalidate">'
                    f'<input id="otp" name="otp" autocomplete="one-time-code" type="text" autofocus>{err}'
                    '<button name="login" id="kc-login" type="submit">Sign In</button></form>')
        self.reply(200, f"<!DOCTYPE html><html><head><title>Sign in to lab</title></head><body>{body}</body></html>",
                   headers)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/realms/lab/.well-known/openid-configuration":
            meta = {"issuer": self.issuer, "authorization_endpoint": self.issuer + "/protocol/openid-connect/auth",
                    "token_endpoint": self.issuer + "/protocol/openid-connect/token"}
            return self.reply(200, json.dumps(meta))
        if u.path == "/realms/lab/protocol/openid-connect/auth":
            assert (q["prompt"], q["max_age"], q["code_challenge_method"]) == ("login", "0", "S256"), q
            sid = secrets.token_urlsafe(12)
            self.sessions[sid] = {"q": q, "step": "password"}
            return self.form_page(sid, headers=[("Set-Cookie", f"AUTH_SESSION_ID={sid}; Path=/realms/lab/; HttpOnly"),
                                                ("Set-Cookie", "KC_RESTART=x; Path=/realms/lab/; HttpOnly")])
        self.reply(404, "<p>not found</p>")

    def sorry(self, why):
        self.reply(400, '<html><head><title>Sign in to lab</title></head><body><h1 id="kc-page-title">'
                        f'We are sorry...</h1><p id="kc-error-message" class="instruction">{why}</p></body></html>')

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode(),
                                           keep_blank_values=True))
        if u.path.endswith("/token"):
            return self.token(form)
        cookies = dict(c.strip().split("=", 1) for c in (self.headers.get("Cookie") or "").split(";") if "=" in c)
        sid = cookies.get("AUTH_SESSION_ID")
        s = self.sessions.get(sid)
        if s is None:
            return self.sorry("Cookie not found. Please make sure cookies are enabled in your browser.")
        if q.get("session_code") != s["code"] or q.get("execution") != f"e-{s['step']}":
            return self.sorry("Action expired. Please continue with login now.")
        type(self).posts.append((s["step"], form))
        if s["step"] == "password":
            if form.get("username") != USER or form.get("password") != PASSWORD:
                return self.form_page(sid, "Invalid username or password.")
            s["step"] = "otp"
            return self.form_page(sid)
        step = self.valid_step(form.get("otp", ""))
        if step is None:
            return self.form_page(sid, "Invalid authenticator code.")
        self.used.add(step)
        del self.sessions[sid]
        code = secrets.token_urlsafe(16)
        self.codes[code] = (s["q"], int(time.time()))
        state = "forged" if self.tamper_state else s["q"]["state"]
        loc = s["q"]["redirect_uri"] + "?" + urllib.parse.urlencode(
            {"state": state, "session_state": "ss", "iss": self.issuer, "code": code})
        self.reply(302, "", [("Location", loc)])

    def valid_step(self, otp):
        now = int(time.time() // 30)
        for c in (now - 1, now, now + 1):   # otpPolicyLookAheadWindow 1
            if c not in self.used and secrets.compare_digest(ap.totp.hotp(self.secret, c), otp):
                return c
        return None

    def token(self, form):
        q, auth_time = self.codes.pop(form.get("code"), (None, 0))
        verifier = form.get("code_verifier", "")
        ok = q and form.get("client_secret") == "csecret" and form.get("redirect_uri") == q["redirect_uri"] and \
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == \
            q["code_challenge"]
        if not ok:
            return self.reply(400, '{"error":"invalid_grant"}')
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": "fastrdp-web", "exp": now + 300, "iat": now, "nonce": q["nonce"],
                  "auth_time": auth_time, "acr": "mfa", "amr": ["pwd", "otp"], "preferred_username": USER}
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        self.reply(200, json.dumps({"id_token": f"{b64({'alg': 'none'})}.{b64(claims)}.", "access_token": "x"}))


class FakeBroker(socketserver.ThreadingUnixStreamServer):
    """mfa_pending / mfa_decide of fastrdp-brokerd, for USER only."""

    def __init__(self, path):
        self.pending: list[dict] = []
        self.seen: list[dict] = []
        broker = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                msg = json.loads(self.rfile.readline())
                broker.seen.append(msg)
                self.wfile.write(json.dumps(broker.answer(msg)).encode() + b"\n")
        super().__init__(path, Handler)

    def wait(self, rid, code="42", address="192.0.2.10"):
        self.pending.append({"id": rid, "method": "nla", "client_address": address, "age_s": 3, "code": code,
                             "single_pending_conflict": False, "needs_fresh_sign_in": False})

    def answer(self, msg):
        if msg.get("user") != USER:
            return {"ok": False, "error": "not permitted", "reason": "denied"}
        if msg["op"] == "mfa_pending":
            conflict = len(self.pending) > 1
            return {"ok": True, "user": USER, "pending": [dict(p, single_pending_conflict=conflict)
                                                          for p in self.pending]}
        if msg["op"] == "mfa_decide":
            hit = [p for p in self.pending if p["id"] == msg["id"]]
            if not hit:
                return {"ok": False, "error": "not decided", "reason": "approval_unknown"}
            if msg["approve"] and len(self.pending) > 1 and not msg.get("bound"):
                return {"ok": False, "error": "not decided", "reason": "approval_conflict"}
            self.pending.remove(hit[0])
            return {"ok": True, "approved": msg["approve"], "others_pending": len(self.pending)}
        return {"ok": False, "error": "unknown op", "reason": "denied"}


class Lab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fastrdp-approve.", dir="/tmp")   # short Unix socket path
        self.addCleanup(shutil.rmtree, self.tmp)
        kc = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeKeycloak)
        FakeKeycloak.issuer = f"http://127.0.0.1:{kc.server_port}/realms/lab"
        FakeKeycloak.secret, _ = ap.totp.parse_secret(SECRET)
        FakeKeycloak.sessions, FakeKeycloak.codes, FakeKeycloak.used, FakeKeycloak.posts = {}, {}, set(), []
        FakeKeycloak.tamper_state = False
        self.broker = FakeBroker(f"{self.tmp}/b.sock")
        cfg = wg_config.parse({
            "webgate": {"public_url": "http://127.0.0.1:1", "broker_socket": f"{self.tmp}/b.sock"},
            "oidc": {"issuer": FakeKeycloak.issuer, "client_id": "fastrdp-web", "required_acr": ["mfa"]},
        })
        self.serve(kc)
        provider = Provider(cfg.oidc, "csecret")
        provider.discover()
        self.app = Webgate(cfg, provider, Signer("cookie-secret"), b"\0" * 16)
        web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.base = f"http://127.0.0.1:{web.server_port}"
        self.app.redirect_uri = self.base + "/web/callback"
        self.serve(web)
        self.serve(self.broker)
        self.lines: list[str] = []
        self.state = f"{self.tmp}/step"

    def serve(self, srv):
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

    def approver(self, url="/web/approve", code=None, password=PASSWORD, browser=None):
        code = code or ap.code_source(self.write("secret", SECRET), self.state, min_left=0,
                                      sleep=lambda s: None)
        return ap.Approver(self.base + url, USER, password, code, browser, self.lines.append)

    def write(self, name, text):
        path = f"{self.tmp}/{name}"
        Path(path).write_text(text + "\n")
        return path

    def decided(self):
        return [m for m in self.broker.seen if m["op"] == "mfa_decide"]

    def assert_nothing_secret(self, *texts):
        sent_codes = [f.get("otp") for step, f in FakeKeycloak.posts if step == "otp"]
        for t in [*texts, *self.lines]:
            for s in [PASSWORD, *sent_codes, "session_code", "state="]:
                self.assertNotIn(s, t)


class QrFlow(Lab):
    def test_qr_url_approves_bound(self):
        self.broker.wait(MINE)
        with self.assertLogs("fastrdp.webgate", "INFO") as logs:
            res = self.approver(f"/web/approve?login={MINE}").run()
        self.assertEqual((res.login, res.decision), (MINE, "approved"))
        self.assertIn("Login approved", res.message)
        self.assertIn("INFO:fastrdp.webgate:web approval: labuser1 approved an RDP login (login-bound link)",
                      logs.output)
        d = self.decided()
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["id"], d[0]["approve"], d[0]["bound"]), (MINE, True, True))
        # the forms as a browser sends them: Keycloak's fields, its submit button, no rememberMe
        self.assertEqual([(s, sorted(f)) for s, f in FakeKeycloak.posts],
                         [("password", ["credentialId", "login", "password", "username"]),
                          ("otp", ["login", "otp"])])
        self.assertEqual(Path(self.state).read_text().strip(), str(min(FakeKeycloak.used)))
        self.assertEqual(self.lines, ["IdP: login form", "IdP: OTP form"])
        self.assert_nothing_secret(res.message)

    def test_single_waiting_login_from_the_list(self):
        self.broker.wait(MINE)
        res = self.approver("/web").run()       # the prefix; no id: the page's list
        self.assertEqual(res.login, MINE)
        self.assertEqual([m["op"] for m in self.broker.seen], ["mfa_pending", "mfa_pending", "mfa_decide"])
        self.assertTrue(self.decided()[0]["bound"])   # its own page, as the QR code opens it
        self.assertEqual(len(FakeKeycloak.used), 1)   # one sign-in for both pages

    def test_deny(self):
        self.broker.wait(MINE)
        res = self.approver(f"/web/approve?login={MINE}").run(approve=False)
        self.assertEqual(res.decision, "denied")
        self.assertEqual(self.decided()[0]["approve"], False)

    def test_bound_approval_while_another_waits(self):
        self.broker.wait(OTHER, code="13", address="198.51.100.7")
        self.broker.wait(MINE)
        res = self.approver().run(login=MINE)
        self.assertEqual(res.login, MINE)
        self.assertEqual([p["id"] for p in self.broker.pending], [OTHER])

    def test_two_waiting_without_an_id(self):
        self.broker.wait(OTHER)
        self.broker.wait(MINE)
        with self.assertRaisesRegex(ap.Failed, "2 RDP logins wait for labuser1, need exactly one"):
            self.approver().run()
        self.assertEqual(self.decided(), [])

    def test_nothing_waiting(self):
        with self.assertRaisesRegex(ap.Failed, "0 RDP logins .* No RDP login is waiting for your approval"):
            self.approver().run()

    def test_unknown_login_id(self):
        self.broker.wait(OTHER)
        with self.assertRaisesRegex(ap.Failed, f"no approve button for login {MINE}: .*no longer waiting"):
            self.approver().run(login=MINE)
        self.assertEqual(self.decided(), [])

    def test_wrong_password(self):
        self.broker.wait(MINE)
        with self.assertRaisesRegex(ap.Failed, "did not accept user name and password: Invalid username or password"):
            self.approver(password="wrong").run(login=MINE)
        self.assertEqual(self.decided(), [])

    def test_wrong_otp(self):
        self.broker.wait(MINE)
        with self.assertRaisesRegex(ap.Failed, "did not accept the TOTP code: Invalid authenticator code"):
            self.approver(code=lambda: "000000" if ap.totp.totp(FakeKeycloak.secret) != "000000" else "111111"
                          ).run(login=MINE)
        self.assertEqual(self.decided(), [])
        self.assertEqual(len([s for s, _ in FakeKeycloak.posts if s == "otp"]), 1)   # one try, no guessing

    def test_state_file_keeps_codes_apart(self):
        """Two sign-ins at the same (frozen) time: with the shared state file the second
        gets the next step; without it Keycloak refuses the reused code."""
        t0 = time.time()
        clock = [t0]
        secret = self.write("secret", SECRET)

        def code_fn(state):
            return ap.code_source(secret, state, 0, clock=lambda: clock[0],
                                  sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        self.broker.wait(MINE)
        self.approver(code=code_fn(self.state)).run(login=MINE)
        self.broker.wait(OTHER)
        self.approver(code=code_fn(self.state)).run(login=OTHER)
        self.assertEqual(len(FakeKeycloak.used), 2)
        clock[0] = t0
        self.broker.wait(MINE)
        with self.assertRaisesRegex(ap.Failed, "Invalid authenticator code"):
            self.approver(code=code_fn(None)).run(login=MINE)

    def test_oidc_state_checked(self):
        FakeKeycloak.tamper_state = True
        self.broker.wait(MINE)
        with self.assertRaisesRegex(ap.Failed, "HTTP 400: Login state mismatch or expired"):
            self.approver().run(login=MINE)
        self.assertEqual(self.decided(), [])

    def test_csrf_token_from_the_page(self):
        """The POST carries the page's csrf; a wrong one or a lost sign-in cookie is refused."""
        class Tamper(ap.Browser):
            mode = None

            def request(self, url, form=None):
                if form and url.endswith("/web/approve"):
                    if self.mode == "csrf":
                        form = [(k, "x" if k == "csrf" else v) for k, v in form]
                    elif self.mode == "cookie":
                        self.jar.clear(domain="127.0.0.1", path="/web", name="fastrdp_web_approve")
                return super().request(url, form)
        for mode, msg in (("csrf", "HTTP 403: Form expired"), ("cookie", "HTTP 303")):
            with self.subTest(mode):
                self.broker.pending = []
                self.broker.wait(MINE)
                b = Tamper()
                b.mode = mode
                with self.assertRaisesRegex(ap.Failed, f"approve refused: {msg}"):
                    self.approver(browser=b).run(login=MINE)
                self.assertEqual(self.decided(), [])

    def test_keycloak_error_page_without_secrets(self):
        class NoCookies(ap.Browser):
            def request(self, url, form=None):
                if form is not None and "login-actions" in url:
                    self.jar.clear()
                return super().request(url, form)
        self.broker.wait(MINE)
        with self.assertRaises(ap.Failed) as cm:
            self.approver(browser=NoCookies()).run(login=MINE)
        msg = str(cm.exception)
        self.assertIn("IdP page without a login form at http://127.0.0.1:", msg)
        self.assertIn("/realms/lab/login-actions/authenticate (HTTP 400): Cookie not found", msg)
        self.assert_nothing_secret(msg)


class Cli(Lab):
    def run_main(self, *args, url=None, password=PASSWORD):
        out, err = io.StringIO(), io.StringIO()
        argv = ["--url", url or self.base + "/web/approve", "--user", USER,
                "--password-file", self.write("pw", password), "--totp-secret-file", self.write("secret", SECRET),
                "--totp-state", self.state, "--min-left", "0", *args]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ap.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        self.broker.wait(MINE)
        rc, out, err = self.run_main("--login", MINE, "-v")
        self.assertEqual((rc, out), (0, f"approved {MINE}\n"))
        self.assertEqual(err, "approve: IdP: login form\napprove: IdP: OTP form\n")
        self.broker.wait(MINE)
        rc, out, err = self.run_main(url=f"{self.base}/web/approve?login={MINE}", password="wrong")
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("did not accept user name and password", err)
        self.assert_nothing_secret(out, err)
        self.assertEqual(self.run_main("--login", "short")[0], 2)
        self.assertEqual(self.run_main(url="ftp://x/")[0], 2)
        self.assertEqual(self.run_main("--pin", "AB:CD")[0], 2)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = ap.main(["--url", self.base, "--user", USER, "--password-file", f"{self.tmp}/none",
                          "--totp-secret-file", self.write("secret", SECRET)])
        self.assertEqual(rc, 2)
        self.assertIn("password file: No such file or directory", err.getvalue())


class Units(unittest.TestCase):
    def test_approve_urls(self):
        for url, want in (("https://h", ("https://h/web/approve", None)),
                          ("https://h/web/", ("https://h/web/approve", None)),
                          ("https://h:8443/x/approve", ("https://h:8443/x/approve", None)),
                          (f"https://h/web/approve?login={MINE}", ("https://h/web/approve", MINE))):
            self.assertEqual(ap.approve_urls(url), want)
        with self.assertRaises(ap.SetupError):
            ap.approve_urls("javascript:alert(1)")

    def test_safe_url(self):
        self.assertEqual(ap.safe_url("https://kc/realms/r/cb?code=SECRET&state=S#f"), "https://kc/realms/r/cb")

    def test_form_data(self):
        page = ap.Page('<form method="POST" action="/a?x=1&amp;y=2"><input type="hidden" name="h" value="v">'
                       '<input name="t"><input type="checkbox" name="c"><input type="radio" name="r" value="1" '
                       'checked><button name="b" value="1">One</button><button name="b2">Two</button>'
                       '<input type="button" name="nb"></form><span class="alert">Boom &amp; more</span>')
        f = page.forms[0]
        self.assertEqual((f.action, f.method), ("/a?x=1&y=2", "post"))
        self.assertEqual(f.data({"t": "typed"}), [("h", "v"), ("t", "typed"), ("r", "1"), ("b", "1")])
        self.assertEqual(page.message(), "Boom & more")

    def test_code_source_errors_hold_no_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "s")
            p.write_text("not base32 !!\n")
            with self.assertRaises(ap.SetupError) as cm:
                ap.code_source(str(p))
            self.assertNotIn("base32 !!", str(cm.exception))


@unittest.skipUnless(shutil.which("openssl"), "openssl")
class Pinning(unittest.TestCase):
    def test_pin(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = f"{d}/k.pem", f"{d}/c.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=lab"],
                           check=True, capture_output=True)
            der = ssl.PEM_cert_to_DER_cert(Path(crt).read_text())
            fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ok)
            srv.handle_error = lambda *a: None      # the refused handshakes
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
            try:
                url = f"https://127.0.0.1:{srv.server_port}/"
                self.assertEqual(ap.Browser(pins=(fp,)).request(url).body, "ok")
                with self.assertRaisesRegex(ap.SetupError, "matches no --pin"):
                    ap.Browser(pins=("00" * 32,)).request(url)
                with self.assertRaisesRegex(ap.Failed, "SSLCertVerificationError"):
                    ap.Browser().request(url)               # system CAs: refused
            finally:
                srv.shutdown()
                srv.server_close()


class Ok(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    unittest.main()
