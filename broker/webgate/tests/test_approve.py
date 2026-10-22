# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""<prefix>/approve ([mfa] mode web / push_or_web): a fresh MFA sign-in at the IdP
(prompt=login, max_age=0, acr enforced, auth_time checked), then the signed-in user's
pending RDP logins from the broker (mfa_pending) with CSRF-protected Approve/Deny
forms (mfa_decide, with the sign-in's auth_time); broker refusals as clear pages.
?login=<id> (the waiting screen's QR code) survives the sign-in and shows that login
first, approvable although others wait (mfa_decide "bound")."""

import http.cookiejar
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastrdp_webgate import config, guacjson  # noqa: E402
from fastrdp_webgate.app import (BrokerError, Webgate, broker_mfa_decide,  # noqa: E402
                                 broker_mfa_pending, make_handler)
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import OidcError, Provider  # noqa: E402
from test_webgate import KEY_HEX, FakeIdP, NoRedirect  # noqa: E402

PENDING = [{"id": "req-1_A", "method": "nla", "client_address": "192.0.2.10", "age_s": 7,
            "single_pending_conflict": False}]
# ids as the broker makes them (mfa.WebApprovals.new_id()): the waiting screen's QR code
# opens <prefix>/approve?login=<id>
MINE, OTHER = "QRcodeOnMyScreen_0123A", "SomebodyElsesLogin-987"


class ApprovalBroker:
    """Unix-socket broker answering per op from self.replies (dict or raw bytes)."""

    def __init__(self, path):
        self.replies = {
            "mfa_pending": {"ok": True, "user": "alice", "pending": [dict(p) for p in PENDING]},
            "mfa_decide": {"ok": True, "approved": True},
        }
        self.seen = []
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(path)
        self.srv.listen(5)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                req = json.loads(conn.makefile().readline())
                self.seen.append(req)
                r = self.replies.get(req.get("op"), {"ok": False, "error": "not permitted", "reason": "denied"})
                conn.sendall(r if isinstance(r, bytes) else json.dumps(r).encode() + b"\n")

    def ops(self):
        return [r["op"] for r in self.seen]


class FreshLoginTests(unittest.TestCase):
    def provider(self):
        p = Provider(config.OidcSection(issuer="https://idp", client_id="web", required_acr=["mfa"]), "s")
        p.meta = {"authorization_endpoint": "https://idp/a"}
        return p

    def query(self, url):
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))

    def test_authorize_url(self):
        p = self.provider()
        q = self.query(p.authorize_url("https://rdp/cb", "s", "n", "c", fresh=True))
        self.assertEqual((q["prompt"], q["max_age"], q["acr_values"]), ("login", "0", "mfa"))
        q = self.query(p.authorize_url("https://rdp/cb", "s", "n", "c"))
        self.assertNotIn("prompt", q)
        self.assertNotIn("max_age", q)

    def test_check_fresh(self):
        p = self.provider()
        self.assertEqual(p.check_fresh({"auth_time": 1000}, 1000), 1000)
        self.assertEqual(p.check_fresh({"auth_time": 950}, 1000), 950)       # clock skew
        for claims in ({}, {"auth_time": "1000"}, {"auth_time": True}, {"auth_time": 1000.5},
                       {"auth_time": 900}):
            with self.subTest(claims=claims), self.assertRaises(OidcError):
                p.check_fresh(claims, 1000)


class ApproveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        idp = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        FakeIdP.issuer = f"http://127.0.0.1:{idp.server_port}"
        FakeIdP.acr, FakeIdP.auth_age, FakeIdP.authorize_queries = "mfa", 0, []
        self.addCleanup(setattr, FakeIdP, "auth_age", 0)
        threading.Thread(target=idp.serve_forever, args=(0.05,), daemon=True).start()
        self.broker = ApprovalBroker(f"{self.tmp}/b.sock")
        cfg = config.parse({
            "webgate": {"public_url": "http://127.0.0.1:1", "broker_socket": f"{self.tmp}/b.sock"},
            "oidc": {"issuer": FakeIdP.issuer, "client_id": "fastrdp-web", "required_acr": ["mfa"]},
        })
        self.provider = Provider(cfg.oidc, "csecret")
        self.provider.discover()
        self.app = Webgate(cfg, self.provider, Signer("cookie-secret"), guacjson.parse_key(KEY_HEX))
        web = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        threading.Thread(target=web.serve_forever, args=(0.05,), daemon=True).start()
        self.base = f"http://127.0.0.1:{web.server_port}"
        self.app.redirect_uri = self.base + "/web/callback"
        self.servers = [idp, web]
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.broker.srv.close()
        shutil.rmtree(self.tmp)

    def fetch(self, url, data=None, headers=None):
        req = urllib.request.Request(url if url.startswith("http") else self.base + url, data=data,
                                     headers=headers or {})
        try:
            r = self.opener.open(req)
            return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers, e.read().decode()

    def sign_in(self, path="/web/approve"):
        _, h, _ = self.fetch(path)
        _, h, _ = self.fetch(h["Location"])                 # IdP "authorize"
        return self.fetch(h["Location"])                    # back to /web/callback

    def cookie(self, name):
        return [c for c in self.jar if c.name == name and c.value]

    def csrf(self):
        body = self.fetch("/web/approve")[2]
        return body.split('name="csrf" value="')[1].split('"')[0]

    def post(self, **form):
        return self.fetch("/web/approve", urllib.parse.urlencode(form).encode())

    # --------------------------------------------------------- sign-in
    def test_fresh_mfa_sign_in_then_pending_list(self):
        status, h, _ = self.fetch("/web/approve")
        self.assertEqual(status, 303)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))
        self.assertEqual((q["prompt"], q["max_age"], q["acr_values"]), ("login", "0", "mfa"))
        _, h, _ = self.fetch(h["Location"])                 # IdP "authorize"
        status, h, _ = self.fetch(h["Location"])            # back to /web/callback
        self.assertEqual((status, h["Location"]), (303, "/web/approve"))
        self.assertTrue(self.cookie("fastrdp_web_approve"))
        self.assertFalse(self.cookie("fastrdp_web"))        # no desktop chooser session
        status, h, body = self.fetch("/web/approve")
        self.assertEqual(status, 200)
        self.assertIn("Signed in as <b>alice</b>", body)
        self.assertIn("From <b>192.0.2.10</b>", body)
        self.assertIn("(7 s ago)", body)
        self.assertIn("RDP client, Kerberos (NLA)", body)
        self.assertIn('name="id" value="req-1_A"', body)
        self.assertIn('value="approve"', body)
        self.assertIn('value="deny"', body)
        self.assertIn("click <b>Deny</b>", body)
        self.assertEqual(self.broker.seen, [{"op": "mfa_pending", "user": "alice"}])
        self.assertEqual(h["X-Frame-Options"], "DENY")

    def test_mfa_required(self):
        FakeIdP.acr = "1"
        with self.assertLogs("fastrdp.webgate", "WARNING") as logs:
            status, _, body = self.sign_in()
        self.assertEqual(status, 403)
        self.assertIn("<title>Second factor required</title>", body)
        self.assertIn(f'(<a href="{FakeIdP.issuer}/account">{FakeIdP.issuer}/account</a>)', body)
        self.assertIn('<a href="/web/approve">Sign in again</a>', body)   # always a fresh sign-in
        self.assertIn("OIDC login of alice refused: acr '1' does not prove MFA (required: mfa; amr: None). "
                      "Keycloak issues acr 'mfa' only with a level-2 (MFA) step", logs.output[0])
        self.assertFalse(self.cookie("fastrdp_web_approve"))
        status, h, _ = self.fetch("/web/approve")              # back to the IdP
        self.assertEqual(status, 303)
        self.assertEqual(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))["prompt"],
                         "login")
        self.assertEqual(self.broker.seen, [])

    def test_reused_idp_session_refused(self):
        FakeIdP.auth_age = 3600     # the IdP ignored prompt=login/max_age=0
        status, _, body = self.sign_in()
        self.assertEqual(status, 403)
        self.assertIn("Login was not accepted.", body)      # not the second-factor page
        self.assertNotIn("Second factor", body)
        FakeIdP.auth_age = None     # no auth_time at all
        self.assertEqual(self.sign_in()[0], 403)
        self.assertFalse(self.cookie("fastrdp_web_approve"))

    def test_chooser_session_does_not_approve(self):
        status, h, _ = self.sign_in("/web/")                    # desktop chooser sign-in
        self.assertEqual(h["Location"], "/web/")
        self.assertNotIn("prompt", FakeIdP.authorize_queries[-1])
        self.assertTrue(self.cookie("fastrdp_web"))
        status, h, _ = self.fetch("/web/approve")
        self.assertEqual(status, 303)
        self.assertTrue(h["Location"].startswith(FakeIdP.issuer + "/auth?"))
        self.assertEqual(self.post(csrf="x", id="req-1_A", decision="approve")[0], 303)
        self.assertNotIn("mfa_decide", self.broker.ops())

    def test_forged_approval_cookie(self):
        forged = Signer("other-secret").dumps("approve", {"user": "bob", "auth_time": int(time.time())}, 300)
        status, _, _ = self.fetch("/web/approve", headers={"Cookie": f"fastrdp_web_approve={forged}"})
        self.assertEqual(status, 303)
        # a chooser session cookie is no approval cookie either (purpose)
        sess = self.app.signer.dumps("session", {"user": "bob"}, 300)
        status, _, _ = self.fetch("/web/approve", headers={"Cookie": f"fastrdp_web_approve={sess}"})
        self.assertEqual(status, 303)
        self.assertEqual(self.broker.seen, [])

    # --------------------------------------------------------- decisions
    def test_approve_and_deny(self):
        self.sign_in()
        auth_time = self.app.signer.loads("approve", self.cookie("fastrdp_web_approve")[0].value)["auth_time"]
        self.assertLessEqual(abs(auth_time - time.time()), 5)
        status, _, body = self.post(csrf=self.csrf(), id="req-1_A", decision="approve", user="bob")
        self.assertEqual(status, 200)
        self.assertIn("Login approved", body)
        self.assertEqual(self.broker.seen[-1], {"op": "mfa_decide", "user": "alice", "id": "req-1_A",
                                                "approve": True, "auth_time": auth_time})
        self.broker.replies["mfa_decide"] = {"ok": True, "approved": False}
        status, _, body = self.post(csrf=self.csrf(), id="req-1_A", decision="deny")
        self.assertEqual(status, 200)
        self.assertIn("Login denied", body)
        self.assertFalse(self.broker.seen[-1]["approve"])
        # only the signed-in user's logins are ever asked for
        self.assertEqual({r["user"] for r in self.broker.seen}, {"alice"})

    def test_csrf_required(self):
        self.sign_in()
        self.assertEqual(self.post(csrf="nope", id="req-1_A", decision="approve")[0], 403)
        self.assertEqual(self.post(id="req-1_A", decision="approve")[0], 403)
        self.assertNotIn("mfa_decide", self.broker.ops())

    def test_post_without_sign_in(self):
        status, h, _ = self.post(csrf="x", id="req-1_A", decision="approve")
        self.assertEqual((status, h["Location"]), (303, "/web/approve"))
        self.assertEqual(self.broker.seen, [])

    def test_approval_needs_mfa_proof(self):
        """allow_without_mfa_proof is for the desktop chooser only: without required_acr or
        required_amr_any no approval page, no sign-in for it, no decision."""
        self.sign_in()
        csrf = self.csrf()
        seen = len(self.broker.seen)
        self.app.cfg.oidc.required_acr, self.app.cfg.oidc.allow_without_mfa_proof = [], True
        FakeIdP.acr = "1"
        for name, request in (("page", lambda: self.fetch("/web/approve")),
                              ("bound page", lambda: self.fetch(f"/web/approve?login={MINE}")),
                              ("decision", lambda: self.post(csrf=csrf, id="req-1_A", decision="approve"))):
            with self.subTest(name), self.assertLogs("fastrdp.webgate", "ERROR") as logs:
                status, h, body = request()
                self.assertEqual(status, 503)
                self.assertIn("not set up correctly", body)
                self.assertIn("allow_without_mfa_proof applies to the desktop chooser only", logs.output[0])
        self.assertEqual(len(self.broker.seen), seen)               # the broker is never asked
        # a sign-in for the approval page that started before the change: refused at the callback
        self.app.cfg.oidc.required_acr = ["mfa"]
        self.jar.clear()
        _, h, _ = self.fetch("/web/approve")
        _, h, _ = self.fetch(h["Location"])                         # IdP "authorize"
        self.app.cfg.oidc.required_acr = []
        with self.assertLogs("fastrdp.webgate", "ERROR"):
            status, _, _ = self.fetch(h["Location"])                # back to /web/callback
        self.assertEqual(status, 503)
        self.assertFalse(self.cookie("fastrdp_web_approve"))

    def test_bad_form(self):
        self.sign_in()
        csrf = self.csrf()
        for form in ({"id": "../x", "decision": "approve"}, {"id": "req-1_A", "decision": "yes"},
                     {"id": "", "decision": "deny"}, {"id": "req-1_A\n", "decision": "deny"}):
            with self.subTest(form):
                self.assertEqual(self.post(csrf=csrf, **form)[0], 400)
        self.assertNotIn("mfa_decide", self.broker.ops())

    def test_nothing_pending(self):
        self.broker.replies["mfa_pending"] = {"ok": True, "user": "alice", "pending": []}
        self.sign_in()
        status, _, body = self.fetch("/web/approve")
        self.assertEqual(status, 200)
        self.assertIn("No RDP login is waiting for your approval", body)
        self.assertNotIn("<form", body)

    def test_several_pending_cannot_be_approved(self):
        self.broker.replies["mfa_pending"]["pending"] = [
            dict(PENDING[0], single_pending_conflict=True),
            dict(PENDING[0], id="req-2", client_address="198.51.100.7", method="tls",
                 single_pending_conflict=True)]
        self.sign_in()
        body = self.fetch("/web/approve")[2]
        self.assertIn("More than one RDP login is waiting", body)
        self.assertIn("198.51.100.7", body)
        self.assertIn("RDP client, password", body)
        self.assertNotIn('value="approve"', body)
        self.assertEqual(body.count('value="deny"'), 2)

    def test_untrusted_values_escaped(self):
        self.broker.replies["mfa_pending"]["pending"] = [
            dict(PENDING[0], client_address="<script>x</script>", method="<b>"),
            dict(PENDING[0], id="bad id\"><script>"),          # not a broker id: left out
            dict(PENDING[0], id="req-1_A\n", code="12\n")]
        self.sign_in()
        body = self.fetch("/web/approve")[2]
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", body)
        self.assertNotIn("<script>", body)
        self.assertEqual(body.count('name="id"'), 2)            # Approve + Deny of the first only

    def test_broker_refusals(self):
        self.sign_in()
        csrf = self.csrf()
        cases = [
            ({"reason": "approval_conflict"}, 409, "More than one RDP login"),
            ({"reason": "approval_finished", "outcome": "expired"}, 409, "has timed out"),
            ({"reason": "approval_finished", "outcome": "approved"}, 409, "already approved"),
            ({"reason": "approval_finished", "outcome": "abandoned"}, 409, "cancelled by the RDP client"),
            ({"reason": "approval_finished"}, 409, "no longer waiting"),
            ({"reason": "approval_unknown"}, 404, "no longer waiting"),
            ({"reason": "denied"}, 403, "refused for your account"),
        ]
        for refusal, status, text in cases:
            with self.subTest(refusal):
                self.broker.replies["mfa_decide"] = {"ok": False, "error": "not decided", **refusal}
                got, _, body = self.post(csrf=csrf, id="req-1_A", decision="approve")
                self.assertEqual(got, status)
                self.assertIn(text, body)
        self.broker.replies["mfa_decide"] = b"garbage\n"
        self.assertEqual(self.post(csrf=csrf, id="req-1_A", decision="approve")[0], 503)
        self.assertTrue(self.cookie("fastrdp_web_approve"))      # none of these drops the sign-in

    def test_stale_sign_in_signs_in_again(self):
        self.sign_in()
        self.broker.replies["mfa_decide"] = {"ok": False, "error": "not decided", "reason": "approval_stale"}
        status, _, body = self.post(csrf=self.csrf(), id="req-1_A", decision="approve")
        self.assertEqual(status, 403)
        self.assertIn("Sign in again", body)
        self.assertFalse(self.cookie("fastrdp_web_approve"))
        status, h, _ = self.fetch("/web/approve")
        self.assertEqual(status, 303)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))
        self.assertEqual(q["prompt"], "login")

    # --------------------------------------------------- login-bound link
    def two_pending(self, **mine):
        """The user's login (MINE, from the QR code) and another one with the same
        password (OTHER); with web_approval_single_pending neither is approvable unbound."""
        self.broker.replies["mfa_pending"]["pending"] = [
            dict(PENDING[0], id=OTHER, client_address="198.51.100.7", method="tls", code="13",
                 single_pending_conflict=True),
            dict(PENDING[0], **{"id": MINE, "code": "42", "single_pending_conflict": True, **mine})]

    def bound_csrf(self, login=MINE):
        body = self.fetch(f"/web/approve?login={login}")[2]
        return body.split('name="csrf" value="')[1].split('"')[0]

    def test_login_id_survives_the_sign_in(self):
        self.two_pending()
        status, h, _ = self.fetch(f"/web/approve?login={MINE}")
        self.assertEqual(status, 303)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))
        self.assertEqual((q["prompt"], q["max_age"]), ("login", "0"))   # still a fresh MFA sign-in
        self.assertNotIn(MINE, h["Location"])                            # the IdP never sees it
        pending = self.app.signer.loads("pending", self.cookie("fastrdp_web_login")[0].value)
        self.assertEqual((pending["a"], pending["l"]), (1, MINE))       # signed, like the return target
        _, h, _ = self.fetch(h["Location"])                 # IdP "authorize"
        status, h, _ = self.fetch(h["Location"])            # back to /web/callback
        self.assertEqual((status, h["Location"]), (303, f"/web/approve?login={MINE}"))
        self.assertNotIn("l", self.app.signer.loads("approve", self.cookie("fastrdp_web_approve")[0].value))
        status, _, body = self.fetch(h["Location"])
        self.assertEqual(status, 200)
        self.assertIn("<h2>This RDP login</h2>", body)
        self.assertEqual(self.broker.seen, [{"op": "mfa_pending", "user": "alice"}])

    def test_login_id_kept_when_sign_in_lacks_mfa(self):
        FakeIdP.acr = "1"
        with self.assertLogs("fastrdp.webgate", "WARNING"):
            status, _, body = self.sign_in(f"/web/approve?login={MINE}")
        self.assertEqual(status, 403)
        self.assertIn(f'<a href="/web/approve?login={MINE}">Sign in again</a>', body)

    def test_bound_login_approvable_while_another_waits(self):
        self.two_pending()
        self.sign_in(f"/web/approve?login={MINE}")
        body = self.fetch(f"/web/approve?login={MINE}")[2]
        mine, others = body.split("<h2>This RDP login</h2>")[1].split("Another login with your password")
        # the login from the QR code first, with Approve and Deny
        self.assertIn("From <b>192.0.2.10</b>", mine)
        self.assertIn("RDP client, Kerberos (NLA), code <b>42</b>", mine)
        self.assertIn(f'name="id" value="{MINE}"', mine)
        self.assertEqual((mine.count('value="approve"'), mine.count('value="deny"')), (1, 1))
        self.assertEqual(mine.count(f'name="login" value="{MINE}"'), 2)
        self.assertIn("somebody sent you this link", mine)
        # the prominent warning above the Approve button, with this login's code next to it
        warning, item = mine.split('<div role="alert"')[1].split("</div>", 1)
        self.assertLess(mine.index('<div role="alert"'), mine.index('value="approve"'))
        self.assertIn("Warning: 2 logins with your account are waiting right now.", warning)
        self.assertIn('Its code is <b style="font-size:1.4em">42</b>: approve it only if <b>your own</b> RDP '
                      "window shows this code.", warning)
        self.assertIn("click <b>Deny</b>", warning)
        self.assertNotIn("13", warning)                              # not the other login's code
        # the other one below, with the warning and Deny only
        self.assertIn("<b>Another login with your password is waiting. Deny it if it is not yours.</b>", body)
        self.assertIn("From <b>198.51.100.7</b>", others)
        self.assertIn("RDP client, password, code <b>13</b>", others)
        self.assertEqual((others.count('value="approve"'), others.count('value="deny"')), (0, 1))
        self.assertNotIn('name="login"', others)
        self.assertIn(f'<a href="/web/approve?login={MINE}">Reload</a>', others)
        self.assertNotIn("More than one RDP login", body)     # the unbound page's refusal

        csrf = self.bound_csrf()
        self.broker.replies["mfa_decide"] = {"ok": True, "approved": True, "others_pending": 1}
        with self.assertLogs("fastrdp.webgate", "INFO") as logs:
            status, _, body = self.post(csrf=csrf, id=MINE, login=MINE, decision="approve")
        self.assertIn("WARNING:fastrdp.webgate:web approval: alice approved an RDP login via the login-bound link "
                      "while 1 other login(s) of the account waited (somebody else with the password?)", logs.output)
        self.assertEqual(status, 200)
        self.assertIn("Login approved", body)
        self.assertEqual(self.broker.seen[-1], {"op": "mfa_decide", "user": "alice", "id": MINE, "approve": True,
                                                "auth_time": self.broker.seen[-1]["auth_time"], "bound": True})
        # bound only for the login the user came with
        for form in ({"id": OTHER, "login": MINE}, {"id": OTHER}, {"id": MINE}, {"id": "req-1_A", "login": "req-1_A"}):
            with self.subTest(form):
                self.post(csrf=csrf, decision="approve", **form)
                self.assertNotIn("bound", self.broker.seen[-1])
        self.post(csrf=csrf, id=OTHER, login=OTHER, decision="deny")    # what a crafted form could say
        self.assertTrue(self.broker.seen[-1]["bound"])                 # Deny is always allowed anyway

    def test_bound_alone(self):
        self.broker.replies["mfa_pending"]["pending"] = [dict(PENDING[0], id=MINE)]
        self.sign_in(f"/web/approve?login={MINE}")
        body = self.fetch(f"/web/approve?login={MINE}")[2]
        self.assertIn("<h2>This RDP login</h2>", body)
        self.assertNotIn("Another login", body)
        self.assertNotIn('role="alert"', body)                       # the warning only while others wait
        self.assertEqual(body.count('value="approve"'), 1)
        with self.assertNoLogs("fastrdp.webgate", "WARNING"):
            self.assertEqual(self.post(csrf=self.bound_csrf(), id=MINE, login=MINE, decision="approve")[0], 200)
        self.broker.replies["mfa_pending"]["pending"] = [dict(PENDING[0], id=MINE, code=None),
                                                         dict(PENDING[0], id=OTHER)]
        body = self.fetch(f"/web/approve?login={MINE}")[2]
        self.assertIn("Approve it only if you started it yourself just now, on your own screen.", body)

    def test_unknown_or_foreign_login_id(self):
        """An id that is not among the signed-in user's pending logins (another user's,
        finished, made up) reads the same: no longer waiting; the user's own pending
        logins follow as on the plain page."""
        self.two_pending()
        self.sign_in(f"/web/approve?login={MINE}")
        for rid in ("BobsLoginIdFromHisQR_x", "AAAAAAAAAAAAAAAAAAAAAA"):
            with self.subTest(rid):
                status, _, body = self.fetch(f"/web/approve?login={rid}")
                self.assertEqual(status, 200)
                self.assertIn("<b>This login is no longer waiting for approval.</b>", body)
                self.assertNotIn("This RDP login", body)
                self.assertNotIn(rid, body)
                self.assertNotIn('value="approve"', body)        # the plain page's single_pending rule
                self.assertIn("More than one RDP login is waiting", body)
        self.broker.replies["mfa_pending"]["pending"] = []
        body = self.fetch(f"/web/approve?login={MINE}")[2]
        self.assertIn("This login is no longer waiting for approval.", body)
        self.assertIn("No RDP login is waiting for your approval", body)
        self.assertNotIn("<form", body)

    def test_malformed_login_id(self):
        for bad in ("../x", "short", "a" * 65, "QRcodeOnMyScreen_0123A%3Cb%3E", "%00" * 20):
            with self.subTest(bad):
                status, h, body = self.fetch(f"/web/approve?login={bad}")
                self.assertEqual(status, 404)                       # no sign-in for it
                self.assertIn("This login is no longer waiting for approval.", body)
                self.assertNotIn("<b>", body.split("<h1>")[1])
                self.assertNotIn("Location", h)
        self.assertEqual(self.broker.seen, [])
        self.assertFalse(self.cookie("fastrdp_web_login"))

    def test_bound_values_escaped(self):
        self.two_pending(client_address="<script>x</script>", method="<b>", code="<i>")
        self.sign_in(f"/web/approve?login={MINE}")
        body = self.fetch(f"/web/approve?login={MINE}")[2]
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", body)
        self.assertNotIn("<script>", body)
        self.assertNotIn("<i>", body)
        self.assertIn("From <b>&lt;script&gt;x&lt;/script&gt;</b>", body.split("This RDP login")[1])

    def test_bound_stale_sign_in_keeps_the_id(self):
        self.two_pending()
        self.sign_in(f"/web/approve?login={MINE}")
        self.broker.replies["mfa_decide"] = {"ok": False, "error": "not decided", "reason": "approval_stale"}
        status, _, body = self.post(csrf=self.bound_csrf(), id=MINE, login=MINE, decision="approve")
        self.assertEqual(status, 403)
        self.assertIn(f'<a href="/web/approve?login={MINE}">Back to the approval page</a>', body)
        self.broker.replies["mfa_decide"] = {"ok": False, "error": "not decided", "reason": "approval_unknown"}
        self.sign_in(f"/web/approve?login={MINE}")
        status, _, body = self.post(csrf=self.bound_csrf(), id=MINE, login=MINE, decision="approve")
        self.assertEqual(status, 404)
        self.assertIn("This login is no longer waiting for approval.", body)

    def test_broker_unavailable(self):
        self.sign_in()
        self.broker.replies["mfa_pending"] = {"ok": False, "error": "access denied", "reason": "denied"}
        status, _, body = self.fetch("/web/approve")
        self.assertEqual(status, 403)
        self.assertIn("refused for your account", body)
        os.unlink(f"{self.tmp}/b.sock")
        self.assertEqual(self.fetch("/web/approve")[0], 503)


class BrokerClientTests(unittest.TestCase):
    def test_ops(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        try:
            b = ApprovalBroker(f"{tmp}/b.sock")
            self.assertEqual(broker_mfa_pending(f"{tmp}/b.sock", "alice"), PENDING)
            self.assertEqual(broker_mfa_decide(f"{tmp}/b.sock", "alice", "req-1_A", False, 1234),
                             {"ok": True, "approved": True})
            broker_mfa_decide(f"{tmp}/b.sock", "alice", MINE, True, 1234, bound=True)
            self.assertEqual(b.seen, [{"op": "mfa_pending", "user": "alice"},
                                      {"op": "mfa_decide", "user": "alice", "id": "req-1_A",
                                       "approve": False, "auth_time": 1234},
                                      {"op": "mfa_decide", "user": "alice", "id": MINE,
                                       "approve": True, "auth_time": 1234, "bound": True}])
            b.replies["mfa_decide"] = {"ok": False, "error": "not decided", "reason": "approval_finished",
                                       "outcome": "denied"}
            with self.assertRaises(BrokerError) as cm:
                broker_mfa_decide(f"{tmp}/b.sock", "alice", "req-1_A", True, 1234)
            self.assertEqual((cm.exception.reason, cm.exception.outcome), ("approval_finished", "denied"))
            b.replies["mfa_pending"] = b"[]\n"                     # JSON, but not an object
            with self.assertRaises(BrokerError) as cm:
                broker_mfa_pending(f"{tmp}/b.sock", "alice")
            self.assertEqual(cm.exception.reason, "unavailable")
            b.srv.close()
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
