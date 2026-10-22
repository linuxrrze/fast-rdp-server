# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Regression tests for webgate branches test_webgate.py does not reach: cookie
signing, config validation, OIDC discovery/ID token edge cases, and the HTTP
error paths (IdP errors, state mismatch, broker refusal, logout, routing)."""

import hashlib
import http.cookiejar
import io
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
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastrdp_webgate import config, guacjson  # noqa: E402
from fastrdp_webgate.app import BrokerError, Webgate, broker_web_token, make_handler  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import OidcError, Provider, pkce_pair  # noqa: E402
from test_webgate import KEY_HEX, FakeIdP, NoRedirect, jwt  # noqa: E402

EXAMPLE = Path(__file__).parent.parent / "config" / "webgate.toml.example"
BASE = {"webgate": {"public_url": "https://rdp"},
        "oidc": {"issuer": "https://idp", "client_id": "c", "required_acr": ["mfa"]}}


def parse(**sections):
    raw = json.loads(json.dumps(BASE))
    for k, v in sections.items():
        raw.setdefault(k, {}).update(v)
    return config.parse(raw)


# ----------------------------------------------------------------- cookies
class SignerTests(unittest.TestCase):
    def setUp(self):
        self.s = Signer("secret")

    def test_roundtrip_and_purpose(self):
        v = self.s.dumps("session", {"user": "alice"}, 60)
        self.assertEqual(self.s.loads("session", v), {"user": "alice"})
        self.assertIsNone(self.s.loads("pending", v))  # a login-state cookie is no session
        self.assertIsNone(Signer("other").loads("session", v))

    def test_expiry(self):
        v = self.s.dumps("session", {"user": "alice"}, 60)
        with mock.patch("fastrdp_webgate.cookies.time.time", return_value=time.time() + 61):
            self.assertIsNone(self.s.loads("session", v))

    def test_tampered_body(self):
        v = self.s.dumps("session", {"user": "alice"}, 60)
        mac = v.split(".")[1]
        import base64
        forged = base64.urlsafe_b64encode(
            json.dumps({"user": "root", "_exp": int(time.time()) + 60}).encode()).rstrip(b"=").decode()
        self.assertIsNone(self.s.loads("session", f"{forged}.{mac}"))

    def test_malformed(self):
        for v in (None, "", "abc", "a.b.c", "!!!.???", "é.é"):
            with self.subTest(v=v):
                self.assertIsNone(self.s.loads("session", v))

    def test_csrf_bound_to_session_and_key(self):
        a = self.s.dumps("session", {"user": "alice"}, 60)
        b = self.s.dumps("session", {"user": "bob"}, 60)
        self.assertNotEqual(self.s.csrf(a), self.s.csrf(b))
        self.assertNotEqual(self.s.csrf(a), Signer("other").csrf(a))
        self.assertEqual(self.s.csrf(a), self.s.csrf(a))


# ------------------------------------------------------------------ config
class ConfigGapTests(unittest.TestCase):
    def test_example_parses(self):
        cfg = config.load(EXAMPLE)
        self.assertEqual(cfg.oidc.required_acr, ["mfa"])
        self.assertEqual(cfg.guacamole.rdp_parameters["color-depth"], "32")

    def test_unknown(self):
        with self.assertRaises(config.ConfigError):
            config.parse({**BASE, "extra": {}})
        with self.assertRaises(config.ConfigError):
            parse(oidc={"typo": 1})

    def test_required(self):
        for sec, key in (("webgate", "public_url"), ("oidc", "issuer"), ("oidc", "client_id")):
            with self.subTest(key=key), self.assertRaises(config.ConfigError):
                parse(**{sec: {key: ""}})

    def test_public_url_https(self):
        with self.assertRaises(config.ConfigError):
            parse(webgate={"public_url": "http://rdp.example.com"})
        parse(webgate={"public_url": "http://localhost:8090"})
        parse(webgate={"public_url": "http://127.0.0.1:8090"})

    def test_rdp_host_and_port(self):
        # the name RDP clients connect to, for the chooser's .rdp downloads
        cfg = parse(webgate={"public_url": "https://web.example.com:8443/x"})
        self.assertEqual((cfg.webgate.rdp_host, cfg.webgate.rdp_port), ("web.example.com", 3389))
        cfg = parse(webgate={"rdp_host": "rdp1.lab.example.com", "rdp_port": 3399})
        self.assertEqual((cfg.webgate.rdp_host, cfg.webgate.rdp_port), ("rdp1.lab.example.com", 3399))
        self.assertEqual(config.load(EXAMPLE).webgate.rdp_host, "rdp1.lab.example.com")
        for bad in ("10.0.0.1", "rdp1.example.com\nusername:s:x", "rdp 1", "-rdp", "rdp1.example.com:3389", 1):
            with self.subTest(host=bad), self.assertRaisesRegex(config.ConfigError, "rdp_host"):
                parse(webgate={"rdp_host": bad})
        for bad in (0, 65536, "3389", True):
            with self.subTest(port=bad), self.assertRaisesRegex(config.ConfigError, "rdp_port"):
                parse(webgate={"rdp_port": bad})

    def test_rdp_audio(self):
        cfg = parse()
        self.assertEqual((cfg.webgate.rdp_audio, cfg.webgate.rdp_audio_input), (True, True))
        cfg = parse(webgate={"rdp_audio": True, "rdp_audio_input": False})
        self.assertEqual((cfg.webgate.rdp_audio, cfg.webgate.rdp_audio_input), (True, False))
        for key in ("rdp_audio", "rdp_audio_input"):
            for bad in ("true", 1, "no"):
                with self.subTest(key=key, value=bad), self.assertRaisesRegex(config.ConfigError, key):
                    parse(webgate={key: bad})

    def test_normalisation(self):
        cfg = parse(webgate={"path_prefix": "web/"}, oidc={"strip_domains": ["Lab.Example.COM"]},
                    guacamole={"rdp_parameters": {"color-depth": 32, "x": True}})
        self.assertEqual(cfg.webgate.path_prefix, "/web")
        self.assertEqual(cfg.oidc.strip_domains, ["lab.example.com"])
        self.assertEqual(cfg.guacamole.rdp_parameters, {"color-depth": "32", "x": "True"})

    def test_read_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "s")
            p.write_text("  value\n")
            self.assertEqual(config.read_secret(str(p)), "value")
            p.write_text("\n")
            with self.assertRaises(config.ConfigError):
                config.read_secret(str(p))


# ------------------------------------------------------------ app helpers
class AppHelperTests(unittest.TestCase):
    def app(self, **sections):
        cfg = parse(**sections)
        return Webgate(cfg, Provider(cfg.oidc, "s"), Signer("x"), guacjson.parse_key(KEY_HEX))

    def test_username_claim(self):
        a = self.app(oidc={"username_claim": "email", "strip_domains": ["lab.example.com"]})
        self.assertEqual(a.username_from_claims({"email": "Bob@LAB.example.com"}), "Bob")
        self.assertIsNone(a.username_from_claims({"preferred_username": "alice"}))  # claim missing
        self.assertIsNone(a.username_from_claims({"email": "a@b@evil.org"}))

    def test_payload_without_pin_or_desktop(self):
        a = self.app(guacamole={"rdp_parameters": {"color-depth": "24"}, "connection_port": 3390})
        data = a.connection_payload("alice", "tok", None)
        params = data["connections"]["Desktop (default)"]["parameters"]
        self.assertEqual(params["ignore-cert"], "true")
        self.assertNotIn("initial-program", params)
        self.assertEqual((params["port"], params["color-depth"], params["security"]), ("3390", "24", "tls"))
        self.assertLessEqual(data["expires"], (time.time() + 31) * 1000)

    def test_rdp_parameters_cannot_override_security_or_pin(self):
        a = self.app(guacamole={"rdp_parameters": {
            "security": "nla", "username": "mallory", "hostname": "evil", "ignore-cert": "true",
            "resize-method": "reconnect"}})
        a.cert_fingerprint = "sha256:aa:bb"
        params = a.connection_payload("alice", "tok", None)["connections"]["Desktop (default)"]["parameters"]
        self.assertEqual((params["security"], params["username"], params["password"]), ("tls", "alice", "tok"))
        self.assertNotEqual(params["hostname"], "evil")
        self.assertNotIn("ignore-cert", params)
        self.assertEqual(params["cert-fingerprints"], "sha256:aa:bb")
        self.assertEqual(params["resize-method"], "reconnect")  # a tuning knob stays overridable

    def test_cookie_flags(self):
        c = self.app().cookie("n", "v", 60)
        for part in ("Path=/web", "HttpOnly", "SameSite=Lax", "Max-Age=60", "Secure"):
            self.assertIn(part, c)
        c = self.app(webgate={"public_url": "http://localhost:1"}).cookie("n", "v", 60)
        self.assertNotIn("Secure", c)


# -------------------------------------------------------------------- OIDC
class OidcGapTests(unittest.TestCase):
    def provider(self, **kw):
        return Provider(config.OidcSection(issuer="https://idp", client_id="web", **kw), "s")

    def test_pkce(self):
        v, c = pkce_pair()
        import base64
        self.assertEqual(c, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode())
        self.assertNotEqual(pkce_pair()[0], v)

    def test_discovery_checks(self):
        p = self.provider()
        good = {"issuer": "https://idp", "authorization_endpoint": "https://idp/a", "token_endpoint": "https://idp/t"}
        for meta in ({**good, "issuer": "https://evil"}, {**good, "token_endpoint": "http://idp/t"},
                     {k: v for k, v in good.items() if k != "authorization_endpoint"}):
            with self.subTest(meta=meta), mock.patch.object(p, "_open", return_value=meta), \
                    self.assertRaises(OidcError):
                p.discover()
        with mock.patch.object(p, "_open", return_value=good):
            p.discover()
        self.assertEqual(p.meta, good)

    def test_open_errors(self):
        p = self.provider()
        req = urllib.request.Request("https://idp/x")
        err = urllib.error.HTTPError("https://idp/x", 401, "no", {}, io.BytesIO(b"denied"))
        self.addCleanup(err.close)
        for exc in (err, urllib.error.URLError("refused"), TimeoutError()):
            with self.subTest(exc=exc), mock.patch("urllib.request.urlopen", side_effect=exc), \
                    self.assertRaises(OidcError):
                p._open(req)

    def test_authorize_and_logout_urls(self):
        p = self.provider(required_acr=["mfa", "gold"])
        p.meta = {"authorization_endpoint": "https://idp/a"}
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(p.authorize_url("https://rdp/cb", "s", "n", "c")).query))
        self.assertEqual((q["acr_values"], q["code_challenge_method"], q["state"]), ("mfa gold", "S256", "s"))
        p2 = self.provider(required_amr_any=["otp"])
        p2.meta = p.meta
        self.assertNotIn("acr_values", p2.authorize_url("https://rdp/cb", "s", "n", "c"))
        self.assertIsNone(p.logout_url("https://rdp/web/"))
        p.meta["end_session_endpoint"] = "https://idp/logout"
        self.assertTrue(p.logout_url("https://rdp/web/").startswith("https://idp/logout?client_id=web&"))

    def test_malformed_id_tokens(self):
        p = self.provider()
        now = 1_800_000_000
        for resp in ({}, {"id_token": 5}, {"id_token": "a.b"}, {"id_token": "a.!!!.c"},
                     {"id_token": jwt({"iss": "https://idp", "aud": "web", "iat": now, "nonce": "n"})},
                     {"id_token": jwt({"iss": "https://idp", "aud": "web", "exp": "never", "iat": now,
                                       "nonce": "n"})}):
            with self.subTest(resp=resp), self.assertRaises(OidcError):
                p.id_token_claims(resp, "n", now)

    def test_amr_and_acr_both_enforced(self):
        p = self.provider(required_acr=["mfa"], required_amr_any=["otp", "hwk"])
        p.check_mfa({"acr": "mfa", "amr": ["pwd", "hwk"]})
        for claims in ({"acr": "mfa", "amr": ["pwd"]}, {"acr": "mfa"}, {"acr": "1", "amr": ["otp"]}):
            with self.subTest(claims=claims), self.assertRaises(OidcError):
                p.check_mfa(claims)


# ------------------------------------------------------------- HTTP paths
class Broker:
    """Unix-socket broker: replies with self.reply (dict) or raw bytes."""

    def __init__(self, path):
        self.reply = {"ok": True, "user": "alice", "token": "fastrdp-web1:TOK", "desktops": ["xfce"]}
        # chooser query (op web_desktops); self.reply answers everything else
        self.desktops_reply = {"ok": True, "user": "alice", "default": "xfce",
                               "desktops": [{"name": "xfce", "label": "XFCE"}]}
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
                r = self.desktops_reply if req.get("op") == "web_desktops" else self.reply
                conn.sendall(r if isinstance(r, bytes) else json.dumps(r).encode() + b"\n")


class HttpGapTests(unittest.TestCase):
    def setUp(self, guac_url="/guacamole/", username_claim="preferred_username"):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        idp = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        FakeIdP.issuer = f"http://127.0.0.1:{idp.server_port}"
        FakeIdP.acr = "mfa"
        threading.Thread(target=idp.serve_forever, args=(0.05,), daemon=True).start()
        self.broker = Broker(f"{self.tmp}/b.sock")
        cfg = config.parse({
            "webgate": {"public_url": "http://127.0.0.1:1", "broker_socket": f"{self.tmp}/b.sock",
                        "desktops": ["xfce"]},
            "oidc": {"issuer": FakeIdP.issuer, "client_id": "fastrdp-web", "required_acr": ["mfa"],
                     "username_claim": username_claim},
            "guacamole": {"url": guac_url},
        })
        self.provider = Provider(cfg.oidc, "csecret")
        self.provider.discover()
        self.key = guacjson.parse_key(KEY_HEX)
        self.app = Webgate(cfg, self.provider, Signer("cookie-secret"), self.key)
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

    def login(self):
        _, h, _ = self.fetch("/web/")
        _, h, _ = self.fetch(h["Location"])
        return self.fetch(h["Location"])

    def csrf(self):
        body = self.fetch("/web/")[2]
        return body.split('name="csrf" value="')[1].split('"')[0]

    def post(self, path, **form):
        return self.fetch(path, urllib.parse.urlencode(form).encode())

    def session_cookies(self):
        return [c for c in self.jar if c.name == "fastrdp_web" and c.value]

    def test_routing_and_headers(self):
        status, h, _ = self.fetch("/web")
        self.assertEqual(status, 303)                      # prefix without slash -> login
        self.assertTrue(h["Location"].startswith(FakeIdP.issuer + "/auth?"))
        status, h, body = self.fetch("/web/healthz")
        self.assertEqual((status, body), (200, "ok"))
        for k in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Cache-Control"):
            self.assertIn(k, h)
        self.assertEqual(self.fetch("/web/nope")[0], 404)
        self.assertEqual(self.fetch("/other/")[0], 404)
        self.assertEqual(self.fetch("/web/logout")[0], 303)
        self.assertEqual(self.post("/web/other", a="b")[0], 404)

    def test_idp_error(self):
        self.fetch("/web/")
        status, _, body = self.fetch("/web/callback?error=access_denied&state=x")
        self.assertEqual(status, 403)
        self.assertIn("access_denied", body)
        self.assertEqual(self.session_cookies(), [])

    def test_state_mismatch_and_missing_pending(self):
        self.assertEqual(self.fetch("/web/callback?code=x&state=y")[0], 400)  # no pending cookie
        _, h, _ = self.fetch("/web/")
        _, h, _ = self.fetch(h["Location"])
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))
        status, _, _ = self.fetch(f"/web/callback?code={q['code']}&state=forged")
        self.assertEqual(status, 400)
        self.assertEqual(self.session_cookies(), [])

    def test_code_replay_refused(self):
        _, h, _ = self.fetch("/web/")
        _, h, _ = self.fetch(h["Location"])
        callback = h["Location"]
        self.assertEqual(self.fetch(callback)[0], 303)
        self.jar.clear()
        self.assertIn(self.fetch(callback)[0], (400, 403))  # pending cookie gone / code used

    def test_pending_cookie_is_no_session(self):
        pending = self.app.signer.dumps("pending", {"user": "alice", "s": "x", "n": "y", "v": "z"}, 600)
        status, _, _ = self.fetch("/web/", headers={"Cookie": f"fastrdp_web={pending}"})
        self.assertEqual(status, 303)

    def test_expired_session(self):
        self.login()
        with mock.patch("fastrdp_webgate.cookies.time.time", return_value=time.time() + 10_000):
            self.assertEqual(self.fetch("/web/")[0], 303)

    def test_broker_refusal_and_outage(self):
        self.login()
        csrf = self.csrf()
        self.broker.reply = {"ok": False, "error": "access denied", "reason": "denied"}
        status, _, body = self.post("/web/connect", csrf=csrf, desktop="")
        self.assertEqual(status, 403)
        self.assertIn("refused for your account", body)
        self.broker.reply = {"ok": False, "error": "access denied", "reason": "not_allowed"}
        status, _, body = self.post("/web/connect", csrf=csrf, desktop="")
        self.assertEqual(status, 403)
        self.assertIn("not allowed", body)
        self.broker.reply = b"garbage\n"
        self.assertEqual(self.post("/web/connect", csrf=csrf, desktop="")[0], 503)
        os.unlink(f"{self.tmp}/b.sock")
        self.assertEqual(self.post("/web/connect", csrf=csrf, desktop="")[0], 503)
        self.assertEqual(self.fetch("/web/")[0], 503)  # chooser

    def test_default_desktop(self):
        self.login()
        status, h, _ = self.post("/web/connect", csrf=self.csrf(), desktop="")
        self.assertEqual(status, 303)
        data = guacjson.decrypt(self.key, urllib.parse.unquote(h["Location"].split("data=", 1)[1]))
        params = data["connections"]["Desktop (default)"]["parameters"]
        self.assertNotIn("initial-program", params)

    def test_desktop_not_offered(self):
        self.login()
        self.assertEqual(self.post("/web/connect", csrf=self.csrf(), desktop="gnome")[0], 400)
        # the chooser asked for the desktop list, but no web token was requested
        self.assertEqual([r["op"] for r in self.broker.seen], ["web_desktops"])

    def test_post_without_session(self):
        status, h, _ = self.post("/web/connect", csrf="x", desktop="xfce")
        self.assertEqual((status, h["Location"]), (303, "/web/"))
        self.assertEqual(self.broker.seen, [])

    def test_oversized_body(self):
        self.login()
        self.assertEqual(self.fetch("/web/connect", b"x" * 5000)[0], 400)

    def test_logout_via_idp(self):
        self.provider.meta["end_session_endpoint"] = FakeIdP.issuer + "/logout"
        self.login()
        status, h, _ = self.post("/web/logout", csrf=self.csrf())
        self.assertEqual(status, 303)
        self.assertTrue(h["Location"].startswith(FakeIdP.issuer + "/logout?"))
        self.assertIn("post_logout_redirect_uri", h["Location"])
        self.assertEqual(self.session_cookies(), [])


class HttpVariantTests(unittest.TestCase):
    """HttpGapTests' server with other settings (not subclassed: no re-run of its tests)."""

    def harness(self, **kw):
        t = HttpGapTests("test_idp_error")
        t.setUp(**kw)
        self.addCleanup(t.tearDown)
        return t

    def test_guacamole_url_with_query(self):
        t = self.harness(guac_url="/guacamole/?ext=json")
        t.login()
        _, h, _ = t.post("/web/connect", csrf=t.csrf(), desktop="xfce")
        self.assertTrue(h["Location"].startswith("/guacamole/?ext=json&data="))

    def test_missing_username_claim_refused(self):
        t = self.harness(username_claim="email")  # FakeIdP sends no email claim
        status, _, _ = t.login()
        self.assertEqual(status, 403)
        self.assertEqual(t.session_cookies(), [])


class BrokerClientTests(unittest.TestCase):
    def test_refused_and_garbage(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        try:
            b = Broker(f"{tmp}/b.sock")
            self.assertEqual(broker_web_token(f"{tmp}/b.sock", "alice")["token"], "fastrdp-web1:TOK")
            b.reply = {"ok": False, "error": "nope"}
            with self.assertRaisesRegex(BrokerError, "nope") as cm:
                broker_web_token(f"{tmp}/b.sock", "alice")
            self.assertEqual(cm.exception.reason, "denied")  # broker without "reason"
            b.reply = {"ok": False, "error": "access denied", "reason": "not_allowed"}
            with self.assertRaises(BrokerError) as cm:
                broker_web_token(f"{tmp}/b.sock", "alice")
            self.assertEqual(cm.exception.reason, "not_allowed")
            b.reply = b"\n"
            with self.assertRaisesRegex(BrokerError, "no answer") as cm:
                broker_web_token(f"{tmp}/b.sock", "alice")
            self.assertEqual(cm.exception.reason, "unavailable")
            self.assertEqual(b.seen[0], {"op": "web_token", "user": "alice"})
            b.srv.close()
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
