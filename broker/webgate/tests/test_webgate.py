# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Tests for fastrdp-webgate: Guacamole crypto parity, ID token checks, full browser flow."""

import base64
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastrdp_webgate import config, guacjson  # noqa: E402
from fastrdp_webgate.app import Webgate, make_handler  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.oidc import OidcError, Provider  # noqa: E402

KEY_HEX = "4c0b569e4c96df157eee1b65dd0e4d41"
REF_SCRIPT = os.environ.get("GUAC_ENCRYPT_JSON")  # guacamole-client doc/encrypt-json.sh


class GuacJsonTests(unittest.TestCase):
    def test_roundtrip(self):
        key = guacjson.parse_key(KEY_HEX)
        data = {"username": "alice", "expires": 1, "connections": {}}
        self.assertEqual(guacjson.decrypt(key, guacjson.encrypt(key, data)), data)

    def test_tamper_detected(self):
        key = guacjson.parse_key(KEY_HEX)
        blob = guacjson.encrypt(key, {"username": "alice"})
        other = guacjson.encrypt(guacjson.parse_key("00" * 16), {"username": "alice"})
        with self.assertRaises(ValueError):
            guacjson.decrypt(key, other)
        self.assertNotEqual(blob, other)

    @unittest.skipUnless(shutil.which("openssl"), "openssl CLI needed")
    def test_matches_guacamole_reference(self):
        """Byte-identical to guacamole-client's encrypt-json.sh (HMAC + AES-128-CBC, IV 0)."""
        payload = {"username": "alice", "expires": 1767225600000,
                   "connections": {"d": {"protocol": "rdp", "parameters": {"hostname": "127.0.0.1"}}}}
        ours = guacjson.encrypt(guacjson.parse_key(KEY_HEX), payload)
        with tempfile.NamedTemporaryFile("wb", suffix=".json") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")).encode())
            fh.flush()
            if REF_SCRIPT:
                ref = subprocess.run(["sh", REF_SCRIPT, KEY_HEX, fh.name], capture_output=True,
                                     check=True).stdout
            else:  # the same two openssl commands the reference script runs
                sig = subprocess.run(["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt",
                                      f"hexkey:{KEY_HEX}", "-binary", fh.name],
                                     capture_output=True, check=True).stdout
                ref = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-K", KEY_HEX, "-iv", "0" * 32,
                                      "-nosalt", "-a"], input=sig + open(fh.name, "rb").read(),
                                     capture_output=True, check=True).stdout
        self.assertEqual(ours, ref.decode().replace("\n", ""))

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            guacjson.parse_key("abcd")


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.c2ln"


class IdTokenTests(unittest.TestCase):
    def setUp(self):
        self.p = Provider(config.OidcSection(issuer="https://idp", client_id="web",
                                             required_acr=["mfa"]), "s")
        self.now = 1_800_000_000
        self.good = {"iss": "https://idp", "aud": "web", "exp": self.now + 300, "iat": self.now,
                     "nonce": "n1", "acr": "mfa", "preferred_username": "alice"}

    def claims(self, **over):
        return self.p.id_token_claims({"id_token": jwt({**self.good, **over})}, "n1", self.now)

    def test_good(self):
        self.assertEqual(self.claims()["preferred_username"], "alice")

    def test_rejections(self):
        for over in ({"iss": "https://evil"}, {"aud": "other"}, {"exp": self.now - 3600},
                     {"nonce": "n2"}, {"iat": self.now + 3600}, {"aud": ["web", "x"]}):
            with self.subTest(over=over), self.assertRaises(OidcError):
                self.claims(**over)

    def test_azp_with_multiple_audiences(self):
        self.assertTrue(self.claims(aud=["web", "x"], azp="web"))

    def test_mfa_required(self):
        self.p.check_mfa(self.claims())
        with self.assertRaises(OidcError):
            self.p.check_mfa(self.claims(acr="1"))

    def test_amr_must_be_a_list(self):
        p = Provider(config.OidcSection(issuer="https://idp", client_id="web", required_amr_any=["otp"]), "s")
        p.check_mfa({"amr": ["pwd", "otp"]})
        with self.assertRaises(OidcError):
            p.check_mfa({"amr": "otp"})  # a string must not match character-wise


class ConfigTests(unittest.TestCase):
    base = {"webgate": {"public_url": "https://rdp"}, "oidc": {"issuer": "https://idp", "client_id": "c"}}

    def test_mfa_proof_required(self):
        with self.assertRaises(config.ConfigError):
            config.parse(self.base)
        config.parse({**self.base, "oidc": {**self.base["oidc"], "required_acr": ["mfa"]}})
        config.parse({**self.base, "oidc": {**self.base["oidc"], "allow_without_mfa_proof": True}})

    def oidc(self, **kw):
        return {**self.base, "oidc": {**self.base["oidc"], **kw}}

    def test_single_factor_amr_refused(self):
        # required_amr_any accepts any listed value, so "pwd" would admit password-only logins
        # and "user"/"pin" a passkey without any proof of possession beyond presence.
        for weak in ("pwd", "kba", "pin", "user", "wia", "rba", "geo"):
            with self.subTest(weak=weak), self.assertRaises(config.ConfigError):
                config.parse(self.oidc(required_amr_any=["otp", weak]))

    def test_passkey_amr_values_accepted(self):
        cfg = config.parse(self.oidc(required_amr_any=["otp", "hwk", "swk", "mfa"]))
        p = Provider(cfg.oidc, "s")
        for amr in (["mfa"], ["hwk"], ["swk", "user"], ["pwd", "otp"]):
            p.check_mfa({"amr": amr})
        for amr in (["pwd"], ["user", "pin"], []):
            with self.subTest(amr=amr), self.assertRaises(OidcError):
                p.check_mfa({"amr": amr})

    def test_acr_zero_refused(self):
        with self.assertRaises(config.ConfigError):
            config.parse(self.oidc(required_acr=["mfa", "0"]))


class UsernameTests(unittest.TestCase):
    def app(self):
        cfg = config.parse({"webgate": {"public_url": "https://rdp"},
                            "oidc": {"issuer": "https://idp", "client_id": "c", "required_acr": ["mfa"],
                                     "strip_domains": ["Lab.Example.com"]}})
        return Webgate(cfg, Provider(cfg.oidc, "s"), Signer("x"), guacjson.parse_key(KEY_HEX))

    def test_domains(self):
        a = self.app()
        u = lambda v: a.username_from_claims({"preferred_username": v})  # noqa: E731
        self.assertEqual(u("alice"), "alice")
        self.assertEqual(u("alice@lab.example.com"), "alice")
        self.assertIsNone(u("alice@gmail.com"))
        self.assertIsNone(u("alice\n"))
        self.assertIsNone(u("../root"))

    def test_pinned_certificate(self):
        a = self.app()
        a.cert_fingerprint = "sha256:aa:bb"
        params = a.connection_payload("alice", "t", None)["connections"]["Desktop (default)"]["parameters"]
        self.assertEqual(params["cert-fingerprints"], "sha256:aa:bb")
        self.assertNotIn("ignore-cert", params)


# ------------------------------------------------------------------ full flow
class FakeIdP(BaseHTTPRequestHandler):
    """Discovery, authorize (auto-approves), token endpoint."""
    codes: dict = {}
    issuer = ""
    acr = "mfa"
    auth_age = 0          # seconds since the "authentication" (auth_time); None: no claim
    authorize_queries: list = []

    def log_message(self, *a):
        pass

    def reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            meta = {"issuer": self.issuer, "authorization_endpoint": self.issuer + "/auth",
                    "token_endpoint": self.issuer + "/token"}
            return self.reply(200, json.dumps(meta).encode())
        if u.path == "/auth":
            assert q["code_challenge_method"] == "S256" and q.get("acr_values") == "mfa"
            code = os.urandom(8).hex()
            FakeIdP.codes[code] = q
            FakeIdP.authorize_queries.append(q)
            loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
            return self.reply(302, b"", [("Location", loc)])
        self.reply(404)

    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        q = FakeIdP.codes.pop(form["code"], None)
        import hashlib
        ok = q and form["client_secret"] == "csecret" and base64.urlsafe_b64encode(
            hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode() == q["code_challenge"]
        if not ok:
            return self.reply(400, b'{"error":"invalid_grant"}')
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": "fastrdp-web", "exp": now + 300, "iat": now,
                  "nonce": q["nonce"], "acr": FakeIdP.acr, "preferred_username": "alice"}
        if FakeIdP.auth_age is not None:
            claims["auth_time"] = now - FakeIdP.auth_age
        tok = jwt(claims)
        self.reply(200, json.dumps({"id_token": tok, "access_token": "x"}).encode())


def fake_broker(path, seen, allowed=("xfce", "gnome"), prefs=None):
    """allowed: desktops the broker permits this user (a mutable list may change later);
    prefs: user -> desktop for RDP logins (web_set_desktop)."""
    prefs = {} if prefs is None else prefs
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(5)

    def run():
        while True:
            conn, _ = srv.accept()
            req = json.loads(conn.makefile().readline())
            seen.append(req)
            if req["op"] == "web_desktops":
                chosen = prefs.get(req["user"])
                reply = {"ok": True, "user": req["user"], "rdp_desktop": chosen,
                         "default": chosen or (allowed[0] if allowed else ""),
                         "desktops": [{"name": d, "label": d.upper()} for d in allowed]}
            elif req["op"] == "web_set_desktop":
                if req["desktop"] is not None and req["desktop"] not in allowed:
                    reply = {"ok": False, "error": "access denied", "reason": "not_allowed"}
                else:
                    prefs[req["user"]] = req["desktop"]
                    reply = {"ok": True, "user": req["user"], "rdp_desktop": req["desktop"]}
            else:
                reply = {"ok": True, "user": req["user"], "token": "fastrdp-web1:TOK",
                         "desktops": list(allowed)}
            conn.sendall(json.dumps(reply).encode() + b"\n")
            conn.close()
    threading.Thread(target=run, daemon=True).start()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        idp = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        FakeIdP.issuer = f"http://127.0.0.1:{idp.server_port}"
        FakeIdP.acr = "mfa"
        threading.Thread(target=idp.serve_forever, daemon=True).start()
        self.seen = []
        self.allowed = ["xfce", "gnome"]
        self.prefs = {}
        fake_broker(f"{self.tmp}/b.sock", self.seen, self.allowed, self.prefs)
        cfg = config.parse({
            "webgate": {"public_url": "http://127.0.0.1:1", "broker_socket": f"{self.tmp}/b.sock",
                        "desktops": ["xfce", "gnome"], "rdp_host": "rdp1.lab.example.com"},
            "oidc": {"issuer": FakeIdP.issuer, "client_id": "fastrdp-web", "required_acr": ["mfa"]},
            "guacamole": {"url": "/guacamole/", "connection_port": 3389},
        })
        provider = Provider(cfg.oidc, "csecret")
        provider.discover()
        self.key = guacjson.parse_key(KEY_HEX)
        app = Webgate(cfg, provider, Signer("cookie-secret"), self.key)
        web = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        threading.Thread(target=web.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{web.server_port}"
        app.redirect_uri = self.base + "/web/callback"  # public_url points at the test server
        self.servers = [idp, web]
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        shutil.rmtree(self.tmp)

    def fetch(self, url, data=None):
        try:
            r = self.opener.open(url, data=data)
            return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def login(self):
        status, h, _ = self.fetch(self.base + "/web/")
        self.assertEqual(status, 303)
        status, h, _ = self.fetch(h["Location"])            # IdP "authorize"
        self.assertEqual(status, 302)
        return self.fetch(h["Location"])                   # back to /web/callback

    def test_full_flow_to_guacamole(self):
        status, h, _ = self.login()
        self.assertEqual((status, h["Location"]), (303, "/web/"))
        status, _, body = self.fetch(self.base + "/web/")
        self.assertIn("alice", body)
        csrf = body.split('name="csrf" value="')[1].split('"')[0]
        status, h, _ = self.fetch(self.base + "/web/connect",
                                  urllib.parse.urlencode({"csrf": csrf, "desktop": "gnome"}).encode())
        self.assertEqual(status, 303)
        self.assertTrue(h["Location"].startswith("/guacamole/?data="))
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        blob = urllib.parse.unquote(h["Location"].split("data=", 1)[1])
        data = guacjson.decrypt(self.key, blob)
        params = data["connections"]["Desktop (gnome)"]["parameters"]
        self.assertEqual((data["username"], params["username"], params["password"]),
                         ("alice", "alice", "fastrdp-web1:TOK"))
        self.assertEqual((params["initial-program"], params["security"]), ("fastrdp:gnome", "tls"))
        self.assertLess(data["expires"] / 1000 - time.time(), 31)
        self.assertEqual(self.seen, [{"op": "web_desktops", "user": "alice"},
                                     {"op": "web_token", "user": "alice"}])

    def test_chooser_lists_only_allowed_desktops(self):
        # Regression: the chooser offered every configured desktop, and a desktop the
        # broker does not allow silently started the user's default instead.
        self.allowed[:] = ["xfce"]
        self.login()
        _, _, body = self.fetch(self.base + "/web/")
        self.assertIn('value="xfce" selected>XFCE<', body)
        self.assertNotIn("gnome", body)
        csrf = body.split('name="csrf" value="')[1].split('"')[0]
        status, h, _ = self.fetch(self.base + "/web/connect",
                                  urllib.parse.urlencode({"csrf": csrf, "desktop": "gnome"}).encode())
        self.assertEqual(status, 403)
        self.assertNotIn("Location", h)

    def test_no_allowed_desktop(self):
        self.allowed[:] = []
        self.login()
        status, _, body = self.fetch(self.base + "/web/")
        self.assertEqual(status, 403)
        self.assertIn("No remote desktop", body)

    def test_csrf_required(self):
        self.login()
        status, _, _ = self.fetch(self.base + "/web/connect", b"csrf=nope&desktop=xfce")
        self.assertEqual(status, 403)
        self.assertEqual(self.seen, [])

    def test_unknown_desktop_rejected(self):
        self.login()
        _, _, body = self.fetch(self.base + "/web/")
        csrf = body.split('name="csrf" value="')[1].split('"')[0]
        status, _, _ = self.fetch(self.base + "/web/connect",
                                  urllib.parse.urlencode({"csrf": csrf, "desktop": "../x"}).encode())
        self.assertEqual(status, 400)

    def test_no_mfa_no_session(self):
        FakeIdP.acr = "1"
        status, _, _ = self.login()
        self.assertEqual(status, 403)
        status, h, _ = self.fetch(self.base + "/web/")
        self.assertEqual(status, 303)  # still not logged in -> back to the IdP

    def test_bad_content_length(self):
        self.login()
        req = urllib.request.Request(self.base + "/web/connect", data=b"x", method="POST",
                                     headers={"Content-Length": "-1"})
        status, _, _ = self.fetch(req)
        self.assertEqual(status, 400)

    def test_logout_requires_post_with_csrf(self):
        self.login()
        _, _, body = self.fetch(self.base + "/web/")
        csrf = body.split('name="csrf" value="')[1].split('"')[0]
        self.fetch(self.base + "/web/logout")                      # GET: no effect
        self.assertIn("alice", self.fetch(self.base + "/web/")[2])
        status, h, _ = self.fetch(self.base + "/web/logout", urllib.parse.urlencode({"csrf": csrf}).encode())
        self.assertEqual(status, 303)
        self.assertEqual(self.fetch(self.base + "/web/")[0], 303)  # logged out -> IdP again

    # ------------------------------------------- RDP apps (mstsc, Windows App)
    def csrf(self):
        _, _, body = self.fetch(self.base + "/web/")
        return body.split('name="csrf" value="')[1].split('"')[0]

    def set_rdp_desktop(self, desktop, csrf):
        return self.fetch(self.base + "/web/rdp-desktop",
                          urllib.parse.urlencode({"csrf": csrf, "desktop": desktop}).encode())

    def test_rdp_desktop_set_and_reset(self):
        self.login()
        _, _, body = self.fetch(self.base + "/web/")
        self.assertIn("currently get <b>XFCE</b> (the default)", body)
        self.assertIn('name="desktop" value="gnome"><button type="submit">Use for Remote Desktop logins', body)
        self.assertNotIn("Use the default again", body)
        status, h, _ = self.set_rdp_desktop("gnome", self.csrf())
        self.assertEqual((status, h["Location"]), (303, "/web/"))
        self.assertEqual(self.seen[-1], {"op": "web_set_desktop", "user": "alice", "desktop": "gnome"})
        _, _, body = self.fetch(self.base + "/web/")
        self.assertIn("currently get <b>GNOME</b> (chosen here)", body)
        self.assertIn("GNOME<br><b>used for Remote Desktop logins</b>", body)
        self.assertIn("Use the default again", body)
        status, _, _ = self.set_rdp_desktop("", self.csrf())
        self.assertEqual(status, 303)
        self.assertEqual(self.seen[-1], {"op": "web_set_desktop", "user": "alice", "desktop": None})
        self.assertIn("(the default)", self.fetch(self.base + "/web/")[2])

    def test_rdp_desktop_needs_csrf_and_sign_in(self):
        status, h, _ = self.set_rdp_desktop("gnome", "nope")  # not signed in
        self.assertEqual((status, h["Location"]), (303, "/web/"))
        self.login()
        status, _, _ = self.set_rdp_desktop("gnome", "nope")
        self.assertEqual(status, 403)
        self.assertNotIn("web_set_desktop", [r["op"] for r in self.seen])
        self.assertEqual(self.prefs, {})

    def test_rdp_desktop_refused(self):
        self.login()
        csrf = self.csrf()
        self.assertEqual(self.set_rdp_desktop("../x", csrf)[0], 400)
        self.assertEqual(self.set_rdp_desktop("mate", csrf)[0], 403)  # the broker refuses it
        self.assertEqual(self.prefs, {})

    def test_rdp_file(self):
        self.login()
        status, h, body = self.fetch(self.base + "/web/rdp/gnome.rdp")
        self.assertEqual(status, 200)
        self.assertEqual(h["Content-Type"], "application/x-rdp")
        self.assertEqual(h["Content-Disposition"], 'attachment; filename="rdp1.lab.example.com-gnome.rdp"')
        self.assertEqual(h["Cache-Control"], "no-store")
        lines = body.split("\r\n")
        self.assertEqual(lines[:2], ["full address:s:rdp1.lab.example.com", "alternate shell:s:fastrdp:gnome"])
        for line in ("enablecredsspsupport:i:1", "authentication level:i:2", "prompt for credentials:i:0"):
            self.assertIn(line, lines)
        self.assertEqual(lines[-1], "")
        # nothing about the user, no credentials or tokens
        for word in ("alice", "username", "password", "TOK", "fastrdp-web1", "cookie"):
            self.assertNotIn(word, body.lower() if word.islower() else body)
        self.assertEqual([r["op"] for r in self.seen], ["web_desktops"])  # no token issued

    def test_rdp_file_only_for_allowed_desktops(self):
        self.login()
        status, h, body = self.fetch(self.base + "/web/rdp/mate.rdp")
        self.assertEqual(status, 403)
        self.assertIn("text/html", h["Content-Type"])
        self.assertNotIn("full address", body)
        self.assertEqual(self.fetch(self.base + "/web/rdp/../x.rdp")[0], 404)
        self.assertEqual(self.fetch(self.base + "/web/rdp/gnome")[0], 404)

    def test_rdp_file_needs_sign_in(self):
        status, h, _ = self.fetch(self.base + "/web/rdp/gnome.rdp")
        self.assertEqual((status, h["Location"]), (303, "/web/"))
        self.assertEqual(self.seen, [])

    def test_rdp_section_lists_desktops_not_offered_in_the_browser(self):
        # [webgate] desktops limits the browser path only; RDP logins are not affected.
        self.allowed[:] = ["xfce", "gnome", "plasma"]
        self.login()
        _, _, body = self.fetch(self.base + "/web/")
        self.assertNotIn('<option value="plasma"', body)
        self.assertIn('href="/web/rdp/plasma.rdp"', body)
        self.assertEqual(self.fetch(self.base + "/web/rdp/plasma.rdp")[0], 200)

    def test_forged_session_cookie(self):
        forged = Signer("other-secret").dumps("session", {"user": "root"}, 600)
        req = urllib.request.Request(self.base + "/web/", headers={"Cookie": f"fastrdp_web={forged}"})
        status, h, _ = self.fetch(req)
        self.assertEqual(status, 303)
        self.assertIn("/auth?", h["Location"])


if __name__ == "__main__":
    unittest.main()
