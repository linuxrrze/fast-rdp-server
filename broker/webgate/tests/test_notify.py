# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Approval notifications ([notify], docs/notifications.md): config checks, the users'
subscription files (notifystore.py), Web Push encryption and VAPID (webpush.py, RFC 8291
Appendix A, RFC 8292), the ntfy and Web Push requests against local fake servers, the
notifier (rate limit, follow-ups, expired subscriptions, failing backends, broker poll
loop) and the opt-in page /notify (sign-in, CSRF, ntfy topic, browser subscription,
service worker, manifest, icons)."""

import http.cookiejar
import json
import logging
import os
import shutil
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE.parents[1] / "brokerd")]   # fastrdp_broker.qrcode
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from fastrdp_webgate import config, guacjson, notify, pwa, webpush  # noqa: E402
from fastrdp_webgate.app import Webgate, make_handler  # noqa: E402
from fastrdp_webgate.cookies import Signer  # noqa: E402
from fastrdp_webgate.notify import Notifier, RateLimit  # noqa: E402
from fastrdp_webgate.notifystore import MAX_SUBSCRIPTIONS, StoreError, SubscriptionStore, TooManyError  # noqa: E402
from fastrdp_webgate.oidc import Provider  # noqa: E402
from test_approve import ApprovalBroker  # noqa: E402
from test_webgate import KEY_HEX, FakeIdP, NoRedirect  # noqa: E402

# RFC 8291 Appendix A
RFC_PLAINTEXT = b"When I grow up, I want to be a watermelon"
RFC_AS_PRIVATE = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
RFC_AS_PUBLIC = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
RFC_UA_PRIVATE = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
RFC_UA_PUBLIC = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
RFC_AUTH = "BTBZMqHH6r4Tts7J_aSIgg"
RFC_SALT = "DGv6ra1nlYgDCS1FRnbzlw"
RFC_BODY = ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6Tlz"
            "AC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")

PENDING = {"event": "pending", "id": "login-id-123456789012", "user": "alice", "method": "nla",
           "client_address": "192.0.2.10", "created": 1_800_000_000, "timeout_s": 90, "code": "42"}
PUSH_HOST = "updates.push.services.mozilla.com"


def private_key(b64: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(webpush.unb64u(b64), "big"), ec.SECP256R1())


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth: bytes) -> bytes:
    """The browser's side of RFC 8291 (for checking what we send)."""
    salt, (rs, idlen) = body[:16], struct.unpack("!IB", body[16:21])
    as_public, ciphertext = body[21:21 + idlen], body[21 + idlen:]
    assert rs == 4096 and len(ciphertext) <= rs
    secret = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ua_public = webpush.public_bytes(ua_private)

    def hkdf(salt, ikm, info, n):
        return HKDF(hashes.SHA256(), n, salt, info).derive(ikm)
    ikm = hkdf(auth, secret, b"WebPush: info\0" + ua_public + as_public, 32)
    plain = AESGCM(hkdf(salt, ikm, b"Content-Encoding: aes128gcm\0", 16)).decrypt(
        hkdf(salt, ikm, b"Content-Encoding: nonce\0", 12), ciphertext, None)
    assert plain.endswith(b"\x02")
    return plain[:-1]


def browser_subscription(endpoint):
    """A browser's push subscription (its private key kept for decrypting)."""
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    sub = {"type": "webpush", "id": "sub1", "label": "Phone", "endpoint": endpoint,
           "p256dh": webpush.b64u(webpush.public_bytes(ua)), "auth": webpush.b64u(auth)}
    return sub, ua, auth


class Recorder:
    """Local HTTP server that records requests and answers `status` (after `delay`)."""

    def __init__(self, status=200, delay=0.0):
        self.status, self.delay, self.requests = status, delay, []
        rec = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                rec.requests.append((self.path, self.headers, body))     # names case-insensitive
                time.sleep(rec.delay)
                try:
                    self.send_response(rec.status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except OSError:
                    pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, args=(0.05,), daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class SyncPool:
    """Runs the notifier's sends at once (deterministic tests)."""

    def submit(self, fn, *args):
        fn(*args)


def cfg_with(tmp, **notify_cfg):
    return config.parse({
        "webgate": {"public_url": "https://rdp.example.com", "broker_socket": f"{tmp}/b.sock"},
        "oidc": {"issuer": "https://idp", "client_id": "web", "required_acr": ["mfa"]},
        "notify": {"backends": ["ntfy", "webpush"], "state_dir": tmp, "ntfy_url": "https://ntfy.example.com",
                   "vapid_private_key_file": f"{tmp}/vapid.pem", "vapid_subject": "mailto:root@example.com",
                   **notify_cfg},
    })


# ------------------------------------------------------------------ config
class NotifyConfigTests(unittest.TestCase):
    BASE = {"webgate": {"public_url": "https://rdp.example.com"},
            "oidc": {"issuer": "https://idp", "client_id": "web", "required_acr": ["mfa"]}}

    def parse(self, **n):
        return config.parse({**self.BASE, "notify": n})

    def test_off_by_default(self):
        n = config.parse(dict(self.BASE)).notify
        self.assertEqual((n.backends, n.rate(), n.alert_on_deny, n.show_code, n.state_dir),
                         ([], (3, 600), True, True, "/var/lib/fastrdp-webgate"))
        self.assertEqual((n.webpush_allowed_hosts, n.webpush_extra_hosts), (config.DEFAULT_PUSH_HOSTS, []))

    def test_valid(self):
        n = self.parse(backends=["ntfy", "webpush"], ntfy_url="https://ntfy.example.com/",
                       vapid_private_key_file="/etc/fastrdp/webgate-vapid.pem",
                       vapid_subject="mailto:root@rdp.example.com", rate_limit="5/3600",
                       webpush_allowed_hosts=["FCM.googleapis.com"]).notify
        self.assertEqual((n.ntfy_url, n.rate(), n.webpush_allowed_hosts),
                         ("https://ntfy.example.com", (5, 3600), ["fcm.googleapis.com"]))
        self.assertEqual(self.parse(backends=["ntfy"], ntfy_url="http://127.0.0.1:8080").notify.ntfy_url,
                         "http://127.0.0.1:8080")

    def test_extra_push_hosts(self):
        good = {"backends": ["webpush"], "vapid_private_key_file": "/k.pem", "vapid_subject": "mailto:a@b.c"}
        n = self.parse(**good, webpush_extra_hosts=["NTFY.example.com", "fcm.googleapis.com"]).notify
        self.assertEqual(n.webpush_allowed_hosts, config.DEFAULT_PUSH_HOSTS + ["ntfy.example.com"])
        self.assertTrue(webpush.endpoint_allowed("https://ntfy.example.com/upAbC?up=1", n.webpush_allowed_hosts))
        self.assertTrue(webpush.endpoint_allowed("https://fcm.googleapis.com/fcm/send/x", n.webpush_allowed_hosts))
        self.assertFalse(webpush.endpoint_allowed("https://ntfy.example.com:8443/up", n.webpush_allowed_hosts))
        self.assertFalse(webpush.endpoint_allowed("https://ntfy.sh/upAbC", n.webpush_allowed_hosts))
        n = self.parse(**good, webpush_allowed_hosts=["push.apple.com"], webpush_extra_hosts=["ntfy.example.com"]).notify
        self.assertEqual(n.webpush_allowed_hosts, ["push.apple.com", "ntfy.example.com"])
        self.assertEqual(self.parse(**good, webpush_extra_hosts=[]).notify.webpush_allowed_hosts,
                         config.DEFAULT_PUSH_HOSTS)

    def test_invalid(self):
        good = {"vapid_private_key_file": "/k.pem", "vapid_subject": "mailto:a@b.c"}
        cases = [
            ({"backends": ["sms"]}, "backends"),
            ({"backends": "ntfy"}, "backends"),
            ({"backends": ["ntfy", "ntfy"], "ntfy_url": "https://n"}, "backends"),
            ({"backends": ["ntfy"]}, "ntfy_url"),
            ({"backends": ["ntfy"], "ntfy_url": "http://ntfy.example.com"}, "ntfy_url"),
            ({"backends": ["ntfy"], "ntfy_url": "https://n/?x=1"}, "ntfy_url"),
            ({"backends": ["webpush"], "vapid_subject": "mailto:a@b.c"}, "vapid_private_key_file"),
            ({"backends": ["webpush"], "vapid_private_key_file": "/k.pem", "vapid_subject": "root"}, "vapid_subject"),
            ({"backends": ["webpush"], **good, "webpush_allowed_hosts": ["127.0.0.1"]}, "allowed_hosts"),
            ({"backends": ["webpush"], **good, "webpush_allowed_hosts": []}, "allowed_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": ["10.0.0.5"]}, "extra_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": ["https://ntfy.example.com"]}, "extra_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": ["ntfy.example.com:8443"]}, "extra_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": ["*.example.com"]}, "extra_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": ["localhost"]}, "extra_hosts"),
            ({"backends": ["webpush"], **good, "webpush_extra_hosts": "ntfy.example.com"}, "extra_hosts"),
            ({"backends": ["ntfy"], "ntfy_url": "https://n", "state_dir": "rel"}, "state_dir"),
            ({"rate_limit": "3"}, "rate_limit"),
            ({"rate_limit": "0/600"}, "rate_limit"),
            ({"rate_limit": "3/10"}, "rate_limit"),
            ({"rate_limit": 3}, "rate_limit"),
            ({"alert_on_deny": "yes"}, "alert_on_deny"),
            ({"show_code": 1}, "show_code"),
            ({"colour": "red"}, "unknown keys"),
        ]
        for n, match in cases:
            with self.subTest(n), self.assertRaisesRegex(config.ConfigError, match):
                self.parse(**n)
        with self.assertRaisesRegex(config.ConfigError, "https"):
            config.parse({**self.BASE, "webgate": {"public_url": "http://rdp.example.com"},
                          "notify": {"backends": ["webpush"], **good}})


# ------------------------------------------------------------------ store
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.store = SubscriptionStore(self.tmp, clock=lambda: 1_800_000_000)

    def test_add_list_remove(self):
        self.assertEqual(self.store.list("alice"), [])
        a = self.store.add("alice", {"type": "ntfy", "label": "ntfy", "topic": "fastrdp-t1"})
        b = self.store.add("alice", {"type": "webpush", "label": "Phone", "endpoint": "https://p/1",
                                     "p256dh": "k", "auth": "a"})
        self.assertEqual(a["created"], 1_800_000_000)
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual([s["id"] for s in self.store.list("alice")], [a["id"], b["id"]])
        self.assertEqual(self.store.list("bob"), [])
        # one ntfy topic per user, one entry per browser endpoint
        c = self.store.add("alice", {"type": "ntfy", "label": "ntfy", "topic": "fastrdp-t2"})
        d = self.store.add("alice", {"type": "webpush", "label": "Phone 2", "endpoint": "https://p/1",
                                     "p256dh": "k2", "auth": "a2"})
        self.assertEqual([s["id"] for s in self.store.list("alice")], [c["id"], d["id"]])
        self.assertTrue(self.store.remove("alice", c["id"]))
        self.assertFalse(self.store.remove("alice", c["id"]))
        self.assertTrue(self.store.remove("alice", d["id"]))
        self.assertFalse(os.path.exists(f"{self.tmp}/notify/alice.json"))   # nothing left, no file

    def test_permissions(self):
        os.makedirs(f"{self.tmp}/notify", 0o755)
        os.chmod(f"{self.tmp}/notify", 0o755)
        self.store.add("alice@example.com", {"type": "ntfy", "topic": "t"})   # SSSD fully qualified name
        self.assertEqual(stat.S_IMODE(os.stat(f"{self.tmp}/notify").st_mode), 0o700)
        st = os.stat(f"{self.tmp}/notify/alice@example.com.json")
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o600, os.geteuid()))
        self.assertEqual(os.listdir(f"{self.tmp}/notify"), ["alice@example.com.json"])   # no temp files

    def test_bad_names(self):
        for name in ("", "..", ".hidden", "a/b", "../alice", "a\0b", "x" * 300, None, "alice json"):
            with self.subTest(name=name), self.assertRaises(StoreError):
                self.store.list(name)
        with self.assertRaises(StoreError):
            self.store.add("alice", {"type": "sms"})

    def test_symlinks_refused(self):
        os.makedirs(f"{self.tmp}/elsewhere")
        os.symlink(f"{self.tmp}/elsewhere", f"{self.tmp}/notify")
        with self.assertRaises(StoreError):
            self.store.add("alice", {"type": "ntfy", "topic": "t"})
        self.assertEqual(os.listdir(f"{self.tmp}/elsewhere"), [])
        os.unlink(f"{self.tmp}/notify")
        self.store.add("alice", {"type": "ntfy", "topic": "t"})
        with open(f"{self.tmp}/secret", "w") as fh:
            fh.write('{"subscriptions": [{"type": "ntfy", "id": "x", "topic": "stolen"}]}')
        os.symlink(f"{self.tmp}/secret", f"{self.tmp}/notify/bob.json")
        for op in (lambda: self.store.list("bob"), lambda: self.store.add("bob", {"type": "ntfy", "topic": "own"}),
                   lambda: self.store.remove("bob", "x")):
            with self.assertRaises(StoreError):
                op()
        self.assertIn("stolen", Path(f"{self.tmp}/secret").read_text())

    def test_limits_and_garbage(self):
        for i in range(MAX_SUBSCRIPTIONS):
            self.store.add("alice", {"type": "webpush", "endpoint": f"https://p/{i}"})
        with self.assertRaises(TooManyError):
            self.store.add("alice", {"type": "webpush", "endpoint": "https://p/x"})
        Path(f"{self.tmp}/notify/carol.json").write_text("{not json")
        with self.assertRaises(StoreError):
            self.store.list("carol")
        Path(f"{self.tmp}/notify/dave.json").write_text('{"subscriptions": [{"type": "x", "id": "1"}, 5]}')
        self.assertEqual(self.store.list("dave"), [])


# ------------------------------------------------------------------ web push
class WebPushTests(unittest.TestCase):
    def test_rfc8291_appendix_a(self):
        as_key, ua_key = private_key(RFC_AS_PRIVATE), private_key(RFC_UA_PRIVATE)
        self.assertEqual(webpush.b64u(webpush.public_bytes(as_key)), RFC_AS_PUBLIC)
        self.assertEqual(webpush.b64u(webpush.public_bytes(ua_key)), RFC_UA_PUBLIC)
        body = webpush.encrypt(RFC_PLAINTEXT, webpush.unb64u(RFC_UA_PUBLIC), webpush.unb64u(RFC_AUTH),
                               as_private=as_key, salt=webpush.unb64u(RFC_SALT))
        self.assertEqual(webpush.b64u(body), RFC_BODY)
        self.assertEqual(decrypt(body, ua_key, webpush.unb64u(RFC_AUTH)), RFC_PLAINTEXT)

    def test_fresh_keys_and_salt(self):
        sub, ua, auth = browser_subscription("https://p/1")
        a = webpush.encrypt(b"hello", webpush.unb64u(sub["p256dh"]), auth)
        b = webpush.encrypt(b"hello", webpush.unb64u(sub["p256dh"]), auth)
        self.assertNotEqual(a[:16], b[:16])
        self.assertEqual(decrypt(a, ua, auth), b"hello")
        with self.assertRaises(webpush.WebPushError):
            webpush.encrypt(b"x" * (webpush.MAX_PAYLOAD + 1), webpush.unb64u(sub["p256dh"]), auth)
        self.assertLessEqual(len(webpush.encrypt(b"x" * webpush.MAX_PAYLOAD, webpush.unb64u(sub["p256dh"]), auth)),
                             4096)

    def test_vapid_jwt(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = webpush.vapid_jwt(key, "https://fcm.googleapis.com", "mailto:root@example.com", now=1_800_000_000)
        header, claims, sig = token.split(".")
        self.assertEqual(json.loads(webpush.unb64u(header)), {"typ": "JWT", "alg": "ES256"})
        c = json.loads(webpush.unb64u(claims))
        self.assertEqual((c["aud"], c["sub"]), ("https://fcm.googleapis.com", "mailto:root@example.com"))
        self.assertGreater(c["exp"], 1_800_000_000)
        self.assertLessEqual(c["exp"], 1_800_000_000 + 24 * 3600)      # RFC 8292: at most 24 h
        raw = webpush.unb64u(sig)
        self.assertEqual(len(raw), 64)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key.public_key().verify(der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
        self.assertEqual(webpush.origin("https://fcm.googleapis.com:443/fcm/send/abc?x"),
                         "https://fcm.googleapis.com:443")

    def test_load_vapid_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        for fmt in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8):
            pem = key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption())
            self.assertEqual(webpush.public_bytes(webpush.load_vapid_key(pem)), webpush.public_bytes(key))
        other = ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        for bad in (other, b"not a key"):
            with self.assertRaises(webpush.WebPushError):
                webpush.load_vapid_key(bad)

    def test_endpoint_allowed(self):
        hosts = config.DEFAULT_PUSH_HOSTS
        for ok in ("https://fcm.googleapis.com/fcm/send/x", f"https://{PUSH_HOST}/wpush/v2/x",
                   "https://web.push.apple.com/QG", "https://wns2-db5p.notify.windows.com/w/?token=x"):
            self.assertTrue(webpush.endpoint_allowed(ok, hosts), ok)
        for bad in ("http://fcm.googleapis.com/x", "https://127.0.0.1/x", "https://evil.example/x",
                    "https://fcm.googleapis.com.evil.example/x", "https://notfcm.googleapis.com.x/",
                    "https://fcm.googleapis.com:8443/x", "https://user@fcm.googleapis.com/x", "ftp://x",
                    "https://[::1]/x", "https://fcm.googleapis.com:99999/x"):
            self.assertFalse(webpush.endpoint_allowed(bad, hosts), bad)
        self.assertTrue(webpush.endpoint_allowed("https://a.fcm.googleapis.com/x", hosts))   # a subdomain
        self.assertFalse(webpush.endpoint_allowed("https://evilfcm.googleapis.com/x", hosts))

    def test_subscription_keys(self):
        sub, _, _ = browser_subscription("https://p/1")
        webpush.check_subscription_keys(sub["p256dh"], sub["auth"])
        for p256dh, auth in ((sub["p256dh"], "AAAA"), ("BAAA", sub["auth"]), ("!!", sub["auth"]),
                             (webpush.b64u(b"\x04" + b"\x01" * 64), sub["auth"])):
            with self.assertRaises(webpush.WebPushError):
                webpush.check_subscription_keys(p256dh, auth)

    def test_send(self):
        rec = Recorder(status=201)
        self.addCleanup(rec.close)
        key = ec.generate_private_key(ec.SECP256R1())
        sub, ua, auth = browser_subscription(rec.url + "/wpush/v2/abc")
        status = webpush.send(sub, b'{"title":"t"}', key, "mailto:root@example.com", ttl=90, topic="tag1")
        self.assertEqual(status, 201)
        ((path, headers, body),) = rec.requests
        self.assertEqual(path, "/wpush/v2/abc")
        self.assertEqual((headers["Content-Encoding"], headers["TTL"], headers["Urgency"], headers["Topic"]),
                         ("aes128gcm", "90", "high", "tag1"))
        self.assertEqual(decrypt(body, ua, auth), b'{"title":"t"}')
        t, k = headers["Authorization"].removeprefix("vapid ").split(", ")
        self.assertEqual(k, "k=" + webpush.b64u(webpush.public_bytes(key)))
        claims = json.loads(webpush.unb64u(t.removeprefix("t=").split(".")[1]))
        self.assertEqual(claims["aud"], rec.url)
        rec.status = 410
        self.assertEqual(webpush.send(sub, b"x", key, "mailto:a@b.c", ttl=1), 410)
        rec.status = 302                                # never followed
        self.assertEqual(webpush.send(sub, b"x", key, "mailto:a@b.c", ttl=1), 302)


# ------------------------------------------------------------------ notifier
class NotifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.ntfy, self.push = Recorder(), Recorder(status=201)
        self.addCleanup(self.ntfy.close)
        self.addCleanup(self.push.close)
        self.cfg = cfg_with(self.tmp, ntfy_url=self.ntfy.url)
        self.store = SubscriptionStore(self.tmp)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.t = 1000.0
        self.notifier = Notifier(self.cfg, self.store, vapid_key=self.key, ntfy_token="tk_secret",
                                 clock=lambda: self.t)
        self.notifier.pool = SyncPool()
        self.notifier.rate = RateLimit(100, 600, clock=lambda: self.t)   # test_rate_limit: the configured one
        sub, self.ua, self.auth = browser_subscription(self.push.url + "/push/1")
        self.web = self.store.add("alice", {k: v for k, v in sub.items() if k not in ("id",)})
        self.topic = self.store.add("alice", {"type": "ntfy", "label": "ntfy", "topic": "fastrdp-abc"})

    def pushed(self, i=-1):
        return json.loads(decrypt(self.push.requests[i][2], self.ua, self.auth))

    def event(self, **kw):
        return {**PENDING, **kw}

    def test_pending(self):
        self.notifier.handle(self.event())
        ((path, headers, body),) = self.ntfy.requests
        self.assertEqual(path, "/fastrdp-abc")
        self.assertEqual((headers["Title"], headers["Click"], headers["Priority"], headers["Authorization"]),
                         ("fastrdp sign-in", "https://rdp.example.com/web/approve", "high", "Bearer tk_secret"))
        text = body.decode()
        self.assertIn("approve your RDP login from 192.0.2.10 (code 42)", text)
        self.assertIn("alice", text)
        pushed = self.pushed()
        self.assertEqual(pushed["url"], "https://rdp.example.com/web/approve")
        self.assertEqual(pushed["body"], text)
        self.assertEqual(pushed["tag"], notify.tag_of(PENDING["id"]))
        self.assertEqual(self.push.requests[-1][1]["Topic"], pushed["tag"])
        self.assertEqual(self.push.requests[-1][1]["TTL"], "90")
        # no secrets, no login id, no other link in what leaves the host: the fixed approval
        # page, never the login-bound one (?login=, the waiting screen's QR code), as the
        # login behind a notification may be somebody else's with the user's password
        for data in (body, json.dumps(pushed).encode(), json.dumps(dict(self.push.requests[-1][1])).encode()):
            for secret in (PENDING["id"].encode(), b"tk_secret", self.auth, self.web["auth"].encode()):
                self.assertNotIn(secret, data)
        self.assertEqual(text.count("http"), 0)                  # the link is the Click header only

    def test_show_code_off_and_unknown_address(self):
        self.cfg.notify.show_code = False
        self.notifier.handle(self.event(client_address=None))
        text = self.ntfy.requests[-1][2].decode()
        self.assertNotIn("code", text)
        self.assertIn("an unknown address", text)

    def test_finished(self):
        self.notifier.handle(self.event())
        self.notifier.handle({"event": "finished", "id": PENDING["id"], "user": "alice", "outcome": "approved"})
        self.assertEqual(len(self.ntfy.requests), 1)               # ntfy cannot replace: nothing
        pushed = self.pushed()
        self.assertEqual((pushed["tag"], pushed["url"]), (notify.tag_of(PENDING["id"]), None))
        self.assertIn("192.0.2.10 was approved", pushed["body"])
        for outcome, text in (("denied", "was denied"), ("expired", "not approved in time")):
            with self.subTest(outcome):
                self.notifier.handle(self.event(id="other-" + outcome))
                self.notifier.handle({"event": "finished", "id": "other-" + outcome, "user": "alice",
                                      "outcome": outcome})
                last = self.ntfy.requests[-1]
                self.assertIn(text, last[2].decode())                 # alert_on_deny
                self.assertIn("change your password", last[2].decode())
                self.assertNotIn("Click", last[1])
        self.cfg.notify.alert_on_deny = False
        before = len(self.ntfy.requests)
        self.notifier.handle(self.event(id="quiet"))
        self.notifier.handle({"event": "finished", "id": "quiet", "user": "alice", "outcome": "denied"})
        self.assertEqual(len(self.ntfy.requests), before + 1)      # the pending one only
        self.assertIn("was denied", self.pushed()["body"])           # Web Push still replaces

    def test_finished_without_pending_ignored(self):
        self.notifier.handle({"event": "finished", "id": "never", "user": "alice", "outcome": "denied"})
        self.notifier.handle(self.event(user="bob"))                # no subscriptions
        self.notifier.handle({"event": "finished", "id": PENDING["id"], "user": "bob", "outcome": "denied"})
        for bad in ({"event": "pending"}, {"event": "pending", "id": 5, "user": "alice"},
                    {"event": "pending", "id": "x", "user": "../x"}, {"event": "other", "id": "x", "user": "alice"}):
            self.notifier.handle(bad)
        self.assertEqual((self.ntfy.requests, self.push.requests), ([], []))

    def test_rate_limit(self):
        self.notifier.rate = RateLimit(*self.cfg.notify.rate(), clock=lambda: self.t)    # "3/600"
        for i in range(5):
            self.notifier.handle(self.event(id=f"id{i}"))
        bodies = [r[2].decode() for r in self.ntfy.requests]
        self.assertEqual(len(bodies), 4)                            # 3 + one alert, then nothing
        self.assertEqual(bodies[3], notify.ALERT)
        self.assertNotIn("Click", self.ntfy.requests[3][1])
        self.assertIsNone(self.pushed()["url"])
        self.t += 600                                               # a new window
        self.notifier.handle(self.event(id="later"))
        self.assertIn("approve your RDP login", self.ntfy.requests[-1][2].decode())
        rl = RateLimit(1, 60, clock=lambda: 0)
        self.assertEqual([rl.check("a"), rl.check("a"), rl.check("a"), rl.check("b")],
                         ["send", "alert", "drop", "send"])

    def test_expired_subscription_removed(self):
        for status, removed in ((413, False), (429, False), (500, False), (404, True)):
            with self.subTest(status):
                self.push.status = status
                self.notifier.handle(self.event(id=f"s{status}"))
                self.assertEqual(any(s["type"] == "webpush" for s in self.store.list("alice")), not removed)
        self.web = self.store.add("alice", {"type": "webpush", "label": "x", "endpoint": self.push.url + "/push/2",
                                            "p256dh": self.web["p256dh"], "auth": self.web["auth"]})
        self.push.status = 410
        self.notifier.handle(self.event(id="gone"))
        self.assertEqual([s["type"] for s in self.store.list("alice")], ["ntfy"])

    def test_backend_failures_never_raise(self):
        self.ntfy.status = 403
        with self.assertLogs("fastrdp.webgate.notify", "WARNING") as logs:
            self.notifier.handle(self.event())
        self.assertTrue(any("HTTP 403" in line and "ntfy_token_file" in line for line in logs.output), logs.output)
        self.ntfy.close()                                           # connection refused
        self.store.add("alice", {"type": "webpush", "label": "bad", "endpoint": self.push.url + "/push/3",
                                 "p256dh": "broken", "auth": "x"})
        with self.assertLogs("fastrdp.webgate.notify", "WARNING"):
            self.notifier.handle(self.event(id="again"))
        with mock.patch.object(self.notifier, "pending_message", side_effect=RuntimeError("boom")), \
                self.assertLogs("fastrdp.webgate.notify", "ERROR"):
            self.notifier.handle(self.event(id="boom"))
        with mock.patch.object(self.store, "list", side_effect=OSError("disk")):
            self.notifier.handle(self.event(id="disk"))

    def test_timeouts_in_the_pool(self):
        self.notifier.pool = notify.ThreadPoolExecutor(max_workers=2)
        self.ntfy.delay = 1.5
        with mock.patch.object(notify, "SEND_TIMEOUT", 0.3), self.assertLogs("fastrdp.webgate.notify", "WARNING"):
            started = time.monotonic()
            self.notifier.handle(self.event())
            self.assertLess(time.monotonic() - started, 0.2)        # handing over never waits
            self.notifier.pool.shutdown(wait=True)
        self.assertLess(time.monotonic() - started, 1.4)
        self.assertEqual(len(self.push.requests), 1)

    def test_only_configured_backends(self):
        self.cfg.notify.backends = ["webpush"]
        self.notifier.handle(self.event())
        self.assertEqual((len(self.ntfy.requests), len(self.push.requests)), (0, 1))

    def test_test_message(self):
        self.assertEqual(self.notifier.test("alice"), 2)
        self.assertIn("Test", self.ntfy.requests[-1][2].decode())
        self.assertEqual(self.notifier.test("nobody"), 0)


class PollLoopTests(unittest.TestCase):
    def test_poll_and_backoff(self):
        tmp = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, tmp)
        cfg = cfg_with(tmp, backends=["ntfy"])
        notifier = Notifier(cfg, SubscriptionStore(tmp))
        seen = []
        notifier.handle = seen.append
        # broker away: the loop keeps trying, quietly
        with self.assertLogs("fastrdp.webgate.notify", "WARNING") as logs:
            t = notifier.start()
            time.sleep(0.3)
        self.assertEqual(sum("not reachable" in line for line in logs.output), 1)
        notifier.stop.set()
        t.join(3)
        self.assertFalse(t.is_alive())
        # a broker that answers: events handed on, the request as protocol.py says
        requests = []
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(f"{tmp}/b.sock")
        srv.listen(5)

        def broker():
            replies = [{"ok": True, "events": [PENDING, "junk"]}, {"ok": True, "events": []}]
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                with conn:
                    requests.append(json.loads(conn.makefile().readline()))
                    conn.sendall(json.dumps(replies[min(len(requests) - 1, 1)]).encode() + b"\n")
        threading.Thread(target=broker, daemon=True).start()
        notifier.stop.clear()
        t = notifier.start()
        for _ in range(100):
            if seen:
                break
            time.sleep(0.02)
        notifier.stop.set()
        srv.close()
        t.join(3)
        self.assertEqual(seen[0], PENDING)
        self.assertEqual(requests[0], {"op": "mfa_events", "wait_s": 25})
        with self.assertRaises(OSError):
            notify.broker_mfa_events(f"{tmp}/none.sock", 0, 1)


# ------------------------------------------------------------------ files
class PwaTests(unittest.TestCase):
    def test_icons(self):
        for size in (192, 512):
            data, ctype = pwa.static_file(f"icon-{size}.png")
            self.assertEqual(ctype, "image/png")
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack("!II", data[16:24]), (size, size))
        self.assertIsNone(pwa.static_file("../app.py"))
        self.assertIsNone(pwa.static_file("sw.js"))                 # only at <prefix>/sw.js

    def test_manifest(self):
        m = json.loads(pwa.manifest("/web"))
        self.assertEqual((m["start_url"], m["scope"], m["display"]), ("/web/notify", "/web/", "standalone"))
        self.assertEqual({i["sizes"] for i in m["icons"]}, {"any", "192x192", "512x512"})

    def test_qr(self):
        svg = pwa.qr_svg("https://ntfy.example.com/fastrdp-" + "A" * 22)
        self.assertTrue(svg.startswith("<svg") and "<path d=\"M" in svg)
        self.assertIsNone(pwa.qr_svg("x" * 1000))
        with mock.patch.object(pwa, "_qr_encoder", return_value=None):
            self.assertIsNone(pwa.qr_svg("https://x"))


# ------------------------------------------------------------------ pages
class NotifyPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        idp = ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
        FakeIdP.issuer = f"http://127.0.0.1:{idp.server_port}"
        FakeIdP.acr, FakeIdP.auth_age, FakeIdP.authorize_queries = "mfa", 0, []
        threading.Thread(target=idp.serve_forever, args=(0.05,), daemon=True).start()
        self.broker = ApprovalBroker(f"{self.tmp}/b.sock")
        self.broker.replies["web_desktops"] = {"ok": True, "user": "alice", "default": "xfce",
                                               "desktops": [{"name": "xfce", "label": "Xfce"}]}
        self.ntfy = Recorder()
        cfg = config.parse({
            "webgate": {"public_url": "http://127.0.0.1:1", "broker_socket": f"{self.tmp}/b.sock"},
            "oidc": {"issuer": FakeIdP.issuer, "client_id": "fastrdp-web", "required_acr": ["mfa"]},
            "notify": {"backends": ["ntfy", "webpush"], "state_dir": self.tmp, "ntfy_url": self.ntfy.url,
                       "vapid_private_key_file": "/unused", "vapid_subject": "mailto:root@example.com"},
        })
        provider = Provider(cfg.oidc, "csecret")
        provider.discover()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.notifier = Notifier(cfg, SubscriptionStore(self.tmp), vapid_key=self.key)
        self.notifier.pool = SyncPool()
        self.app = Webgate(cfg, provider, Signer("cookie-secret"), guacjson.parse_key(KEY_HEX),
                           notifier=self.notifier)
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
        self.ntfy.close()
        self.broker.srv.close()
        shutil.rmtree(self.tmp)

    def fetch(self, url, data=None):
        req = urllib.request.Request(url if url.startswith("http") else self.base + url, data=data)
        try:
            r = self.opener.open(req)
            return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers, e.read()

    def sign_in(self, path="/web/notify"):
        _, h, _ = self.fetch(path)
        _, h, _ = self.fetch(h["Location"])                 # IdP "authorize"
        return self.fetch(h["Location"])                    # back to /web/callback

    def page(self):
        status, headers, body = self.fetch("/web/notify")
        self.assertEqual(status, 200)
        return headers, body.decode()

    def csrf(self):
        return self.page()[1].split('name="csrf" value="')[1].split('"')[0]

    def post(self, path="/web/notify", **form):
        return self.fetch(path, urllib.parse.urlencode(form).encode())

    def test_sign_in_returns_to_the_page(self):
        status, h, _ = self.fetch("/web/notify")
        self.assertEqual(status, 303)
        self.assertTrue(h["Location"].startswith(FakeIdP.issuer + "/auth?"))
        self.assertNotIn("prompt", FakeIdP.authorize_queries[-1] if FakeIdP.authorize_queries else {})
        status, h, _ = self.sign_in()
        self.assertEqual((status, h["Location"]), (303, "/web/notify"))
        headers, body = self.page()
        self.assertIn("Signed in as <b>alice</b>", body)
        self.assertIn("http://127.0.0.1:1/web/approve", body)
        self.assertIn("None yet.", body)
        self.assertIn(f'data-key="{self.notifier.vapid_public_key}"', body)
        self.assertIn('<script src="/web/static/notify.js" defer></script>', body)
        self.assertIn('<link rel="manifest" href="/web/manifest.webmanifest">', body)
        self.assertNotIn("<script>", body)                      # no inline scripts
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.broker.seen[-1], {"op": "web_desktops", "user": "alice"})
        # the chooser links to it
        self.assertIn("/web/notify", self.fetch("/web/")[2].decode())

    def test_sign_in_without_mfa(self):
        FakeIdP.acr = "1"
        with self.assertLogs("fastrdp.webgate", "WARNING") as logs:
            status, _, body = self.sign_in()
        body = body.decode()
        self.assertEqual(status, 403)
        self.assertIn("<title>Second factor required</title>", body)
        self.assertIn(f'(<a href="{FakeIdP.issuer}/account">', body)
        self.assertIn('<a href="/web/notify?login=fresh">Sign in again</a>', body)
        self.assertIn("OIDC login of alice refused: acr '1' does not prove MFA", logs.output[0])
        # sign in again: fresh at the IdP, back to the opt-in page
        FakeIdP.acr = "mfa"
        status, h, _ = self.sign_in("/web/notify?login=fresh")
        self.assertEqual(FakeIdP.authorize_queries[-1]["prompt"], "login")
        self.assertEqual((status, h["Location"]), (303, "/web/notify"))
        self.assertIn("Signed in as <b>alice</b>", self.page()[1])

    def test_approval_sign_in_is_not_enough(self):
        appr = self.app.signer.dumps("approve", {"user": "alice", "auth_time": int(time.time())}, 300)
        req = urllib.request.Request(self.base + "/web/notify", headers={"Cookie": f"fastrdp_web_approve={appr}"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.build_opener(NoRedirect).open(req)
        self.assertEqual(cm.exception.code, 303)
        cm.exception.close()

    def test_ntfy_topic(self):
        self.sign_in()
        status, h, _ = self.post(csrf=self.csrf(), action="ntfy-on")
        self.assertEqual((status, h["Location"]), (303, "/web/notify?m=ntfy"))
        (sub,) = self.notifier.store.list("alice")
        self.assertRegex(sub["topic"], r"^fastrdp-[A-Za-z0-9_-]{22}$")
        body = self.fetch("/web/notify?m=ntfy")[2].decode()
        self.assertIn("ntfy is set up", body)
        self.assertIn(f"{self.ntfy.url}/{sub['topic']}", body)
        self.assertIn("<svg", body)                                 # the QR code
        self.assertIn("ntfy://127.0.0.1:", body)
        self.post(csrf=self.csrf(), action="test")
        self.assertEqual(self.ntfy.requests[-1][0], "/" + sub["topic"])
        self.post(csrf=self.csrf(), action="ntfy-on")              # a new topic replaces it
        (new,) = self.notifier.store.list("alice")
        self.assertNotEqual(new["topic"], sub["topic"])
        status, h, _ = self.post(csrf=self.csrf(), action="remove", id=new["id"])
        self.assertEqual(h["Location"], "/web/notify?m=removed")
        self.assertEqual(self.notifier.store.list("alice"), [])

    def test_csrf_required(self):
        self.sign_in()
        for form in ({"action": "ntfy-on"}, {"action": "ntfy-on", "csrf": "nope"}):
            self.assertEqual(self.post(**form)[0], 403)
        sub, _, _ = browser_subscription(f"https://{PUSH_HOST}/wpush/v2/x")
        self.assertEqual(self.post("/web/notify/webpush", csrf="nope", endpoint=sub["endpoint"],
                                   p256dh=sub["p256dh"], auth=sub["auth"])[0], 403)
        self.assertEqual(self.notifier.store.list("alice"), [])
        self.assertEqual(self.post(csrf=self.csrf(), action="frobnicate")[0], 400)

    def test_without_sign_in(self):
        for path in ("/web/notify", "/web/notify/webpush"):
            status, h, _ = self.post(path, csrf="x", action="ntfy-on")
            self.assertEqual((status, h["Location"]), (303, "/web/"))
        self.assertFalse(os.path.exists(f"{self.tmp}/notify"))

    def test_webpush_subscription(self):
        self.sign_in()
        csrf = self.csrf()
        sub, _, _ = browser_subscription(f"https://{PUSH_HOST}/wpush/v2/x")
        form = {"csrf": csrf, "endpoint": sub["endpoint"], "p256dh": sub["p256dh"], "auth": sub["auth"],
                "label": "Phone <b>"}
        status, h, body = self.post("/web/notify/webpush", **form)
        self.assertEqual((status, body), (200, b"ok"))
        (stored,) = self.notifier.store.list("alice")
        self.assertEqual((stored["endpoint"], stored["label"]), (sub["endpoint"], "Phone b"))
        page = self.page()[1]
        self.assertIn("Phone b (browser, since", page)
        import hashlib
        self.assertIn(hashlib.sha256(sub["endpoint"].encode()).hexdigest()[:16], page)
        for bad, status in (({"endpoint": "http://127.0.0.1:8080/x"}, 400),
                            ({"endpoint": "https://intranet.example/x"}, 400),
                            ({"p256dh": "AAAA"}, 400), ({"auth": ""}, 400)):
            with self.subTest(bad):
                self.assertEqual(self.post("/web/notify/webpush", **{**form, **bad})[0], status)
        self.assertEqual(len(self.notifier.store.list("alice")), 1)

    def test_static_files(self):
        cases = {"/web/sw.js": "text/javascript; charset=utf-8",
                 "/web/manifest.webmanifest": "application/manifest+json",
                 "/web/static/notify.js": "text/javascript; charset=utf-8",
                 "/web/static/icon.svg": "image/svg+xml",
                 "/web/static/icon-192.png": "image/png"}
        for path, ctype in cases.items():
            with self.subTest(path):
                status, h, body = self.fetch(path)              # no sign-in needed
                self.assertEqual((status, h["Content-Type"], h["Cache-Control"]), (200, ctype, "no-cache"))
                self.assertEqual(h["X-Content-Type-Options"], "nosniff")
                self.assertTrue(body)
        self.assertIn(b"notificationclick", self.fetch("/web/sw.js")[2])
        script = self.fetch("/web/static/notify.js")[2].decode()
        self.assertIn("On Android without Google services, use the ntfy app (F-Droid), or IronFox/Fennec "
                      "with a UnifiedPush app.", script.replace('" +\n    "', ""))
        self.assertNotIn("innerHTML", script)                  # messages go in as text only
        self.assertEqual(self.fetch("/web/static/../app.py")[0], 404)
        self.assertEqual(self.fetch("/web/static/nothing.js")[0], 404)

    def test_off_without_backends(self):
        self.app.notifier = None
        for path in ("/web/notify", "/web/sw.js", "/web/manifest.webmanifest", "/web/static/notify.js"):
            self.assertEqual(self.fetch(path)[0], 404, path)
        self.assertEqual(self.post(csrf="x", action="test")[0], 404)

    def test_account_from_the_broker(self):
        """Stored under the account the broker resolves (its events name that one)."""
        self.broker.replies["web_desktops"]["user"] = "alice@example.com"
        self.sign_in()
        self.post(csrf=self.csrf(), action="ntfy-on")
        self.assertEqual(len(self.notifier.store.list("alice@example.com")), 1)
        self.broker.replies["web_desktops"] = {"ok": False, "error": "access denied", "reason": "not_allowed"}
        self.assertEqual(self.fetch("/web/notify")[0], 403)
        self.broker.replies["web_desktops"] = {"ok": True, "user": "../etc", "desktops": []}
        self.assertEqual(self.fetch("/web/notify")[0], 403)

    def test_approve_page_shows_the_code(self):
        self.broker.replies["mfa_pending"]["pending"][0]["code"] = "42"
        self.broker.replies["mfa_pending"]["pending"].append(
            dict(self.broker.replies["mfa_pending"]["pending"][0], id="req-2", code="<b>"))
        self.sign_in("/web/approve")
        body = self.fetch("/web/approve")[2].decode()
        self.assertIn("code <b>42</b>", body)
        self.assertNotIn("code <b><b>", body)


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
