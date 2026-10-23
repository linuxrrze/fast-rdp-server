# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] mode code_or_web: the user types the authenticator code on the proxy's waiting
screen ({"op": "code"} lines, protocol.py) and Keycloak checks it (keycloak_otp.py, a
direct grant with username + code), or approves the login on the webgate's approval page
(passkey); the first success wins. Wrong codes count per login ([mfa] code_attempts) and
per user ([mfa] code_user_failures within code_failure_window); a Keycloak that cannot be
reached costs no attempt. A module without "code_entry": 1 gets the approval page only."""

import asyncio
import base64
import http.server
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

from fastrdp_broker import config, keycloak_otp, ui
from fastrdp_broker.config import KeycloakOtpSection, MfaSection
from fastrdp_broker.keycloak_otp import KeycloakError, KeycloakOtp
from fastrdp_broker.mfa import CodeFailures
from test_web_approval import ADDR, MINIMAL, Clock, _ApprovalHarness

KC = {"issuer": "https://kc.example.org/realms/lab", "client_id": "fastrdp-otp-check",
      "client_secret_file": "/etc/fastrdp/keycloak-otp.secret"}


# ------------------------------------------------------------------ config
class CodeConfigTests(unittest.TestCase):
    def parse(self, mfa=None, kc=None):
        return config.parse({**MINIMAL, "mfa": {"mode": "code_or_web", "keycloak": {**KC, **(kc or {})},
                                                **(mfa or {})}}).mfa

    def test_valid(self):
        mfa = self.parse(kc={"issuer": "https://kc.example.org:8443/auth/realms/lab/"})
        self.assertEqual(self.parse(kc={"issuer": "http://127.0.0.1:8080/realms/lab"}).keycloak.issuer,
                         "http://127.0.0.1:8080/realms/lab")       # plain http on loopback only
        self.assertEqual((mfa.code_attempts, mfa.code_user_failures, mfa.code_failure_window), (3, 10, 900))
        self.assertEqual(mfa.keycloak.issuer, "https://kc.example.org:8443/auth/realms/lab")
        self.assertIn("code_or_web", config.WEB_APPROVAL_MODES)

    def test_invalid(self):
        bad = {
            "issuer must": ({}, {"issuer": "http://kc.example.org/realms/lab"}),
            "issuer must  ": ({}, {"issuer": "http://localhost.example.org/realms/lab"}),
            "issuer must ": ({}, {"issuer": "https://kc.example.org/lab"}),
            "client_id is required": ({}, {"client_id": ""}),
            "client_secret_file must": ({}, {"client_secret_file": "secret"}),
            "timeout must": ({}, {"timeout": 0}),
            "required_amr must": ({}, {"required_amr": ""}),
            "required_amr must ": ({}, {"required_amr": "o t p"}),
            "code_attempts must": ({"code_attempts": 0}, {}),
            "code_attempts must ": ({"code_attempts": 11}, {}),
            "code_user_failures must": ({"code_user_failures": True}, {}),
            "code_failure_window must": ({"code_failure_window": 59}, {}),
        }
        for msg, (mfa, kc) in bad.items():
            with self.subTest(msg), self.assertRaisesRegex(config.ConfigError, msg.strip()):
                self.parse(mfa, kc)
        with self.assertRaisesRegex(config.ConfigError, r"needs \[web\] enabled"):
            config.parse({"desktops": MINIMAL["desktops"], "mfa": {"mode": "code_or_web", "keycloak": KC}})
        with self.assertRaisesRegex(config.ConfigError, r"unknown keys: password"):
            self.parse(kc={"password": "x"})

    def test_keycloak_only_where_used(self):
        self.assertEqual(config.parse({**MINIMAL, "mfa": {"mode": "web"}}).mfa.keycloak.issuer, "")


# ------------------------------------------------------------------ texts
class CodeTextTests(unittest.TestCase):
    def test_prompt(self):
        t = ui.WaitingTexts(config.UiSection(approve_url="https://rdp.example.org/web/approve"))
        msg = t.mfa("en", "code_or_web", 90, "alice", "42", "id1", {"state": "ready", "attempts_left": 3}, 6)
        self.assertEqual(msg["code_entry"], {"digits": 6, "label": "Authenticator code:",
                                             "checking": "Checking the code…", "message": ""})
        self.assertIn("qr", msg)
        self.assertEqual(msg["lines"][0], "Approve the sign-in")
        self.assertIn("Login code: 42", msg["lines"])
        wrong = t.mfa("de", "code_or_web", 50, "alice", "42", "id1", {"state": "wrong", "attempts_left": 2}, 0)
        self.assertEqual((wrong["code_entry"]["digits"], wrong["code_entry"]["message"]),
                         (0, "Falscher Code. Verbleibende Versuche: 2"))
        blocked = t.mfa("en", "code_or_web", 50, "alice", "42", "id1", {"state": "blocked", "attempts_left": 2})
        self.assertNotIn("code_entry", blocked)
        self.assertIn("Too many wrong codes. Please use the approval page.", blocked["lines"])
        for lang, table in ui.BUILTIN_TEXTS.items():
            for key in ui.TEXT_KEYS:
                with self.subTest(lang=lang, key=key):
                    ui.check_template(table[key])

    def test_other_methods_have_no_field(self):
        t = ui.WaitingTexts(config.UiSection())
        self.assertNotIn("code_entry", t.mfa("en", "web", 90, "alice", "42", "id1"))


# ------------------------------------------------------------------ checker
def jwt(claims: dict) -> str:
    """An unsigned JWT with these claims (the broker does not check signatures:
    keycloak_otp.KeycloakOtp.token_problem)."""
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIn0.{part}.sig"


class FakeKeycloak(http.server.ThreadingHTTPServer):
    """Token and logout endpoints of one realm; `token` is the token endpoint's answer
    (status, JSON body), by default a right code."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), self.Handler)
        self.issuer = f"http://127.0.0.1:{self.server_address[1]}/realms/lab"
        self.logout_status = 204
        self.requests: list[tuple[str, dict]] = []
        self.token = (200, self.tokens())

    def tokens(self, **claims) -> dict:
        """A 200 body like Keycloak's for the code check client: ID token with amr ["otp"],
        overridden by `claims` (None removes one)."""
        base = {"iss": self.issuer, "aud": "fastrdp-otp-check", "azp": "fastrdp-otp-check", "typ": "ID",
                "exp": int(time.time()) + 300, "sub": "u-1", "amr": ["otp"]}
        base = {k: v for k, v in {**base, **claims}.items() if v is not None}
        return {"access_token": jwt({**base, "typ": "Bearer"}), "id_token": jwt(base), "refresh_token": "rt-1"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            srv = self.server
            form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
            srv.requests.append((self.path, form))
            if self.path.endswith("/token"):
                status, body = srv.token
            else:
                status, body = srv.logout_status, None
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


WRONG_CODE = (400, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
NO_OTP = (401, {"error": "fastrdp_no_otp"})              # Deny access [tested: Keycloak 26.8.1]
BAD_SECRET = (401, {"error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
SERVER_ERROR = (500, {"error": "unknown_error"})


class KeycloakOtpTests(unittest.TestCase):
    def setUp(self):
        self.kc = FakeKeycloak()
        threading.Thread(target=self.kc.serve_forever, daemon=True).start()
        self.addCleanup(self.kc.server_close)
        self.addCleanup(self.kc.shutdown)
        self.otp = KeycloakOtp(KeycloakOtpSection(issuer=self.kc.issuer, client_id="fastrdp-otp-check",
                                                  client_secret_file="/nonexistent", timeout=5), secret="s3cret")

    def test_right_code_ends_the_session(self):
        self.assertEqual(self.otp.check("alice", "123456"), keycloak_otp.OK)
        (tpath, token), (lpath, logout) = self.kc.requests
        self.assertEqual(tpath, "/realms/lab/protocol/openid-connect/token")
        self.assertEqual(token, {"grant_type": "password", "client_id": "fastrdp-otp-check",
                                 "client_secret": "s3cret", "username": "alice", "totp": "123456",
                                 "scope": "openid"})
        self.assertEqual(lpath, "/realms/lab/protocol/openid-connect/logout")
        self.assertEqual(logout, {"client_id": "fastrdp-otp-check", "client_secret": "s3cret",
                                  "refresh_token": "rt-1"})

    def test_answers(self):
        """Every refusal: the right kind, no logout, never the code in a log."""
        cases = {"wrong code": (WRONG_CODE, keycloak_otp.WRONG, "INFO", "Invalid user credentials"),
                 "no OTP credential": (NO_OTP, keycloak_otp.NO_OTP, "INFO", "has no OTP credential"),
                 "wrong client secret": (BAD_SECRET, keycloak_otp.OFF, "ERROR", "client secret or client_id"),
                 "server error": (SERVER_ERROR, keycloak_otp.OFF, "ERROR", "lost its Deny access step"),
                 "other 401": ((401, {"error": "access_denied"}), keycloak_otp.OFF, "ERROR", "HTTP 401"),
                 "other 400": ((400, {"error": "invalid_request"}), keycloak_otp.OFF, "ERROR", "HTTP 400"),
                 "not JSON": ((502, None), keycloak_otp.OFF, "ERROR", "HTTP 502")}
        for what, (answer, result, level, text) in cases.items():
            with self.subTest(what):
                self.kc.token = answer
                self.kc.requests.clear()
                with self.assertLogs("fastrdp_broker.keycloak_otp", "INFO") as logs:
                    self.assertEqual(self.otp.check("alice", "654321"), result)
                self.assertEqual(len(self.kc.requests), 1)       # no logout
                self.assertEqual(logs.records[0].levelname, level)
                self.assertIn(text, logs.output[0])
                self.assertFalse(any("654321" in line for line in logs.output), logs.output)

    def test_token_without_otp_in_amr_refused(self):
        """Safeguard 2: a 200 counts only with "otp" in amr (a flow that lost its Deny or
        OTP step gives amr []); the session is ended all the same."""
        cases = {"amr empty": {"amr": []}, "no amr": {"amr": None}, "amr other": {"amr": ["pwd"]},
                 "other issuer": {"iss": "https://evil.example/realms/lab"},
                 "other audience": {"aud": "fastrdp-web"}, "other azp": {"azp": "fastrdp-web"},
                 "expired": {"exp": int(time.time()) - 3600}}
        for what, claims in cases.items():
            with self.subTest(what):
                self.kc.token = (200, self.kc.tokens(**claims))
                self.kc.requests.clear()
                with self.assertLogs("fastrdp_broker.keycloak_otp", "ERROR") as logs:
                    self.assertEqual(self.otp.check("alice", "123456"), keycloak_otp.OFF)
                self.assertIn("issued a token without", logs.output[0])
                self.assertEqual([p.rsplit("/", 1)[1] for p, _ in self.kc.requests], ["token", "logout"])

    def test_access_token_when_no_id_token(self):
        body = self.kc.tokens()
        del body["id_token"]
        self.kc.token = (200, body)
        self.assertEqual(self.otp.check("alice", "123456"), keycloak_otp.OK)
        body = self.kc.tokens(amr=[])
        del body["id_token"]
        self.kc.token = (200, body)
        with self.assertLogs("fastrdp_broker.keycloak_otp", "ERROR"):
            self.assertEqual(self.otp.check("alice", "123456"), keycloak_otp.OFF)

    def test_required_amr_configurable(self):
        otp = KeycloakOtp(KeycloakOtpSection(issuer=self.kc.issuer, client_id="fastrdp-otp-check",
                                             client_secret_file="/x", required_amr="totp"), secret="s")
        with self.assertLogs("fastrdp_broker.keycloak_otp", "ERROR"):
            self.assertEqual(otp.check("alice", "123456"), keycloak_otp.OFF)
        self.kc.token = (200, self.kc.tokens(amr=["totp"]))
        self.assertEqual(otp.check("alice", "123456"), keycloak_otp.OK)

    def test_failed_logout_still_accepts(self):
        self.kc.logout_status = 400
        with self.assertLogs("fastrdp_broker.keycloak_otp", "WARNING") as logs:
            self.assertEqual(self.otp.check("alice", "123456"), keycloak_otp.OK)
        self.assertIn("not ended: HTTP 400", logs.output[0])

    def test_unreachable_raises(self):
        self.kc.shutdown()
        self.kc.server_close()
        with self.assertRaises(KeycloakError):
            self.otp.check("alice", "123456")

    def test_secret_read_per_check(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("from-file\n")
        self.addCleanup(os.unlink, fh.name)
        otp = KeycloakOtp(KeycloakOtpSection(issuer=self.kc.issuer, client_id="fastrdp-otp-check",
                                             client_secret_file=fh.name))
        self.assertEqual(otp.check("alice", "123456"), keycloak_otp.OK)
        self.assertEqual(self.kc.requests[0][1]["client_secret"], "from-file")
        missing = KeycloakOtp(KeycloakOtpSection(issuer=self.kc.issuer, client_id="c",
                                                 client_secret_file="/nonexistent"))
        with self.assertRaisesRegex(KeycloakError, "not readable"):
            missing.check("alice", "123456")


class CodeFailuresTests(unittest.TestCase):
    def test_window(self):
        clock = Clock()
        f = CodeFailures(MfaSection(code_user_failures=2, code_failure_window=100), clock)
        f.record("alice")
        self.assertFalse(f.blocked("alice"))
        clock.t += 50
        f.record("alice")
        self.assertTrue(f.blocked("alice"))
        self.assertFalse(f.blocked("bob"))
        clock.t += 51          # the first one left the window
        self.assertFalse(f.blocked("alice"))
        clock.t += 100
        self.assertFalse(f.blocked("alice"))
        self.assertEqual(f.failures, {})


# ------------------------------------------------------------------ broker
class _CodeHarness(_ApprovalHarness):
    mode = "code_or_web"

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.kc = self.broker.mfa.kc = mock.Mock()
        self.kc.check.return_value = keycloak_otp.WRONG
        self.mfa_cfg.code_attempts = 3
        self.broker.waiting.cfg.approve_url = "https://rdp.example.org/web/approve"

    async def code_login(self, codes=(), *, code_entry=1, after=None, timeout=10, **kw):
        """A login like the module with the waiting screen and the code field: sends
        `codes` one by one, each after a prompt with a code field; `after(reader, writer,
        progress)` runs at the first prompt after the last. Returns (progress messages,
        reply or None)."""
        msg = {"op": "login", "session_id": "s1", "method": "tls", "user": "alice", "password": "pw",
               "client_address": ADDR, "progress": 1, "code_entry": code_entry, **kw}
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps(msg).encode() + b"\n")
        await writer.drain()
        progress, todo = [], list(codes)
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout)
                if not line:
                    return progress, None
                line = json.loads(line)
                if "progress" not in line:
                    return progress, line
                progress.append(line)
                if line.get("progress") != "mfa":
                    continue
                if todo and "code_entry" in line:
                    writer.write(json.dumps({"op": "code", "code": todo.pop(0)}).encode() + b"\n")
                    await writer.drain()
                elif not todo and after:
                    await after(reader, writer, progress)
                    after = None
        finally:
            writer.close()

    def fields(self, progress):
        return [p["code_entry"] for p in progress if p.get("progress") == "mfa" and "code_entry" in p]


class CodeOrWebTests(_CodeHarness, unittest.IsolatedAsyncioTestCase):
    async def test_right_code(self):
        self.kc.check.side_effect = lambda user, code: keycloak_otp.OK if code == "123456" else keycloak_otp.WRONG
        self.broker.grace.seconds = 300
        with self.assertLogs("fastrdp_broker.mfa", "INFO") as logs:
            progress, reply = await self.code_login(["111111", "123456"])
        self.assertTrue(reply["ok"], reply)
        self.assertEqual([c.args for c in self.kc.check.call_args_list], [("alice", "111111"), ("alice", "123456")])
        first, second = self.fields(progress)
        self.assertEqual((first["digits"], first["message"]), (6, ""))
        self.assertEqual(second["message"], "Wrong code. Attempts left: 2")
        self.assertIn("qr", progress[0])
        self.assertEqual(progress[-1]["progress"], "session_start")
        self.assertEqual(self.broker.mfa.approvals.pending, {})     # the web entry ended
        self.assertEqual([e.factor for e in self.broker.grace.entries.values()], ["keycloak_otp"])
        self.assertFalse(any("123456" in line or "111111" in line for line in logs.output), logs.output)

    async def test_web_wins_and_closes_the_field(self):
        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        progress, reply = await self.code_login(after=approve)
        self.assertTrue(reply["ok"], reply)
        self.kc.check.assert_not_called()

    async def test_too_many_wrong_codes(self):
        progress, reply = await self.code_login(["000001", "000002", "000003"])
        self.assertEqual(reply, self.refused("mfa_failed"))
        self.assertEqual(self.kc.check.call_count, 3)
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.ensure.assert_not_called()

    async def test_deny_fails(self):
        async def deny(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid, approve=False)

        _, reply = await self.code_login(after=deny)
        self.assertEqual(reply, self.refused("mfa_failed"))

    async def test_timeout(self):
        self.mfa_cfg.web_approval_timeout = 1
        _, reply = await self.code_login()
        self.assertEqual(reply, self.refused("mfa_timeout"))

    async def test_timeout_also_during_a_slow_check(self):
        self.mfa_cfg.web_approval_timeout = 1
        release = threading.Event()
        self.addCleanup(release.set)
        self.kc.check.side_effect = lambda user, code: keycloak_otp.OK if release.wait(10) else keycloak_otp.WRONG
        started = asyncio.get_running_loop().time()
        _, reply = await self.code_login(["123456"])
        self.assertEqual(reply, self.refused("mfa_timeout"))
        self.assertLess(asyncio.get_running_loop().time() - started, 5)

    async def test_keycloak_unreachable_costs_no_attempt(self):
        results = [KeycloakError("down"), KeycloakError("down"), KeycloakError("down"), keycloak_otp.OK]
        self.kc.check.side_effect = lambda user, code: (_ for _ in ()).throw(r) if isinstance(
            r := results.pop(0), Exception) else r
        progress, reply = await self.code_login(["000001", "000002", "000003", "000004"])
        self.assertTrue(reply["ok"], reply)   # four codes, three attempts
        self.assertEqual([f["message"] for f in self.fields(progress)][1:],
                         ["The code could not be checked. Try again or use the approval page."] * 3)

    async def test_no_otp_closes_the_field_without_an_attempt(self):
        """A user without an OTP credential (Deny access in Keycloak's flow): the field
        closes with a hint to the passkey, no attempt is counted, approval still works."""
        self.kc.check.return_value = keycloak_otp.NO_OTP

        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        progress, reply = await self.code_login(["123456"], after=approve)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.kc.check.call_count, 1)
        closed = [p for p in progress if p.get("progress") == "mfa" and "code_entry" not in p]
        self.assertTrue(any("No authenticator app is set up" in line for p in closed for line in p["lines"]),
                        progress)
        self.assertIn("qr", closed[-1])
        self.assertFalse(self.broker.mfa.code_failures.blocked("alice"))
        self.assertEqual(self.broker.mfa.code_failures.failures, {})

    async def test_unusable_check_closes_the_field_without_an_attempt(self):
        """OFF (setup error, token without otp in amr, odd answers): no attempt, no further
        codes for this login (no unlimited guessing), approval still works."""
        self.kc.check.return_value = keycloak_otp.OFF
        self.broker.grace.seconds = 300

        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        progress, reply = await self.code_login(["123456"], after=approve)
        self.assertTrue(reply["ok"], reply)
        closed = [p for p in progress if p.get("progress") == "mfa" and "code_entry" not in p]
        self.assertTrue(any("cannot be checked at the moment" in line for p in closed for line in p["lines"]),
                        progress)
        self.assertEqual(self.broker.mfa.code_failures.failures, {})
        self.assertEqual([e.factor for e in self.broker.grace.entries.values()], ["web"])

    async def test_no_otp_then_timeout(self):
        self.mfa_cfg.web_approval_timeout = 1
        self.kc.check.return_value = keycloak_otp.NO_OTP
        _, reply = await self.code_login(["123456"])
        self.assertEqual(reply, self.refused("mfa_timeout"))

    async def test_user_limit_closes_the_field_web_still_works(self):
        self.mfa_cfg.code_user_failures = 2
        self.mfa_cfg.code_attempts = 5

        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        progress, reply = await self.code_login(["000001", "000002"], after=approve)
        # the second wrong code reaches the limit: the next prompt has no field
        self.assertTrue(reply["ok"], reply)
        blocked = [p for p in progress if p.get("progress") == "mfa" and "code_entry" not in p]
        self.assertTrue(any("Too many wrong codes" in line for p in blocked for line in p["lines"]), progress)
        # a new login of the same user starts without a field
        with self.assertLogs("fastrdp_broker.mfa", "WARNING"):
            task = asyncio.create_task(self.code_login(after=None, timeout=3))
            (rid,) = await self.wait_pending()
            await self.decide(rid)
            progress, reply = await task
        self.assertTrue(reply["ok"])
        self.assertEqual(self.fields(progress), [])
        self.assertEqual(self.kc.check.call_count, 2)

    async def test_without_code_entry_web_only(self):
        async def approve():
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        for name, kw in {"old module": {"code_entry": None}, "no waiting screen": {"progress": None}}.items():
            with self.subTest(name):
                task = asyncio.create_task(self.code_login(**kw))
                await approve()
                progress, reply = await task
                self.assertTrue(reply["ok"], reply)
                self.assertEqual(self.fields(progress), [])
                if kw.get("progress", 1) is None:
                    self.assertEqual(progress, [])
                else:
                    self.assertEqual(progress[0]["method"], "web")

    async def test_code_without_code_entry_is_a_protocol_error(self):
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps({"op": "login", "session_id": "s1", "method": "tls", "user": "alice",
                                 "password": "pw", "progress": 1}).encode() + b"\n")
        await writer.drain()
        json.loads(await reader.readline())   # the mfa prompt (web only)
        writer.write(b'{"op": "code", "code": "123456"}\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")   # closed without a reply
        writer.close()
        self.kc.check.assert_not_called()

    async def test_malformed_codes_are_protocol_errors(self):
        for bad in ('{"op": "code", "code": "12a456"}', '{"op": "code", "code": "123"}',
                    '{"op": "code", "code": 123456}', '{"op": "code", "code": "١٢٣٤٥٦"}',
                    '{"op": "other"}'):
            with self.subTest(bad):
                async def send(reader, writer, progress, bad=bad):
                    writer.write(bad.encode() + b"\n")
                    await writer.drain()

                _, reply = await self.code_login(after=send)
                self.assertIsNone(reply)
        self.kc.check.assert_not_called()
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_proxy_drop_ends_everything(self):
        async def drop(reader, writer, progress):
            await self.wait_pending()
            writer.close()

        _, reply = await self.code_login(after=drop)
        self.assertIsNone(reply)
        for _ in range(100):
            if not self.broker.mfa.approvals.pending:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_late_code_is_dropped(self):
        # approved on the web while a code is on its way: the code is not checked
        async def approve_then_code(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)
            writer.write(b'{"op": "code", "code": "123456"}\n')
            await writer.drain()

        _, reply = await self.code_login(after=approve_then_code)
        self.assertTrue(reply["ok"], reply)
        self.kc.check.assert_not_called()

    async def test_exempt_and_grace_skip_it(self):
        self.broker.mfa.cfg.exempt_groups = ["mfa-exempt"]
        progress, reply = await self.code_login(user="carol")
        self.assertTrue(reply["ok"])
        self.assertEqual([p["progress"] for p in progress], ["session_start"])


if __name__ == "__main__":
    unittest.main()
