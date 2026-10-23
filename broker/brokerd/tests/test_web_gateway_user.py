# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[web] enabled with a missing [web] gateway_user (fastrdp-webgate not installed yet):
the broker starts, refuses the webgate's operations to every uid, keeps RDP logins
working and picks the account up once it exists (Broker.web_gateway_uid)."""

import pwd
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test_gaps
from fastrdp_broker import __main__ as cli
from fastrdp_broker.server import WEB_UID_RETRY, Broker
from test_gaps import _BrokerHarness, request
from test_server import EXAMPLE, ME

MISSING = "_fastrdp-test-nogw"
NOT_PERMITTED = {"ok": False, "error": "not permitted", "reason": "denied"}
WEBGATE_OPS = (
    {"op": "web_token", "user": "alice"},
    {"op": "web_desktops", "user": "alice"},
    {"op": "web_set_desktop", "user": "alice", "desktop": "xfce"},
    {"op": "mfa_pending", "user": "alice"},
    {"op": "mfa_decide", "user": "alice", "id": "x", "approve": True, "auth_time": 0},
    {"op": "mfa_events"},
)


class MissingGatewayUserTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # The gateway account resolves to the test's own uid once it "exists" (the test acts as
        # proxy and webgate, like test_web_approval.py); the proxy account stays the real one.
        self.gw_exists = False
        self.lookups = 0
        real_getpwnam, real_make_cfg = pwd.getpwnam, test_gaps.make_cfg

        def getpwnam(name):
            if name != MISSING:
                return real_getpwnam(name)
            self.lookups += 1
            if not self.gw_exists:
                raise KeyError(name)
            return real_getpwnam(ME.pw_name)

        def make_cfg(*a, **kw):
            cfg = real_make_cfg(*a, **kw)
            cfg.web.gateway_user = MISSING
            return cfg

        self.gw_patches = [mock.patch("pwd.getpwnam", side_effect=getpwnam),
                           mock.patch("test_gaps.make_cfg", side_effect=make_cfg)]
        for p in self.gw_patches:
            p.start()
        await super().asyncSetUp()

    async def asyncTearDown(self):
        await super().asyncTearDown()
        for p in self.gw_patches:
            p.stop()

    def expire_retry(self):
        self.broker.web_uid_missing_since -= WEB_UID_RETRY

    async def test_startup_logs_and_continues(self):
        self.assertIsNone(self.broker.web_uid)
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            Broker(self.cfg)
        self.assertTrue(any(line.startswith("ERROR") and repr(MISSING) in line and "fastrdp-webgate" in line
                            and "RDP logins are not affected" in line for line in logs.output), logs.output)

    async def test_mfa_mode_logged_at_startup(self):
        for mode, expected in (("web", "ERROR:fastrdp.broker:[mfa] web: RDP logins that owe"),
                               ("push_or_web", "WARNING:fastrdp.broker:[mfa] push_or_web: only push")):
            with self.subTest(mode), mock.patch.object(self.cfg.mfa, "mode", mode), \
                    mock.patch("fastrdp_broker.mfa.PrivacyIdea"), \
                    self.assertLogs("fastrdp.broker", "WARNING") as logs:
                Broker(self.cfg)
            self.assertTrue(any(line.startswith(expected) for line in logs.output), logs.output)

    async def test_rdp_logins_unaffected(self):
        self.assertTrue((await self.login())["ok"])
        self.assertTrue((await self.nla())["ok"])

    async def test_webgate_ops_refused_to_every_uid(self):
        for msg in WEBGATE_OPS:
            with self.subTest(msg["op"]), self.assertLogs("fastrdp.broker", "WARNING") as logs:
                self.assertEqual(await request(self.cfg.broker.socket, msg), NOT_PERMITTED)
            self.assertIn(f"([web] gateway_user {MISSING!r} does not exist)", logs.output[-1])
        # root, the would-be webgate uid and an unrelated uid (peer uids the test cannot fake)
        for uid in (0, ME.pw_uid, ME.pw_uid + 1):
            self.assertFalse(self.broker.from_webgate(uid))
        self.assertEqual(self.lookups, 1)   # at startup; again only after WEB_UID_RETRY

    async def test_account_created_later(self):
        self.gw_exists = True
        reply = await request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})
        self.assertEqual(reply, NOT_PERMITTED)          # not looked up again yet
        self.expire_retry()
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(any("now exists" in line for line in logs.output), logs.output)
        self.assertEqual(self.broker.web_uid, ME.pw_uid)
        self.assertFalse(self.broker.from_webgate(ME.pw_uid + 1))
        lookups = self.lookups
        self.assertTrue(self.broker.from_webgate(ME.pw_uid))
        self.assertEqual(self.lookups, lookups)         # kept once found

    async def test_still_missing_after_retry(self):
        self.expire_retry()
        self.assertFalse(self.broker.from_webgate(ME.pw_uid))
        self.assertEqual(self.lookups, 2)
        self.assertIsNone(self.broker.web_uid)

    async def test_web_mfa_refused_at_once(self):
        self.set_mfa("web")
        started = time.monotonic()
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            reply = await self.login()
        self.assertEqual(reply, self.refused("mfa_failed"))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(self.broker.mfa.approvals), 0)
        self.assertTrue(any("web approval unavailable" in line for line in logs.output), logs.output)
        self.ensure.assert_not_called()
        self.set_mfa("web", exempt=["mfa-exempt"])
        self.assertTrue((await self.login(user="carol"))["ok"])    # owes no second factor


class CheckTests(unittest.TestCase):
    def run_check(self, gateway_user):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker.toml"
            path.write_text(EXAMPLE.read_text() + f'\n[web]\nenabled = true\ngateway_user = "{gateway_user}"\n')
            with mock.patch("builtins.print") as out:
                rc = cli.daemon_main(["-c", str(path), "--check"])
        out.assert_called_with("config ok")
        return rc

    def test_missing_gateway_user_warns(self):
        with self.assertLogs(level="WARNING") as logs:
            self.assertEqual(self.run_check(MISSING), 0)
        self.assertTrue(any(repr(MISSING) in line and "does not exist" in line for line in logs.output),
                        logs.output)

    def test_existing_gateway_user_quiet(self):
        with self.assertNoLogs(level="WARNING"):
            self.assertEqual(self.run_check(ME.pw_name), 0)


if __name__ == "__main__":
    unittest.main()
