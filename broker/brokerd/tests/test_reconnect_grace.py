# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] reconnect_grace (grace.py): a reconnect of the same account, login method,
principal and (by default) client address skips a second factor passed less than N
seconds ago. Off by default, counted from the real second factor (never extended),
recorded only after a fully successful login, memory only."""

import contextlib
import io
import json
import unittest
from unittest import mock

from fastrdp_broker import __main__ as cli
from fastrdp_broker import config, pamauth
from fastrdp_broker.backends import BackendError
from fastrdp_broker.grace import GraceKey, ReconnectGrace
from test_gaps import EXAMPLE, _BrokerHarness, raw_example

MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}}
ADDR, OTHER_ADDR = "192.0.2.10", "198.51.100.7"


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


# ------------------------------------------------------------------ config
class GraceConfigTests(unittest.TestCase):
    def test_default_off_and_bound_to_address(self):
        cfg = config.parse(dict(MINIMAL))
        self.assertEqual(cfg.mfa.reconnect_grace, 0)
        self.assertTrue(cfg.mfa.reconnect_grace_same_address)
        ex = config.parse(raw_example())  # commented out in the example
        self.assertEqual((ex.mfa.reconnect_grace, ex.mfa.reconnect_grace_same_address), (0, True))

    def test_valid(self):
        for good in (0, 1, 600, config.MAX_RECONNECT_GRACE):
            with self.subTest(good):
                cfg = config.parse({**MINIMAL, "mfa": {"reconnect_grace": good,
                                                       "reconnect_grace_same_address": False}})
                self.assertEqual(cfg.mfa.reconnect_grace, good)
                self.assertFalse(cfg.mfa.reconnect_grace_same_address)

    def test_invalid(self):
        for bad in (-1, config.MAX_RECONNECT_GRACE + 1, 1.5, "600", True):
            with self.subTest(bad), self.assertRaisesRegex(config.ConfigError, "reconnect_grace must"):
                config.parse({**MINIMAL, "mfa": {"reconnect_grace": bad}})
        with self.assertRaisesRegex(config.ConfigError, "true or false"):
            config.parse({**MINIMAL, "mfa": {"reconnect_grace_same_address": "yes"}})


# ------------------------------------------------------------------ store
class GraceStoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.g = ReconnectGrace(300, True, self.clock)

    def key(self, user="alice", method="nla", principal="alice@EXAMPLE.COM", address=ADDR):
        return self.g.key(user, method, principal, address)

    def test_disabled_has_no_keys(self):
        self.assertIsNone(ReconnectGrace(0, True, self.clock).key("alice", "nla", "alice@EXAMPLE.COM", ADDR))

    def test_binding(self):
        self.assertEqual(self.key(), GraceKey("alice", "nla", "alice@EXAMPLE.COM", ADDR))
        self.assertIsNone(self.key(address=None))            # same_address but unknown address
        self.assertIsNone(self.key(principal=None))          # NLA always has a principal
        self.assertIsNone(self.key(method="web"))
        self.assertEqual(self.key(method="tls").principal, None)   # client-supplied, ignored
        g = ReconnectGrace(300, False, self.clock)
        self.assertEqual(g.key("alice", "tls", None, ADDR), GraceKey("alice", "tls", None, None))
        self.assertEqual(g.key("alice", "tls", None, None), GraceKey("alice", "tls", None, None))

    def test_expiry_and_prune(self):
        self.g.record(self.key(), self.clock(), "push", ADDR)
        self.g.record(self.key(user="bob", principal="bob@EXAMPLE.COM"), self.clock() + 100, "otp", ADDR)
        self.clock.t += 299
        entry, age = self.g.lookup(self.key())
        self.assertEqual((entry.factor, entry.address, age), ("push", ADDR, 299))
        self.clock.t += 1                                    # exactly 300 s: over
        self.assertIsNone(self.g.lookup(self.key()))
        self.assertEqual(len(self.g.entries), 1)             # alice pruned, bob kept
        self.clock.t += 100
        self.assertEqual(len(self.g), 0)
        self.assertEqual(self.g.entries, {})

    def test_absolute_not_sliding(self):
        self.g.record(self.key(), self.clock(), "push", ADDR)
        for _ in range(5):                                   # lookups never extend it
            self.clock.t += 50
            self.assertIsNotNone(self.g.lookup(self.key()))
        self.clock.t += 50
        self.assertIsNone(self.g.lookup(self.key()))

    def test_older_second_factor_does_not_replace_newer(self):
        t0 = self.clock()
        self.g.record(self.key(), t0 + 10, "push", ADDR)
        self.g.record(self.key(), t0, "otp", ADDR)            # slow session start of an older login
        self.assertEqual(self.g.entries[self.key()].passed_at, t0 + 10)

    def test_clear(self):
        self.g.record(self.key(), self.clock(), "push", ADDR)
        self.g.record(self.key(method="tls"), self.clock(), "otp", ADDR)
        self.g.record(self.key(user="bob", principal="bob@EXAMPLE.COM"), self.clock(), "push", ADDR)
        self.assertEqual(self.g.clear("alice"), 2)
        self.assertEqual(self.g.clear("alice"), 0)
        self.assertEqual(self.g.clear(), 1)

    def test_clear_blocks_login_in_flight(self):
        # A second factor approved before the clear (session still starting) records nothing.
        passed = self.clock()
        self.clock.t += 5
        self.g.clear("alice")
        self.g.record(self.key(), passed, "push", ADDR)
        self.assertIsNone(self.g.lookup(self.key()))
        self.g.record(self.key(user="bob", principal="bob@EXAMPLE.COM"), passed, "push", ADDR)
        self.assertEqual(len(self.g), 1)                     # other users unaffected
        self.g.clear()
        self.g.record(self.key(user="bob", principal="bob@EXAMPLE.COM"), passed + 1, "push", ADDR)
        self.assertEqual(len(self.g), 0)
        self.g.record(self.key(), self.clock() + 1, "push", ADDR)   # later second factor: fine
        self.assertEqual(len(self.g), 1)


# ------------------------------------------------------------------ broker
class GraceLoginTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.clock = Clock()
        self.broker.grace.clock = self.clock
        self.pi = self.set_mfa("push", exempt=["mfa-exempt"])
        self.pi.trigger_challenge.return_value = "tx"
        self.pi.wait_for_push.return_value = True

    def enable(self, seconds=300, same_address=True):
        self.broker.grace.seconds = seconds
        self.broker.grace.same_address = same_address

    def tls(self, **kw):
        return self.login(**{"client_address": ADDR, **kw})

    def nla_at(self, **kw):
        return self.nla(**{"client_address": ADDR, **kw})

    @property
    def pushes(self):
        return self.pi.trigger_challenge.call_count

    async def test_off_by_default(self):
        self.assertFalse(self.broker.grace.enabled)
        for _ in range(2):
            self.assertTrue((await self.nla_at())["ok"])
        self.assertEqual(self.pushes, 2)
        self.assertEqual(len(self.broker.grace.entries), 0)

    async def test_skip_within_window(self):
        self.enable()
        self.assertTrue((await self.nla_at())["ok"])
        self.clock.t += 120
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await self.nla_at()
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pushes, 1)
        self.assertTrue(any("second factor skipped: reconnect grace (push passed 120s ago from 192.0.2.10)"
                            in line for line in logs.output), logs.output)
        self.assertEqual(self.ensure.await_count, 2)

    async def test_expiry(self):
        self.enable()
        await self.nla_at()
        self.clock.t += 300
        self.assertTrue((await self.nla_at())["ok"])
        self.assertEqual(self.pushes, 2)

    async def test_absolute_not_sliding(self):
        self.enable()
        await self.nla_at()                                  # real push at t0
        self.clock.t += 200
        await self.nla_at()                                  # grace login: no refresh
        self.clock.t += 101                                  # t0 + 301
        await self.nla_at()
        self.assertEqual(self.pushes, 2)
        self.clock.t += 299                                  # the new push restarts the period
        await self.nla_at()
        self.assertEqual(self.pushes, 2)

    async def test_other_address(self):
        self.enable(same_address=True)
        await self.nla_at()
        await self.nla_at(client_address=OTHER_ADDR)
        self.assertEqual(self.pushes, 2)
        self.enable(same_address=False)
        self.broker.grace.clear()
        self.clock.t += 1
        await self.nla_at()
        await self.nla_at(client_address=OTHER_ADDR)
        self.assertEqual(self.pushes, 3)

    async def test_unknown_address_never_bound(self):
        self.enable(same_address=True)
        await self.nla()                                     # no client_address
        await self.nla()
        self.assertEqual(self.pushes, 2)
        self.assertEqual(len(self.broker.grace.entries), 0)

    async def test_login_method_must_match(self):
        self.enable()
        await self.nla_at()
        self.assertTrue((await self.tls())["ok"])            # NLA grace never covers TLS
        self.assertEqual(self.pushes, 2)
        self.broker.grace.clear()
        self.clock.t += 1
        await self.tls()
        await self.nla_at()                                  # nor TLS grace NLA
        self.assertEqual(self.pushes, 4)
        await self.tls()
        await self.nla_at()
        self.assertEqual(self.pushes, 4)

    async def test_principal_must_match(self):
        self.enable()
        self.cfg.auth.realms.append("OTHER.ORG")
        await self.nla_at()                                  # alice@EXAMPLE.COM
        await self.login(method="nla", principal="alice@OTHER.ORG", client_address=ADDR)
        self.assertEqual(self.pushes, 2)

    async def test_tls_principal_field_ignored(self):
        self.enable()
        await self.tls()
        await self.tls(principal="alice@EXAMPLE.COM")
        self.assertEqual(self.pushes, 1)

    async def test_failed_mfa_records_nothing(self):
        self.enable()
        self.pi.wait_for_push.return_value = False
        self.assertEqual(await self.nla_at(), self.refused("mfa_timeout"))
        self.assertEqual(len(self.broker.grace.entries), 0)
        self.pi.wait_for_push.return_value = True
        await self.nla_at()
        self.assertEqual(self.pushes, 2)

    async def test_backend_failure_records_nothing(self):
        self.enable()
        self.ensure.side_effect = BackendError("no session")
        reply = await self.nla_at()
        self.assertEqual(reply["reason"], "backend")
        self.assertEqual(len(self.broker.grace.entries), 0)

    async def test_refusals_record_nothing(self):
        self.enable()
        self.cfg.auth.allow_groups = ["rdp-users"]
        self.assertEqual(await self.nla_at(user="eve"), self.refused("not_allowed"))
        self.pi.trigger_challenge.return_value = None        # no token
        self.assertEqual(await self.nla_at(), self.refused("mfa_failed"))
        self.assertEqual(len(self.broker.grace.entries), 0)

    async def test_first_factor_still_checked(self):
        self.enable()
        await self.tls()
        pamauth.authenticate.side_effect = pamauth.PamError("authenticate", 7, "Authentication failure")
        self.assertEqual(await self.tls(password="wrong"), self.DENIED)
        pamauth.authenticate.side_effect = None

    async def test_account_check_still_runs(self):
        self.enable()
        await self.nla_at()
        pamauth.account_ok.side_effect = pamauth.PamError("account", 13, "expired")
        self.assertEqual(await self.nla_at(), self.refused("not_allowed"))
        pamauth.account_ok.side_effect = None
        self.assertEqual(self.pushes, 1)

    async def test_allow_groups_still_checked(self):
        self.enable()
        await self.nla_at()
        self.cfg.auth.allow_groups = ["nobody-group"]
        self.assertEqual(await self.nla_at(), self.refused("not_allowed"))

    async def test_exempt_and_kdc_record_nothing(self):
        self.enable()
        self.assertTrue((await self.nla_at(user="carol"))["ok"])
        self.cfg.mfa.nla_kdc_enforced = True
        self.assertTrue((await self.nla_at())["ok"])
        self.assertEqual(self.pushes, 0)
        self.assertEqual(len(self.broker.grace.entries), 0)

    async def test_tls_otp_reconnect(self):
        # mstsc resends the typed "password+OTP": the stale OTP must not be checked again.
        self.enable()
        self.set_mfa("otp")
        self.broker.mfa.pi.check_otp.return_value = True
        self.assertTrue((await self.tls(password="pw123456"))["ok"])
        self.broker.mfa.pi.check_otp.return_value = False    # replayed OTP would fail
        self.assertTrue((await self.tls(password="pw123456"))["ok"])
        self.assertEqual(self.broker.mfa.pi.check_otp.call_count, 1)
        self.assertEqual(pamauth.authenticate.call_args.args[2], "pw")
        self.assertTrue((await self.tls(password="password"))["ok"])  # no OTP typed
        self.assertEqual(pamauth.authenticate.call_args.args[2], "password")
        # elsewhere: refused before PAM, as without grace
        pamauth.authenticate.reset_mock()
        self.assertEqual(await self.tls(password="password", client_address=OTHER_ADDR),
                         self.refused("mfa_failed"))
        pamauth.authenticate.assert_not_called()

    async def test_status_and_clear(self):
        self.enable()
        await self.nla_at()
        await self.tls()
        self.assertEqual((await self.broker.status())["mfa_grace_entries"], 2)
        with self.assertLogs("fastrdp.broker", "WARNING"):
            self.assertEqual(await self.broker.clear_grace({"op": "clear_grace", "user": "alice"}),
                             {"ok": True, "cleared": 2})
        await self.nla_at()
        self.assertEqual(self.pushes, 3)

    async def test_clear_is_root_only(self):
        # a non-root caller even when the tests run as root (CI containers)
        with mock.patch("fastrdp_broker.server.peer_uid", return_value=65534):
            reply = await self.login(op="clear_grace")
        self.assertEqual(reply["error"], "not permitted")


class CtlTests(unittest.TestCase):
    def run_ctl(self, *args):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.makefile.return_value = io.StringIO('{"ok": true, "cleared": 1}\n')
        with mock.patch.object(cli.socket, "socket", return_value=sock), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.ctl_main(["-c", str(EXAMPLE), *args])
        return rc, json.loads(sock.sendall.call_args.args[0])

    def test_clear_grace(self):
        self.assertEqual(self.run_ctl("clear-grace", "alice"), (0, {"op": "clear_grace", "user": "alice"}))
        self.assertEqual(self.run_ctl("clear-grace"), (0, {"op": "clear_grace"}))
        self.assertEqual(self.run_ctl("logout", "bob")[1], {"op": "logout", "user": "bob"})


class StartupLogTests(unittest.TestCase):
    def test_logged_when_enabled(self):
        import tempfile

        from fastrdp_broker.server import Broker
        from test_server import make_cfg

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(tmp, mode="push", reconnect_grace=600, privacyidea={"url": "https://pi"})
            with self.assertLogs("fastrdp.broker", "INFO") as logs:
                Broker(cfg)
        self.assertTrue(any("reconnect_grace" in line and "600s" in line for line in logs.output), logs.output)


if __name__ == "__main__":
    unittest.main()
