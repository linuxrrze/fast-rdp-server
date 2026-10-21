# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Logins must not depend on the broker (root) being able to read the user's home.

Kerberized NFS homes (sec=krb5/krb5i/krb5p) refuse root (no user credentials,
root_squash): EACCES, or EKEYEXPIRED. An unreachable NFS server blocks instead.
In every case the broker must fall back to the group/global default desktop.
"""

import asyncio
import errno
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, identity
from fastrdp_broker.backends import Target
from fastrdp_broker.config import ConfigError
from fastrdp_broker.identity import LocalUser
from test_server import ME, make_cfg
from test_units import load_example


def home_user(home: str, groups=("rdp-kde",)) -> LocalUser:
    return LocalUser(ME.pw_name, ME.pw_uid, ME.pw_gid, home, frozenset(groups))


class UnreadableHomeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.parse(load_example())
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        os.makedirs(f"{self.home}/.config/fastrdp")
        Path(f"{self.home}/.config/fastrdp/desktop").write_text("mate\n")
        self.user = home_user(self.home)

    def tearDown(self):
        os.chmod(self.home, 0o700)
        self.tmp.cleanup()

    def test_preference_is_used_when_readable(self):
        self.assertEqual(identity.choose_desktop(self.cfg, self.user, None), "mate")

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_home_without_permissions_falls_back_to_group_default(self):
        os.chmod(self.home, 0)  # like root on a sec=krb5 mount: EACCES
        self.assertIsNone(identity.read_desktop_pref(self.user))
        self.assertEqual(identity.choose_desktop(self.cfg, self.user, None), "plasma")
        nogroup = home_user(self.home, groups=())
        self.assertEqual(identity.choose_desktop(self.cfg, nogroup, None), self.cfg.default_desktop)

    def test_open_errors_mean_no_preference(self):
        for code in (errno.EACCES, errno.EPERM, errno.EKEYEXPIRED, errno.EIO, errno.ESTALE):
            with self.subTest(errno=errno.errorcode[code]), \
                    mock.patch("fastrdp_broker.identity.os.open", side_effect=OSError(code, os.strerror(code))):
                self.assertIsNone(identity.read_desktop_pref(self.user))
                self.assertEqual(identity.choose_desktop(self.cfg, self.user, None), "plasma")

    def test_read_errors_mean_no_preference(self):
        # The ticket can expire between open() and read(): NFS then fails the READ.
        with mock.patch("fastrdp_broker.identity.os.read", side_effect=OSError(errno.EKEYEXPIRED, "expired")), \
                mock.patch("fastrdp_broker.identity.os.close", wraps=os.close) as close:
            self.assertIsNone(identity.read_desktop_pref(self.user))
            close.assert_called_once()  # no fd leak
        with mock.patch("fastrdp_broker.identity.os.fstat", side_effect=OSError(errno.EIO, "I/O error")):
            self.assertIsNone(identity.read_desktop_pref(self.user))

    def test_hint_does_not_touch_home(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref") as read:
            self.assertEqual(identity.choose_desktop(self.cfg, self.user, "fastrdp:gnome"), "gnome")
            read.assert_not_called()

    def test_explicit_pref_skips_reading(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref") as read:
            self.assertEqual(identity.choose_desktop(self.cfg, self.user, None, pref=None), "plasma")
            self.assertEqual(identity.choose_desktop(self.cfg, self.user, None, pref="mate"), "mate")
            read.assert_not_called()


class HomeReadTimeoutConfigTests(unittest.TestCase):
    def test_default_and_validation(self):
        self.assertEqual(config.parse(load_example()).broker.home_read_timeout, 3.0)
        for good in (0, 0.5, 10):
            raw = load_example()
            raw["broker"]["home_read_timeout"] = good
            self.assertEqual(config.parse(raw).broker.home_read_timeout, good)
        for bad in (-1, 61, "3", True):
            raw = load_example()
            raw["broker"]["home_read_timeout"] = bad
            with self.subTest(value=bad), self.assertRaises(ConfigError):
                config.parse(raw)


class BrokerHomeTests(unittest.IsolatedAsyncioTestCase):
    """Broker.login with a home directory that hangs (hard NFS mount, server down)."""

    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name, web=True)
        self.cfg.broker.home_read_timeout = 0.3
        self.broker = Broker(self.cfg)
        self.ensure = mock.AsyncMock(return_value=Target("127.0.0.1", 3390, "alice", "tok", "", "tls"))
        for b in self.broker.backends.values():
            b.ensure = self.ensure
        self.user = home_user("/nfs/home/alice", groups=("rdp-users",))
        self.release = threading.Event()
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", return_value=self.user),
            mock.patch("fastrdp_broker.identity.resolve_login", return_value=self.user),
            mock.patch("fastrdp_broker.pamauth.account_ok"),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        self.release.set()
        for p in self.patches:
            p.stop()
        self.broker.home_pool.shutdown(wait=True)
        self.tmp.cleanup()

    def hanging_read(self, user):
        self.release.wait(10)
        return "gnome"

    async def nla_login(self, sid="s1", hint=None):
        msg = {"op": "login", "session_id": sid, "method": "nla", "user": "alice",
               "principal": "alice@EXAMPLE.COM"}
        if hint:
            msg["desktop_hint"] = hint
        return await self.broker.login(msg)

    async def test_hanging_home_falls_back_to_default(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", side_effect=self.hanging_read), \
                self.assertLogs("fastrdp.broker", "WARNING") as logs:
            t0 = time.monotonic()
            reply = await self.nla_login()
            elapsed = time.monotonic() - t0
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["desktop"], self.cfg.default_desktop)
        self.assertLess(elapsed, 3)
        self.assertIn("/nfs/home/alice", "\n".join(logs.output))

    async def test_event_loop_keeps_serving_while_a_home_hangs(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", side_effect=self.hanging_read), \
                self.assertLogs("fastrdp.broker", "WARNING"):
            ticks = 0

            async def ticker():
                nonlocal ticks
                while True:
                    await asyncio.sleep(0.02)
                    ticks += 1

            task = asyncio.create_task(ticker())
            replies = await asyncio.gather(*(self.nla_login(f"s{i}") for i in range(8)))
            task.cancel()
        self.assertTrue(all(r["ok"] for r in replies))
        self.assertGreater(ticks, 5)  # the loop was not blocked by the hung reads

    async def test_unreadable_home_uses_default(self):
        with mock.patch("fastrdp_broker.identity.os.open", side_effect=OSError(errno.EACCES, "denied")):
            reply = await self.nla_login()
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["desktop"], self.cfg.default_desktop)

    async def test_readable_preference_still_wins(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", return_value="gnome"):
            reply = await self.nla_login()
        self.assertEqual(reply["desktop"], "gnome")

    async def test_hint_skips_home(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref") as read:
            reply = await self.nla_login(hint="fastrdp:gnome")
        self.assertEqual(reply["desktop"], "gnome")
        read.assert_not_called()

    async def test_timeout_zero_never_reads_homes(self):
        self.cfg.broker.home_read_timeout = 0
        with mock.patch("fastrdp_broker.identity.read_desktop_pref") as read:
            reply = await self.nla_login()
            web = await self.broker.web_desktops({"op": "web_desktops", "user": "alice"})
        self.assertTrue(reply["ok"])
        self.assertEqual(web["default"], self.cfg.default_desktop)
        read.assert_not_called()

    async def test_web_desktop_chooser_survives_hanging_home(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", side_effect=self.hanging_read), \
                self.assertLogs("fastrdp.broker", "WARNING"):
            reply = await self.broker.web_desktops({"op": "web_desktops", "user": "alice"})
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["default"], self.cfg.default_desktop)


if __name__ == "__main__":
    unittest.main()
