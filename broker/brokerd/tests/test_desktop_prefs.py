# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Desktop chosen for RDP logins on the webgate's chooser page (op web_set_desktop).

Stored by the broker under <state_dir>/desktop-prefs/<account>, never in the user's
home (root cannot read Kerberized NFS homes). Precedence: client hint > this choice >
~/.config/fastrdp/desktop > group default > global default; a choice that is no longer
allowed is ignored.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, identity
from fastrdp_broker.desktopprefs import PREFS_DIR, DesktopPrefs, PrefsError
from test_gaps import _BrokerHarness, request, user
from test_units import load_example


class DesktopPrefsStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = self.tmp.name
        self.dir = Path(self.state, PREFS_DIR)
        self.prefs = DesktopPrefs(self.state)

    def tearDown(self):
        self.tmp.cleanup()

    def test_set_get_clear(self):
        self.assertIsNone(self.prefs.get("alice"))
        self.prefs.set("alice", None)  # nothing stored: no directory created
        self.assertFalse(self.dir.exists())
        self.prefs.set("alice", "gnome")
        self.assertEqual(self.prefs.get("alice"), "gnome")
        self.assertEqual((self.dir / "alice").read_text(), "gnome\n")
        self.prefs.set("alice", "plasma")
        self.assertEqual(self.prefs.get("alice"), "plasma")
        self.assertIsNone(self.prefs.get("bob"))
        self.prefs.set("alice", None)
        self.assertIsNone(self.prefs.get("alice"))
        self.assertEqual(os.listdir(self.dir), [])  # no temporary files left behind
        self.prefs.set("alice@example.com", "xfce")  # fully qualified SSSD names
        self.assertEqual(self.prefs.get("alice@example.com"), "xfce")

    def test_modes_and_owner(self):
        os.chmod(self.state, 0o755)
        self.prefs.set("alice", "gnome")
        st = os.lstat(self.dir)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o700, os.geteuid()))
        st = os.lstat(self.dir / "alice")
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o600, os.geteuid()))
        os.chmod(self.dir, 0o755)  # a loosened mode is tightened again
        self.prefs.set("alice", "xfce")
        self.assertEqual(stat.S_IMODE(os.lstat(self.dir).st_mode), 0o700)

    def test_symlinked_file_is_not_followed(self):
        self.prefs.set("bob", "xfce")
        secret = Path(self.state, "secret")
        secret.write_text("gnome\n")
        os.symlink(secret, self.dir / "alice")
        self.assertIsNone(self.prefs.get("alice"))
        self.prefs.set("alice", "plasma")  # replaces the link, the target stays untouched
        self.assertEqual(secret.read_text(), "gnome\n")
        self.assertFalse((self.dir / "alice").is_symlink())
        self.assertEqual(self.prefs.get("alice"), "plasma")

    def test_symlinked_directory_is_refused(self):
        elsewhere = Path(self.state, "elsewhere")
        elsewhere.mkdir()
        (elsewhere / "alice").write_text("gnome\n")
        os.symlink(elsewhere, self.dir)
        self.assertIsNone(self.prefs.get("alice"))
        with self.assertRaises(PrefsError):
            self.prefs.set("alice", "xfce")
        self.assertEqual((elsewhere / "alice").read_text(), "gnome\n")

    def test_other_files_ignored(self):
        self.prefs.set("bob", "xfce")
        (self.dir / "alice").mkdir()
        self.assertIsNone(self.prefs.get("alice"))
        (self.dir / "carol").write_text("../../etc\n")
        self.assertIsNone(self.prefs.get("carol"))
        (self.dir / "dave").write_text("")
        self.assertIsNone(self.prefs.get("dave"))

    def test_unusable_names_and_desktops(self):
        for name in ("", ".", "..", ".tmp-x", "a/b", "../alice", "a\0b"):
            with self.subTest(name=name), self.assertRaises(PrefsError):
                self.prefs.set(name, "xfce")
            with self.subTest(name=name), self.assertRaises(PrefsError):
                self.prefs.get(name)
        for desktop in ("", "../x", "a b", "x\n", "x" * 65):
            with self.subTest(desktop=desktop), self.assertRaises(PrefsError):
                self.prefs.set("alice", desktop)


class PrecedenceTests(unittest.TestCase):
    """identity.choose_desktop with the webgate choice (`web_pref`)."""

    def setUp(self):
        self.cfg = config.parse(load_example())
        self.cfg.desktops["mate"].groups = ["rdp-mate"]
        self.user = user(groups=("rdp-users", "rdp-kde"))  # group default: plasma

    def choose(self, hint=None, pref=None, web_pref=None, u=None):
        return identity.choose_desktop(self.cfg, u or self.user, hint, pref=pref, web_pref=web_pref)

    def test_order(self):
        self.assertEqual(self.choose(), "plasma")
        self.assertEqual(self.choose(pref="lxqt"), "lxqt")
        self.assertEqual(self.choose(pref="lxqt", web_pref="gnome"), "gnome")  # beats ~/.config
        self.assertEqual(self.choose("fastrdp:xfce", pref="lxqt", web_pref="gnome"), "xfce")  # hint wins

    def test_disallowed_choice_ignored(self):
        self.assertEqual(self.choose(pref="lxqt", web_pref="mate"), "lxqt")
        self.assertEqual(self.choose(web_pref="mate"), "plasma")
        self.assertEqual(self.choose(web_pref="removed-desktop"), "plasma")

    def test_choice_skips_reading_home(self):
        with mock.patch("fastrdp_broker.identity.read_desktop_pref") as read:
            self.assertEqual(identity.choose_desktop(self.cfg, self.user, None, web_pref="gnome"), "gnome")
            read.assert_not_called()


class WebSetDesktopTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.cfg.desktops["mate"].groups = ["rdp-mate"]  # alice is only in rdp-users
        tgt = mock.patch("fastrdp_broker.tgt.obtain", new_callable=mock.AsyncMock)  # gnome/plasma logins
        tgt.start()
        self.addCleanup(tgt.stop)

    def set_desktop(self, desktop, user="alice"):
        return request(self.cfg.broker.socket, {"op": "web_set_desktop", "user": user, "desktop": desktop})

    def desktops(self, user="alice"):
        return request(self.cfg.broker.socket, {"op": "web_desktops", "user": user})

    def stored(self, name="alice"):
        return self.broker.desktop_prefs.get(name)

    async def test_set_and_clear(self):
        reply = await self.desktops()
        self.assertEqual((reply["default"], reply["rdp_desktop"]), ("xfce", None))
        self.assertEqual(await self.set_desktop("gnome"), {"ok": True, "user": "alice", "rdp_desktop": "gnome"})
        self.assertEqual(self.stored(), "gnome")
        self.assertTrue(Path(self.cfg.broker.state_dir, PREFS_DIR, "alice").is_file())
        reply = await self.desktops()
        self.assertEqual((reply["default"], reply["rdp_desktop"]), ("gnome", "gnome"))
        self.assertEqual(await self.set_desktop(None), {"ok": True, "user": "alice", "rdp_desktop": None})
        self.assertIsNone(self.stored())
        self.assertEqual((await self.desktops())["default"], "xfce")

    async def test_login_uses_choice_hint_wins(self):
        await self.set_desktop("gnome")
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", return_value="lxqt") as read:
            reply = await self.nla()
            self.assertEqual(reply["desktop"], "gnome")
            read.assert_not_called()  # the home is not read when the choice decides
            reply = await self.nla(desktop_hint="fastrdp:plasma")
            self.assertEqual(reply["desktop"], "plasma")

    async def test_choice_no_longer_allowed_is_ignored(self):
        await self.set_desktop("gnome")
        self.cfg.desktops["gnome"].groups = ["rdp-gnome-only"]
        with mock.patch("fastrdp_broker.identity.read_desktop_pref", return_value="lxqt"), \
                self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await self.nla()
        self.assertEqual(reply["desktop"], "lxqt")  # next in line: ~/.config/fastrdp/desktop
        self.assertEqual(sum("chosen on the web gateway is not allowed" in m for m in logs.output), 1)
        self.assertEqual(self.stored(), "gnome")  # kept: allowed again once the group comes back
        self.assertIsNone((await self.desktops())["rdp_desktop"])

    async def test_disallowed_or_unknown_desktop_refused(self):
        for desktop in ("mate", "no-such-desktop", "../etc"):
            with self.subTest(desktop=desktop):
                self.assertEqual(await self.set_desktop(desktop), self.refused("not_allowed"))
        self.assertIsNone(self.stored())
        self.assertFalse(Path(self.cfg.broker.state_dir, PREFS_DIR).exists())

    async def test_refused_users(self):
        self.cfg.auth.allow_groups = ["rdp-users"]
        self.assertEqual(await self.set_desktop("xfce", user="eve"), self.refused("not_allowed"))
        self.assertEqual(await self.set_desktop("xfce", user="mallory"), self.DENIED)  # unknown

    async def test_only_for_webgate(self):
        with mock.patch.object(self.broker, "web_uid", os.getuid() + 1):
            reply = await self.set_desktop("gnome")
        self.assertEqual(reply, {"ok": False, "error": "not permitted", "reason": "denied"})
        self.assertIsNone(self.stored())

    async def test_desktop_field_required(self):
        reply = await request(self.cfg.broker.socket, {"op": "web_set_desktop", "user": "alice"})
        self.assertEqual(reply, {})  # protocol error: connection closed, nothing cleared
        for bad in (1, ["gnome"]):
            with self.subTest(desktop=bad):
                self.assertEqual(await self.set_desktop(bad), {})

    async def test_write_failure(self):
        with mock.patch.object(self.broker.desktop_prefs, "set", side_effect=OSError(28, "No space left")):
            reply = await self.set_desktop("gnome")
        self.assertEqual(reply, {"ok": False, "error": "not stored", "reason": "unavailable"})


if __name__ == "__main__":
    unittest.main()
