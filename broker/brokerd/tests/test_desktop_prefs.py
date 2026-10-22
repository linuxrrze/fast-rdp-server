# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Desktop chosen for RDP logins on the webgate's chooser page (op web_set_desktop),
or by an admin (op desktop_pref, fastrdpctl desktop).

Stored by the broker under <state_dir>/desktop-prefs/<account>, never in the user's
home (root cannot read Kerberized NFS homes). Precedence: client hint > this choice >
~/.config/fastrdp/desktop > group default > global default; a choice that is no longer
allowed is ignored.
"""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import __main__ as cli
from fastrdp_broker import config, identity
from fastrdp_broker.desktopprefs import PREFS_DIR, DesktopPrefs, PrefsError
from test_gaps import EXAMPLE, _BrokerHarness, request, user
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


class AdminDesktopTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    """op desktop_pref (fastrdpctl desktop): root shows, sets and clears the stored choice."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.cfg.desktops["mate"].groups = ["rdp-mate"]  # alice is only in rdp-users
        self.cfg.group_defaults = {"rdp-kde": "plasma"}
        self.home = mock.patch("fastrdp_broker.identity.read_desktop_pref", return_value=None)
        self.read_home = self.home.start()
        self.addCleanup(self.home.stop)

    async def admin(self, uid=0, **fields):
        with mock.patch("fastrdp_broker.server.peer_uid", return_value=uid):
            return await request(self.cfg.broker.socket, {"op": "desktop_pref", "user": "alice", **fields})

    async def test_show_set_clear(self):
        reply = await self.admin()
        self.assertEqual({k: reply[k] for k in ("ok", "user", "rdp_desktop", "home_desktop", "desktop",
                                                 "source", "group", "login_allowed")},
                         {"ok": True, "user": "alice", "rdp_desktop": None, "home_desktop": None,
                          "desktop": "xfce", "source": "default", "group": None, "login_allowed": True})
        self.assertIn("gnome", reply["allowed"])
        self.assertNotIn("mate", reply["allowed"])
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            reply = await self.admin(set="gnome")
        self.assertIn("alice: desktop for RDP logins set to gnome by fastrdpctl", logs.output[0])
        self.assertEqual((reply["rdp_desktop"], reply["rdp_desktop_allowed"], reply["desktop"], reply["source"]),
                         ("gnome", True, "gnome", "web_pref"))
        self.assertEqual(self.broker.desktop_prefs.get("alice"), "gnome")
        self.assertEqual((await self.desktops())["rdp_desktop"], "gnome")  # the webgate's view
        reply = await self.admin(clear=True)
        self.assertEqual((reply["rdp_desktop"], reply["desktop"]), (None, "xfce"))
        self.assertIsNone(self.broker.desktop_prefs.get("alice"))

    def desktops(self):
        return request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})

    async def test_why(self):
        self.read_home.return_value = "lxqt"
        reply = await self.admin()
        self.assertEqual((reply["home_desktop"], reply["desktop"], reply["source"]), ("lxqt", "lxqt", "home_file"))
        self.read_home.return_value = None
        self.users["alice"] = user(groups=("rdp-users", "rdp-kde"))
        reply = await self.admin()
        self.assertEqual((reply["desktop"], reply["source"], reply["group"]), ("plasma", "group_default", "rdp-kde"))
        # a stored desktop no longer allowed is shown, and ignored
        self.broker.desktop_prefs.set("alice", "mate")
        reply = await self.admin()
        self.assertEqual((reply["rdp_desktop"], reply["rdp_desktop_allowed"], reply["desktop"]),
                         ("mate", False, "plasma"))
        self.cfg.auth.allow_groups = ["rdp-admins"]
        self.assertFalse((await self.admin())["login_allowed"])
        for d in self.cfg.desktops.values():
            d.groups = ["nobody-is-here"]
        reply = await self.admin()
        self.assertEqual((reply["desktop"], reply["source"], reply["allowed"]), (None, "none", []))

    async def test_not_allowed_desktop_refused(self):
        for desktop in ("mate", "no-such-desktop", "../etc"):
            with self.subTest(desktop=desktop):
                reply = await self.admin(set=desktop)
                self.assertEqual((reply["ok"], reply["reason"], reply["user"]), (False, "not_allowed", "alice"))
                self.assertIn("gnome", reply["allowed"])
        self.assertIsNone(self.broker.desktop_prefs.get("alice"))

    async def test_root_only(self):
        # nobody; the webgate and proxy (the test's uid), unless the tests run as root
        # (CI containers, dpkg-buildpackage's dh_auto_test): root may use the op
        for uid in (65534, *([os.getuid()] if os.getuid() else [1000])):
            with self.subTest(uid=uid):
                reply = await self.admin(uid=uid, set="gnome")
                self.assertEqual(reply, {"ok": False, "error": "not permitted", "reason": "denied"})
        self.assertIsNone(self.broker.desktop_prefs.get("alice"))

    async def test_bad_requests(self):
        for fields in ({"set": "gnome", "clear": True}, {"clear": "yes"}, {"set": 1}):
            with self.subTest(fields=fields):
                self.assertEqual(await self.admin(**fields), {})  # protocol error: connection closed
        self.assertEqual(await self.admin(user="mallory"), self.DENIED)  # unknown account
        self.assertIsNone(self.broker.desktop_prefs.get("alice"))

    async def test_write_failure(self):
        with mock.patch.object(self.broker.desktop_prefs, "set", side_effect=OSError(28, "No space left")):
            reply = await self.admin(clear=True)
        self.assertEqual(reply, {"ok": False, "error": "not stored", "reason": "unavailable"})


class CtlDesktopTests(unittest.TestCase):
    REPLY = {"ok": True, "user": "alice", "rdp_desktop": "mate", "rdp_desktop_allowed": False,
             "home_desktop": None, "desktop": "plasma", "source": "group_default", "group": "rdp-kde",
             "allowed": ["xfce", "plasma"], "login_allowed": False}

    def run_ctl(self, *args, reply=None):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.makefile.return_value = io.StringIO(json.dumps(reply or self.REPLY) + "\n")
        out = io.StringIO()
        with mock.patch.object(cli.socket, "socket", return_value=sock), contextlib.redirect_stdout(out):
            rc = cli.ctl_main(["-c", str(EXAMPLE), *args])
        return rc, json.loads(sock.sendall.call_args.args[0]), out.getvalue()

    def test_requests(self):
        self.assertEqual(self.run_ctl("desktop", "alice")[1], {"op": "desktop_pref", "user": "alice"})
        self.assertEqual(self.run_ctl("desktop", "alice", "gnome")[1],
                         {"op": "desktop_pref", "user": "alice", "set": "gnome"})
        self.assertEqual(self.run_ctl("desktop", "alice", "--clear")[1],
                         {"op": "desktop_pref", "user": "alice", "clear": True})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.ctl_main(["-c", str(EXAMPLE), "desktop", "alice", "gnome", "--clear"])

    def test_output(self):
        rc, _, out = self.run_ctl("desktop", "alice")
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"stored choice: +mate \(not allowed for the account now: ignored\)")
        self.assertRegex(out, r"RDP logins get: +plasma \(default of group rdp-kde;")
        self.assertRegex(out, r"allowed desktops: +xfce, plasma")
        self.assertIn("not in [auth] allow_groups", out)
        self.assertEqual(json.loads(self.run_ctl("desktop", "alice", "--json")[2]), self.REPLY)

    def test_refusal_is_json(self):
        refused = {"ok": False, "error": "desktop 'mate' is not allowed for alice", "reason": "not_allowed",
                   "user": "alice", "allowed": ["xfce"]}
        rc, _, out = self.run_ctl("desktop", "alice", "mate", reply=refused)
        self.assertEqual((rc, json.loads(out)), (1, refused))


if __name__ == "__main__":
    unittest.main()
