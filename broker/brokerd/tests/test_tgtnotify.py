# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Kerberos login reminder in desktop sessions (tgt-notify, backlog K4).

Regressions: sessions silently lost Kerberized NFS/SMB access once the TGT's
renew-until had passed; the reminder must warn once per threshold (not at every
check, not again after a restart), start over after a new TGT (reconnect with a
password), stay quiet without a TGT (SSO logins), and read the cache the session uses
(no KRB5CCNAME, C locale, UTC)."""

import json
import os
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from fastrdp_broker import tgtnotify
from fastrdp_broker.tgtnotify import EXPIRED, ConfigError, Settings, State, TgtStatus

REPO = Path(__file__).resolve().parents[3]


def ts(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


H = 3600
NOW = ts("2026-10-21T12:00:00")

KLIST = """Ticket cache: KCM:1500:41562
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 08:00:00  10/21/26 18:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
\trenew until 10/28/26 08:00:00, Flags: FRIA
10/21/26 08:05:12  10/21/26 18:00:00  nfs/files.example.com@EXAMPLE.COM
\tFlags: FAT
"""
NOT_RENEWABLE = """Ticket cache: KCM:1500:41562
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 08:00:00  10/21/26 18:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
\tFlags: FIA
"""
NO_TGT = """Ticket cache: KCM:1500:41562
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 08:05:12  10/21/26 18:00:00  HTTP/intranet.example.com@EXAMPLE.COM
"""


def status(deadline_in: float, expires_in: float | None = None, renewable=True) -> TgtStatus:
    expires = NOW + (expires_in if expires_in is not None else deadline_in)  # renewed by sssd
    return TgtStatus("alice@EXAMPLE.COM", expires, renewable, NOW + deadline_in)


class Parsing(unittest.TestCase):
    def test_renewable_deadline_is_renew_until(self):
        s = tgtnotify.tgt_status(KLIST)
        self.assertEqual(s.principal, "alice@EXAMPLE.COM")
        self.assertTrue(s.renewable)
        self.assertEqual(s.deadline, ts("2026-10-28T08:00:00"))
        self.assertEqual(s.expires, ts("2026-10-21T18:00:00"))

    def test_not_renewable_deadline_is_expiry(self):
        s = tgtnotify.tgt_status(NOT_RENEWABLE)
        self.assertFalse(s.renewable)
        self.assertEqual(s.deadline, ts("2026-10-21T18:00:00"))

    def test_no_tgt(self):
        self.assertIsNone(tgtnotify.tgt_status(NO_TGT))
        self.assertIsNone(tgtnotify.tgt_status(""))

    def test_klist_runs_on_the_default_cache_in_c_locale(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, KLIST, ""))
        with mock.patch.dict(os.environ, {"KRB5CCNAME": "FILE:/tmp/other", "LANG": "de_DE.UTF-8"}), \
                mock.patch("shutil.which", return_value="/usr/bin/klist"), \
                mock.patch("subprocess.run", run):
            s = tgtnotify.read_tgt()
        self.assertEqual(s.deadline, ts("2026-10-28T08:00:00"))
        self.assertEqual(run.call_args.args[0], ["klist", "-f"])
        env = run.call_args.kwargs["env"]
        self.assertNotIn("KRB5CCNAME", env)    # the cache rpc.gssd and the session use
        self.assertEqual((env["LC_ALL"], env["TZ"]), ("C", "UTC"))

    def test_no_cache_or_no_klist_is_quiet(self):
        with mock.patch("shutil.which", return_value="/usr/bin/klist"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 1, "", "klist: Credentials cache 'KCM:1500' not found")):
            self.assertIsNone(tgtnotify.read_tgt())
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(tgtnotify.read_tgt())


class Due(unittest.TestCase):
    S = Settings()

    def test_thresholds(self):
        self.assertIsNone(tgtnotify.due(self.S, status(25 * H), set(), NOW))
        self.assertEqual(tgtnotify.due(self.S, status(23 * H), set(), NOW), ("86400", ["86400"]))
        self.assertEqual(tgtnotify.due(self.S, status(1 * H), set(), NOW), ("7200", ["86400", "7200"]))
        # the 24 h warning was shown: only the 2 h one comes later
        self.assertIsNone(tgtnotify.due(self.S, status(20 * H), {"86400"}, NOW))
        self.assertEqual(tgtnotify.due(self.S, status(1 * H), {"86400"}, NOW)[0], "7200")
        self.assertIsNone(tgtnotify.due(self.S, status(1 * H), {"86400", "7200"}, NOW))

    def test_expired(self):
        self.assertEqual(tgtnotify.due(self.S, status(-60), {"86400", "7200"}, NOW),
                         (EXPIRED, [EXPIRED, "86400", "7200"]))
        # renewal stopped (sssd offline): the TGT expired before its renew-until
        self.assertEqual(tgtnotify.due(self.S, status(3 * 24 * H, expires_in=-1), set(), NOW)[0], EXPIRED)
        self.assertIsNone(tgtnotify.due(self.S, status(-60), {EXPIRED}, NOW))
        self.assertIsNone(tgtnotify.due(Settings(notify_expired=False), status(-60), set(), NOW))

    def test_no_tgt_never_due(self):
        self.assertIsNone(tgtnotify.due(self.S, None, set(), NOW))

    def test_only_expired(self):
        s = Settings(thresholds=())
        self.assertIsNone(tgtnotify.due(s, status(60), set(), NOW))
        self.assertEqual(tgtnotify.due(s, status(-1), set(), NOW), (EXPIRED, [EXPIRED]))


class CheckOnce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "k.json"
        self.sent = []
        self.ok = True

    def tearDown(self):
        self.tmp.cleanup()

    def sender(self, summary, body, urgency):
        self.sent.append((summary, body, urgency))
        return self.ok

    def check(self, st, now=NOW, settings=None):
        return tgtnotify.check_once(settings or Settings(), State(self.path), now,
                                    reader=lambda: st, sender=self.sender)

    def test_once_per_threshold_also_across_restarts(self):
        st = status(23 * H)
        self.assertEqual(self.check(st), "86400")
        for _ in range(3):                       # later checks, new checker processes
            self.assertIsNone(self.check(st, NOW + 600))
        self.assertEqual(self.check(st, NOW + 22 * H), "7200")
        self.assertIsNone(self.check(st, NOW + 22.5 * H))
        self.assertEqual(self.check(st, NOW + 24 * H), EXPIRED)
        self.assertIsNone(self.check(st, NOW + 30 * H))
        self.assertEqual([u for _, _, u in self.sent], ["normal", "critical", "critical"])
        summary, body, _ = self.sent[0]
        self.assertEqual(summary, "Kerberos login ends in 23 hours")
        self.assertIn("reconnect with your password", body)
        self.assertIn("kinit", body)
        self.assertEqual(json.loads(self.path.read_text())["shown"], sorted([EXPIRED, "86400", "7200"]))

    def test_new_tgt_starts_over(self):
        self.assertEqual(self.check(status(1 * H)), "7200")
        # reconnect with a password: a new TGT, renew-until 7 days later
        self.assertIsNone(self.check(status(7 * 24 * H), NOW + 600))
        self.assertEqual(self.check(status(7 * 24 * H), NOW + 6 * 24 * H + 1), "86400")
        self.assertEqual(len(self.sent), 2)

    def test_failed_notification_is_retried(self):
        self.ok = False
        self.assertIsNone(self.check(status(1 * H)))
        self.assertFalse(self.path.exists())
        self.ok = True
        self.assertEqual(self.check(status(1 * H), NOW + 600), "7200")

    def test_no_tgt_quiet(self):
        self.assertIsNone(self.check(None))
        self.assertEqual(self.sent, [])

    def test_unreadable_state_starts_fresh(self):
        self.path.write_text("{not json")
        self.assertEqual(self.check(status(1 * H)), "7200")


class Texts(unittest.TestCase):
    def test_placeholders_and_urgency(self):
        s = tgtnotify.parse_settings({"summary": "Noch {left} ({principal})", "body": "Ab {deadline}: {{H:}}"})
        with mock.patch("time.localtime", time.gmtime):
            summary, body, urgency = tgtnotify.message(s, "86400", status(3 * H), NOW)
        self.assertEqual(summary, "Noch 3 hours (alice@EXAMPLE.COM)")
        self.assertEqual(body, "Ab Wed 21 Oct 15:00: {H:}")
        self.assertEqual(urgency, "normal")
        self.assertEqual(tgtnotify.message(s, "7200", status(1 * H), NOW)[2], "critical")
        self.assertEqual(tgtnotify.message(s, EXPIRED, status(-1), NOW)[0], tgtnotify.EXPIRED_SUMMARY)

    def test_human_left(self):
        self.assertEqual(tgtnotify.human_left(3 * 86400 + 5), "3 days")
        self.assertEqual(tgtnotify.human_left(23 * H + 59 * 60), "23 hours")
        self.assertEqual(tgtnotify.human_left(H + 30 * 60), "1 hour 30 minutes")
        self.assertEqual(tgtnotify.human_left(20), "1 minute")


class Config(unittest.TestCase):
    def test_parse(self):
        s = tgtnotify.parse_settings({"enabled": False, "thresholds": ["2h", "1d", 600, "2h"],
                                      "interval": "5s", "notify_expired": False})
        self.assertFalse(s.enabled)
        self.assertEqual(s.thresholds, (86400, 7200, 600))
        self.assertEqual(s.interval, tgtnotify.MIN_INTERVAL_S)
        self.assertFalse(s.notify_expired)

    def test_rejects(self):
        for raw in ({"enabled": "yes"}, {"thresholds": "24h"}, {"thresholds": ["0h"]}, {"thresholds": ["1w"]},
                    {"thresholds": [True]}, {"interval": "soon"}, {"summary": ""}, {"body": "{user}"},
                    {"body": "{left"}, {"title": "x"}, {"summary": 3}):
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                tgtnotify.parse_settings(raw)

    def test_load(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(tgtnotify.load(Path(d) / "missing.conf"), Settings())
            p = Path(d) / "tgt-notify.conf"
            p.write_text('enabled = true\nthresholds = ["12h"]\ninterval = "15m"\n')
            self.assertEqual(tgtnotify.load(p).thresholds, (43200,))
            p.write_text("enabled = \n")
            with self.assertRaisesRegex(ConfigError, str(p)):
                tgtnotify.load(p)


class Send(unittest.TestCase):
    def test_notify_send(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch("shutil.which", side_effect=lambda t: f"/usr/bin/{t}"), mock.patch("subprocess.run", run):
            self.assertTrue(tgtnotify.send("S", "-B", "critical"))
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[0], "notify-send")
        self.assertIn("--urgency=critical", cmd)
        self.assertEqual(cmd[-3:], ["--", "S", "-B"])     # texts never read as options

    def test_gdbus_fallback(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "(uint32 7,)", ""))
        with mock.patch("shutil.which", side_effect=lambda t: "/usr/bin/gdbus" if t == "gdbus" else None), \
                mock.patch("subprocess.run", run):
            self.assertTrue(tgtnotify.send('Say "hi"', "a\\b\nc", "normal"))
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:3], ["gdbus", "call", "--session"])
        self.assertIn('"Say \\"hi\\""', cmd)
        self.assertIn('"a\\\\b\\nc"', cmd)
        self.assertIn("{'urgency': <byte 1>}", cmd)

    def test_no_daemon(self):
        with mock.patch("shutil.which", side_effect=lambda t: f"/usr/bin/{t}"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 1, "", "GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown")), \
                mock.patch("sys.stderr"):
            self.assertFalse(tgtnotify.send("S", "B", "normal"))


class Main(unittest.TestCase):
    def run_main(self, conf: str, *args, env=None):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.conf"
            p.write_text(conf)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": d, "DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"}):
                return tgtnotify.main(["--config", str(p), *args]), Path(d)

    def test_disabled_does_nothing(self):
        with mock.patch.object(tgtnotify, "check_once") as check:
            rc, d = self.run_main("enabled = false\n", "--once")
        self.assertEqual(rc, 0)
        check.assert_not_called()

    def test_bad_config(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(self.run_main("thresholds = 5\n")[0], 2)

    def test_once_checks_and_locks(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": d, "DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"}), \
                mock.patch.object(tgtnotify, "check_once") as check:
            self.assertEqual(tgtnotify.main(["--config", "/nonexistent", "--once"]), 0)
            check.assert_called_once()
            base = Path(d) / "fastrdp-tgt-notify"
            self.assertEqual(oct(base.stat().st_mode & 0o777), "0o700")
            # a second checker for the same session bus exits at once
            import fcntl
            with open(base / f"{tgtnotify.session_key()}.lock", "w") as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                check.reset_mock()
                self.assertEqual(tgtnotify.main(["--config", "/nonexistent", "--once"]), 0)
                check.assert_not_called()

    def test_session_key_per_bus(self):
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:abstract=/tmp/dbus-a,guid=1"}):
            a = tgtnotify.session_key()
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:abstract=/tmp/dbus-a,guid=2"}):
            self.assertEqual(tgtnotify.session_key(), a)
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:abstract=/tmp/dbus-b,guid=1"}):
            self.assertNotEqual(tgtnotify.session_key(), a)

    def test_launcher(self):
        """broker/session/libexec/tgt-notify: isolated interpreter, the broker's private
        module path, quiet exit without fastrdp-broker."""
        text = (REPO / "broker/session/libexec/tgt-notify").read_text()
        self.assertTrue(text.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn('sys.path.insert(0, "/usr/lib/fastrdp/python")', text)
        self.assertTrue(os.access(REPO / "broker/session/libexec/tgt-notify", os.X_OK))
        res = subprocess.run(["python3", "-I", str(REPO / "broker/session/libexec/tgt-notify"), "--status"],
                             capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
