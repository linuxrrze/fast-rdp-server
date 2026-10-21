# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""TGT visibility in `fastrdpctl status` / `fastrdpctl tickets` (backlog K2, tickets.py).

Regressions: klist output parsed with the host's locale or time zone; the TGT looked
up in another cache than the session's default one (KRB5CCNAME, root's view); a hung
KCM blocking status; ticket contents beyond metadata in the reply."""

import contextlib
import io
import json
import unittest
from datetime import datetime, timezone
from unittest import mock

from fastrdp_broker import __main__ as cli
from fastrdp_broker import sysutil, tickets
from fastrdp_broker.state import Session
from test_gaps import EXAMPLE, _BrokerHarness, user


def ts(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


NOW = ts("2026-10-21T12:00:00")

# MIT klist -f, LC_ALL=C TZ=UTC: "%x %X" of the C locale, renew and flags on one line
KCM = """Ticket cache: KCM:1500:41562
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 08:00:00  10/21/26 18:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
\trenew until 10/28/26 08:00:00, Flags: FRIA
10/21/26 08:05:12  10/21/26 18:00:00  host/files.example.com@EXAMPLE.COM
\tFlags: FAT
"""
# not renewable, no flags (-f not given), FILE cache as a bare path
NOT_RENEWABLE = """Ticket cache: FILE:/tmp/krb5cc_1500
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 08:00:00  10/21/26 18:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
"""
EXPIRED = """Ticket cache: KCM:1500:7
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
10/20/26 08:00:00  10/20/26 18:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
\trenew until 10/27/26 08:00:00, Flags: RIA
"""
# klist -A: two caches; long dates ("%d %b %Y %T" fallback); flags on their own line
ALL = """Ticket cache: KCM:1500:41562
Default principal: alice@EXAMPLE.COM

Valid starting       Expires              Service principal
21 Oct 2026 08:00:00 21 Oct 2026 12:30:00 krbtgt/EXAMPLE.COM@EXAMPLE.COM
\trenew until 22 Oct 2026 08:00:00
\tFlags: FRIA

Ticket cache: KCM:1500:999
Default principal: admin@CORP.EXAMPLE.COM

Valid starting     Expires            Service principal
10/21/26 09:00:00  10/21/26 19:00:00  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM
"""
NO_TGT = """Ticket cache: KCM:1500:3
Default principal: alice@EXAMPLE.COM

Valid starting     Expires            Service principal
"""
LIST = """Principal name                 Cache name
--------------                 ----------
alice@EXAMPLE.COM              KCM:1500:41562
admin@CORP.EXAMPLE.COM         KCM:1500:999 (Expired)
"""


class ParserTests(unittest.TestCase):
    def test_kcm_renewable(self):
        [cache] = tickets.parse_klist(KCM)
        self.assertEqual((cache.name, cache.principal), ("KCM:1500:41562", "alice@EXAMPLE.COM"))
        self.assertEqual(len(cache.tickets), 2)
        tgt = tickets.find_tgt(cache)
        self.assertEqual(tgt.service, "krbtgt/EXAMPLE.COM@EXAMPLE.COM")
        self.assertEqual(tgt.expires, ts("2026-10-21T18:00:00"))
        self.assertEqual(tgt.renew_until, ts("2026-10-28T08:00:00"))
        self.assertEqual(tgt.flags, "FRIA")
        self.assertEqual(cache.tickets[1].flags, "FAT")
        self.assertEqual(tickets.describe(cache, NOW), {
            "principal": "alice@EXAMPLE.COM", "cache": "KCM:1500:41562", "cache_type": "KCM",
            "expires": "2026-10-21T18:00:00Z", "expires_in": 6 * 3600, "renewable": True,
            "renew_until": "2026-10-28T08:00:00Z", "renew_in": 6 * 86400 + 20 * 3600, "state": "ok"})

    def test_not_renewable(self):
        [cache] = tickets.parse_klist(NOT_RENEWABLE)
        info = tickets.describe(cache, NOW)
        self.assertEqual((info["state"], info["renewable"], info["cache_type"]),
                         ("not_renewable_soon", False, "FILE"))
        self.assertNotIn("renew_until", info)

    def test_expired(self):
        info = tickets.describe(tickets.parse_klist(EXPIRED)[0], NOW)
        self.assertEqual(info["state"], "expired")
        self.assertLess(info["expires_in"], 0)

    def test_multiple_caches_and_long_dates(self):
        first, second = tickets.parse_klist(ALL)
        self.assertEqual(second.principal, "admin@CORP.EXAMPLE.COM")
        self.assertEqual(tickets.find_tgt(second).service, "krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM")
        tgt = tickets.find_tgt(first)
        self.assertEqual((tgt.renew_until, tgt.flags), (ts("2026-10-22T08:00:00"), "FRIA"))
        self.assertEqual(tickets.describe(first, NOW)["state"], "expiring")   # 30 min left
        tgt.expires = ts("2026-10-21T18:00:00")
        self.assertEqual(tickets.describe(first, NOW)["state"], "not_renewable_soon")  # renewal ends in 20 h

    def test_no_tgt_and_no_cache(self):
        self.assertEqual(tickets.describe(tickets.parse_klist(NO_TGT)[0], NOW)["state"], "none")
        self.assertEqual(tickets.parse_klist("klist: Credentials cache 'KCM:1500' not found\n"), [])
        self.assertEqual(tickets.describe(None)["state"], "none")

    def test_renewable_flag_wins_and_renew_till_at_expiry(self):
        [cache] = tickets.parse_klist(KCM)
        tgt = tickets.find_tgt(cache)
        tgt.flags = "FIA"   # KDC did not grant renewable
        self.assertFalse(tickets.describe(cache, NOW)["renewable"])
        tgt.flags, tgt.renew_until = "FRIA", tgt.expires
        self.assertEqual(tickets.describe(cache, NOW)["state"], "not_renewable_soon")

    def test_time_formats(self):
        expect = ts("2026-10-21T08:00:00")
        for text in ("10/21/26 08:00:00", "10/21/2026 08:00:00", "21 Oct 2026 08:00:00",
                     "Wed Oct 21 08:00:00 2026", "2026-10-21T08:00:00", "20261021080000",
                     "10/21/26 08:00"):
            with self.subTest(text):
                self.assertEqual(tickets.parse_time(text), expect)
        with self.assertRaises(ValueError):
            tickets.parse_time("21.10.2026 08:00")

    def test_list(self):
        self.assertEqual(tickets.parse_list(LIST), [("alice@EXAMPLE.COM", "KCM:1500:41562", False),
                                                    ("admin@CORP.EXAMPLE.COM", "KCM:1500:999", True)])


def results(**by_args):
    """run_dropped mock: klist output per argument tuple."""
    async def run(user, *argv, env=None, timeout=15):
        return by_args[" ".join(argv[1:])]
    return mock.AsyncMock(side_effect=run)


class QueryTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_as_user_in_c_locale_utc(self):
        run = results(**{"-f": sysutil.Result(0, KCM, ""), "-l": sysutil.Result(0, LIST, "")})
        alice = user()
        with mock.patch("fastrdp_broker.sysutil.run_dropped", run):
            info = await tickets.query(alice, NOW)
        self.assertEqual((info["state"], info["caches"]), ("ok", 2))
        for call in run.await_args_list:
            self.assertIs(call.args[0], alice)        # the user's ids: the session's KCM view
            self.assertEqual(call.args[1], "klist")
            self.assertEqual(call.kwargs["env"], {"LC_ALL": "C", "TZ": "UTC"})  # no KRB5CCNAME
            self.assertLessEqual(call.kwargs["timeout"], 5)

    async def test_no_cache(self):
        run = results(**{"-f": sysutil.Result(1, "", "klist: Credentials cache 'KCM:1500' not found\n")})
        with mock.patch("fastrdp_broker.sysutil.run_dropped", run):
            info = await tickets.query(user())
        self.assertEqual(info, {"state": "none", "error": "klist: Credentials cache 'KCM:1500' not found"})

    async def test_timeout_and_missing_klist(self):
        for exc in (sysutil.CommandError("timeout: klist"), FileNotFoundError("klist")):
            with self.subTest(exc=exc), self.assertLogs("fastrdp.tickets", "WARNING"), \
                    mock.patch("fastrdp_broker.sysutil.run_dropped", side_effect=exc):
                self.assertEqual((await tickets.query(user()))["state"], "unknown")


class StatusTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def test_status_reports_each_account_once(self):
        self.broker.state.put(Session("alice", "gnome", "gnome", port=41000, rdp_password="sec"))
        self.broker.state.put(Session("alice", "xrdp", "xfce"))
        self.broker.state.put(Session("carol", "xrdp", "xfce"))
        for b in self.broker.backends.values():
            b.alive = mock.AsyncMock(return_value=True)
        run = results(**{"-f": sysutil.Result(0, KCM, ""), "-l": sysutil.Result(0, LIST, "")})
        with mock.patch("fastrdp_broker.sysutil.run_dropped", run), \
                mock.patch("fastrdp_broker.server.peer_uid", return_value=0):
            from test_server import request
            status = await request(self.cfg.broker.socket, {"op": "status"})
            one = await request(self.cfg.broker.socket, {"op": "tickets", "user": "eve"})
            unknown = await request(self.cfg.broker.socket, {"op": "tickets", "user": "nobody-here"})
        self.assertEqual(sorted(status["tickets"]), ["alice", "carol"])
        self.assertEqual(run.await_count, 4 + 2)   # klist -f and -l per account, not per session
        self.assertEqual(status["tickets"]["alice"]["principal"], "alice@EXAMPLE.COM")
        self.assertEqual(sorted(one["tickets"]), ["eve"])
        self.assertEqual(unknown["tickets"]["nobody-here"]["state"], "unknown")
        self.assertNotIn("sec", json.dumps(status))

    async def test_tickets_is_root_only(self):
        with mock.patch("fastrdp_broker.server.peer_uid", return_value=65534):
            reply = await self.login(op="tickets")
        self.assertEqual(reply["error"], "not permitted")


STATUS_REPLY = {
    "ok": True, "connected": 1, "pending_tokens": 0, "pending_web_tokens": 0, "mfa_grace_entries": 0,
    "sessions": [{"user": "alice", "backend": "gnome", "desktop": "gnome", "port": 41000,
                  "rdp_user": "alice", "started": NOW, "last_login": NOW}],
    "tickets": {"alice": tickets.describe(tickets.parse_klist(KCM)[0], NOW),
                "bob": {"state": "none", "error": "klist: Credentials cache 'KCM:1501' not found"}},
}


class CtlTests(unittest.TestCase):
    def run_ctl(self, reply, *args):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.makefile.return_value = io.StringIO(json.dumps(reply) + "\n")
        out = io.StringIO()
        with mock.patch.object(cli.socket, "socket", return_value=sock), contextlib.redirect_stdout(out):
            rc = cli.ctl_main(["-c", str(EXAMPLE), *args])
        return rc, json.loads(sock.sendall.call_args.args[0]), out.getvalue()

    def test_status_table(self):
        rc, req, out = self.run_ctl(STATUS_REPLY, "status")
        self.assertEqual((rc, req), (0, {"op": "status"}))
        self.assertIn("alice  gnome    gnome    41000  2026-10-21 12:00", out)
        self.assertRegex(out, r"alice +ok +alice@EXAMPLE.COM +2026-10-21T18:00:00Z \(6h00m\) +"
                              r"2026-10-28T08:00:00Z \(6d20h\) +KCM:1500:41562")
        self.assertRegex(out, r"bob +none +- +- +- +klist: Credentials cache 'KCM:1501' not found")
        self.assertIn("connected: 1", out)

    def test_status_json(self):
        rc, _, out = self.run_ctl(STATUS_REPLY, "status", "--json")
        self.assertEqual(json.loads(out), STATUS_REPLY)

    def test_tickets(self):
        reply = {"ok": True, "tickets": STATUS_REPLY["tickets"]}
        rc, req, out = self.run_ctl(reply, "tickets", "alice")
        self.assertEqual((rc, req), (0, {"op": "tickets", "user": "alice"}))
        self.assertTrue(out.startswith("USER"))
        self.assertEqual(self.run_ctl(reply, "tickets")[1], {"op": "tickets"})
        self.assertEqual(self.run_ctl({"ok": True, "tickets": {}}, "tickets")[2], "no session users\n")

    def test_error_reply_is_json(self):
        rc, _, out = self.run_ctl({"ok": False, "error": "not permitted"}, "status")
        self.assertEqual((rc, json.loads(out)["error"]), (1, "not permitted"))
