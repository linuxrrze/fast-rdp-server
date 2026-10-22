# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] mode web / push_or_web: a login waits in the broker until its user approves it
on fastrdp-webgate's approval page (ops mfa_pending / mfa_decide, webgate uid only).
Approve continues the login, Deny fails it (mfa_failed), no decision in time fails it
(mfa_timeout); push_or_web runs a privacyIDEA push alongside, the first answer wins."""

import asyncio
import json
import os
import threading
import time
import unittest
from unittest import mock

from fastrdp_broker import config, tickets
from fastrdp_broker.config import MfaSection
from fastrdp_broker.mfa import WebApprovals
from fastrdp_broker.privacyidea import PrivacyIdeaError
from test_gaps import _BrokerHarness, raw_example, request

MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}, "web": {"enabled": True}}
ADDR, OTHER_ADDR = "192.0.2.10", "198.51.100.7"


# ------------------------------------------------------------------ config
class WebApprovalConfigTests(unittest.TestCase):
    def test_defaults(self):
        mfa = config.parse(dict(MINIMAL)).mfa
        self.assertEqual((mfa.web_approval_timeout, mfa.web_approval_max_auth_age,
                          mfa.web_approval_single_pending), (90, 30, True))
        ex = config.parse(raw_example()).mfa  # commented out in the example
        self.assertEqual((ex.web_approval_timeout, ex.web_approval_max_auth_age), (90, 30))

    def test_web_modes_need_web_enabled(self):
        for mode in ("web", "push_or_web"):
            with self.subTest(mode), self.assertRaisesRegex(config.ConfigError, r"needs \[web\] enabled"):
                config.parse({"desktops": MINIMAL["desktops"],
                              "mfa": {"mode": mode, "privacyidea": {"url": "https://pi"}}})

    def test_privacyidea_only_where_used(self):
        self.assertEqual(config.parse({**MINIMAL, "mfa": {"mode": "web"}}).mfa.mode, "web")
        with self.assertRaisesRegex(config.ConfigError, "url is required"):
            config.parse({**MINIMAL, "mfa": {"mode": "push_or_web"}})
        cfg = config.parse({**MINIMAL, "mfa": {"mode": "push_or_web", "privacyidea": {"url": "https://pi"}}})
        self.assertEqual(cfg.mfa.mode, "push_or_web")

    def test_valid(self):
        cfg = config.parse({**MINIMAL, "mfa": {"mode": "web", "web_approval_timeout": 510,
                                               "web_approval_max_auth_age": 0,
                                               "web_approval_single_pending": False}})
        self.assertEqual((cfg.mfa.web_approval_timeout, cfg.mfa.web_approval_max_auth_age,
                          cfg.mfa.web_approval_single_pending), (510, 0, False))

    def test_invalid(self):
        for bad in (9, 511, 90.5, "90", True):
            with self.subTest(timeout=bad), self.assertRaisesRegex(config.ConfigError, "approval_timeout must"):
                config.parse({**MINIMAL, "mfa": {"web_approval_timeout": bad}})
        for bad in (-1, 301, "30", False):
            with self.subTest(age=bad), self.assertRaisesRegex(config.ConfigError, "max_auth_age must"):
                config.parse({**MINIMAL, "mfa": {"web_approval_max_auth_age": bad}})
        with self.assertRaisesRegex(config.ConfigError, "true or false"):
            config.parse({**MINIMAL, "mfa": {"web_approval_single_pending": "yes"}})


# ------------------------------------------------------------------ store
class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class WebApprovalStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_finished_ids_forgotten_after_a_while(self):
        clock = Clock()
        store = WebApprovals(MfaSection(web_approval_timeout=30), clock, lambda: 1_800_000_000.0)
        task = asyncio.create_task(store.wait("alice", "nla", ADDR))
        await asyncio.sleep(0)
        (rid,) = store.pending
        store.decide("alice", rid, True, 1_800_000_000)
        self.assertEqual(await task, "web")
        self.assertEqual((len(store), store.finished[rid][:2]), (0, ("alice", "approved")))
        clock.t += WebApprovals.FINISHED_KEEP
        store.prune()
        self.assertEqual(store.finished, {})


# ------------------------------------------------------------------ broker
class _ApprovalHarness(_BrokerHarness):
    """The broker with a web approval mode; the test acts as proxy and webgate (same uid)."""
    mode = "web"

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.pi = self.set_mfa(self.mode)
        self.mfa_cfg = self.broker.mfa.cfg
        self.mfa_cfg.web_approval_timeout = 10

    def start(self, **kw):
        """A login waiting in the broker (TLS, client address ADDR unless given)."""
        return asyncio.create_task(self.login(**{"client_address": ADDR, **kw}))

    def pending_op(self, user="alice"):
        return request(self.cfg.broker.socket, {"op": "mfa_pending", "user": user})

    def decide(self, rid, approve=True, user="alice", auth_time=None, bound=None):
        msg = {"op": "mfa_decide", "user": user, "id": rid, "approve": approve,
               "auth_time": int(time.time()) if auth_time is None else auth_time}
        if bound is not None:
            msg["bound"] = bound
        return request(self.cfg.broker.socket, msg)

    async def wait_pending(self, n=1, user="alice"):
        """The ids of `user`'s pending logins once there are n of them (oldest first)."""
        for _ in range(250):
            reply = await self.pending_op(user)
            if len(reply.get("pending", [])) >= n:
                return [p["id"] for p in reply["pending"]]
            await asyncio.sleep(0.02)
        self.fail(f"{n} pending web approval(s) for {user} expected, got {reply}")

    def refused_decision(self, reason, outcome=None):
        reply = {"ok": False, "error": "not decided", "reason": reason}
        if outcome:
            reply["outcome"] = outcome
        return reply

    async def proxy_login(self):
        """A login whose connection the test can close like the proxy does."""
        _, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps({"op": "login", "session_id": "s1", "method": "tls", "user": "alice",
                                 "password": "pw", "client_address": ADDR}).encode() + b"\n")
        await writer.drain()
        return writer


class WebApprovalTests(_ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    async def test_approve(self):
        with self.assertLogs("fastrdp_broker.mfa", "INFO") as logs:
            login = self.start()
            reply = await self.pending_op()
            for _ in range(250):
                if reply["pending"]:
                    break
                await asyncio.sleep(0.02)
                reply = await self.pending_op()
        self.assertTrue(any("web approval pending for alice from 192.0.2.10" in line
                            for line in logs.output), logs.output)
        self.assertEqual(reply["user"], "alice")
        (entry,) = reply["pending"]
        self.assertEqual({k: entry[k] for k in ("method", "client_address", "single_pending_conflict")},
                         {"method": "tls", "client_address": ADDR, "single_pending_conflict": False})
        self.assertIsInstance(entry["age_s"], int)
        self.assertGreaterEqual(len(entry["id"]), 20)
        self.assertFalse(login.done())                       # still waiting
        self.ensure.assert_not_called()
        self.assertEqual(await self.decide(entry["id"]), {"ok": True, "approved": True, "others_pending": 0})
        self.assertTrue((await login)["ok"])
        self.ensure.assert_awaited_once()
        self.assertEqual((await self.pending_op())["pending"], [])
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_nla_login(self):
        login = asyncio.create_task(self.nla(client_address=ADDR))
        (rid,) = await self.wait_pending()
        self.assertEqual((await self.pending_op())["pending"][0]["method"], "nla")
        await self.decide(rid)
        self.assertTrue((await login)["ok"])

    async def test_deny(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertEqual(await self.decide(rid, approve=False), {"ok": True, "approved": False, "others_pending": 0})
        self.assertEqual(await login, self.refused("mfa_failed"))
        self.ensure.assert_not_called()
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_timeout(self):
        self.mfa_cfg.web_approval_timeout = 0.3
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertEqual(await login, self.refused("mfa_timeout"))
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.assertEqual(await self.decide(rid), self.refused_decision("approval_finished", "expired"))
        self.ensure.assert_not_called()

    async def test_proxy_drop_removes_entry(self):
        writer = await self.proxy_login()
        (rid,) = await self.wait_pending()
        with self.assertLogs("fastrdp_broker.mfa", "INFO") as logs:
            writer.close()
            for _ in range(250):
                if not self.broker.mfa.approvals.pending:
                    break
                await asyncio.sleep(0.02)
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.assertTrue(any("web approval wait for alice cancelled" in line for line in logs.output), logs.output)
        self.assertEqual(await self.decide(rid), self.refused_decision("approval_finished", "abandoned"))
        self.ensure.assert_not_called()
        self.assertEqual(self.broker.active, {})

    async def test_ops_only_for_the_webgate(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        not_permitted = {"ok": False, "error": "not permitted", "reason": "denied"}
        with mock.patch.object(self.broker, "web_uid", os.getuid() + 1):
            self.assertEqual(await self.pending_op(), not_permitted)
            self.assertEqual(await self.decide(rid), not_permitted)
        with mock.patch.object(self.broker, "web_uid", None):      # [web] disabled
            self.assertEqual(await self.decide(rid), not_permitted)
        self.assertFalse(login.done())
        await self.decide(rid, approve=False)
        await login

    async def test_other_users_id_refused(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertEqual((await self.pending_op("eve"))["pending"], [])
        for approve in (True, False):
            self.assertEqual(await self.decide(rid, approve, user="eve"),
                             self.refused_decision("approval_unknown"))
        self.assertEqual(await self.decide("no-such-id"), self.refused_decision("approval_unknown"))
        self.assertFalse(login.done())
        await self.decide(rid)
        self.assertTrue((await login)["ok"])
        # eve never learns how alice's login ended either
        self.assertEqual(await self.decide(rid, user="eve"), self.refused_decision("approval_unknown"))

    async def test_two_pending_refused_with_single_pending(self):
        first = self.start()
        second = self.start(client_address=OTHER_ADDR)
        ids = await self.wait_pending(2)
        reply = await self.pending_op()
        self.assertEqual([p["single_pending_conflict"] for p in reply["pending"]], [True, True])
        self.assertEqual([p["client_address"] for p in reply["pending"]], [ADDR, OTHER_ADDR])
        for rid in ids:
            self.assertEqual(await self.decide(rid), self.refused_decision("approval_conflict"))
        self.assertFalse(first.done() or second.done())
        # denying is always possible; with one login left it can be approved
        await self.decide(ids[1], approve=False)
        self.assertEqual(await second, self.refused("mfa_failed"))
        self.assertFalse((await self.pending_op())["pending"][0]["single_pending_conflict"])
        await self.decide(ids[0])
        self.assertTrue((await first)["ok"])

    async def test_bound_approves_despite_another_pending(self):
        """The user came with the id from its own waiting screen's QR code (webgate
        ?login=<id>): that login is approved, the other one (somebody else's with the
        same password?) stays pending and can still be denied."""
        first = self.start()
        second = self.start(client_address=OTHER_ADDR)
        ids = await self.wait_pending(2)
        self.assertEqual(await self.decide(ids[1], bound=False), self.refused_decision("approval_conflict"))
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            self.assertEqual(await self.decide(ids[1], bound=True), {"ok": True, "approved": True, "others_pending": 1})
        self.assertIn(f"INFO:fastrdp.broker:web approval for alice from {OTHER_ADDR} (tls login): approved via "
                      "the login-bound link on the approval page", logs.output)
        # the webgate warned on the page; the log says it too
        self.assertIn("WARNING:fastrdp.broker:web approval for alice via the login-bound link while 1 other "
                      "login(s) of the account waited: somebody else may have the password", logs.output)
        self.assertTrue((await second)["ok"])
        self.assertEqual(await self.wait_pending(), [ids[0]])
        self.assertFalse(first.done())
        await self.decide(ids[0], approve=False)
        self.assertEqual(await first, self.refused("mfa_failed"))

    async def test_others_pending_counts_own_logins_only(self):
        """mfa_decide's others_pending: the deciding user's other waiting logins, never
        another user's (nor any id)."""
        mine, eves = self.start(), self.start(user="eve", client_address=OTHER_ADDR)
        (rid,) = await self.wait_pending()
        await self.wait_pending(user="eve")
        with self.assertNoLogs("fastrdp.broker", "WARNING"):
            reply = await self.decide(rid, bound=True)
        self.assertEqual(reply, {"ok": True, "approved": True, "others_pending": 0})
        self.assertTrue((await mine)["ok"])
        (eve_id,) = await self.wait_pending(user="eve")
        self.assertEqual(await self.decide(eve_id, approve=False, user="eve"),
                         {"ok": True, "approved": False, "others_pending": 0})
        await eves

    async def test_bound_relaxes_nothing_else(self):
        first = self.start()
        second = self.start(client_address=OTHER_ADDR)
        ids = await self.wait_pending(2)
        created = self.broker.mfa.approvals.pending[ids[0]].created_wall
        # another user's id looks unknown, bound or not
        self.assertEqual(await self.decide(ids[0], user="eve", bound=True),
                         self.refused_decision("approval_unknown"))
        self.assertEqual(await self.decide("no-such-id", bound=True), self.refused_decision("approval_unknown"))
        # the sign-in must still be fresh
        self.assertEqual(await self.decide(ids[0], auth_time=int(created) - 40, bound=True),
                         self.refused_decision("approval_stale"))
        self.assertFalse(first.done() or second.done())
        await self.decide(ids[0], approve=False, bound=True)
        self.assertEqual(await first, self.refused("mfa_failed"))
        # a finished login stays finished
        self.assertEqual(await self.decide(ids[0], bound=True), self.refused_decision("approval_finished", "denied"))
        await self.decide(ids[1], bound=True)
        self.assertTrue((await second)["ok"])

    async def test_two_pending_allowed_without_single_pending(self):
        self.mfa_cfg.web_approval_single_pending = False
        first, second = self.start(), self.start(client_address=OTHER_ADDR)
        ids = await self.wait_pending(2)
        self.assertFalse((await self.pending_op())["pending"][0]["single_pending_conflict"])
        for rid, others in zip(ids, (1, 0)):
            self.assertEqual(await self.decide(rid), {"ok": True, "approved": True, "others_pending": others})
        self.assertTrue((await first)["ok"] and (await second)["ok"])

    async def test_stale_sign_in_refused(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        created = self.broker.mfa.approvals.pending[rid].created_wall
        self.assertEqual(await self.decide(rid, auth_time=int(created) - 40),
                         self.refused_decision("approval_stale"))
        self.mfa_cfg.web_approval_max_auth_age = 0
        self.assertEqual(await self.decide(rid, auth_time=int(created) - 1),
                         self.refused_decision("approval_stale"))
        self.assertFalse(login.done())
        self.mfa_cfg.web_approval_max_auth_age = 30
        self.assertEqual(await self.decide(rid, auth_time=int(created) - 29), {"ok": True, "approved": True, "others_pending": 0})
        self.assertTrue((await login)["ok"])

    async def test_stale_sign_in_may_still_deny(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertEqual(await self.decide(rid, approve=False, auth_time=0), {"ok": True, "approved": False, "others_pending": 0})
        self.assertEqual(await login, self.refused("mfa_failed"))

    async def test_already_decided(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        await self.decide(rid)
        await login
        for approve in (True, False):
            self.assertEqual(await self.decide(rid, approve),
                             self.refused_decision("approval_finished", "approved"))
        login = self.start()
        (rid,) = await self.wait_pending()
        await self.decide(rid, approve=False)
        await login
        self.assertEqual(await self.decide(rid), self.refused_decision("approval_finished", "denied"))

    async def test_malformed_decision_is_a_protocol_error(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        for bad in ({"approve": "yes"}, {"approve": 1}, {"auth_time": "now"}, {"auth_time": None},
                    {"auth_time": True}, {"id": None}, {"bound": "yes"}, {"bound": 1}):
            with self.subTest(bad):
                msg = {"op": "mfa_decide", "user": "alice", "id": rid, "approve": True,
                       "auth_time": int(time.time()), **bad}
                self.assertEqual(await request(self.cfg.broker.socket, msg), {})   # connection dropped
        self.assertFalse(login.done())
        await self.decide(rid, approve=False)
        await login

    async def test_reconnect_grace_records_web(self):
        self.broker.grace.seconds = 300
        login = self.start()
        (rid,) = await self.wait_pending()
        await self.decide(rid)
        self.assertTrue((await login)["ok"])
        (entry,) = self.broker.grace.entries.values()
        self.assertEqual((entry.factor, entry.address), ("web", ADDR))
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            self.assertTrue((await self.login(client_address=ADDR))["ok"])     # no approval needed
        self.assertTrue(any("reconnect grace (web passed" in line for line in logs.output), logs.output)
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_denied_records_no_grace(self):
        self.broker.grace.seconds = 300
        login = self.start()
        (rid,) = await self.wait_pending()
        await self.decide(rid, approve=False)
        await login
        self.assertEqual(self.broker.grace.entries, {})

    async def test_exempt_and_kdc_enforced_skip_it(self):
        self.mfa_cfg.exempt_groups = ["mfa-exempt"]
        self.assertTrue((await self.login(user="carol", client_address=ADDR))["ok"])
        self.mfa_cfg.nla_kdc_enforced = True
        self.assertTrue((await self.nla(client_address=ADDR))["ok"])
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_no_pending_without_web_mode(self):
        self.set_mfa("none")
        self.assertTrue((await self.login())["ok"])
        self.assertEqual(await self.pending_op(), {"ok": True, "user": "alice", "pending": []})

    async def test_status_counts_pending(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        status = await self.broker.status()
        self.assertEqual(status["mfa_pending_approvals"], 1)
        self.assertIn("MFA web approvals pending: 1", tickets.format_status(status)[-1])
        await self.decide(rid, approve=False)
        await login
        self.assertEqual((await self.broker.status())["mfa_pending_approvals"], 0)


class PushOrWebTests(_ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    """push_or_web: a privacyIDEA push and the web approval at the same time."""
    mode = "push_or_web"

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.pi.trigger_challenge.return_value = "tx"
        self.cancels = []
        self.started = threading.Event()

        def wait_for_push(user, txid, cancel):  # never approved; stops when cancelled
            self.cancels.append(cancel)
            self.started.set()
            cancel.wait(30)
            return False

        self.pi.wait_for_push.side_effect = wait_for_push

    async def test_web_wins(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertTrue(await asyncio.to_thread(self.started.wait, 5))
        with self.assertLogs("fastrdp_broker.mfa", "INFO") as logs:
            await self.decide(rid)
            reply = await login
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(self.cancels[0].is_set(), "push still polling")
        self.assertTrue(any("push wait for alice cancelled" in line for line in logs.output), logs.output)

    async def test_push_wins(self):
        release = threading.Event()

        def wait_for_push(user, txid, cancel):
            self.cancels.append(cancel)
            release.wait(5)
            return True

        self.pi.wait_for_push.side_effect = wait_for_push
        self.broker.grace.seconds = 300
        login = self.start()
        (rid,) = await self.wait_pending()
        release.set()
        self.assertTrue((await login)["ok"])
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.assertEqual(await self.decide(rid), self.refused_decision("approval_finished", "abandoned"))
        self.assertEqual([e.factor for e in self.broker.grace.entries.values()], ["push"])

    async def test_web_deny_fails_and_stops_push(self):
        login = self.start()
        (rid,) = await self.wait_pending()
        self.assertTrue(await asyncio.to_thread(self.started.wait, 5))
        await self.decide(rid, approve=False)
        self.assertEqual(await login, self.refused("mfa_failed"))
        self.assertTrue(self.cancels[0].is_set())
        self.ensure.assert_not_called()

    async def test_push_refused_fails_and_removes_web_entry(self):
        # wait_for_push ends without approval well before push_timeout: the final check refused it
        self.pi.wait_for_push.side_effect = None
        self.pi.wait_for_push.return_value = False
        self.assertEqual(await self.login(client_address=ADDR), self.refused("mfa_failed"))
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.ensure.assert_not_called()

    async def test_push_timed_out_web_still_approves(self):
        self.mfa_cfg.privacyidea.push_timeout = 0
        self.pi.wait_for_push.side_effect = None
        self.pi.wait_for_push.return_value = False
        login = self.start()
        (rid,) = await self.wait_pending()
        await asyncio.sleep(0.05)
        self.assertFalse(login.done())
        await self.decide(rid)
        self.assertTrue((await login)["ok"])

    async def test_without_push_token_web_still_approves(self):
        self.pi.trigger_challenge.return_value = None
        login = self.start()
        (rid,) = await self.wait_pending()
        await asyncio.sleep(0.05)
        self.assertFalse(login.done())
        await self.decide(rid)
        self.assertTrue((await login)["ok"])

    async def test_privacyidea_down_web_still_approves(self):
        self.pi.trigger_challenge.side_effect = PrivacyIdeaError("down")
        with self.assertLogs("fastrdp_broker.mfa", "WARNING") as logs:
            login = self.start()
            (rid,) = await self.wait_pending()
            await asyncio.sleep(0.05)
        self.assertIn("push for alice: down; waiting for web approval only", logs.output[-1])
        self.assertFalse(login.done())
        await self.decide(rid)
        self.assertTrue((await login)["ok"])

    async def test_nothing_in_time(self):
        self.mfa_cfg.web_approval_timeout = 0.3
        login = self.start()
        await self.wait_pending()
        self.assertEqual(await login, self.refused("mfa_timeout"))
        self.assertTrue(self.cancels[0].is_set())
        self.assertEqual(self.broker.mfa.approvals.pending, {})

    async def test_proxy_drop_stops_both(self):
        writer = await self.proxy_login()
        await self.wait_pending()
        self.assertTrue(await asyncio.to_thread(self.started.wait, 5))
        writer.close()
        for _ in range(250):
            if not self.broker.mfa.approvals.pending and self.cancels[0].is_set():
                break
            await asyncio.sleep(0.02)
        self.assertEqual(self.broker.mfa.approvals.pending, {})
        self.assertTrue(self.cancels[0].is_set())
        self.ensure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
