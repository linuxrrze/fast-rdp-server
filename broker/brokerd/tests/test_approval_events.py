# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Approval notifications, broker side (mfa.ApprovalEvents, op mfa_events): every login
that starts waiting for web approval and every end of such a wait becomes an event for
fastrdp-webgate's notifier. Events are queued without waiting and never touch the
login; a full queue drops them; only the webgate's uid may collect them. The two-digit
correlation code appears on the waiting screen, the approval page and in the events."""

import asyncio
import os
import time
import unittest
from unittest import mock

from fastrdp_broker import tickets, ui
from fastrdp_broker.config import MfaSection, UiSection
from fastrdp_broker.mfa import ApprovalEvents, MfaDenied, WebApprovals
from test_gaps import request
from test_waiting_screen import URL, _ProgressMixin
from test_web_approval import ADDR, Clock, _ApprovalHarness


# ------------------------------------------------------------------ store
class ApprovalEventsTests(unittest.IsolatedAsyncioTestCase):
    def store(self, **kw):
        self.clock = Clock()
        approvals = WebApprovals(MfaSection(web_approval_timeout=30, **kw), self.clock, lambda: 1_800_000_000.0)
        approvals.events.clock = self.clock
        return approvals

    async def pending(self, store, n=1):
        for _ in range(100):
            if len(store.pending) >= n:
                return
            await asyncio.sleep(0)
        self.fail("login not pending")

    async def test_nothing_kept_without_a_consumer(self):
        store = self.store()
        task = asyncio.create_task(store.wait("alice", "tls", ADDR))
        await self.pending(store)
        self.assertEqual(store.events.queue.qsize(), 0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual((store.events.queue.qsize(), store.events.dropped), (0, 0))

    async def test_events_for_every_outcome(self):
        store = self.store()
        self.assertEqual(await store.events.get(0), [])         # a consumer from now on
        outcomes = {}

        async def one(outcome):
            if outcome == "expired":
                store.cfg.web_approval_timeout = 0.01
            task = asyncio.create_task(store.wait("alice", "nla", ADDR))
            await self.pending(store)
            (rid,) = store.pending
            if outcome == "approved":
                store.decide("alice", rid, True, 1_800_000_000)
            elif outcome == "denied":
                store.decide("alice", rid, False, 0)
            elif outcome == "abandoned":
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            store.cfg.web_approval_timeout = 30
            outcomes[outcome] = rid

        for outcome in ("approved", "denied", "expired", "abandoned"):
            await one(outcome)
        events = await store.events.get(0, store.still_news)
        # the "pending" events of logins already ended are left out; their end comes
        self.assertEqual([(e["event"], e["outcome"]) for e in events],
                         [("finished", o) for o in ("approved", "denied", "expired", "abandoned")])
        self.assertEqual([e["id"] for e in events], list(outcomes.values()))
        self.assertEqual({e["user"] for e in events}, {"alice"})
        self.assertEqual(store.events.sent, 4)

    async def test_pending_event(self):
        store = self.store()
        await store.events.get(0)
        task = asyncio.create_task(store.wait("alice", "tls", ADDR))
        await self.pending(store)
        (entry,) = store.pending.values()
        (event,) = await store.events.get(0)
        self.assertEqual(event, {"event": "pending", "id": entry.id, "user": "alice", "method": "tls",
                                 "client_address": ADDR, "created": 1_800_000_000, "timeout_s": 30,
                                 "code": entry.code})
        self.assertRegex(entry.code, r"^[0-9]{2}\Z")
        self.assertEqual(store.list("alice")[0]["code"], entry.code)
        store.decide("alice", entry.id, False, 0)
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(await store.events.get(0),
                         [{"event": "finished", "id": entry.id, "user": "alice", "outcome": "denied"}])

    async def test_full_queue_drops_without_blocking(self):
        store = self.store(web_approval_single_pending=False)
        store.events.queue = asyncio.Queue(2)
        await store.events.get(0)
        tasks = [asyncio.create_task(store.wait("alice", "tls", ADDR)) for _ in range(4)]
        await self.pending(store, 4)                            # nobody waited for the queue
        self.assertEqual((store.events.queue.qsize(), store.events.dropped), (2, 2))
        for rid in list(store.pending):
            store.decide("alice", rid, True, 1_800_000_000)
        self.assertEqual(await asyncio.gather(*tasks), ["web"] * 4)
        self.assertEqual(store.events.dropped, 6)               # their "finished" events too
        self.assertEqual(store.events.status()["dropped"], 6)

    async def test_consumer_gone(self):
        store = self.store()
        await store.events.get(0)
        store.events.put({"event": "x"})
        self.assertTrue(store.events.consumer())
        self.clock.t += ApprovalEvents.CONSUMER_GONE
        self.assertFalse(store.events.consumer())
        store.events.put({"event": "y"})                        # not kept; leftovers dropped
        self.assertEqual(store.events.queue.qsize(), 0)
        self.assertEqual(store.events.dropped, 0)

    async def test_long_poll(self):
        store = self.store()
        started = time.monotonic()
        self.assertEqual(await store.events.get(0.2), [])
        self.assertGreaterEqual(time.monotonic() - started, 0.15)
        poll = asyncio.create_task(store.events.get(5))
        await asyncio.sleep(0.05)
        self.assertTrue(store.events.consumer())                # while it waits
        task = asyncio.create_task(store.wait("alice", "tls", ADDR))
        (event,) = await asyncio.wait_for(poll, 2)              # at once, not after 5 s
        self.assertEqual(event["event"], "pending")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_codes_differ_per_user(self):
        store = self.store(web_approval_single_pending=False)
        tasks = [asyncio.create_task(store.wait("alice", "tls", ADDR)) for _ in range(5)]
        await self.pending(store, 5)
        codes = [e.code for e in store.pending.values()]
        self.assertEqual(len(set(codes)), 5)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_put_errors_never_reach_the_login(self):
        store = self.store()
        await store.events.get(0)
        with mock.patch.object(store.events.queue, "put_nowait", side_effect=asyncio.QueueFull):
            task = asyncio.create_task(store.wait("alice", "tls", ADDR))
            await self.pending(store)
            (rid,) = store.pending
            store.decide("alice", rid, False, 0)
            with self.assertRaises(MfaDenied):
                await task
        self.assertEqual(store.events.dropped, 2)


# ------------------------------------------------------------------ broker
class MfaEventsOpTests(_ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    def events_op(self, wait_s=0, **kw):
        return request(self.cfg.broker.socket, {"op": "mfa_events", "wait_s": wait_s, **kw})

    async def test_pending_and_finished(self):
        self.assertEqual(await self.events_op(), {"ok": True, "events": []})
        poll = asyncio.create_task(self.events_op(5))
        await asyncio.sleep(0.1)
        login = self.start()
        reply = await asyncio.wait_for(poll, 3)
        (event,) = reply["events"]
        (row,) = (await self.pending_op())["pending"]
        self.assertEqual((event["event"], event["id"], event["user"], event["client_address"], event["code"]),
                         ("pending", row["id"], "alice", ADDR, row["code"]))
        await self.decide(row["id"], approve=False)
        self.assertEqual(await login, self.refused("mfa_failed"))
        self.assertEqual((await self.events_op())["events"],
                         [{"event": "finished", "id": row["id"], "user": "alice", "outcome": "denied"}])
        status = await self.broker.status()
        self.assertEqual({k: status["mfa_events"][k] for k in ("consumer", "queued", "sent", "dropped")},
                         {"consumer": True, "queued": 0, "sent": 2, "dropped": 0})
        self.assertIn("approval notifications: events sent 2, dropped 0", tickets.format_status(status)[-1])

    async def test_only_for_the_webgate(self):
        # patches web_uid instead of assuming the tests' own uid (CI runs them as root)
        not_permitted = {"ok": False, "error": "not permitted", "reason": "denied"}
        with mock.patch.object(self.broker, "web_uid", os.getuid() + 1):
            self.assertEqual(await self.events_op(), not_permitted)
        with mock.patch.object(self.broker, "web_uid", None):       # [web] disabled
            self.assertEqual(await self.events_op(), not_permitted)
        self.assertIsNone(self.broker.mfa.approvals.events.last_poll)   # never counted as a poll
        self.assertNotIn("approval notifications", "\n".join(tickets.format_status(await self.broker.status())))

    async def test_bad_wait_is_a_protocol_error(self):
        for bad in (26, -1, "5", True, 2.5):
            with self.subTest(bad):
                self.assertEqual(await self.events_op(bad), {})      # connection dropped
        self.assertEqual(await request(self.cfg.broker.socket, {"op": "mfa_events"}), {"ok": True, "events": []})

    async def test_login_does_not_wait_for_the_notifier(self):
        await self.events_op()
        self.broker.mfa.approvals.events.queue = asyncio.Queue(1)
        self.mfa_cfg.web_approval_single_pending = False
        logins = [self.start() for _ in range(3)]
        ids = await self.wait_pending(3)
        for rid in ids:
            await self.decide(rid)
        for login in logins:
            self.assertTrue((await login)["ok"])
        self.assertGreaterEqual(self.broker.mfa.approvals.events.dropped, 2)


class CodeOnScreenTests(_ProgressMixin, _ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.broker.waiting = ui.WaitingTexts(UiSection(approve_url=URL))

    async def test_web(self):
        login = asyncio.create_task(self.login_lines())
        (rid,) = await self.wait_pending()
        (row,) = (await self.pending_op())["pending"]
        await self.decide(rid)
        progress, reply = await login
        self.assertTrue(reply["ok"], reply)
        self.assertIn(f"Login code: {row['code']}", progress[0]["lines"])

    async def test_push_or_web_same_code_on_both_panels(self):
        self.set_mfa("push_or_web")
        self.broker.mfa.pi.trigger_challenge.return_value = None   # no push token: web only
        login = asyncio.create_task(self.login_lines())
        (rid,) = await self.wait_pending()
        (row,) = (await self.pending_op())["pending"]
        await self.decide(rid)
        progress, _ = await login
        mfa = [p for p in progress if p["progress"] == "mfa"]
        self.assertEqual([m["method"] for m in mfa], ["push_or_web", "web"])
        for m in mfa:
            self.assertIn(f"Login code: {row['code']}", m["lines"])

    def test_texts(self):
        texts = ui.WaitingTexts(UiSection(approve_url=URL))
        self.assertIn("Anmeldecode: 07", texts.mfa("de", "web", 90, "alice", "07")["lines"])
        # without a code (push) the line is left out
        self.assertFalse(any("code" in line.lower() and ":" in line
                             for line in texts.mfa("en", "push", 60, "alice")["lines"]))
        ui.check_template("Code {code}")


if __name__ == "__main__":
    unittest.main()
