# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""LAB ONLY [mfa] lab_keypress_users: listed accounts skip the second factor; the waiting
screen's code field (protocol.py "code_entry") asks for any digits and Enter instead.
Fail closed: without the module's code field the configured second factor applies.
Never earns reconnect grace; unlisted users and web logins are unchanged."""

import asyncio
import json
import unittest

from fastrdp_broker import config, mfa, ui
from test_web_approval import ADDR, MINIMAL, _ApprovalHarness


class LabKeypressConfigTests(unittest.TestCase):
    def parse(self, users):
        return config.parse({**MINIMAL, "mfa": {"mode": "web", "lab_keypress_users": users}}).mfa

    def test_valid(self):
        self.assertEqual(config.parse(dict(MINIMAL)).mfa.lab_keypress_users, [])
        self.assertEqual(self.parse(["alice", "bob@example.com", "t_1.x-y"]).lab_keypress_users,
                         ["alice", "bob@example.com", "t_1.x-y"])

    def test_invalid(self):
        for name, users in {"a string": "alice", "an empty name": [""], "a space": ["al ice"],
                            "a newline": ["alice\n"], "a number": [1], "a leading dot": [".x"],
                            "too many": [f"u{i}" for i in range(33)]}.items():
            with self.subTest(name), self.assertRaisesRegex(config.ConfigError, "lab_keypress_users"):
                self.parse(users)


class LabKeypressTextTests(unittest.TestCase):
    def test_prompt(self):
        t = ui.WaitingTexts(config.UiSection(approve_url="https://rdp.example.org/web/approve"))
        msg = t.mfa("en", "lab_keypress", 60, "alice", None, None, {"state": "ready", "attempts_left": 0}, 6)
        self.assertEqual(msg["code_entry"], {"digits": 0, "label": "Any 4 digits + Enter:",
                                             "checking": "Checking the code…", "message": ""})
        self.assertEqual(msg["lines"][0], "LAB ONLY: no second factor for alice")
        self.assertNotIn("qr", msg)
        self.assertNotIn("approve_url", msg)
        de = t.mfa("de", "lab_keypress", 60, "alice", None, None, {"state": "ready", "attempts_left": 0}, 6)
        self.assertEqual(de["lines"][0], "NUR LABOR: kein zweiter Faktor für alice")
        self.assertEqual(de["code_entry"]["label"], "4 Ziffern + Eingabe:")
        for lang, table in ui.BUILTIN_TEXTS.items():
            for key in ("mfa_lab_keypress", "lab_keypress_label"):
                with self.subTest(lang=lang, key=key):
                    self.assertIn(key, ui.TEXT_KEYS)
                    ui.check_template(table[key])


class LabKeypressTests(_ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    """[mfa] mode web with alice on the lab list; the test acts as the proxy module."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.mfa_cfg.lab_keypress_users = ["alice"]
        self.broker.grace.seconds = 300

    async def keypress_login(self, key="0000", *, code_entry=1, after=None, timeout=10, **kw):
        """A login like the module with the waiting screen; `key` is sent at the first
        prompt with a code field (None: nothing). Returns (progress, reply or None)."""
        msg = {"op": "login", "session_id": "s1", "method": "tls", "user": "alice", "password": "pw",
               "client_address": ADDR, "progress": 1, "code_entry": code_entry, **kw}
        msg = {k: v for k, v in msg.items() if v is not None}
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps(msg).encode() + b"\n")
        await writer.drain()
        progress = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout)
                if not line:
                    return progress, None
                line = json.loads(line)
                if "progress" not in line:
                    return progress, line
                progress.append(line)
                if line.get("progress") == "mfa" and "code_entry" in line and key is not None:
                    writer.write(json.dumps({"op": "code", "code": key}).encode() + b"\n")
                    await writer.drain()
                    key = None
                elif line.get("progress") == "mfa" and after:
                    await after(reader, writer, progress)
                    after = None
        finally:
            writer.close()

    async def test_listed_user_passes_on_enter_without_grace(self):
        with self.assertLogs(level="INFO") as logs:
            progress, reply = await self.keypress_login("1234")
        self.assertTrue(reply["ok"], reply)
        prompt = progress[0]
        self.assertEqual((prompt["progress"], prompt["method"]), ("mfa", "lab_keypress"))
        self.assertEqual(prompt["code_entry"]["digits"], 0)
        self.assertIn("LAB ONLY", prompt["lines"][0])
        self.assertEqual(progress[-1]["progress"], "session_start")
        self.assertEqual(self.broker.mfa.approvals.pending, {})     # no approval page wait
        self.assertEqual(len(self.broker.grace), 0)                  # never earns grace
        warnings = [r for r in logs.records if r.levelname == "WARNING"]
        self.assertTrue(any("NO second factor" in r.getMessage() for r in warnings), logs.output)
        self.assertTrue(any("logged in without a second factor" in r.getMessage() for r in warnings))
        self.assertFalse(any("1234" in line for line in logs.output), logs.output)
        self.ensure.assert_awaited_once()

    async def test_no_key_times_out(self):
        orig = mfa.LAB_KEYPRESS_TIMEOUT
        mfa.LAB_KEYPRESS_TIMEOUT = 0.3
        try:
            _, reply = await self.keypress_login(None)
        finally:
            mfa.LAB_KEYPRESS_TIMEOUT = orig
        self.assertEqual(reply, self.refused("mfa_timeout"))
        self.ensure.assert_not_called()

    async def test_unlisted_user_keeps_the_configured_factor(self):
        self.mfa_cfg.lab_keypress_users = ["bob"]

        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        progress, reply = await self.keypress_login(None, after=approve)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(progress[0]["method"], "web")
        self.assertNotIn("code_entry", progress[0])
        self.assertEqual([e.factor for e in self.broker.grace.entries.values()], ["web"])

    async def test_fails_closed_without_the_code_field(self):
        # an older module, or the waiting screen off: the approval page as configured
        async def approve(reader, writer, progress):
            (rid,) = await self.wait_pending()
            await self.decide(rid)

        for name, kw in {"no code field": {"code_entry": None}, "no waiting screen": {"progress": None}}.items():
            with self.subTest(name):
                self.broker.grace.clear(None)   # the previous subtest's web approval earned grace
                task = asyncio.create_task(self.keypress_login(None, **kw))
                with self.assertLogs("fastrdp.broker", "WARNING") as logs:
                    await approve(None, None, None)
                    progress, reply = await task
                self.assertTrue(reply["ok"], reply)
                self.assertTrue(any("the web second factor applies" in line for line in logs.output), logs.output)
                self.assertFalse(any(p.get("method") == "lab_keypress" for p in progress))

    async def test_without_the_code_field_a_code_cannot_pass(self):
        # a module that did not announce the field must not get the login through with a code line
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps({"op": "login", "session_id": "s1", "method": "tls", "user": "alice",
                                 "password": "pw", "progress": 1}).encode() + b"\n")
        await writer.drain()
        self.assertEqual(json.loads(await reader.readline())["method"], "web")
        writer.write(b'{"op": "code", "code": "0000"}\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")   # protocol error, no reply
        writer.close()
        self.ensure.assert_not_called()

    async def test_push_mode_also_replaced(self):
        pi = self.set_mfa("push")
        self.mfa_cfg.lab_keypress_users = ["alice"]
        _, reply = await self.keypress_login("9999")
        self.assertTrue(reply["ok"], reply)
        pi.trigger_challenge.assert_not_called()

    async def test_exempt_mode_none_unchanged(self):
        self.set_mfa("none")
        self.mfa_cfg.lab_keypress_users = ["alice"]
        progress, reply = await self.keypress_login(None)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual([p["progress"] for p in progress], ["session_start"])

    async def test_start_warning(self):
        from fastrdp_broker.server import Broker
        self.cfg.mfa.lab_keypress_users = ["alice", "bob"]
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            Broker(self.cfg)
        self.assertTrue(any("[mfa] lab_keypress_users is set: these users log in WITHOUT a second factor: "
                            "alice, bob" in line for line in logs.output), logs.output)


if __name__ == "__main__":
    unittest.main()
