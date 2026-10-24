# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Desktop picker on the proxy's waiting screen ([broker] desktop_picker, protocol.py
"choose_desktop" and {"op": "choice"}, Broker.pick_desktop, login_unless_abandoned).

The picker is offered only when the module asked for progress messages and announced
"picker": 1, the login named no desktop, and the user may use more than one desktop;
"if_multiple" also leaves out users who chose one before. The module answers once, after
the prompt; anything else while the login is pending stays a protocol error."""

import asyncio
import json
import unittest
from unittest import mock

from fastrdp_broker import config, ui
from fastrdp_broker.config import ConfigError, Desktop
from fastrdp_broker.state import Session
from test_gaps import _BrokerHarness, raw_example, user

ALL = ["xfce", "mate", "cinnamon", "lxqt", "plasma-x11", "gnome", "plasma"]  # broker.toml.example


class PickerConfigTests(unittest.TestCase):
    def parse(self, **broker):
        raw = raw_example()
        raw["broker"].update(broker)
        return config.parse(raw).broker

    def test_defaults(self):
        b = self.parse()
        self.assertEqual((b.desktop_picker, b.desktop_picker_timeout, b.desktop_picker_when_running),
                         ("never", 10, "preselect"))
        b = self.parse(desktop_picker="always", desktop_picker_timeout=60, desktop_picker_when_running="skip")
        self.assertEqual((b.desktop_picker, b.desktop_picker_timeout, b.desktop_picker_when_running),
                         ("always", 60, "skip"))
        self.assertEqual(self.parse(desktop_picker="if_multiple", desktop_picker_timeout=3).desktop_picker_timeout, 3)

    def test_invalid(self):
        bad = {
            "desktop_picker must": {"desktop_picker": "on"},
            "desktop_picker must ": {"desktop_picker": True},
            "desktop_picker_timeout must": {"desktop_picker_timeout": 61},
            "desktop_picker_timeout must ": {"desktop_picker_timeout": 2},
            "desktop_picker_timeout must  ": {"desktop_picker_timeout": 10.5},
            "desktop_picker_timeout must   ": {"desktop_picker_timeout": True},
            "desktop_picker_when_running must": {"desktop_picker_when_running": "ask"},
        }
        for msg, broker in bad.items():
            with self.subTest(msg), self.assertRaisesRegex(ConfigError, msg.strip()):
                self.parse(**broker)


class PickerTextTests(unittest.TestCase):
    OPTIONS = [{"name": "xfce", "label": "Xfce", "running": False, "reconnects": "MATE"},
               {"name": "mate", "label": "MATE", "running": True, "reconnects": None},
               {"name": "gnome", "label": "GNOME", "running": False, "reconnects": None}]

    def test_prompt(self):
        t = ui.WaitingTexts(config.UiSection())
        msg = t.picker("en", "alice", self.OPTIONS, "mate", 10)
        self.assertEqual({k: msg[k] for k in ("progress", "default", "timeout_s", "countdown")},
                         {"progress": "choose_desktop", "default": "mate", "timeout_s": 10,
                          "countdown": "Continuing in"})
        self.assertEqual(msg["options"], [
            {"name": "xfce", "label": "Xfce (opens the running MATE)", "running": False},
            {"name": "mate", "label": "MATE (running)", "running": True},
            {"name": "gnome", "label": "GNOME", "running": False}])
        self.assertEqual(msg["lines"], ["Choose your desktop"])
        self.assertEqual(msg["hint"], "1-3, arrow keys + Enter, or click. Esc: MATE")
        de = t.picker("de", "alice", self.OPTIONS, "gnome", 10)
        self.assertEqual((de["lines"], de["options"][1]["label"], de["hint"][-10:]),
                         (["Desktop auswählen"], "MATE (läuft)", "Esc: GNOME"))

    def test_own_texts_and_limits(self):
        t = ui.WaitingTexts(config.UiSection(texts={"en": {
            "picker_title": "Hello {user}\nPick one of {count} (default {desktop})",
            "picker_running": "{desktop} " + "x" * 80, "picker_hint": "a\nb"}}))
        msg = t.picker("en", "alice", self.OPTIONS, "xfce", 10)
        self.assertEqual(msg["lines"], ["Hello alice", "Pick one of 3 (default Xfce)"])
        self.assertEqual(len(msg["options"][1]["label"]), ui.MAX_OPTION_LABEL)
        self.assertEqual(msg["hint"], "a")    # one line
        for lang, table in ui.BUILTIN_TEXTS.items():
            for key in ("picker_title", "picker_hint", "picker_countdown", "picker_running",
                        "picker_reconnects"):
                with self.subTest(lang=lang, key=key):
                    ui.check_template(table[key])
        with self.assertRaisesRegex(ConfigError, r"unknown placeholder \{password\}"):
            config.parse({"desktops": {"x": {"backend": "gnome"}},
                          "ui": {"de": {"picker_title": "{password}"}}})


class _PickerHarness(_BrokerHarness):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.cfg.broker.desktop_picker = "always"
        self.cfg.broker.desktop_picker_timeout = 10
        self.cfg.broker.session_tgt = "off"  # GNOME/Plasma logins: no PAM TGT step here

    async def picker_login(self, answer=None, *, raw=None, timeout=10, after_prompt=None,
                           raw_first=False, **kw):
        """Login like the proxy module with the waiting screen and the picker; answers the
        first choose_desktop prompt with {"op": "choice", "desktop": answer} (`raw`: these
        bytes instead, right after the request with `raw_first`; answer=... sends nothing).
        Returns (progress messages, reply or None if the connection closed)."""
        msg = {"op": "login", "session_id": "s1", "method": "tls", "user": "alice", "password": "pw",
               "client_address": "192.0.2.10", "progress": 1, "picker": 1, **kw}
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps(msg).encode() + b"\n" + (raw if raw_first else b""))
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
                if line["progress"] == "choose_desktop":
                    if after_prompt:
                        await after_prompt(reader, writer)
                        if writer.is_closing():
                            return progress, None
                    if raw is not None:
                        writer.write(raw)
                    elif answer is not ...:
                        writer.write(json.dumps({"op": "choice", "desktop": answer}).encode() + b"\n")
                    await writer.drain()
        finally:
            writer.close()

    def prompts(self, progress):
        return [p for p in progress if p["progress"] == "choose_desktop"]

    def started(self):
        """The desktop of the last back-end start."""
        return self.ensure.await_args.args[0].desktop.name


class PickerTests(_PickerHarness, unittest.IsolatedAsyncioTestCase):
    async def test_choice(self):
        progress, reply = await self.picker_login("gnome")
        self.assertEqual((reply["ok"], reply["desktop"], self.started()), (True, "gnome", "gnome"))
        (prompt,) = self.prompts(progress)
        self.assertEqual([o["name"] for o in prompt["options"]], ALL)
        self.assertEqual((prompt["default"], prompt["timeout_s"]), ("xfce", 10))
        self.assertEqual(prompt["options"][0], {"name": "xfce", "label": "Xfce", "running": False})
        self.assertEqual(prompt["hint"], "1-7, arrow keys + Enter, or click. Esc: Xfce")
        # the session start comes after the choice and names it
        self.assertEqual([p["progress"] for p in progress], ["choose_desktop", "session_start"])
        self.assertEqual(progress[-1]["lines"], ["Connecting to your desktop (gnome)…"])

    async def test_default_on_null_or_empty(self):
        for answer in (None, ""):
            with self.subTest(answer=answer):
                progress, reply = await self.picker_login(answer)
                self.assertEqual((reply["desktop"], len(self.prompts(progress))), ("xfce", 1))

    async def test_answer_not_offered_gets_the_default(self):
        self.cfg.desktops["gnome"].groups = ["gnome-users"]          # alice may not use it
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            for answer in ("gnome", "nonexistent"):
                progress, reply = await self.picker_login(answer)
                self.assertEqual(reply["desktop"], "xfce")
                self.assertNotIn("gnome", [o["name"] for o in self.prompts(progress)[0]["options"]])
        self.assertEqual(sum("was not offered" in line for line in logs.output), 2)

    async def test_never_and_not_offered(self):
        cases = {
            "mode never": ({"desktop_picker": "never"}, {}),
            "client hint": ({}, {"desktop_hint": "fastrdp:mate"}),
            "hint the broker ignores": ({}, {"desktop_hint": "explorer.exe"}),
            "module without the picker": ({}, {"picker": None}),
            "module without progress messages": ({}, {"progress": None}),
        }
        for name, (broker, kw) in cases.items():
            with self.subTest(name):
                for k, v in {"desktop_picker": "always", **broker}.items():
                    setattr(self.cfg.broker, k, v)
                progress, reply = await self.picker_login(..., **kw)
                self.assertTrue(reply["ok"], reply)
                self.assertEqual(self.prompts(progress), [])
                self.assertEqual(reply["desktop"], "mate" if "fastrdp:mate" in kw.values() else "xfce")
                if "progress" in kw:
                    self.assertEqual(progress, [])

    async def test_single_desktop(self):
        for name, desk in self.cfg.desktops.items():
            desk.groups = [] if name == "plasma" else ["admins"]
        self.cfg.default_desktop = "plasma"
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            progress, reply = await self.picker_login(...)
        self.assertEqual((reply["desktop"], self.prompts(progress)), ("plasma", []))
        # field report: the picker "never showed" without a word in the log
        self.assertTrue(any("no desktop picker: plasma is the only desktop this user may use" in line
                            for line in logs.output), logs.output)

    async def test_skips_and_ignored_choices_logged(self):
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            _, reply = await self.picker_login(..., desktop_hint="fastrdp:nonexistent")
        self.assertEqual(reply["desktop"], "xfce")
        self.assertTrue(any("desktop 'fastrdp:nonexistent' named by the client is not available or not "
                            "allowed; ignored" in line for line in logs.output), logs.output)
        self.assertTrue(any("no desktop picker: the client named a desktop ('fastrdp:nonexistent')" in line
                            for line in logs.output), logs.output)

    async def test_if_multiple(self):
        self.cfg.broker.desktop_picker = "if_multiple"
        # nothing chosen yet: shown; a group default counts as nothing chosen
        progress, reply = await self.picker_login("mate")
        self.assertEqual((reply["desktop"], self.prompts(progress)[0]["default"]), ("mate", "xfce"))
        self.users["alice"] = user("alice", ("rdp-users", "rdp-gnome"))
        progress, reply = await self.picker_login(None)
        self.assertEqual((reply["desktop"], self.prompts(progress)[0]["default"]), ("gnome", "gnome"))
        # chosen on the web gateway / with fastrdpctl, or in ~/.config/fastrdp/desktop: not shown
        self.broker.desktop_prefs.set("alice", "plasma")
        progress, reply = await self.picker_login(...)
        self.assertEqual((reply["desktop"], self.prompts(progress)), ("plasma", []))
        self.broker.desktop_prefs.set("alice", None)
        with mock.patch.object(self.broker, "read_desktop_pref", mock.AsyncMock(return_value="lxqt")):
            progress, reply = await self.picker_login(...)
        self.assertEqual((reply["desktop"], self.prompts(progress)), ("lxqt", []))

    async def test_always_preselects_the_stored_choice(self):
        self.broker.desktop_prefs.set("alice", "plasma")
        progress, reply = await self.picker_login(None)
        self.assertEqual((reply["desktop"], self.prompts(progress)[0]["default"]), ("plasma", "plasma"))
        progress, reply = await self.picker_login("lxqt")
        self.assertEqual(reply["desktop"], "lxqt")
        self.assertEqual(self.broker.desktop_prefs.get("alice"), "plasma")   # not stored

    async def test_after_mfa(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        progress, reply = await self.picker_login("gnome")
        self.assertEqual([p["progress"] for p in progress], ["mfa", "choose_desktop", "session_start"])
        self.assertEqual(reply["desktop"], "gnome")
        pi.wait_for_push.return_value = False                    # MFA refused: no picker
        progress, reply = await self.picker_login("gnome")
        self.assertEqual(([p["progress"] for p in progress], reply), (["mfa"], self.refused("mfa_timeout")))

    async def test_web_login_never_asks(self):
        token = self.broker.web_tokens.issue("alice", None)
        progress, reply = await self.picker_login(..., password=token, client_address="127.0.0.1")
        self.assertEqual((reply["ok"], self.prompts(progress)), (True, []))

    async def test_at_most_nine_rows_with_the_default(self):
        for i in range(5):
            self.cfg.desktops[f"extra{i}"] = Desktop(f"extra{i}", "xrdp", xsession="xfce")
        self.cfg.default_desktop = "extra4"                            # the 12th
        progress, reply = await self.picker_login("extra4")
        names = [o["name"] for o in self.prompts(progress)[0]["options"]]
        self.assertEqual(names, ALL + ["extra0", "extra4"])
        self.assertEqual(reply["desktop"], "extra4")

    async def test_running_sessions(self):
        self.broker.state.put(Session(user="alice", backend="gnome", desktop="gnome"))
        self.broker.state.put(Session(user="alice", backend="xrdp", desktop="mate"))
        self.broker.backends["xrdp"].alive = mock.AsyncMock(return_value=True)
        progress, reply = await self.picker_login(None)
        prompt = self.prompts(progress)[0]
        labels = {o["name"]: (o["label"], o["running"]) for o in prompt["options"]}
        self.assertEqual(labels["gnome"], ("gnome (running)", True))
        self.assertEqual(labels["mate"], ("mate (running)", True))
        self.assertEqual(labels["xfce"], ("Xfce (opens the running mate)", False))
        self.assertEqual(labels["plasma"], ("plasma", False))
        # the default xfce is an xrdp desktop: the running xrdp session is preselected
        self.assertEqual((prompt["default"], reply["desktop"]), ("mate", "mate"))
        # a gone xrdp session (the back-end says so) is not marked; gnome is preselected
        self.broker.backends["xrdp"].alive = mock.AsyncMock(return_value=False)
        progress, reply = await self.picker_login(None)
        self.assertEqual((self.prompts(progress)[0]["default"], reply["desktop"]), ("gnome", "gnome"))
        # a back-end that hangs or fails counts as not running
        self.broker.backends["gnome"].alive = mock.AsyncMock(side_effect=OSError("boom"))
        progress, reply = await self.picker_login(None)
        self.assertEqual((self.prompts(progress)[0]["default"], reply["desktop"]), ("xfce", "xfce"))

    async def test_running_xrdp_session_without_record(self):
        # field report 2026-10-24: an Xfce session ran, the picker preselected gnome
        self.broker.backends["xrdp"].untracked_desktop = mock.AsyncMock(return_value="mate")
        progress, reply = await self.picker_login(None)
        prompt = self.prompts(progress)[0]
        labels = {o["name"]: (o["label"], o["running"]) for o in prompt["options"]}
        self.assertEqual(labels["mate"], ("mate (running)", True))
        self.assertEqual((prompt["default"], reply["desktop"]), ("mate", "mate"))
        # a back-end that cannot tell is logged, not hidden
        self.broker.backends["xrdp"].untracked_desktop = mock.AsyncMock(side_effect=TimeoutError())
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            await self.picker_login(None)
        self.assertTrue(any("xrdp session state unknown: TimeoutError" in line for line in logs.output),
                        logs.output)

    async def test_running_skip(self):
        self.cfg.broker.desktop_picker_when_running = "skip"
        progress, reply = await self.picker_login(None)
        self.assertEqual((len(self.prompts(progress)), reply["desktop"]), (1, "xfce"))  # nothing runs
        self.broker.state.put(Session(user="alice", backend="plasma", desktop="plasma"))
        progress, reply = await self.picker_login(...)
        self.assertEqual((self.prompts(progress), reply["desktop"]), ([], "plasma"))

    @mock.patch("fastrdp_broker.server.PICKER_GRACE", 0)
    async def test_no_answer_gets_the_default(self):
        self.cfg.broker.desktop_picker_timeout = 1
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            progress, reply = await self.picker_login(...)
        self.assertEqual((reply["desktop"], len(self.prompts(progress))), ("xfce", 1))
        self.assertTrue(any("no answer from the proxy within 1s; xfce" in line for line in logs.output))

    @mock.patch("fastrdp_broker.server.PICKER_GRACE", 0)
    async def test_late_answer_ignored(self):
        self.cfg.broker.desktop_picker_timeout = 1
        entered, release = asyncio.Event(), asyncio.Event()
        target = self.ensure.return_value

        async def slow_ensure(req):
            entered.set()
            await release.wait()
            return target

        self.ensure.side_effect = slow_ensure

        async def late(reader, writer):
            await asyncio.wait_for(entered.wait(), 5)           # the broker moved on
            writer.write(b'{"op": "choice", "desktop": "gnome"}\n')
            await writer.drain()
            await asyncio.sleep(0.1)
            release.set()

        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            progress, reply = await self.picker_login(..., after_prompt=late)
        self.assertEqual(reply["desktop"], "xfce")
        self.assertTrue(any("came too late; ignored" in line for line in logs.output), logs.output)


class PickerProtocolTests(_PickerHarness, unittest.IsolatedAsyncioTestCase):
    async def closed_with(self, logs_expected, **kw):
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            progress, reply = await self.picker_login(**kw)
        self.assertIsNone(reply)                    # closed without a reply
        self.assertTrue(any(logs_expected in line for line in logs.output), logs.output)
        self.assertEqual(self.broker.active, {})
        return progress

    def slow_start(self):
        async def ensure(req):
            await asyncio.sleep(30)

        self.ensure.side_effect = ensure

    async def test_malformed_answers(self):
        for raw in (b"not json\n", b'{"op": "status"}\n', b'{"op": "choice"}\n',
                    b'{"op": "choice", "desktop": 5}\n', b'["choice"]\n',
                    b'{"op": "choice", "desktop": "' + b"x" * 65 + b'"}\n'):
            with self.subTest(raw=raw):
                await self.closed_with("protocol error", raw=raw)
        self.ensure.assert_not_called()

    async def test_two_answers(self):
        self.slow_start()                                        # still starting
        await self.closed_with("data received while a login was pending",
                               raw=b'{"op":"choice","desktop":"gnome"}\n{"op":"choice","desktop":null}\n')

    async def test_answer_before_the_prompt(self):
        """Data before a prompt (here: during the MFA push) stays a protocol error."""
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        started = asyncio.Event()
        loop = asyncio.get_running_loop()

        def wait_for_push(user, txid, cancel):
            loop.call_soon_threadsafe(started.set)
            cancel.wait(30)
            return False

        pi.wait_for_push.side_effect = wait_for_push

        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps({"op": "login", "session_id": "s1", "method": "tls", "user": "alice",
                                 "password": "pw", "progress": 1, "picker": 1}).encode() + b"\n")
        await writer.drain()
        await asyncio.wait_for(started.wait(), 5)
        with self.assertLogs("fastrdp.broker", "WARNING") as logs:
            writer.write(b'{"op": "choice", "desktop": "gnome"}\n')
            await writer.drain()
            rest = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        self.assertNotIn(b'"ok"', rest)                     # the mfa progress line at most
        self.assertIn("data received while a login was pending", logs.output[-1])

    async def test_picker_without_announcement(self):
        """Without "picker": 1 no prompt goes out, and a choice line is a protocol error."""
        self.slow_start()
        progress = await self.closed_with("data received while a login was pending", picker=None,
                                          raw=b'{"op":"choice","desktop":"gnome"}\n', raw_first=True)
        self.assertEqual(self.prompts(progress), [])

    async def test_abandoned_during_the_picker(self):
        async def give_up(reader, writer):
            writer.close()

        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            progress, reply = await self.picker_login(..., after_prompt=give_up)
            for _ in range(100):
                if any("abandoned" in line for line in logs.output):
                    break
                await asyncio.sleep(0.02)
        self.assertEqual((len(self.prompts(progress)), reply), (1, None))
        self.assertTrue(any("login of session s1 abandoned" in line for line in logs.output), logs.output)
        self.ensure.assert_not_called()
        self.assertEqual(self.broker.active, {})
        # the broker keeps serving
        self.assertTrue((await self.login())["ok"])


if __name__ == "__main__":
    unittest.main()
