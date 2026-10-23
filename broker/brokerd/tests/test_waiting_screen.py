# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Progress messages for the proxy's waiting screen (protocol.py "progress", ui.py, [ui],
proxy.ini [FastRDP] WaitingScreen) and the QR code of the approval page (qrcode.py)."""

import asyncio
import json
import unittest
from unittest import mock

from fastrdp_broker import config, qrcode, ui
from fastrdp_broker.config import UiSection
from fastrdp_broker.mfa import WebApprovals
from test_gaps import _BrokerHarness, raw_example
from test_web_approval import _ApprovalHarness

MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce", "label": "XFCE"}}}
URL = "https://rdp1.lab.example.com/web/approve"
ID = "Zm9vYmFyYmF6cXV4cXV1eA"      # like mfa.WebApprovals.new_id()
ADDR = "192.0.2.10"

# The QR code of URL from Nayuki's qrcodegen 1.8.0 (level M, boostecl=False; version 3,
# mask chosen by penalty), the reference implementation this encoder was checked against.
QR_REFERENCE = [
    "11111110101000101111101111111",
    "10000010110001100110101000001",
    "10111010001101001001001011101",
    "10111010110011111100101011101",
    "10111010010101111101001011101",
    "10000010001110101011101000001",
    "11111110101010101010101111111",
    "00000000110000000110000000000",
    "10110111011100100100001001011",
    "00111000111100101111111010001",
    "00011011110011001010011000110",
    "11011001100001001001000000001",
    "01010111001101110100000101100",
    "01110100110100111101001100111",
    "00010010110001100101010000111",
    "01000100111010101000010010010",
    "11100110001010110011010011010",
    "00101100100110011100100101110",
    "10010011100011110100110010100",
    "00110101011101110110010000100",
    "01001011101001101111111111100",
    "00000000110110001110100011111",
    "11111110100110101111101011010",
    "10000010100011100010100011001",
    "10111010010010010110111110111",
    "10111010100000011000010111001",
    "10111010110011000110100100101",
    "10000010000101001000110001010",
    "11111110111001101010101101010",
]


# ------------------------------------------------------------------ QR code
class QrCodeTests(unittest.TestCase):
    def test_reference_symbol(self):
        self.assertEqual(qrcode.encode(URL.encode()), QR_REFERENCE)

    def test_version_by_length(self):
        # level M byte capacities: version 1 = 14 bytes, version 10 = 213 bytes
        for n, size in ((0, 21), (14, 21), (15, 25), (213, 57), (214, 61), (2331, 177)):
            with self.subTest(n):
                rows = qrcode.encode(b"x" * n)
                self.assertEqual((len(rows), {len(r) for r in rows}), (size, {size}))
                self.assertTrue(all(set(r) <= {"0", "1"} for r in rows))
        with self.assertRaises(qrcode.QrError):
            qrcode.encode(b"x" * 214, max_version=10)
        with self.assertRaises(qrcode.QrError):
            qrcode.encode(b"x" * 2332)

    def test_function_patterns(self):
        rows = qrcode.encode(URL.encode())
        finder = ["1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"]
        n = len(rows)
        for x0, y0 in ((0, 0), (n - 7, 0), (0, n - 7)):
            self.assertEqual([r[x0:x0 + 7] for r in rows[y0:y0 + 7]], finder)
        self.assertEqual(rows[6][8:n - 8], "10" * ((n - 16) // 2) + "1")   # timing pattern
        self.assertEqual(rows[n - 8][8], "1")                               # dark module
        # format information: both copies agree, BCH code checks, level M (00)
        first = ([rows[i][8] for i in range(6)] + [rows[7][8], rows[8][8], rows[8][7]]
                 + [rows[8][14 - i] for i in range(9, 15)])
        second = [rows[8][n - 1 - i] for i in range(8)] + [rows[n - 15 + i][8] for i in range(8, 15)]
        self.assertEqual(first, second)
        word = sum(int(b) << i for i, b in enumerate(first)) ^ 0x5412
        data, rem = word >> 10, word >> 10
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        self.assertEqual(word, data << 10 | rem)
        self.assertEqual(data >> 3, 0b00)

    def test_decodes(self):
        """With zxing-cpp (test-only, e.g. a venv under build/) the symbol must decode."""
        try:
            import zxingcpp  # noqa: F401
            from PIL import Image
        except ImportError:
            self.skipTest("zxing-cpp and Pillow not installed (test-only)")
        longest = "https://" + "a" * 156 + ".example/web/approve"
        for text in (URL, ui.login_url(longest, ID), "x"):
            rows = qrcode.encode(text.encode())
            n = len(rows) + 8
            img = Image.new("L", (n * 4, n * 4), 255)
            for y, row in enumerate(rows):
                for x, c in enumerate(row):
                    if c == "1":
                        img.paste(0, ((x + 4) * 4, (y + 4) * 4, (x + 5) * 4, (y + 5) * 4))
            self.assertEqual([r.text for r in zxingcpp.read_barcodes(img)], [text])


# ------------------------------------------------------------------ config
class UiConfigTests(unittest.TestCase):
    def parse(self, ui_raw):
        return config.parse({**MINIMAL, "ui": ui_raw}).ui

    def test_defaults(self):
        self.assertEqual(config.parse(dict(MINIMAL)).ui, UiSection())
        ex = config.parse(raw_example()).ui
        self.assertEqual((ex.language, ex.approve_url, ex.qr_code, ex.texts), ("en", "", True, {}))

    def test_valid(self):
        cfg = self.parse({"language": "de", "language_from_keyboard": False, "approve_url": URL,
                          "qr_code": False, "fr": {"mfa_push": "Approuvez {user}\nsvp", "countdown": "Reste :"},
                          "de": {"session_start": "{desktop} startet …"}})
        self.assertEqual((cfg.language, cfg.approve_url, set(cfg.texts)), ("de", URL, {"fr", "de"}))
        self.assertEqual(self.parse({"language": "fr", "fr": {"countdown": "Reste :"}}).language, "fr")

    def test_invalid(self):
        bad = {
            "language must be": {"language": "fr"},                       # no texts in fr
            "language code": {"DE": {"countdown": "x"}},
            "unknown keys": {"de": {"greeting": "Hallo"}},
            r"unknown placeholder \{password\}": {"de": {"mfa_push": "{password}"}},
            r"unknown placeholder \{user.__class__\}": {"de": {"mfa_push": "{user.__class__}"}},
            "unknown placeholder": {"de": {"mfa_push": "{user:>99999}"}},
            "braces": {"de": {"mfa_push": "{user"}},
            "control characters": {"de": {"mfa_push": "a\tb"}},
            "must be a string": {"de": {"mfa_push": 5}},
            "longer than": {"de": {"mfa_push": "x" * 2001}},
            "approve_url must": {"approve_url": "http://rdp1.example.com/web/approve"},
            "approve_url must ": {"approve_url": "https://" + "a" * 177},       # 185 characters
            "approve_url must  ": {"approve_url": "https://rdp1 .example.com/"},
            "qr_code must": {"qr_code": "yes"},
            "language_from_keyboard must": {"language_from_keyboard": 1},
            r"\[ui\]: unknown keys": {"colour": "blue"},
        }
        for msg, raw in bad.items():
            with self.subTest(msg), self.assertRaisesRegex(config.ConfigError, msg.strip()):
                self.parse(raw)
        longest = "https://" + "a" * 176
        self.assertEqual((self.parse({"approve_url": longest}).approve_url, len(longest)),
                         (longest, config.MAX_APPROVE_URL))


# ------------------------------------------------------------------ texts
class WaitingTextsTests(unittest.TestCase):
    def texts(self, **kw):
        return ui.WaitingTexts(UiSection(**kw))

    def test_language(self):
        t = self.texts()
        self.assertEqual([t.language(k) for k in (0x0407, 0x00010407, 0x0807, 0x0409, 0x040C, 0, None)],
                         ["de", "de", "de", "en", "en", "en", "en"])
        self.assertEqual(self.texts(language="de").language(0x040C), "de")    # no French texts
        self.assertEqual(self.texts(language_from_keyboard=False).language(0x0407), "en")
        self.assertEqual(self.texts(texts={"fr": {"countdown": "Reste :"}}).language(0x040C), "fr")

    def test_mfa_messages(self):
        t = self.texts(approve_url=URL)
        push = t.mfa("en", "push", 60, "alice")
        self.assertEqual({k: push[k] for k in ("progress", "method", "timeout_s", "countdown")},
                         {"progress": "mfa", "method": "push", "timeout_s": 60, "countdown": "Time left:"})
        self.assertNotIn("qr", push)
        self.assertNotIn("approve_url", push)
        self.assertIn("alice", " ".join(push["lines"]))
        for method in ("web", "push_or_web"):
            msg = t.mfa("de", method, 90, "alice", "07", ID)
            # the QR code names the login, the text the page as configured (to type it)
            self.assertEqual((msg["approve_url"], msg["qr"], msg["countdown"]),
                             (URL, qrcode.encode(f"{URL}?login={ID}".encode()), "Verbleibend:"))
            self.assertIn(URL, msg["lines"])
            self.assertFalse(any(ID in line for line in msg["lines"]), msg["lines"])
            self.assertTrue(msg["lines"][0].startswith("Anmeldung"), msg["lines"])
        # without an id (none of the broker's own calls): the page itself
        self.assertEqual(t.mfa("en", "web", 90, "alice")["qr"], QR_REFERENCE)

    def test_login_url(self):
        self.assertEqual(ui.login_url(URL, ID), f"{URL}?login={ID}")
        self.assertEqual(ui.login_url("https://h/approve?x=1", ID), f"https://h/approve?x=1&login={ID}")
        self.assertEqual(ui.login_url("https://h/approve#top", ID), f"https://h/approve?login={ID}#top")

    def test_longest_url_fits(self):
        """[ui] approve_url of config.MAX_APPROVE_URL characters with the login's id (as
        long as mfa.WebApprovals.new_id() makes it): still a version 10 QR code (57 rows,
        what the module draws), also with a query of its own."""
        rid = WebApprovals.new_id()
        self.assertRegex(rid, r"^[A-Za-z0-9_-]{%d}$" % config.LOGIN_ID_CHARS)
        for longest in ("https://" + "a" * (config.MAX_APPROVE_URL - 8),
                        "https://h/?" + "a" * (config.MAX_APPROVE_URL - 11)):
            with self.subTest(longest[:12]):
                cfg = config.parse({**MINIMAL, "ui": {"approve_url": longest}}).ui
                msg = ui.WaitingTexts(cfg).mfa("en", "web", 90, "alice", "07", rid)
                self.assertEqual(len(msg["qr"]), 17 + 4 * ui.QR_MAX_VERSION)
                self.assertEqual(len(ui.login_url(longest, rid)), 213)

    def test_without_url_or_qr(self):
        msg = self.texts().mfa("en", "web", 90, "alice")
        self.assertNotIn("qr", msg)
        self.assertNotIn("approve_url", msg)
        self.assertFalse(any("{" in line or line == "" for line in msg["lines"]), msg["lines"])
        msg = self.texts(approve_url=URL, qr_code=False).mfa("en", "web", 90, "alice")
        self.assertEqual((msg["approve_url"], "qr" in msg), (URL, False))

    def test_own_texts_and_limits(self):
        t = self.texts(texts={"en": {"session_start": "{desktop} for {user}\n" + "y" * 500},
                              "fr": {"countdown": "Reste :"},
                              "de": {"mfa_push": "\n".join(["Zeile {timeout} {method}"] * 30)}})
        self.assertEqual(t.session_start("en", "alice", "XFCE")["lines"], ["XFCE for alice", "y" * ui.MAX_LINE])
        self.assertEqual(t.mfa("de", "push", 60, "a")["lines"], ["Zeile 60 push"] * ui.MAX_LINES)
        self.assertEqual(t.mfa("fr", "push", 60, "a")["countdown"], "Reste :")   # rest from English
        self.assertEqual(t.mfa("fr", "push", 60, "a")["lines"], t.mfa("en", "push", 60, "a")["lines"])

    def test_builtin_texts_valid(self):
        for lang, table in ui.BUILTIN_TEXTS.items():
            self.assertEqual(set(table), set(ui.TEXT_KEYS), lang)
            for template in table.values():
                ui.check_template(template)


# ------------------------------------------------------------------ broker
class _ProgressMixin:
    async def login_lines(self, timeout=10, **kw):
        """Login like the proxy module with "progress": 1; (progress messages, reply)."""
        msg = {"op": "login", "session_id": "s", "method": "tls", "user": "alice", "password": "pw",
               "client_address": ADDR, "progress": 1, **kw}
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps(msg).encode() + b"\n")
        await writer.drain()
        progress = []
        try:
            while True:
                line = json.loads(await asyncio.wait_for(reader.readline(), timeout))
                if "progress" not in line:
                    return progress, line
                progress.append(line)
        finally:
            writer.close()

    def kinds(self, progress):
        return [(p["progress"], p.get("method")) for p in progress]


class ProgressTests(_ProgressMixin, _BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.broker.waiting = ui.WaitingTexts(UiSection(approve_url=URL))

    async def test_only_when_asked(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(json.dumps({"op": "login", "session_id": "s", "method": "tls", "user": "alice",
                                 "password": "pw"}).encode() + b"\n")
        await writer.drain()
        first = json.loads(await reader.readline())
        writer.close()
        self.assertTrue(first["ok"], first)          # the reply, nothing before it
        self.assertNotIn("progress", first)

    async def test_push(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        self.broker.mfa.cfg.privacyidea.push_timeout = 45
        progress, reply = await self.login_lines()
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.kinds(progress), [("mfa", "push"), ("session_start", None)])
        self.assertEqual(progress[0]["timeout_s"], 45)
        self.assertNotIn("qr", progress[0])
        self.assertEqual(progress[1]["lines"], ["Connecting to your desktop (Xfce)…"])

    async def test_push_refused_still_reports(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = False
        progress, reply = await self.login_lines()
        self.assertEqual(reply, self.refused("mfa_timeout"))
        self.assertEqual(self.kinds(progress), [("mfa", "push")])

    async def test_no_progress_without_wait(self):
        """Exempt group, OTP appended, nla_kdc_enforced, KDC evidence: no MFA wait, only
        the session start."""
        pi = self.set_mfa("otp_or_push", exempt=["mfa-exempt"])
        pi.check_otp.return_value = True
        progress, reply = await self.login_lines(user="carol")
        self.assertEqual((reply["ok"], self.kinds(progress)), (True, [("session_start", None)]))
        progress, reply = await self.login_lines(password="pw123456")
        self.assertEqual((reply["ok"], self.kinds(progress)), (True, [("session_start", None)]))
        pi.trigger_challenge.assert_not_called()
        self.cfg.auth.realms = ["EXAMPLE.COM"]
        self.broker.cfg.mfa.kdc_evidence_as_mfa = ["ind:pkinit"]
        progress, reply = await self.login_lines(method="nla", principal="alice@EXAMPLE.COM",
                                                 password=None, kdc_evidence=["ind:pkinit"])
        self.assertEqual((reply["ok"], self.kinds(progress)), (True, [("session_start", None)]))
        self.broker.cfg.mfa.nla_kdc_enforced = True
        progress, reply = await self.login_lines(method="nla", principal="alice@EXAMPLE.COM", password=None)
        self.assertEqual((reply["ok"], self.kinds(progress)), (True, [("session_start", None)]))
        pi.trigger_challenge.assert_not_called()

    async def test_reconnect_grace(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        self.broker.grace.seconds = 300
        progress, _ = await self.login_lines()
        self.assertEqual(self.kinds(progress), [("mfa", "push"), ("session_start", None)])
        progress, reply = await self.login_lines()                     # within the grace
        self.assertEqual((reply["ok"], self.kinds(progress)), (True, [("session_start", None)]))
        self.assertEqual(pi.trigger_challenge.call_count, 1)

    async def test_language_from_keyboard(self):
        progress, reply = await self.login_lines(keyboard_layout=0x0407)
        self.assertTrue(reply["ok"])
        self.assertEqual(progress[0]["lines"], ["Verbindung zu Ihrem Desktop (Xfce) wird hergestellt…"])
        with self.assertRaises(json.JSONDecodeError):          # protocol error: no reply
            await self.login_lines(keyboard_layout="0x407")

    async def test_errors_never_fail_the_login(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        with mock.patch.object(self.broker.waiting, "mfa", side_effect=RuntimeError("boom")), \
             mock.patch.object(self.broker.waiting, "session_start", side_effect=RuntimeError("boom")):
            progress, reply = await self.login_lines()
        self.assertEqual((reply["ok"], progress), (True, []))
        # a writer that fails, or a closed one
        writer = mock.Mock()
        writer.is_closing.return_value = False
        writer.write.side_effect = ConnectionResetError
        self.broker.progress_writer(writer)({"progress": "mfa"})
        writer.is_closing.return_value = True
        writer.write.reset_mock()
        self.broker.progress_writer(writer)({"progress": "mfa"})
        writer.write.assert_not_called()


class WebProgressTests(_ProgressMixin, _ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.broker.waiting = ui.WaitingTexts(UiSection(approve_url=URL))

    async def test_web(self):
        login = asyncio.create_task(self.login_lines())
        (rid,) = await self.wait_pending()
        await self.decide(rid)
        progress, reply = await login
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.kinds(progress), [("mfa", "web"), ("session_start", None)])
        mfa = progress[0]
        self.assertEqual((mfa["timeout_s"], mfa["approve_url"], mfa["qr"]),
                         (10, URL, qrcode.encode(f"{URL}?login={rid}".encode())))
        self.assertIn(URL, mfa["lines"])
        self.assertEqual(mfa["lines"][-1], "Scan the code to open the approval page.")


class PushOrWebProgressTests(_ProgressMixin, _ApprovalHarness, unittest.IsolatedAsyncioTestCase):
    mode = "push_or_web"

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.broker.waiting = ui.WaitingTexts(UiSection(approve_url=URL))

    async def test_push_unavailable_then_web(self):
        self.pi.trigger_challenge.return_value = None      # no push token: web only
        login = asyncio.create_task(self.login_lines())
        (rid,) = await self.wait_pending()
        await self.decide(rid)
        progress, reply = await login
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.kinds(progress), [("mfa", "push_or_web"), ("mfa", "web"), ("session_start", None)])
        self.assertEqual(progress[0]["timeout_s"], 10)
        self.assertLessEqual(progress[1]["timeout_s"], 10)
        # both panels name the one pending login
        for p in progress[:2]:
            self.assertEqual(p["qr"], qrcode.encode(f"{URL}?login={rid}".encode()))

    async def test_push_wins(self):
        self.pi.trigger_challenge.return_value = "tx"
        self.pi.wait_for_push.return_value = True
        progress, reply = await self.login_lines()
        self.assertTrue(reply["ok"], reply)
        # the push's own message is not sent: the panel already offers both
        self.assertEqual(self.kinds(progress)[0], ("mfa", "push_or_web"))
        self.assertEqual(self.kinds(progress)[-1], ("session_start", None))


if __name__ == "__main__":
    unittest.main()
