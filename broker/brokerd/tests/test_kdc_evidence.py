# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] kdc_evidence_as_mfa: a Kerberos NLA login whose ticket carries a listed item
(authentication indicator or PAC group SID, "kdc_evidence" from the proxy module) skips
privacyIDEA for that login; everything else keeps the second factor."""

import tempfile
import unittest
from unittest import mock

import test_server
from fastrdp_broker import config
from test_server import make_cfg, request

MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}}
PI = {"url": "https://pi"}
AMA = "sid:S-1-5-21-1-2-3-1300"


class KdcEvidenceConfigTests(unittest.TestCase):
    def parse(self, items, realms=("EXAMPLE.COM",)):
        return config.parse({**MINIMAL, "auth": {"realms": list(realms)},
                             "mfa": {"mode": "push", "kdc_evidence_as_mfa": items, "privacyidea": PI}})

    def test_default_off(self):
        self.assertEqual(config.parse(dict(MINIMAL)).mfa.kdc_evidence_as_mfa, [])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(make_cfg(tmp).mfa.kdc_evidence_as_mfa, [])

    def test_valid_items(self):
        items = ["ind:pkinit", "ind:passkey", "sid:S-1-18-4", "sid:S-1-18-3", AMA]
        self.assertEqual(self.parse(items).mfa.kdc_evidence_as_mfa, items)

    def test_malformed_items_refused(self):
        for bad in (["pkinit"], ["ind:"], ["ind:two words"], ["ind:" + "x" * 65], ["sid:S-1"],
                    ["sid:s-1-18-4"], ["sid:S-1-5-21-1-2-x"], ["group:admins"], [""], [4],
                    "ind:pkinit", {"ind": "pkinit"}, ["sid:S-1-18-4\n"]):
            with self.subTest(bad), self.assertRaisesRegex(config.ConfigError, "kdc_evidence_as_mfa must"):
                self.parse(bad)

    def test_single_factor_items_refused(self):
        for weak in ("ind:hardened", "sid:S-1-18-1", "sid:S-1-18-2", "sid:S-1-1-0", "sid:S-1-5-11",
                     "sid:S-1-5-32-545", "sid:S-1-5-21-1-2-3-513"):
            with self.subTest(weak), self.assertRaisesRegex(config.ConfigError, "no second factor"):
                self.parse(["ind:pkinit", weak])

    def test_needs_realms(self):
        with self.assertRaisesRegex(config.ConfigError, "kdc_evidence_as_mfa needs"):
            self.parse(["ind:pkinit"], realms=())


class KdcEvidenceLoginTests(unittest.IsolatedAsyncioTestCase):
    # The broker of test_server.BrokerTests (real sockets, PAM and back-end mocked).
    asyncTearDown = test_server.BrokerTests.asyncTearDown

    async def asyncSetUp(self):
        await test_server.BrokerTests.asyncSetUp(self)
        self.broker.mfa.cfg.mode = "push"
        self.broker.mfa.pi = mock.Mock()
        self.broker.mfa.pi.trigger_challenge.return_value = "tx1"
        self.broker.mfa.pi.wait_for_push.return_value = False   # a push would be refused
        self.broker.cfg.mfa.kdc_evidence_as_mfa = ["ind:pkinit", AMA]

    def nla(self, sid: str, evidence=None, principal: str = "alice@EXAMPLE.COM", **extra) -> dict:
        msg = {"op": "login", "session_id": sid, "method": "nla", "user": "alice",
               "principal": principal, "client_address": "192.0.2.10", **extra}
        if evidence is not None:
            msg["kdc_evidence"] = evidence
        return msg

    @property
    def pushes(self) -> int:
        return self.broker.mfa.pi.trigger_challenge.call_count

    async def test_indicator_skips_push(self):
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await request(self.cfg.broker.socket, self.nla("e1", ["ind:pkinit"]))
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pushes, 0)
        self.assertTrue(any("second factor from KDC evidence ind:pkinit" in line
                            and "alice@EXAMPLE.COM" in line for line in logs.output), logs.output)

    async def test_pac_group_sid_skips_push(self):
        evidence = ["sid:S-1-18-1", "sid:S-1-5-21-1-2-3-513", AMA]
        reply = await request(self.cfg.broker.socket, self.nla("e2", evidence))
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pushes, 0)

    async def test_no_match_keeps_push(self):
        for sid, evidence in (("e3", []), ("e4", ["ind:hardened", "sid:S-1-18-1"]),
                              ("e5", None), ("e6", ["ind:PKINIT", "sid:S-1-5-21-1-2-3-13000"])):
            with self.subTest(evidence):
                reply = await request(self.cfg.broker.socket, self.nla(sid, evidence))
                self.assertFalse(reply["ok"])              # push refused
        self.assertEqual(self.pushes, 4)

    async def test_off_ignores_evidence(self):
        self.broker.cfg.mfa.kdc_evidence_as_mfa = []
        reply = await request(self.cfg.broker.socket, self.nla("e7", ["ind:pkinit"]))
        self.assertFalse(reply["ok"])
        self.assertEqual(self.pushes, 1)

    async def test_tls_ignores_evidence(self):
        # Only the module reports evidence, and only for Kerberos NLA: on a TLS login the
        # field (like "principal" and "smartcard") is not the KDC's word.
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "e8", "method": "tls", "user": "alice", "password": "pw",
            "principal": "alice@EXAMPLE.COM", "smartcard": True, "kdc_evidence": ["ind:pkinit"]})
        self.assertFalse(reply["ok"])
        self.assertEqual(self.pushes, 1)

    async def test_smartcard_flag_is_not_evidence(self):
        reply = await request(self.cfg.broker.socket, self.nla("e9", [], password="123456", smartcard=True))
        self.assertFalse(reply["ok"])
        self.assertEqual(self.pushes, 1)

    async def test_unlisted_realm_keeps_push(self):
        self.broker.cfg.auth.realms = ["EXAMPLE.COM", "OTHER.ORG"]
        self.broker.cfg.mfa.kdc_evidence_as_mfa = ["ind:pkinit"]
        reply = await request(self.cfg.broker.socket, self.nla("e10", ["ind:pkinit"], principal="alice@OTHER.ORG"))
        self.assertTrue(reply["ok"], reply)                # OTHER.ORG is accepted ...
        self.broker.cfg.auth.realms = []                   # ... a realm that is not listed never skips
        reply = await request(self.cfg.broker.socket, self.nla("e11", ["ind:pkinit"], principal="alice@ELSE.ORG"))
        self.assertFalse(reply["ok"])
        self.assertEqual(self.pushes, 1)

    async def test_malformed_field_refused(self):
        for sid, bad in (("e12", "ind:pkinit"), ("e13", [1]), ("e14", ["x" * 300]), ("e15", ["s"] * 1025)):
            with self.subTest(bad):
                reply = await request(self.cfg.broker.socket, self.nla(sid, bad))
                self.assertFalse(reply.get("ok"))
        self.assertEqual(self.pushes, 0)
        self.assertEqual(self.ensure.await_count, 0)

    async def test_records_grace(self):
        self.broker.grace.seconds = 300
        reply = await request(self.cfg.broker.socket, self.nla("e16", ["ind:pkinit"]))
        self.assertTrue(reply["ok"], reply)
        entries = list(self.broker.grace.entries.values())
        self.assertEqual([e.factor for e in entries], ["kdc ind:pkinit"])
        # a reconnect without the evidence (e.g. a password ticket) rides on that grace,
        # as after a push
        reply = await request(self.cfg.broker.socket, self.nla("e17", []))
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pushes, 0)

    async def test_exempt_and_mode_none_unchanged(self):
        self.broker.mfa.cfg.mode = "none"
        reply = await request(self.cfg.broker.socket, self.nla("e18", []))
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pushes, 0)

    async def test_session_tgt_required_still_refuses(self):
        self.broker.cfg.broker.session_tgt = "required"
        reply = await request(self.cfg.broker.socket, self.nla("e19", ["ind:pkinit"]))
        self.assertFalse(reply["ok"])
        self.assertEqual(self.pushes, 0)


class StartupLogTests(unittest.TestCase):
    def test_logs_when_enabled(self):
        from fastrdp_broker.server import Broker

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(tmp, mode="push", kdc_evidence_as_mfa=["ind:pkinit", "sid:S-1-18-4"],
                           privacyidea={"url": "https://pi.example.com"})
            with self.assertLogs("fastrdp.broker", "INFO") as logs:
                Broker(cfg)
        self.assertTrue(any("kdc_evidence_as_mfa" in line and "ind:pkinit or sid:S-1-18-4" in line
                            for line in logs.output), logs.output)


if __name__ == "__main__":
    unittest.main()
