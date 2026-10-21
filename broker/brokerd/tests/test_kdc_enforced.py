# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[mfa] nla_kdc_enforced: Kerberos NLA logins skip privacyIDEA (the KDC enforces passkey/
PKINIT pre-authentication for TERMSRV tickets), everything else keeps the second factor."""

import tempfile
import unittest
from unittest import mock

import test_server
from fastrdp_broker import config, pamauth
from fastrdp_broker.tokens import WEB_TOKEN_PREFIX
from test_server import make_cfg, request

MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}}


class KdcEnforcedConfigTests(unittest.TestCase):
    def test_default_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(make_cfg(tmp).mfa.nla_kdc_enforced)
        self.assertFalse(config.parse(dict(MINIMAL)).mfa.nla_kdc_enforced)

    def test_needs_realms(self):
        raw = {**MINIMAL, "auth": {"realms": []},
               "mfa": {"mode": "push", "nla_kdc_enforced": True, "privacyidea": {"url": "https://pi"}}}
        with self.assertRaisesRegex(config.ConfigError, "nla_kdc_enforced needs"):
            config.parse(raw)
        raw["auth"] = {"realms": ["example.com"]}
        self.assertTrue(config.parse(raw).mfa.nla_kdc_enforced)

    def test_must_be_bool(self):
        raw = {**MINIMAL, "auth": {"realms": ["EXAMPLE.COM"]}, "mfa": {"nla_kdc_enforced": "yes"}}
        with self.assertRaisesRegex(config.ConfigError, "true or false"):
            config.parse(raw)


class KdcEnforcedLoginTests(unittest.IsolatedAsyncioTestCase):
    # The broker of test_server.BrokerTests (real sockets, PAM and back-end mocked),
    # without inheriting its tests.
    asyncTearDown = test_server.BrokerTests.asyncTearDown

    async def asyncSetUp(self):
        await test_server.BrokerTests.asyncSetUp(self)
        self.broker.mfa.cfg.mode = "push"
        self.broker.mfa.pi = mock.Mock()
        self.broker.mfa.pi.trigger_challenge.return_value = "tx1"
        self.broker.mfa.pi.wait_for_push.return_value = False   # a push would be refused
        self.broker.cfg.mfa.nla_kdc_enforced = True

    def nla(self, sid: str, principal: str = "alice@EXAMPLE.COM", **extra) -> dict:
        return {"op": "login", "session_id": sid, "method": "nla", "user": "alice",
                "principal": principal, **extra}

    async def test_nla_skips_push(self):
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await request(self.cfg.broker.socket, self.nla("k1"))
        self.assertTrue(reply["ok"], reply)
        self.broker.mfa.pi.trigger_challenge.assert_not_called()
        self.assertTrue(any("nla_kdc_enforced" in line and "alice@EXAMPLE.COM" in line for line in logs.output),
                        logs.output)

    async def test_smartcard_nla_skips_push_and_drops_pin(self):
        reply = await request(self.cfg.broker.socket, self.nla("k2", password="123456", smartcard=True))
        self.assertTrue(reply["ok"], reply)
        self.broker.mfa.pi.trigger_challenge.assert_not_called()
        self.assertIsNone(self.ensure.call_args.args[0].password)

    async def test_remote_guard_like_sso(self):
        # Remote Credential Guard logins are Kerberos NLA logins without a password: the KDC
        # vouches for them as for SSO, and without nla_kdc_enforced they get the push.
        reply = await request(self.cfg.broker.socket, self.nla("k7", remote_guard=True))
        self.assertTrue(reply["ok"], reply)
        self.broker.mfa.pi.trigger_challenge.assert_not_called()
        self.broker.cfg.mfa.nla_kdc_enforced = False
        reply = await request(self.cfg.broker.socket, self.nla("k8", remote_guard=True))
        self.assertFalse(reply["ok"])                     # push refused
        self.broker.mfa.pi.trigger_challenge.assert_called_once()

    async def test_off_still_pushes(self):
        self.broker.cfg.mfa.nla_kdc_enforced = False
        reply = await request(self.cfg.broker.socket, self.nla("k3"))
        self.assertFalse(reply["ok"])
        self.broker.mfa.pi.trigger_challenge.assert_called_once()

    async def test_tls_still_needs_second_factor(self):
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "k4", "method": "tls", "user": "alice", "password": "pw"})
        self.assertFalse(reply["ok"])                     # push refused
        self.broker.mfa.pi.trigger_challenge.assert_called_once()
        pamauth.authenticate.assert_called()

    async def test_tls_with_principal_field_is_not_nla(self):
        # A client-controlled field never turns a TLS login into a KDC-vouched one.
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "k5", "method": "tls", "user": "alice", "password": "pw",
            "principal": "alice@EXAMPLE.COM", "smartcard": True})
        self.assertFalse(reply["ok"])
        self.broker.mfa.pi.trigger_challenge.assert_called_once()

    async def test_foreign_realm_still_denied(self):
        reply = await request(self.cfg.broker.socket, self.nla("k6", principal="alice@EVIL.ORG"))
        self.assertFalse(reply["ok"])
        self.broker.mfa.pi.trigger_challenge.assert_not_called()

    async def test_unlisted_realm_without_realm_check_keeps_push(self):
        # Defence in depth: should [auth] realms ever be emptied at runtime, a principal
        # from a realm that is not listed never skips the second factor.
        self.broker.cfg.auth.realms = []
        reply = await request(self.cfg.broker.socket, self.nla("k7", principal="alice@OTHER.ORG"))
        self.assertFalse(reply["ok"])
        self.broker.mfa.pi.trigger_challenge.assert_called_once()

    async def test_web_token_unchanged(self):
        token = self.broker.web_tokens.issue("alice", None)
        self.assertTrue(token.startswith(WEB_TOKEN_PREFIX))
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "k8", "method": "tls", "user": "alice", "password": token,
            "client_address": "127.0.0.1"})
        self.assertTrue(reply["ok"], reply)               # IdP did the MFA, as before
        self.broker.mfa.pi.trigger_challenge.assert_not_called()

    async def test_mode_none_no_effect(self):
        self.broker.mfa.cfg.mode = "none"
        reply = await request(self.cfg.broker.socket, self.nla("k9"))
        self.assertTrue(reply["ok"], reply)
        self.broker.mfa.pi.trigger_challenge.assert_not_called()

    async def test_session_tgt_required_still_refuses_passwordless(self):
        self.broker.cfg.broker.session_tgt = "required"
        reply = await request(self.cfg.broker.socket, self.nla("k10"))
        self.assertFalse(reply["ok"])


class StartupWarningTests(unittest.TestCase):
    def test_warns_when_enabled(self):
        from fastrdp_broker.server import Broker

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(tmp, mode="push", nla_kdc_enforced=True,
                           privacyidea={"url": "https://pi.example.com"})
            with self.assertLogs("fastrdp.broker", "WARNING") as logs:
                Broker(cfg)
        self.assertIn("nla_kdc_enforced", logs.output[0])
        self.assertIn("EXAMPLE.COM", logs.output[0])


if __name__ == "__main__":
    unittest.main()
