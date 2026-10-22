# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""End-to-end tests of the broker socket protocol with mocked PAM/back-ends."""

import asyncio
import json
import os
import pwd
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, identity
from fastrdp_broker.backends import Target
from fastrdp_broker.identity import LocalUser

EXAMPLE = Path(__file__).parent.parent / "config" / "broker.toml.example"
ME = pwd.getpwuid(os.getuid())


def make_cfg(tmp: str, web: bool = False, **mfa) -> config.Config:
    with open(EXAMPLE, "rb") as fh:
        raw = tomllib.load(fh)
    raw["broker"].update(
        socket=f"{tmp}/broker.sock",
        token_socket=f"{tmp}/token.sock",
        proxy_user=ME.pw_name,
        socket_group="",
        state_dir=f"{tmp}/state",
        runtime_dir=f"{tmp}/run",
        home_check="off",  # fake users' homes do not exist; test_home_dir.py covers it
    )
    raw["auth"]["allow_groups"] = []
    raw["mfa"]["mode"] = "none"
    raw["mfa"].update(mfa)
    if web:
        raw["web"] = {"enabled": True, "gateway_user": ME.pw_name, "allowed_clients": ["127.0.0.1"]}
    return config.parse(raw)


def fake_user(name="alice"):
    return LocalUser(name, 1500, 1500, "/nonexistent", frozenset({"rdp-users"}))


async def request(path: str, msg: dict) -> dict:
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(json.dumps(msg).encode() + b"\n")
    await writer.drain()
    try:
        line = await reader.readline()
    except ConnectionResetError:  # server hung up without reading (rejected peer)
        line = b""
    writer.close()
    return json.loads(line) if line else {}


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name, web=True)
        self.broker = Broker(self.cfg)
        self.target = Target("127.0.0.1", 3390, "alice", "fastrdp1:tok", "", "tls", "ab" * 32)
        self.ensure = mock.AsyncMock(return_value=self.target)
        self.broker.backends["xrdp"].ensure = self.ensure
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", side_effect=lambda n, r, a: fake_user(n)),
            mock.patch("fastrdp_broker.identity.resolve_login",
                       side_effect=lambda n, a: fake_user(identity.normalize_rdp_user(n))),
            mock.patch("fastrdp_broker.pamauth.authenticate"),
            mock.patch("fastrdp_broker.pamauth.account_ok"),
        ]
        for p in self.patches:
            p.start()
        self.task = asyncio.create_task(self.broker.serve())
        for _ in range(50):
            if os.path.exists(self.cfg.broker.token_socket):
                break
            await asyncio.sleep(0.02)

    async def asyncTearDown(self):
        self.task.cancel()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    async def test_nla_login(self):
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s1", "method": "nla", "user": "EXAMPLE\\alice",
            "principal": "alice@EXAMPLE.COM", "password": "pw", "width": 2560, "height": 1440,
        })
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["target"]["port"], 3390)
        req = self.ensure.call_args.args[0]
        self.assertEqual((req.user.name, req.password, req.width, req.desktop.name), ("alice", "pw", 2560, "xfce"))

    async def test_smartcard_pin_never_used_as_password(self):
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "sc", "method": "nla", "user": "alice",
            "principal": "alice@EXAMPLE.COM", "password": "123456", "smartcard": True,
        })
        self.assertTrue(reply["ok"], reply)
        self.assertIsNone(self.ensure.call_args.args[0].password)

    async def test_remote_guard_identity_only(self):
        # Remote Credential Guard: the proxy module discarded the forwarded Kerberos tickets.
        # The principal is the identity; a password sent along anyway is never used.
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            reply = await request(self.cfg.broker.socket, {
                "op": "login", "session_id": "rg", "method": "nla", "user": "alice",
                "principal": "alice@EXAMPLE.COM", "password": "pw", "remote_guard": True,
            })
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["user"], "alice")
        self.assertIsNone(self.ensure.call_args.args[0].password)
        self.assertTrue(any("remote credential guard: identity only, credentials discarded" in line
                            and "alice@EXAMPLE.COM" in line for line in logs.output), logs.output)

    async def test_nla_principal_is_the_identity(self):
        # The CredSSP user name never selects the account (tests/test_principal.py).
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s2", "method": "nla", "user": "bob",
            "principal": "alice@EXAMPLE.COM",
        })
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["user"], "alice")
        self.assertEqual(self.ensure.call_args.args[0].user.name, "alice")

    async def test_foreign_realm_denied(self):
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s3", "method": "nla", "user": "alice",
            "principal": "alice@EVIL.ORG",
        })
        self.assertFalse(reply["ok"])

    async def test_tls_login_checks_password(self):
        from fastrdp_broker import pamauth

        pamauth.authenticate.side_effect = pamauth.PamError("authenticate", 7, "Authentication failure")
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s4", "method": "tls", "user": "alice", "password": "wrong",
        })
        self.assertFalse(reply["ok"])
        pamauth.authenticate.side_effect = None
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s5", "method": "tls", "user": "alice", "password": "right",
        })
        self.assertTrue(reply["ok"])

    async def test_tls_otp_split_and_verify(self):
        self.broker.mfa.cfg.mode = "otp"
        self.broker.mfa.pi = mock.Mock()
        self.broker.mfa.pi.check_otp.return_value = True
        from fastrdp_broker import pamauth

        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s6", "method": "tls", "user": "alice", "password": "pw654321",
        })
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(pamauth.authenticate.call_args.args[2], "pw")
        self.broker.mfa.pi.check_otp.assert_called_with("alice", "654321")
        self.assertEqual(self.ensure.call_args.args[0].password, "pw")

    async def test_nla_with_otp_mode_denied(self):
        self.broker.mfa.cfg.mode = "otp"
        self.broker.mfa.pi = mock.Mock()
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s7", "method": "nla", "user": "alice",
            "principal": "alice@EXAMPLE.COM",
        })
        self.assertFalse(reply["ok"])

    async def test_push(self):
        self.broker.mfa.cfg.mode = "push"
        self.broker.mfa.pi = mock.Mock()
        self.broker.mfa.pi.trigger_challenge.return_value = "tx1"
        self.broker.mfa.pi.wait_for_push.return_value = True
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s8", "method": "nla", "user": "alice",
            "principal": "alice@EXAMPLE.COM", "password": "pw",
        })
        self.assertTrue(reply["ok"])
        self.broker.mfa.pi.wait_for_push.assert_called_with("alice", "tx1", mock.ANY)

    async def test_token_socket_rejects_non_root(self):
        tok = self.broker.tokens.issue("alice", None)
        reply = await request(self.cfg.broker.token_socket, {"op": "redeem", "user": "alice", "token": tok})
        if os.getuid() != 0:
            self.assertEqual(reply, {})
            self.assertEqual(self.broker.tokens.redeem("alice", tok), (True, None))

    async def test_status_requires_root(self):
        reply = await request(self.cfg.broker.socket, {"op": "status"})
        if os.getuid() != 0:
            self.assertEqual(reply, {"ok": False, "error": "not permitted", "reason": "denied"})

    async def test_garbage_is_dropped(self):
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(b"not json\n")
        await writer.drain()
        self.assertEqual(await reader.read(), b"")
        writer.close()


class WebTokenTests(BrokerTests):
    """Browser path: webgate -> web_token -> Guacamole/guacd -> proxy (TLS) -> broker."""

    async def get_web_token(self, user="alice"):
        reply = await request(self.cfg.broker.socket, {"op": "web_token", "user": user})
        self.assertTrue(reply["ok"], reply)
        self.assertIn("xfce", reply["desktops"])
        return reply["token"]

    async def test_web_desktops_lists_only_allowed(self):
        # Regression: the webgate chooser offered desktops the broker then refused, and
        # the session silently fell back to the default desktop.
        self.cfg.desktops["mate"].groups = ["rdp-mate-only"]  # alice is only in rdp-users
        reply = await request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})
        self.assertTrue(reply["ok"], reply)
        names = [d["name"] for d in reply["desktops"]]
        self.assertIn("xfce", names)
        self.assertNotIn("mate", names)
        self.assertIn({"name": "xfce", "label": "Xfce"}, reply["desktops"])
        self.assertIn(reply["default"], names)
        self.assertNotIn("token", reply)
        token_reply = await request(self.cfg.broker.socket, {"op": "web_token", "user": "alice"})
        self.assertNotIn("mate", token_reply["desktops"])

    async def test_web_desktops_only_for_webgate(self):
        with mock.patch.object(self.broker, "web_uid", os.getuid() + 1):
            reply = await request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})
        self.assertFalse(reply["ok"])

    def web_login(self, token, address="127.0.0.1", user="alice"):
        return request(self.cfg.broker.socket, {
            "op": "login", "session_id": "w1", "method": "tls", "user": user,
            "password": token, "client_address": address, "desktop_hint": "fastrdp:mate",
        })

    async def test_web_token_login_once_and_skips_mfa(self):
        self.broker.mfa.cfg.mode = "push"
        self.broker.mfa.pi = mock.Mock()
        token = await self.get_web_token()
        self.assertTrue(token.startswith("fastrdp-web1:"))
        reply = await self.web_login(token)
        self.assertTrue(reply["ok"], reply)
        self.broker.mfa.pi.trigger_challenge.assert_not_called()
        from fastrdp_broker import pamauth
        pamauth.authenticate.assert_not_called()
        self.assertIsNone(self.ensure.call_args.args[0].password)
        self.assertFalse((await self.web_login(token))["ok"])  # single use

    async def test_web_token_wrong_client_address(self):
        token = await self.get_web_token()
        self.assertFalse((await self.web_login(token, address="10.1.2.3"))["ok"])

    async def test_web_token_bound_to_user(self):
        token = await self.get_web_token("alice")
        self.assertFalse((await self.web_login(token, user="bob"))["ok"])

    async def test_web_token_not_valid_for_xrdp_pam(self):
        token = await self.get_web_token()
        self.assertEqual(self.broker.tokens.redeem("alice", token), (False, None))


class WebDisabledTests(unittest.IsolatedAsyncioTestCase):
    async def test_web_token_op_refused_when_disabled(self):
        from fastrdp_broker.server import Broker

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(tmp)
            broker = Broker(cfg)
            task = asyncio.create_task(broker.serve())
            for _ in range(50):
                if os.path.exists(cfg.broker.socket):
                    break
                await asyncio.sleep(0.02)
            reply = await request(cfg.broker.socket, {"op": "web_token", "user": "alice"})
            self.assertEqual(reply, {"ok": False, "error": "not permitted", "reason": "denied"})
            task.cancel()


if __name__ == "__main__":
    unittest.main()
