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

from fastrdp_broker import config
from fastrdp_broker.backends import Target
from fastrdp_broker.identity import LocalUser

EXAMPLE = Path(__file__).parent.parent / "config" / "broker.toml.example"
ME = pwd.getpwuid(os.getuid())


def make_cfg(tmp: str, **mfa) -> config.Config:
    with open(EXAMPLE, "rb") as fh:
        raw = tomllib.load(fh)
    raw["broker"].update(
        socket=f"{tmp}/broker.sock",
        token_socket=f"{tmp}/token.sock",
        proxy_user=ME.pw_name,
        state_dir=f"{tmp}/state",
        runtime_dir=f"{tmp}/run",
    )
    raw["auth"]["allow_groups"] = []
    raw["mfa"]["mode"] = "none"
    raw["mfa"].update(mfa)
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
        self.cfg = make_cfg(self.tmp.name)
        self.broker = Broker(self.cfg)
        self.target = Target("127.0.0.1", 3390, "alice", "fastrdp1:tok", "", "tls")
        self.ensure = mock.AsyncMock(return_value=self.target)
        self.broker.backends["xrdp"].ensure = self.ensure
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", side_effect=lambda n, r, a: fake_user(n)),
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

    async def test_nla_principal_mismatch_denied(self):
        reply = await request(self.cfg.broker.socket, {
            "op": "login", "session_id": "s2", "method": "nla", "user": "bob",
            "principal": "alice@EXAMPLE.COM",
        })
        self.assertEqual(reply, {"ok": False, "error": "access denied"})
        self.ensure.assert_not_called()

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
        self.broker.mfa.pi.wait_for_push.assert_called_with("alice", "tx1")

    async def test_token_socket_rejects_non_root(self):
        tok = self.broker.tokens.issue("alice", None)
        reply = await request(self.cfg.broker.token_socket, {"op": "redeem", "user": "alice", "token": tok})
        if os.getuid() != 0:
            self.assertEqual(reply, {})
            self.assertEqual(self.broker.tokens.redeem("alice", tok), (True, None))

    async def test_status_requires_root(self):
        reply = await request(self.cfg.broker.socket, {"op": "status"})
        if os.getuid() != 0:
            self.assertEqual(reply, {"ok": False, "error": "not permitted"})

    async def test_garbage_is_dropped(self):
        reader, writer = await asyncio.open_unix_connection(self.cfg.broker.socket)
        writer.write(b"not json\n")
        await writer.drain()
        self.assertEqual(await reader.read(), b"")
        writer.close()


if __name__ == "__main__":
    unittest.main()
