# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Connection type for the xrdp hop: [network] lan_networks / xrdp_autodetect_profile."""

import asyncio
import os
import tempfile
import tomllib
import unittest
from unittest import mock

from fastrdp_broker import config, conntype
from fastrdp_broker.backends import Target
from test_server import EXAMPLE, fake_user, make_cfg, request

LAN = conntype.parse_networks(["10.0.0.0/8", "192.168.1.0/24", "2001:db8:1::/48"])


class ForBackend(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(conntype.for_backend(7, "10.1.2.3", LAN, "wan"), "lan")
        self.assertEqual(conntype.for_backend(7, "192.168.1.200", LAN, "wan"), "lan")
        self.assertEqual(conntype.for_backend(7, "192.168.2.1", LAN, "wan"), "wan")
        self.assertEqual(conntype.for_backend(7, "203.0.113.7", LAN, "wan"), "wan")

    def test_ipv6(self):
        self.assertEqual(conntype.for_backend(7, "2001:db8:1::42", LAN, "wan"), "lan")
        self.assertEqual(conntype.for_backend(7, "2001:db8:2::42", LAN, "wan"), "wan")
        self.assertEqual(conntype.for_backend(7, "fe80::1%eth0", conntype.parse_networks(["fe80::/10"]),
                                              "wan"), "lan")

    def test_ipv4_mapped_ipv6(self):
        # dual-stack listener: the peer address of an IPv4 client
        self.assertEqual(conntype.for_backend(7, "::ffff:10.1.2.3", LAN, "wan"), "lan")
        self.assertEqual(conntype.for_backend(7, "::ffff:203.0.113.7", LAN, "wan"), "wan")
        # an IPv6 network never matches an IPv4 client
        self.assertEqual(conntype.for_backend(7, "10.1.2.3", conntype.parse_networks(["::/0"]), "wan"), "wan")

    def test_explicit_client_choice_kept(self):
        for t in range(1, 7):
            with self.subTest(t):
                self.assertIsNone(conntype.for_backend(t, "10.1.2.3", LAN, "wan"))
                self.assertIsNone(conntype.for_backend(t, "203.0.113.7", LAN, "modem"))

    def test_unset_and_invalid_are_overridden(self):
        for t in (0, 7, 8, 255, None, "6", True, 6.0):
            with self.subTest(t):
                self.assertEqual(conntype.for_backend(t, "10.1.2.3", LAN, "wan"), "lan")
                self.assertEqual(conntype.for_backend(t, "203.0.113.7", LAN, "satellite"), "satellite")

    def test_empty_list_only_profile(self):
        self.assertEqual(conntype.for_backend(7, "10.1.2.3", (), "wan"), "wan")
        self.assertIsNone(conntype.for_backend(7, "10.1.2.3", (), "default"))

    def test_default_profile_changes_nothing_outside_the_lan(self):
        self.assertIsNone(conntype.for_backend(7, "203.0.113.7", LAN, "default"))
        self.assertEqual(conntype.for_backend(7, "10.1.2.3", LAN, "default"), "lan")

    def test_unparsable_or_missing_address(self):
        for addr in (None, "", "rdp.example.com", "10.1.2", "::ffff:zz"):
            with self.subTest(addr):
                self.assertEqual(conntype.for_backend(7, addr, LAN, "wan"), "wan")


class ConfigParse(unittest.TestCase):
    def raw(self, **network):
        with open(EXAMPLE, "rb") as fh:
            raw = tomllib.load(fh)
        raw["network"] = network
        return raw

    def test_defaults(self):
        with open(EXAMPLE, "rb") as fh:
            raw = tomllib.load(fh)
        raw.pop("network", None)
        cfg = config.parse(raw)
        self.assertEqual((cfg.network.lan, cfg.network.xrdp_autodetect_profile), ((), "wan"))

    def test_networks_parsed(self):
        cfg = config.parse(self.raw(lan_networks=["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]))
        self.assertEqual([str(n) for n in cfg.network.lan], ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"])

    def test_invalid_networks_refused(self):
        for bad in (["10.0.0.0/33"], ["10.1.2.3/8"], ["lan"], ["2001:db8::/129"], [10], "10.0.0.0/8",
                    ["10.0.0.0/8", ""]):
            with self.subTest(bad), self.assertRaisesRegex(config.ConfigError, "lan_networks"):
                config.parse(self.raw(lan_networks=bad))

    def test_profiles(self):
        for p in conntype.PROFILES:
            self.assertEqual(config.parse(self.raw(xrdp_autodetect_profile=p)).network.xrdp_autodetect_profile, p)
        for bad in ("autodetect", "LAN", "fast", ""):
            with self.subTest(bad), self.assertRaisesRegex(config.ConfigError, "xrdp_autodetect_profile"):
                config.parse(self.raw(xrdp_autodetect_profile=bad))

    def test_unknown_key_and_parsed_field_refused(self):
        for key in ("lan", "networks"):
            with self.subTest(key), self.assertRaisesRegex(config.ConfigError, "unknown keys"):
                config.parse(self.raw(**{key: []}))


class LoginReply(unittest.IsolatedAsyncioTestCase):
    """The login reply's target carries connection_type for xrdp desktops only."""

    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        cfg = make_cfg(self.tmp.name)
        cfg.network.lan = conntype.parse_networks(["10.0.0.0/8", "2001:db8::/32"])
        self.cfg = cfg
        self.broker = Broker(cfg)
        for name in ("xrdp", "gnome"):
            self.broker.backends[name].ensure = mock.AsyncMock(
                return_value=Target("127.0.0.1", 3390, "alice", "fastrdp1:tok", "", "tls"))
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", side_effect=lambda n, r, a: fake_user(n)),
            mock.patch("fastrdp_broker.pamauth.authenticate"),
            mock.patch("fastrdp_broker.pamauth.account_ok"),
        ]
        for p in self.patches:
            p.start()
        self.task = asyncio.create_task(self.broker.serve())
        for _ in range(50):
            if os.path.exists(cfg.broker.socket):
                break
            await asyncio.sleep(0.02)

    async def asyncTearDown(self):
        self.task.cancel()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    async def login(self, address, ctype, hint=None):
        msg = {"op": "login", "session_id": f"s-{address}-{ctype}-{hint}", "method": "tls",
               "user": "alice", "password": "pw", "client_address": address, "desktop_hint": hint}
        if ctype is not None:
            msg["connection_type"] = ctype
        reply = await request(self.cfg.broker.socket, msg)
        self.assertTrue(reply["ok"], reply)
        return reply["target"].get("connection_type")

    async def test_xrdp(self):
        self.assertEqual(await self.login("10.9.8.7", 7), "lan")
        self.assertEqual(await self.login("::ffff:10.9.8.7", 0), "lan")
        self.assertEqual(await self.login("2001:db8::5", None), "lan")
        self.assertEqual(await self.login("203.0.113.7", 7), "wan")
        self.assertIsNone(await self.login("10.9.8.7", 2))      # explicit client choice
        self.assertIsNone(await self.login("203.0.113.7", 6))

    async def test_profile_default_and_empty_list(self):
        self.cfg.network.lan = ()
        self.cfg.network.xrdp_autodetect_profile = "default"
        self.assertIsNone(await self.login("10.9.8.7", 7))
        self.cfg.network.xrdp_autodetect_profile = "broadband_low"
        self.assertEqual(await self.login("10.9.8.7", 7), "broadband_low")

    async def test_not_for_gnome(self):
        self.assertIsNone(await self.login("10.9.8.7", 7, "fastrdp:gnome"))
        self.assertIsNone(await self.login("203.0.113.7", 7, "fastrdp:gnome"))
