# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[broker.session_tgt_groups]: session_tgt per group (backlog K5).

Members of listed groups get the strictest mode of their groups (required > auto > off)
instead of [broker] session_tgt; everybody else keeps the global mode. "required" for
a group refuses only its members' logins without a password, before MFA (also within
reconnect grace, with nla_kdc_enforced, Remote Credential Guard and web logins)."""

import unittest
from unittest import mock

from fastrdp_broker import config, identity, pamauth, sysutil
from fastrdp_broker.config import ConfigError
from test_fqnames import FakeNss
from test_fqnames import auth as fq_auth
from test_gaps import _BrokerHarness, raw_example, user

PW = "S3cret-pw!"
MINIMAL = {"desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}}


def parse(groups, default=None):
    broker = {"session_tgt_groups": groups}
    if default:
        broker["session_tgt"] = default
    return config.parse({**MINIMAL, "broker": broker})


class SessionTgtGroupsConfigTests(unittest.TestCase):
    def test_default_empty(self):
        self.assertEqual(config.parse(dict(MINIMAL)).broker.session_tgt_groups, {})
        self.assertEqual(config.parse(raw_example()).broker.session_tgt_groups, {})  # commented out

    def test_valid(self):
        groups = {"nfs-homes": "required", "kiosk": "off", "Domain Users@example.com": "auto"}
        self.assertEqual(parse(groups).broker.session_tgt_groups, groups)

    def test_example_section_parses(self):
        # the commented example in broker.toml.example, uncommented
        import tomllib
        raw = tomllib.loads('[broker.session_tgt_groups]\n"nfs-homes" = "required"\n"kiosk" = "off"\n')
        cfg = config.parse({**MINIMAL, **raw})
        self.assertEqual(cfg.broker.session_tgt_groups, {"nfs-homes": "required", "kiosk": "off"})

    def test_invalid(self):
        for bad in (["nfs-homes"], "nfs-homes=required", {"nfs-homes": ["required"]}):
            with self.subTest(bad), self.assertRaisesRegex(ConfigError, "session_tgt_groups"):
                parse(bad)
        for mode in ("yes", "", True, "Required"):
            with self.subTest(mode), self.assertRaisesRegex(ConfigError, "mode must be one of"):
                parse({"nfs-homes": mode})
        for group in ("", " ", " nfs-homes", "nfs\nhomes"):
            with self.subTest(group=group), self.assertRaisesRegex(ConfigError, "invalid group name"):
                parse({group: "required"})


class EffectiveModeTests(unittest.TestCase):
    def mode(self, groups, user_groups, default="auto"):
        return identity.session_tgt_mode(parse(groups, default), user("alice", user_groups))

    def test_no_group_listed_or_matching_is_the_default(self):
        self.assertEqual(self.mode({}, ("rdp-users",)), ("auto", None))
        self.assertEqual(self.mode({"nfs-homes": "required"}, ("rdp-users",), "off"), ("off", None))

    def test_group_overrides_default_both_ways(self):
        self.assertEqual(self.mode({"nfs-homes": "required"}, ("nfs-homes",)), ("required", "nfs-homes"))
        # a group may also relax a stricter default (local accounts without Kerberos)
        self.assertEqual(self.mode({"local": "auto"}, ("local",), "required"), ("auto", "local"))
        self.assertEqual(self.mode({"kiosk": "off"}, ("kiosk",), "required"), ("off", "kiosk"))

    def test_strictest_wins_in_any_order(self):
        groups = {"kiosk": "off", "staff": "auto", "nfs-homes": "required"}
        for order in (groups, dict(reversed(groups.items()))):
            with self.subTest(list(order)):
                self.assertEqual(self.mode(order, ("kiosk", "staff", "nfs-homes")), ("required", "nfs-homes"))
                self.assertEqual(self.mode(order, ("kiosk", "staff")), ("auto", "staff"))
                self.assertEqual(self.mode(order, ("kiosk",)), ("off", "kiosk"))
        # tie: the first listed group is named
        self.assertEqual(self.mode({"a": "required", "b": "required"}, ("a", "b")), ("required", "a"))

    def test_fully_qualified_group_names(self):
        """SSSD with fully qualified names: 'rdp-users@example.com' matches both its own
        name and the short alias; groups of foreign domains only by their full name."""
        a = fq_auth()
        with FakeNss():
            u = identity.resolve_login("marcel", a)
        self.assertEqual(u.name, "marcel@example.com")
        for listed in ("rdp-users", "rdp-users@example.com", "admins@other.example.org"):
            with self.subTest(listed):
                cfg = parse({listed: "required"})
                self.assertEqual(identity.session_tgt_mode(cfg, u), ("required", listed))
        cfg = parse({"admins": "required"})   # other.example.org is not one of our domains
        self.assertEqual(identity.session_tgt_mode(cfg, u), ("auto", None))


class SessionTgtGroupsLoginTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    """alice: default user; nina: Kerberized home (group nfs-homes = required); kai:
    kiosk (group kiosk = off)."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.users["nina"] = user("nina", ("rdp-users", "nfs-homes"), uid=1501)
        self.users["kai"] = user("kai", ("rdp-users", "kiosk"), uid=1502)
        self.cfg.broker.session_tgt_groups = {"nfs-homes": "required", "kiosk": "off"}
        self.establish = mock.Mock(return_value="KCM:")
        self.klist = mock.AsyncMock(return_value=sysutil.Result(0, "", ""))
        for p in (mock.patch("fastrdp_broker.pamauth.establish_credentials", self.establish),
                  mock.patch("fastrdp_broker.sysutil.run_dropped", self.klist)):
            p.start()
            self.patches.append(p)

    def gnome(self, who, password=PW, **kw):
        return self.nla(user=who, password=password, desktop_hint="fastrdp:gnome", **kw)

    def _request(self, msg):
        from test_server import request
        return request(self.cfg.broker.socket, msg)

    async def test_required_group_refuses_only_its_members_without_password(self):
        pi = self.set_mfa("push")
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            self.assertEqual(await self.gnome("nina", password=None), self.DENIED)       # SSO
        out = "\n".join(logs.output)
        self.assertIn("nina: session_tgt = required (group nfs-homes; default auto)", out)
        self.assertIn("[broker.session_tgt_groups] nfs-homes = required", out)
        self.assertEqual(await self.gnome("nina", smartcard=True), self.DENIED)
        self.assertEqual(await self.nla(user="nina", password=None, remote_guard=True), self.DENIED)
        self.assertEqual(await self.nla(user="nina", password=None), self.DENIED)     # xrdp too
        pi.trigger_challenge.assert_not_called()   # refused before MFA
        self.ensure.assert_not_called()
        # everybody else: SSO without a password works as with session_tgt = auto
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        for who in ("alice", "kai"):
            with self.subTest(who):
                self.assertTrue((await self.gnome(who, password=None))["ok"])
                self.assertTrue((await self.nla(user=who, password=None, remote_guard=True))["ok"])
        self.establish.assert_not_called()

    async def test_required_group_with_password_gets_tgt(self):
        self.assertTrue((await self.gnome("nina"))["ok"])
        self.establish.assert_called_once_with("fastrdp-tgt", "nina", PW)
        self.assertTrue((await self.login(user="nina", password=PW, desktop_hint="fastrdp:plasma"))["ok"])
        self.assertEqual(self.establish.call_count, 2)

    async def test_required_group_tgt_failure_refuses(self):
        self.establish.side_effect = pamauth.PamError("authenticate", 7, "Authentication failure")
        self.assertEqual(await self.gnome("nina"), self.DENIED)
        self.ensure.assert_not_called()
        with self.assertLogs("fastrdp.broker", "WARNING"):
            self.assertTrue((await self.gnome("alice"))["ok"])      # auto: only a warning

    async def test_off_group_never_requests_tgt(self):
        self.cfg.broker.session_tgt = "required"
        self.assertTrue((await self.gnome("kai"))["ok"])
        self.assertTrue((await self.gnome("kai", password=None))["ok"])  # not refused either
        self.establish.assert_not_called()
        # the global default still applies to users in no listed group
        self.assertEqual(await self.gnome("alice", password=None), self.DENIED)
        self.assertTrue((await self.gnome("alice"))["ok"])
        self.establish.assert_called_once_with("fastrdp-tgt", "alice", PW)

    async def test_web_refused_for_required_group_only(self):
        self.assertFalse((await self._request({"op": "web_token", "user": "nina"}))["ok"])
        self.assertFalse((await self._request({"op": "web_desktops", "user": "nina"}))["ok"])
        self.assertTrue((await self._request({"op": "web_token", "user": "alice"}))["ok"])
        self.assertTrue((await self._request({"op": "web_token", "user": "kai"}))["ok"])

    async def test_reconnect_grace_does_not_bypass_required_group(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        self.broker.grace.seconds = 300
        addr = {"client_address": "192.0.2.10"}
        self.assertTrue((await self.gnome("nina", **addr))["ok"])       # push, grace recorded
        self.assertEqual(len(self.broker.grace), 1)
        self.assertEqual(await self.gnome("nina", password=None, **addr), self.DENIED)
        self.assertTrue((await self.gnome("nina", **addr))["ok"])       # within grace, password
        self.assertEqual(pi.trigger_challenge.call_count, 1)

    async def test_kdc_enforced_does_not_bypass_required_group(self):
        pi = self.set_mfa("push")
        self.cfg.mfa.nla_kdc_enforced = True
        self.assertEqual(await self.gnome("nina", password=None), self.DENIED)
        self.assertTrue((await self.gnome("alice", password=None))["ok"])   # KDC vouches, no TGT needed
        pi.trigger_challenge.assert_not_called()

    async def test_no_log_line_when_group_mode_equals_default(self):
        self.cfg.broker.session_tgt = "required"
        with self.assertLogs("fastrdp.broker", "INFO") as logs:
            self.assertTrue((await self.gnome("nina"))["ok"])
        self.assertFalse(any("session_tgt = required (group" in line for line in logs.output), logs.output)


if __name__ == "__main__":
    unittest.main()
