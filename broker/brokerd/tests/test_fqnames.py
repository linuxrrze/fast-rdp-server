# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""SSSD with fully qualified names (use_fully_qualified_names = true, Ansible
fastrdp_sssd_fully_qualified_names; broker [auth] strip_realm = false).

NSS is faked like files + sss answer then: directory users and groups exist only as
'name@example.com', a local account 'marcel' (in /etc/passwd) has the short name of the
directory user 'marcel@example.com'. With short names that local account shadows the
directory user; with fully qualified names it cannot.
"""

import grp
import os
import pwd
import re
import tempfile
import unittest
from unittest import mock

from fastrdp_broker import config, identity, sysutil
from fastrdp_broker.backends import Target
from fastrdp_broker.backends.xrdp import XrdpBackend
from fastrdp_broker.identity import IdentityError, LocalUser
from fastrdp_broker.state import Session, StateStore
from test_server import make_cfg

LOCAL = {"marcel": 1001, "carol": 1003}                      # /etc/passwd
DIRECTORY = {"marcel@example.com": 50001, "bob@example.com": 50002,
             "dora@ipa.example.com": 50004}                  # SSSD, fully qualified
GROUPS = {1001: "marcel", 1003: "carol", 50001: "domain users@example.com",
          50002: "domain users@example.com", 50004: "ipausers@ipa.example.com",
          60001: "rdp-users@example.com", 60002: "admins@other.example.org", 60003: "rdp-users"}


def fake_getpwnam(name):
    uid = LOCAL.get(name) or DIRECTORY.get(name)    # files first, then sss
    if uid is None:
        raise KeyError(name)
    home = f"/home/{name.split('@')[0]}"             # fallback_homedir = /home/%u
    return pwd.struct_passwd((name, "x", uid, uid, "", home, "/bin/bash"))


def fake_getgrouplist(name, gid):
    return [gid, 60001, 60002] if "@" in name else [gid]


def fake_getgrgid(gid):
    if gid not in GROUPS:
        raise KeyError(gid)
    return grp.struct_group((GROUPS[gid], "x", gid, []))


class FakeNss:
    def __enter__(self):
        self.patches = [
            mock.patch("pwd.getpwnam", side_effect=fake_getpwnam),
            mock.patch("os.getgrouplist", side_effect=fake_getgrouplist),
            mock.patch("grp.getgrgid", side_effect=fake_getgrgid),
            mock.patch("fastrdp_broker.identity.krb5_localname", return_value=None),
        ]
        self.getpwnam = self.patches[0].start()
        for p in self.patches[1:]:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()

    def tried(self):
        return [c.args[0] for c in self.getpwnam.call_args_list]


def auth(strip_realm=False, realms=("EXAMPLE.COM",), domains=("example.com",)):
    return config.AuthSection(realms=list(realms), strip_realm=strip_realm, domains=list(domains))


class ResolveTests(unittest.TestCase):
    def principal(self, principal, a):
        name, realm = identity.split_principal(principal)
        with FakeNss():
            return identity.resolve_principal(name, realm, a)

    def test_fully_qualified_principal_is_the_directory_user(self):
        u = self.principal("marcel@EXAMPLE.COM", auth())
        self.assertEqual((u.name, u.uid, u.home), ("marcel@example.com", 50001, "/home/marcel"))

    def test_short_names_let_the_local_account_shadow(self):
        # strip_realm = true (short SSSD names): the local "marcel" wins. The reason for
        # fully qualified names; documented in docs/auth-matrix.md.
        self.assertEqual(self.principal("marcel@EXAMPLE.COM", auth(strip_realm=True)).uid, 1001)

    def test_candidate_order(self):
        with FakeNss() as nss:
            identity.resolve("bob", "EXAMPLE.COM", auth())
            self.assertEqual(nss.tried(), ["bob@example.com"])
        with FakeNss() as nss:
            identity.resolve("bob", "EXAMPLE.COM", auth(strip_realm=True))
            self.assertEqual(nss.tried(), ["bob", "bob@example.com"])
        with FakeNss() as nss:
            # a local-only account still logs in (last candidate)
            self.assertEqual(identity.resolve("carol", "EXAMPLE.COM", auth()).name, "carol")
            self.assertEqual(nss.tried(), ["carol@example.com", "carol"])

    def test_freeipa_domain_other_than_realm(self):
        a = auth(realms=["IPA.EXAMPLE.ORG"], domains=["ipa.example.com"])
        self.assertEqual(self.principal("dora@IPA.EXAMPLE.ORG", a).name, "dora@ipa.example.com")
        with self.assertRaises(IdentityError):  # without [auth] domains: SSSD knows no "dora@ipa.example.org"
            self.principal("dora@IPA.EXAMPLE.ORG", auth(realms=["IPA.EXAMPLE.ORG"], domains=[]))
        with FakeNss() as nss, self.assertRaises(IdentityError):
            # domains qualify names of accepted realms only
            identity.resolve("dora", "OTHER.ORG", a)
        self.assertEqual(nss.tried(), ["dora@other.org", "dora"])

    def test_tls_and_web_names(self):
        for typed in ("marcel", "EXAMPLE\\marcel", "marcel@example.com", "marcel@EXAMPLE.COM",
                      "marcel@unrelated.example.net"):
            with self.subTest(typed=typed), FakeNss():
                self.assertEqual(identity.resolve_login(typed, auth()).name, "marcel@example.com")
        with FakeNss():
            self.assertEqual(identity.resolve_login("carol", auth()).name, "carol")
            self.assertEqual(identity.resolve_login("marcel", auth(strip_realm=True)).name, "marcel")
            with self.assertRaises(IdentityError):
                identity.resolve_login("ghost", auth())
            with self.assertRaises(IdentityError):
                identity.resolve_login("a/b", auth())
        with FakeNss() as nss:
            for bad in ("carol\n", "carol\n@example.com"):   # SAFE_NAME is a fullmatch
                with self.subTest(bad=bad), self.assertRaises(IdentityError):
                    identity.resolve_login(bad, auth())
            with self.assertRaises(IdentityError):
                identity.resolve("carol\n", "EXAMPLE.COM", auth())
            self.assertEqual(nss.tried(), [])

    def test_typed_domain_selects_the_qualifier(self):
        a = auth(realms=["EXAMPLE.COM"], domains=["example.com", "ipa.example.com"])
        with FakeNss() as nss:
            identity.resolve_login("dora@ipa.example.com", a)
            self.assertEqual(nss.tried(), ["dora@ipa.example.com"])

    def test_short_names_unchanged(self):
        # Default (strip_realm = true): the typed short name first, as before.
        with FakeNss() as nss:
            self.assertEqual(identity.resolve_login("EXAMPLE\\carol", config.AuthSection()).name, "carol")
            self.assertEqual(nss.tried(), ["carol"])

    def test_qualified_groups_match_short_group_names(self):
        with FakeNss():
            u = identity.resolve("marcel", "EXAMPLE.COM", auth())
        self.assertIn("rdp-users@example.com", u.groups)
        self.assertIn("rdp-users", u.groups)
        self.assertIn("domain users", u.groups)
        self.assertNotIn("admins", u.groups)  # not one of our domains
        self.assertTrue(identity.user_allowed(u, config.AuthSection(allow_groups=["rdp-users"])))
        self.assertTrue(identity.user_allowed(u, config.AuthSection(allow_groups=["rdp-users@example.com"])))
        self.assertFalse(identity.user_allowed(u, config.AuthSection(allow_groups=["admins"])))

    def test_short_name(self):
        a = auth()
        self.assertEqual(identity.short_name("marcel@example.com", a), "marcel")
        self.assertEqual(identity.short_name("marcel@EXAMPLE.COM", a), "marcel")
        self.assertEqual(identity.short_name("marcel", a), "marcel")
        self.assertEqual(identity.short_name("x@other.example.org", a), "x@other.example.org")
        self.assertEqual(identity.short_name("@example.com", a), "@example.com")

    def test_credssp_short_name_is_not_another_account(self):
        user = LocalUser("marcel@example.com", 50001, 50001, "/home/marcel", frozenset())
        with FakeNss():
            # "marcel" is also a local account; qualified, it is this user
            self.assertFalse(identity.names_other_account("marcel", user, auth()))
            self.assertTrue(identity.names_other_account("marcel", user))  # without qualifiers
            self.assertTrue(identity.names_other_account("bob", user, auth()))
            self.assertFalse(identity.names_other_account("ghost", user, auth()))


class ConfigTests(unittest.TestCase):
    def parse(self, **auth_raw):
        raw = {"auth": auth_raw, "desktops": {"xfce": {"backend": "xrdp", "xsession": "xfce"}}}
        return config.parse(raw).auth

    def test_domains(self):
        self.assertEqual(self.parse().domains, [])
        self.assertEqual(self.parse(domains=["Example.COM", "ipa.example.com"]).domains,
                         ["example.com", "ipa.example.com"])
        for bad in (["example.com/x"], ["exa mple.com"], "example.com", [""], [1]):
            with self.subTest(bad=bad), self.assertRaises(config.ConfigError):
                self.parse(domains=bad)

    def test_strip_realm_is_a_bool(self):
        self.assertFalse(self.parse(strip_realm=False).strip_realm)
        with self.assertRaises(config.ConfigError):
            self.parse(strip_realm="false")


class LoginTests(unittest.IsolatedAsyncioTestCase):
    """Whole logins with fully qualified names: NLA, TLS, MFA, web."""

    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name, web=True)
        self.cfg.auth.strip_realm = False
        self.cfg.auth.domains = ["example.com"]
        self.cfg.auth.allow_groups = ["rdp-users"]  # directory group "rdp-users@example.com"
        self.cfg.broker.home_read_timeout = 0
        self.broker = Broker(self.cfg)
        self.ensure = mock.AsyncMock(return_value=Target("127.0.0.1", 3390, "u", "t", "", "tls", "ab" * 32))
        for b in self.broker.backends.values():
            b.ensure = self.ensure
        self.nss = FakeNss().__enter__()
        self.pam = [mock.patch("fastrdp_broker.pamauth.account_ok"),
                    mock.patch("fastrdp_broker.pamauth.authenticate")]
        self.account_ok, self.authenticate = [p.start() for p in self.pam]

    async def asyncTearDown(self):
        for p in self.pam:
            p.stop()
        self.nss.__exit__()
        self.broker.home_pool.shutdown(wait=True)
        self.tmp.cleanup()

    async def test_nla(self):
        reply = await self.broker.login({"op": "login", "session_id": "s", "method": "nla", "user": "marcel",
                                         "principal": "marcel@EXAMPLE.COM", "password": "pw"})
        self.assertEqual(reply["user"], "marcel@example.com")
        req = self.ensure.call_args.args[0]
        # the CredSSP name "marcel" (also a local account) is this user: password kept
        self.assertEqual((req.user.uid, req.password), (50001, "pw"))
        self.assertEqual(self.account_ok.call_args.args[1], "marcel@example.com")

    async def test_tls(self):
        reply = await self.broker.login({"op": "login", "session_id": "s", "method": "tls",
                                         "user": "EXAMPLE\\marcel", "password": "pw"})
        self.assertEqual(reply["user"], "marcel@example.com")
        self.assertEqual(self.authenticate.call_args.args[1:3], ("marcel@example.com", "pw"))

    async def test_mfa_user_is_the_short_name(self):
        self.cfg.mfa.mode = "push"
        with mock.patch.object(self.broker.mfa, "verify", mock.AsyncMock(return_value="push")) as verify:
            reply = await self.broker.login({"op": "login", "session_id": "s", "method": "nla", "user": "marcel",
                                             "principal": "marcel@EXAMPLE.COM", "password": "pw"})
        self.assertEqual(reply["user"], "marcel@example.com")
        self.assertEqual(verify.call_args.args[0], "marcel")  # privacyIDEA's name in both modes

    async def test_web(self):
        # fastrdp-webgate strips @example.com from the OIDC claim and sends "marcel"
        issued = await self.broker.issue_web_token({"op": "web_token", "user": "marcel"})
        self.assertEqual(issued["user"], "marcel@example.com")
        # Guacamole logs in with the name the webgate gave it
        reply = await self.broker.login({"op": "login", "session_id": "w", "method": "tls", "user": "marcel",
                                         "password": issued["token"], "client_address": "127.0.0.1"})
        self.assertEqual(reply["user"], "marcel@example.com")
        self.assertEqual(self.ensure.call_args.args[0].user.uid, 50001)

    async def test_local_account_still_logs_in(self):
        self.cfg.auth.allow_groups = []
        reply = await self.broker.login({"op": "login", "session_id": "s", "method": "tls",
                                         "user": "carol", "password": "pw"})
        self.assertEqual(reply["user"], "carol")

    def test_session_units_and_paths(self):
        user = LocalUser("marcel@example.com", 50001, 50001, "/home/marcel", frozenset())
        # systemd allows '@' in instance names (unit_name_is_valid: VALID_CHARS_WITH_AT)
        valid = re.compile(r"[A-Za-z0-9:_.\\-]+@[A-Za-z0-9:_.\\@-]+\.service")
        for name, unit in (("gnome", "gnome-headless-session@marcel@example.com.service"),
                           ("plasma", "fastrdp-plasma@marcel@example.com.service")):
            with self.subTest(name):
                self.assertEqual(self.broker.backends[name].unit(user), unit)
                self.assertRegex(unit, valid)
        self.assertTrue(self.broker.backends["plasma"].env_path(user).endswith(
            "/sessions/marcel@example.com.plasma.env"))  # the unit's %i
        store = StateStore(f"{self.tmp.name}/state2")
        store.put(Session(user="marcel@example.com", backend="gnome", desktop="gnome", port=33901))
        self.assertEqual(StateStore(f"{self.tmp.name}/state2").get("marcel@example.com", "gnome").port, 33901)


class SystemdTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_as_user_by_uid(self):
        # systemd-run --machine=USER@.host splits at the first '@'
        user = LocalUser("marcel@example.com", 50001, 50001, "/home/marcel", frozenset())
        with mock.patch("fastrdp_broker.sysutil.ensure_user_manager", mock.AsyncMock()), \
                mock.patch("fastrdp_broker.sysutil.run", mock.AsyncMock()) as run:
            await sysutil.run_as_user(user, "grdctl", "status")
        argv = run.call_args.args
        self.assertIn("--machine=50001@.host", argv)
        self.assertNotIn("marcel@example.com", " ".join(argv))

    async def test_xrdp_sessions_of_a_qualified_user(self):
        cfg = make_cfg(tempfile.gettempdir())
        backend = XrdpBackend.__new__(XrdpBackend)
        backend.cfg = cfg

        async def run(*argv, **kw):
            if argv[1] == "list-sessions":
                out = ("3 50001 marcel@example.com seat0 tty2\n"
                       "4 1001 marcel - pts/1\n")
            else:
                out = "Service=xrdp-sesman\nState=active\n"
            return sysutil.Result(0, out, "")
        with mock.patch("fastrdp_broker.sysutil.run", side_effect=run):
            self.assertEqual(await backend.live_sessions("marcel@example.com"), ["3"])
            self.assertEqual(await backend.live_sessions("marcel"), ["4"])


if __name__ == "__main__":
    unittest.main()
