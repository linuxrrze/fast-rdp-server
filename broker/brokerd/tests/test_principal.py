# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""NLA logins: the Kerberos principal is the identity, not the CredSSP user name.

Windows users type UPNs whose local part differs from the account name
(marcel.ritter@corp.example.com -> mritter) or DOMAIN\\user forms; the broker used to
refuse those (docs/windows-clients.md §3.6). NSS is faked like SSSD answers it:
getpwnam() finds accounts by name, by name@domain and by UPN.
"""

import ctypes
import ctypes.util
import grp
import os
import pwd
import tempfile
import unittest
from unittest import mock

from fastrdp_broker import identity
from fastrdp_broker.backends import Target
from fastrdp_broker.identity import IdentityError
from fastrdp_broker.server import Denied
from test_server import make_cfg

ACCOUNTS = {"mritter": 1501, "bob": 1502, "carol": 1503, "alice": 1504, "root": 0}
ALIASES = {  # what SSSD (AD provider) also resolves: name@domain and UPN lookups
    "mritter@example.com": "mritter",
    "marcel.ritter@corp.example.com": "mritter",   # UPN, other suffix and local part
    "bob@partner.example.com": "carol",            # carol's UPN; "bob" is someone else
}


def fake_getpwnam(name):
    name = ALIASES.get(name, name)
    if name not in ACCOUNTS:
        raise KeyError(name)
    uid = ACCOUNTS[name]
    return pwd.struct_passwd((name, "x", uid, uid, "", f"/home/{name}", "/bin/sh"))


class FakeNss:
    def __init__(self, localname=None):
        self.patches = [
            mock.patch("pwd.getpwnam", side_effect=fake_getpwnam),
            mock.patch("os.getgrouplist", side_effect=lambda n, g: [g]),
            mock.patch("grp.getgrgid", side_effect=lambda g: grp.struct_group(("rdp-users", "x", g, []))),
            mock.patch("fastrdp_broker.identity.krb5_localname", side_effect=localname or (lambda p: None)),
        ]

    def __enter__(self):
        return [p.start() for p in self.patches][-1]

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


class ResolvePrincipalTests(unittest.TestCase):
    def setUp(self):
        self.auth = make_cfg(tempfile.gettempdir()).auth

    def resolve(self, principal, **kw):
        name, realm = identity.split_principal(principal)
        with FakeNss(**kw):
            return identity.resolve_principal(name, realm, self.auth)

    def test_canonical_name(self):
        # AD canonicalises the client name to the sAMAccountName, whatever was typed.
        self.assertEqual(self.resolve("mritter@EXAMPLE.COM").name, "mritter")

    def test_enterprise_principal_resolves_by_upn(self):
        u = self.resolve("marcel.ritter\\@corp.example.com@EXAMPLE.COM")
        self.assertEqual((u.name, u.uid), ("mritter", 1501))

    def test_enterprise_local_part_never_used(self):
        # bob@partner.example.com is carol's UPN; the local account "bob" is another person.
        self.assertEqual(self.resolve("bob\\@partner.example.com@EXAMPLE.COM").name, "carol")
        with self.assertRaises(IdentityError):  # unknown UPN: not the local account "bob"
            self.resolve("bob\\@unknown.example.com@EXAMPLE.COM")

    def test_krb5_localauth_fallback(self):
        mapped = []

        def localname(principal):
            mapped.append(principal)
            return "mritter"
        self.assertEqual(self.resolve("m.ritter@EXAMPLE.COM", localname=localname).name, "mritter")
        self.assertEqual(mapped, ["m.ritter@EXAMPLE.COM"])

    def test_no_account_refused(self):
        with self.assertRaises(IdentityError):
            self.resolve("ghost@EXAMPLE.COM")

    def test_root_and_multi_component_refused(self):
        for principal in ("root@EXAMPLE.COM", "alice/admin@EXAMPLE.COM", "host/rdp1.example.com@EXAMPLE.COM"):
            with self.subTest(principal=principal), self.assertRaises(IdentityError):
                self.resolve(principal)
        with self.assertRaises(IdentityError):  # localauth mapping to root
            self.resolve("x@EXAMPLE.COM", localname=lambda p: "root")

    def test_unescape(self):
        self.assertEqual(identity.unescape_principal_name("a\\@b.c"), "a@b.c")
        self.assertEqual(identity.unescape_principal_name("a\\/b"), "a/b")


@unittest.skipUnless(ctypes.util.find_library("krb5"), "libkrb5 not installed")
class Krb5LocalnameTests(unittest.TestCase):
    """The real krb5_aname_to_localname() through ctypes, with a throwaway krb5.conf."""

    def test_auth_to_local(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf") as conf:
            conf.write("[libdefaults]\n default_realm = EXAMPLE.COM\n"
                       "[realms]\n EXAMPLE.COM = {\n  auth_to_local_names = {\n"
                       "   m.ritter = mritter\n  }\n  auth_to_local = DEFAULT\n }\n")
            conf.flush()
            with mock.patch.dict(os.environ, {"KRB5_CONFIG": conf.name}):
                self.assertEqual(identity.krb5_localname("m.ritter@EXAMPLE.COM"), "mritter")
                self.assertEqual(identity.krb5_localname("alice@EXAMPLE.COM"), "alice")
                self.assertIsNone(identity.krb5_localname("alice@OTHER.ORG"))
                self.assertIsNone(identity.krb5_localname("bad@@"))


class NlaLoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from fastrdp_broker.server import Broker

        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name)  # realms = ["EXAMPLE.COM"]
        self.broker = Broker(self.cfg)
        self.ensure = mock.AsyncMock(return_value=Target("127.0.0.1", 3390, "u", "t", "", "tls"))
        for b in self.broker.backends.values():
            b.ensure = self.ensure
        self.nss = FakeNss()
        self.nss.__enter__()
        self.pam = [mock.patch("fastrdp_broker.pamauth.account_ok"),
                    mock.patch("fastrdp_broker.pamauth.authenticate")]
        self.account_ok, self.authenticate = [p.start() for p in self.pam]
        self.cfg.broker.home_read_timeout = 0

    async def asyncTearDown(self):
        for p in self.pam:
            p.stop()
        self.nss.__exit__()
        self.broker.home_pool.shutdown(wait=True)
        self.tmp.cleanup()

    async def nla(self, user, principal, password="pw"):
        msg = {"op": "login", "session_id": "s", "method": "nla", "user": user,
               "principal": principal, "password": password}
        reply = await self.broker.login(msg)
        req = self.ensure.call_args.args[0]
        return reply["user"], req.password

    async def test_upn_with_other_local_part(self):
        # mstsc: typed UPN, AD ticket for the sAMAccountName. Password kept (same account).
        self.assertEqual(await self.nla("marcel.ritter@corp.example.com", "mritter@EXAMPLE.COM"),
                         ("mritter", "pw"))
        self.assertEqual(self.account_ok.call_args.args[1], "mritter")

    async def test_domain_backslash_user(self):
        self.assertEqual(await self.nla("CORP\\mritter", "mritter@EXAMPLE.COM"), ("mritter", "pw"))

    async def test_enterprise_principal(self):
        self.assertEqual(await self.nla("marcel.ritter@corp.example.com",
                                        "marcel.ritter\\@corp.example.com@EXAMPLE.COM"),
                         ("mritter", "pw"))

    async def test_unknown_credssp_name_is_informational(self):
        self.assertEqual(await self.nla("whoever@nowhere.example", "mritter@EXAMPLE.COM"), ("mritter", "pw"))

    async def test_other_account_named_drops_password(self):
        # The client cannot become bob; bob's (or any) password is not used for mritter.
        with self.assertLogs("fastrdp.broker", "WARNING"):
            self.assertEqual(await self.nla("bob", "mritter@EXAMPLE.COM"), ("mritter", None))

    async def test_foreign_realm_refused(self):
        with self.assertRaises(Denied):
            await self.broker.login({"op": "login", "session_id": "s", "method": "nla",
                                     "user": "mritter", "principal": "mritter@EVIL.ORG"})
        self.account_ok.assert_not_called()

    async def test_principal_without_account_refused(self):
        with self.assertRaises(IdentityError):
            await self.broker.login({"op": "login", "session_id": "s", "method": "nla",
                                     "user": "mritter", "principal": "ghost@EXAMPLE.COM"})
        self.ensure.assert_not_called()

    async def test_tls_password_path_unchanged(self):
        # TLS logins still use the typed name, normalised; no principal involved.
        msg = {"op": "login", "session_id": "s", "method": "tls", "user": "CORP\\mritter", "password": "pw"}
        with mock.patch("fastrdp_broker.identity.resolve_principal") as rp:
            reply = await self.broker.login(msg)
            self.assertEqual(reply["user"], "mritter")
            self.assertEqual(self.authenticate.call_args.args[1:3], ("mritter", "pw"))
            msg["user"] = "marcel.ritter@corp.example.com"  # local part only: not an account
            with self.assertRaises(IdentityError):
                await self.broker.login(msg)
            rp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
