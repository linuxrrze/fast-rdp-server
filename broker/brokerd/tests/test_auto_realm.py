# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[auth] realms and domains left out of broker.toml (the packaged default,
packaging/defaults/fastrdp-broker): taken from krb5.conf's default_realm and sssd.conf's
[sssd] domains; explicit values, also empty lists, always win."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from fastrdp_broker import config

REPO = Path(__file__).resolve().parents[3]
PACKAGED = REPO / "packaging/defaults/fastrdp-broker/etc/fastrdp/broker.toml"


class Host(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.krb5 = self.dir / "krb5.conf"
        self.sssd = self.dir / "sssd" / "sssd.conf"
        self.sssd.parent.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))
        return path

    def load(self, toml):
        toml += '\n[desktops.xfce]\nbackend = "xrdp"\nxsession = "xfce"\n'
        broker = self.write(self.dir / "broker.toml", toml)
        return config.load(broker, krb5_conf=self.krb5, sssd_conf=self.sssd)


class Krb5DefaultRealm(Host):
    def test_libdefaults(self):
        self.write(self.krb5, """
            [realms]
            default_realm = NOT.THIS
            [libdefaults]
                dns_lookup_kdc = true
                default_realm = example.com
            """)
        self.assertEqual(config.krb5_default_realm(self.krb5), "EXAMPLE.COM")

    def test_includedir_first_wins(self):
        # as /etc/krb5.conf.d/fastrdp before krb5.conf's own [libdefaults]
        d = self.dir / "krb5.conf.d"
        self.write(d / "fastrdp", "[libdefaults]\n default_realm = SNIPPET.ORG\n")
        self.write(d / "skipped.txt", "[libdefaults]\n default_realm = SKIPPED\n")
        self.write(self.krb5, f"includedir {d}\n[libdefaults]\n default_realm = MAIN.ORG\n")
        self.assertEqual(config.krb5_default_realm(self.krb5), "SNIPPET.ORG")

    def test_include_and_missing(self):
        inc = self.write(self.dir / "inc.conf", "[libdefaults]\ndefault_realm = INC.ORG\n")
        self.write(self.krb5, f"# comment\ninclude {inc}\n")
        self.assertEqual(config.krb5_default_realm(self.krb5), "INC.ORG")
        self.assertIsNone(config.krb5_default_realm(self.dir / "missing"))
        self.write(self.krb5, f"include {self.krb5}\n")  # loop: depth limit
        self.assertIsNone(config.krb5_default_realm(self.krb5))


class SssdDomains(Host):
    def test_domains_conf_d_wins(self):
        self.write(self.sssd, "[sssd]\nservices = nss, pam\ndomains = Example.com, ipa.example.com\n"
                              "[domain/example.com]\ndomains = no\n")
        self.assertEqual(config.sssd_domains(self.sssd), ["example.com", "ipa.example.com"])
        self.write(self.sssd.parent / "conf.d" / "50-x.conf", "[sssd]\ndomains = other.org\n")
        self.assertEqual(config.sssd_domains(self.sssd), ["other.org"])

    def test_unreadable(self):
        self.assertEqual(config.sssd_domains(self.dir / "none" / "sssd.conf"), [])


class Load(Host):
    def test_packaged_default_takes_the_host_values(self):
        self.write(self.krb5, "[libdefaults]\ndefault_realm = EXAMPLE.COM\n")
        self.write(self.sssd, "[sssd]\ndomains = example.com\n")
        cfg = config.load(PACKAGED, krb5_conf=self.krb5, sssd_conf=self.sssd)
        self.assertEqual(cfg.auth.realms, ["EXAMPLE.COM"])
        self.assertEqual(cfg.auth.domains, ["example.com"])
        self.assertEqual(cfg.detected["realms"][0], ["EXAMPLE.COM"])
        self.assertIn("default_realm", cfg.detected["realms"][1])
        self.assertEqual(cfg.default_desktop, "xfce")

    def test_nothing_on_the_host(self):
        cfg = self.load("[auth]\n")
        self.assertEqual(cfg.auth.realms, [])
        self.assertEqual(cfg.auth.domains, [])
        self.assertEqual(set(cfg.detected), {"realms", "domains"})

    def test_explicit_values_win(self):
        self.write(self.krb5, "[libdefaults]\ndefault_realm = EXAMPLE.COM\n")
        self.write(self.sssd, "[sssd]\ndomains = example.com\n")
        cfg = self.load('[auth]\nrealms = []\ndomains = ["ipa.example.org"]')
        self.assertEqual(cfg.auth.realms, [])
        self.assertEqual(cfg.auth.domains, ["ipa.example.org"])
        self.assertEqual(cfg.detected, {})

    def test_no_auth_table(self):
        self.write(self.krb5, "[libdefaults]\ndefault_realm = example.com\n")
        cfg = self.load("")
        self.assertEqual(cfg.auth.realms, ["EXAMPLE.COM"])

    def test_invalid_sssd_domain_names_dropped(self):
        self.write(self.sssd, "[sssd]\ndomains = LDAP, bad name, ok.example\n")
        cfg = self.load("[auth]\n")
        self.assertEqual(cfg.auth.domains, ["ldap", "ok.example"])


if __name__ == "__main__":
    unittest.main()
