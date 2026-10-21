# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""TERMSRV keytab helpers (broker/sbin, packaged in fastrdp-broker, copied by the
identity role for the build install method): fastrdp-termsrv-check and
fastrdp-termsrv-keytab against fake klist/ktutil/install, and their settings
(options > environment > /etc/fastrdp/termsrv.conf > defaults). No root, no Kerberos.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CHECK = REPO / "broker/sbin/fastrdp-termsrv-check"
KEYTAB = REPO / "broker/sbin/fastrdp-termsrv-keytab"
CONF = REPO / "broker/sbin/termsrv.conf"

KLIST_HEAD = "Keytab name: FILE:{kt}\nKVNO Principal\n---- " + "-" * 60 + "\n"

# Fake "keytabs" are text files, one "KVNO PRINCIPAL ENCTYPE [KEY]" line per entry.
FAKE_KTUTIL = r'''#!/usr/bin/env python3
# ktutil on stdin commands: rkt FILE, list [-k] [-e], delent SLOT (later slots shift up),
# wkt FILE, quit
import sys
entries = []
for line in sys.stdin:
    cmd = line.split()
    if not cmd:
        continue
    if cmd[0] == "rkt":
        entries += [e.split() for e in open(cmd[1]).read().splitlines() if e.strip()]
    elif cmd[0] == "list":
        print("slot KVNO Principal")
        print("---- ---- " + "-" * 60)
        for i, (kvno, princ, enc, *key) in enumerate(entries, 1):
            line = f"{i:4d} {kvno:>4} {princ}"
            if "-e" in cmd:
                line += f" ({enc})"
            if "-k" in cmd:
                line += f"  (0x{key[0] if key else '00'})"
            print(line)
    elif cmd[0] == "delent":
        del entries[int(cmd[1]) - 1]
    elif cmd[0] == "wkt":
        with open(cmd[1], "w") as fh:
            fh.writelines(" ".join(e) + "\n" for e in entries)
'''
FAKE_KLIST = r'''#!/bin/sh
# klist -k FILE / klist -ke FILE on a fake keytab
case $1 in -k|-ke) [ -r "$2" ] || { echo "klist: no such file $2" >&2; exit 1; } ;; *) exit 1 ;; esac
echo "Keytab name: FILE:$2"
echo "KVNO Principal"
echo "---- -----------------------------------------------------------"
while read -r kvno princ enc; do
    if [ "$1" = -ke ]; then echo "   $kvno $princ ($enc)"; else echo "   $kvno $princ"; fi
done < "$2"
'''
FAKE_INSTALL = r'''#!/bin/sh
# install -o OWNER -g GROUP -m MODE SRC DST: logs the call, copies (no chown as non-root)
echo "$*" >> "$FAKE_LOG"
eval "src=\${$(($# - 1))}"; eval "dst=\${$#}"
cp "$src" "$dst"
'''


def tools(tmp):
    """Directory with fake klist, ktutil, install first in PATH."""
    bin_dir = Path(tmp) / "bin"
    bin_dir.mkdir()
    for name, text in (("ktutil", FAKE_KTUTIL), ("klist", FAKE_KLIST), ("install", FAKE_INSTALL)):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    return bin_dir


class TermsrvKeytabCheck(unittest.TestCase):
    """fastrdp-termsrv-check: AES key per TERMSRV principal at its newest kvno (klist -ke)."""

    def run_check(self, entries, *principals, args=None, env=None, conf=None):
        """conf: text of the settings file ({kt} = the test keytab)."""
        with tempfile.TemporaryDirectory() as tmp:
            kt = Path(tmp) / "termsrv.keytab"
            if conf is not None:
                (Path(tmp) / "termsrv.conf").write_text(conf.replace("{kt}", str(kt)))
            kt.write_text(KLIST_HEAD.format(kt=kt) + "".join(
                f"{kvno:4d} {p} ({e})\n" for kvno, p, e in entries))
            klist = Path(tmp) / "klist"   # fake klist -ke KEYTAB: prints the "keytab"
            klist.write_text('#!/bin/sh\n[ "$1" = -ke ] && exec cat "$2"\nexit 1\n')
            klist.chmod(0o755)
            e = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}", FASTRDP_TERMSRV_CONF="/nonexistent")
            e.pop("FASTRDP_TERMSRV_KEYTAB", None)
            if conf is not None:
                e["FASTRDP_TERMSRV_CONF"] = str(Path(tmp) / "termsrv.conf")
            e.update(env or {})
            argv = ["-k", str(kt)] if args is None else [a.replace("{kt}", str(kt)) for a in args]
            return subprocess.run([str(CHECK), *argv, *principals], env=e, capture_output=True, text=True)

    FQDN, SHORT = "TERMSRV/rdp1.lab.example.com", "TERMSRV/RDP1"

    def test_aes_for_both(self):
        r = self.run_check([(3, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96"),
                            (3, f"{self.SHORT}@LAB.EXAMPLE.COM", "aes128-cts-hmac-sha1-96"),
                            (3, f"{self.SHORT}@LAB.EXAMPLE.COM", "DEPRECATED:arcfour-hmac")],
                           self.FQDN, "termsrv/rdp1")   # any case, realm optional
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout.count("ok   "), 2)

    def test_rc4_only_fails(self):
        r = self.run_check([(3, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96"),
                            (3, f"{self.SHORT}@LAB.EXAMPLE.COM", "DEPRECATED:arcfour-hmac")],
                           self.FQDN, self.SHORT)
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"FAIL {self.SHORT}: no AES key at kvno 3", r.stdout)
        self.assertIn("msDS-SupportedEncryptionTypes", r.stdout)  # fix hint

    def test_newest_kvno_counts(self):
        # AES only at the old kvno: tickets use the new key, which is RC4.
        r = self.run_check([(2, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96"),
                            (3, f"{self.FQDN}@LAB.EXAMPLE.COM", "arcfour-hmac"),
                            (2, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes128-cts-hmac-sha1-96")], self.FQDN)
        self.assertEqual(r.returncode, 1)
        r = self.run_check([(4, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96"),
                            (3, f"{self.FQDN}@LAB.EXAMPLE.COM", "arcfour-hmac")], self.FQDN)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_missing_principal_and_realm(self):
        entries = [(3, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96"),
                   (3, "host/rdp1.lab.example.com@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96")]
        r = self.run_check(entries, self.FQDN, self.SHORT)
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"FAIL {self.SHORT}: no key in", r.stdout)
        self.assertEqual(self.run_check(entries, f"{self.FQDN}@OTHER.ORG").returncode, 1)
        self.assertEqual(self.run_check(entries, "TERMSRV/rdp1").returncode, 1)  # no prefix match

    def test_unreadable_keytab_and_usage(self):
        r = subprocess.run([str(CHECK), "-k", "/nonexistent", self.FQDN],
                           env=dict(os.environ, PATH="/nonexistent"), capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot read /nonexistent", r.stdout)
        self.assertEqual(subprocess.run([str(CHECK)], capture_output=True).returncode, 2)

    def test_default_keytab_from_settings(self):
        entries = [(3, f"{self.FQDN}@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96")]
        conf = '# FASTRDP_TERMSRV_KEYTAB=/commented/out\nFASTRDP_TERMSRV_KEYTAB = "{kt}"\n'
        r = self.run_check(entries, self.FQDN, args=[], conf=conf)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # the environment wins over the file
        r = self.run_check(entries, self.FQDN, args=[], conf=conf, env={"FASTRDP_TERMSRV_KEYTAB": "/env.keytab"})
        self.assertIn("cannot read /env.keytab", r.stdout)
        r = self.run_check(entries, self.FQDN, args=[])   # built-in default
        self.assertIn("cannot read /etc/fastrdp/termsrv.keytab", r.stdout)


class TermsrvKeytabExtract(unittest.TestCase):
    """fastrdp-termsrv-keytab: the TERMSRV/* entries of the host keytab plus the machine
    account entries with the same keys, root:<group> 0640."""

    # adcli: one key set for the account and all its SPNs (aa.., bb..)
    HOST = [("3", "RDP1$@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96", "aa11"),
            ("3", "TERMSRV/rdp1.lab.example.com@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96", "aa11"),
            ("3", "host/rdp1.lab.example.com@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96", "aa11"),
            ("3", "TERMSRV/RDP1@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96", "aa11"),
            ("3", "RestrictedKrbHost/RDP1@LAB.EXAMPLE.COM", "aes256-cts-hmac-sha1-96", "aa11"),
            ("3", "TERMSRV/RDP1@LAB.EXAMPLE.COM", "aes128-cts-hmac-sha1-96", "bb22"),
            ("3", "RDP1$@LAB.EXAMPLE.COM", "aes128-cts-hmac-sha1-96", "bb22")]
    TERMSRV = ["TERMSRV/rdp1.lab.example.com@LAB.EXAMPLE.COM", "TERMSRV/RDP1@LAB.EXAMPLE.COM",
               "TERMSRV/RDP1@LAB.EXAMPLE.COM"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = tools(self.tmp.name)
        self.log = self.dir / "install.log"
        self.src = self.dir / "krb5.keytab"
        self.src.write_text("".join(" ".join(e) + "\n" for e in self.HOST))
        self.dst = self.dir / "termsrv.keytab"

    def tearDown(self):
        self.tmp.cleanup()

    def run_extract(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("FASTRDP_")}
        e.update(PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_LOG=str(self.log),
                 FASTRDP_TERMSRV_CONF=str(self.dir / "termsrv.conf"))
        e.update(env or {})
        return subprocess.run([str(KEYTAB), *args], env=e, capture_output=True, text=True)

    def written(self, path=None):
        return [line.split()[1] for line in (path or self.dst).read_text().splitlines()]

    def test_termsrv_and_machine_keys(self):
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.written(), ["RDP1$@LAB.EXAMPLE.COM"] + self.TERMSRV + ["RDP1$@LAB.EXAMPLE.COM"])
        self.assertNotIn("note:", r.stderr)
        self.assertEqual(self.log.read_text().split()[:6], ["-o", "root", "-g", "_fastrdp-proxy", "-m", "0640"])
        self.assertTrue(self.log.read_text().strip().endswith(f"{self.dst}.new"))
        self.assertFalse(Path(f"{self.dst}.new").exists())   # renamed into place

    def test_machine_entry_only_with_a_termsrv_key(self):
        # a machine account entry whose key no TERMSRV entry has (other kvno, other key,
        # another account) is not copied: the proxy gets no new key
        self.src.write_text("".join(" ".join(e) + "\n" for e in self.HOST[1:6]) +
                            "2 RDP1$@LAB.EXAMPLE.COM aes256-cts-hmac-sha1-96 aa11\n"
                            "3 RDP1$@LAB.EXAMPLE.COM aes256-cts-hmac-sha1-96 cc33\n"
                            "3 OTHER$@LAB.EXAMPLE.COM aes256-cts-hmac-sha1-96 dd44\n")
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.written(), self.TERMSRV)
        self.assertIn("note: no machine account", r.stderr)   # Windows clients will fail

    def test_without_machine_keys(self):
        r = self.run_extract("-n", "-s", str(self.src), "-d", str(self.dst))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.written(), self.TERMSRV)
        self.assertNotIn("note:", r.stderr)
        (self.dir / "termsrv.conf").write_text("FASTRDP_TERMSRV_KEYTAB_MACHINE=no\n")
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst))
        self.assertEqual(self.written(), self.TERMSRV)
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst),
                             env={"FASTRDP_TERMSRV_KEYTAB_MACHINE": "yes"})   # environment wins
        self.assertEqual(len(self.written()), 5)
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst),
                             env={"FASTRDP_TERMSRV_KEYTAB_MACHINE": "maybe"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("must be yes or no", r.stderr)

    def test_no_termsrv_keys(self):
        self.src.write_text("3 host/rdp1.lab.example.com@LAB.EXAMPLE.COM aes256-cts-hmac-sha1-96 aa11\n"
                            "3 RDP1$@LAB.EXAMPLE.COM aes256-cts-hmac-sha1-96 aa11\n")
        self.dst.write_text("old\n")
        r = self.run_extract("-s", str(self.src), "-d", str(self.dst))
        self.assertEqual(r.returncode, 1)
        self.assertIn("no TERMSRV keys in", r.stderr)
        self.assertEqual(self.dst.read_text(), "old\n")   # the proxy keeps its keytab

    def test_missing_host_keytab(self):
        r = self.run_extract("-s", str(self.dir / "missing"), "-d", str(self.dst))
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"cannot read {self.dir / 'missing'}", r.stderr)
        self.assertFalse(self.dst.exists())

    def test_usage(self):
        self.assertEqual(self.run_extract("-x").returncode, 2)
        self.assertEqual(self.run_extract("extra").returncode, 2)

    def test_settings_precedence(self):
        other = self.dir / "other.keytab"
        (self.dir / "termsrv.conf").write_text(
            f"# FASTRDP_TERMSRV_KEYTAB_GROUP=commented\nFASTRDP_HOST_KEYTAB={self.src}\n"
            f'FASTRDP_TERMSRV_KEYTAB="{self.dst}"\nFASTRDP_TERMSRV_KEYTAB_GROUP = conf-group  \n')
        self.assertEqual(self.run_extract().returncode, 0)   # file only
        self.assertIn("-g conf-group ", self.log.read_text())
        self.assertEqual(len(self.written()), 5)
        r = self.run_extract(env={"FASTRDP_TERMSRV_KEYTAB_GROUP": "env-group",
                                  "FASTRDP_TERMSRV_KEYTAB": str(other)})   # environment wins
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-g env-group ", self.log.read_text().splitlines()[-1])
        self.assertEqual(len(self.written(other)), 5)
        r = self.run_extract("-g", "opt-group", env={"FASTRDP_TERMSRV_KEYTAB_GROUP": "env-group"})
        self.assertIn("-g opt-group ", self.log.read_text().splitlines()[-1])   # option wins

    def test_defaults(self):
        # no settings: reads /etc/krb5.keytab (missing or unreadable here)
        r = self.run_extract()
        if Path("/etc/krb5.keytab").exists():
            self.skipTest("host has /etc/krb5.keytab")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot read /etc/krb5.keytab", r.stderr)


class ShippedSettings(unittest.TestCase):
    def test_termsrv_conf_sets_nothing(self):
        # The packaged conffile only documents the defaults: every setting is commented out.
        lines = [line for line in CONF.read_text().splitlines() if line.strip() and not line.startswith("#")]
        self.assertEqual(lines, [])
        for key in ("FASTRDP_HOST_KEYTAB", "FASTRDP_TERMSRV_KEYTAB", "FASTRDP_TERMSRV_KEYTAB_GROUP",
                    "FASTRDP_TERMSRV_KEYTAB_MACHINE"):
            self.assertIn(f"#{key}=", CONF.read_text())
            self.assertIn(key, KEYTAB.read_text())

    def test_scripts_are_not_templates(self):
        for script in (CHECK, KEYTAB):
            self.assertNotIn("{{", script.read_text())
            self.assertTrue(os.access(script, os.X_OK))


if __name__ == "__main__":
    unittest.main()
