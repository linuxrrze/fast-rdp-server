# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Tests for scripts/fastrdp-setup (non-interactive mode; remembered answers interactively).

    python3 -m unittest discover -s scripts/tests      # or: make test-setup

PyYAML (for parsing the output and the role defaults) and ansible-vault are used when
present; without ansible-vault a stub stands in for it.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ROLES = REPO / "ansible" / "roles"

try:
    import yaml
except ImportError:      # plain admin machine
    yaml = None


def load_tool():
    loader = importlib.machinery.SourceFileLoader("fastrdp_setup", str(REPO / "scripts" / "fastrdp-setup"))
    spec = importlib.util.spec_from_loader("fastrdp_setup", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


setup = load_tool()

SECRETS = {
    "join_password": "J0in-Secret!x",
    "privacyidea_service_password": "PI-Service-Secret#7",
    "web_oidc_client_secret": "oidc-Client-Secret-42",
}

LAB = {
    "profile": "lab",
    "hosts": "rdp1.lab.example.com",
    "ssh_user": "admin",
    "identity_provider": "ad",
    "join_password": SECRETS["join_password"],
    "desktops": "xfce",
    "install_method": "build",
}

STUB_VAULT = textwrap.dedent("""\
    #!/usr/bin/env python3
    # ansible-vault stand-in: "encrypt --vault-password-file F --output OUT -"
    import sys
    args = sys.argv[1:]
    assert args[0] == "encrypt" and args[-1] == "-", args
    out = args[args.index("--output") + 1]
    data = sys.stdin.read().encode()
    with open(out, "w") as f:
        f.write("$ANSIBLE_VAULT;1.1;AES256\\n" + data.hex() + "\\n")
""")


def role_defaults():
    merged = {}
    for f in sorted(ROLES.glob("*/defaults/main.yml")):
        merged.update(yaml.safe_load(f.read_text()) or {})
    return merged


def role_corpus():
    files = [p for p in ROLES.rglob("*") if p.is_file()] + [REPO / "ansible" / "site.yml"]
    return "\n".join(p.read_text(errors="replace") for p in files)


class SetupTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fastrdp-setup-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out = self.tmp / "inventories"
        self.pwfile = self.tmp / "vault-pass"
        self.pwfile.write_text("test-vault-password\n")
        self.stub = self.tmp / "ansible-vault-stub"
        self.stub.write_text(STUB_VAULT)
        self.stub.chmod(0o755)
        # PEM files for the production answers
        self.cert = self.tmp / "rdp.crt"
        self.cert.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        self.key = self.tmp / "rdp.key"
        self.key.write_text("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
        self.ca = self.tmp / "pi-ca.pem"
        self.ca.write_text(self.cert.read_text())

    def production(self, **over):
        a = {
            "profile": "production",
            "hosts": ["rdp1.corp.example.com", "rdp2.corp.example.com"],
            "name": "corp",
            "ssh_user": "deploy",
            "become_password": True,
            "identity_provider": "ipa",
            "domain": "corp.example.com",
            "realm": "CORP.EXAMPLE.COM",
            "join_user": "admin",
            "allow_groups": "rdp-users,rdp-admins",
            "desktops": "xfce,gnome,plasma",
            "default_desktop": "gnome",
            "gpu": "nvidia",
            "lan_networks": "10.0.0.0/8, 2001:db8::/32",
            "mfa_mode": "otp_or_push",
            "privacyidea_url": "https://pi.corp.example.com/",
            "privacyidea_realm": "corp",
            "privacyidea_ca": str(self.ca),
            "privacyidea_service_user": "fastrdp-svc",
            "mfa_exempt_groups": ["breakglass"],
            "allow_tls_logins": "yes",
            "web_enabled": True,
            "web_oidc_issuer": "https://sso.corp.example.com/realms/corp",
            "web_oidc_client_id": "fastrdp",
            "install_method": "apt",
            "apt_channel": "stable",
            "apt_key_checksum": "sha256:" + "ab" * 32,
            "tls": "provided",
            "tls_cert": str(self.cert),
            "tls_key": str(self.key),
        }
        a.update(SECRETS)
        a.pop("join_password")       # comes from the environment instead
        a.update(over)
        return a

    def run_tool(self, answers, *extra, env=None, vault=None):
        """Run main() in-process; returns (rc, stdout, stderr)."""
        path = self.tmp / "answers.json"
        path.write_text(json.dumps(answers))
        environ = {k: v for k, v in os.environ.items() if not k.startswith("FASTRDP_")}
        environ["FASTRDP_ANSIBLE_VAULT"] = str(vault or self.stub)
        environ.update(env or {})
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, environ, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = setup.main(["--non-interactive", "--answers", str(path), "--output-dir", str(self.out),
                             "--vault-password-file", str(self.pwfile), *extra])
        return rc, out.getvalue(), err.getvalue()

    def generate(self, answers, *extra, **kw):
        rc, out, err = self.run_tool(answers, *extra, **kw)
        self.assertEqual(rc, 0, err)
        name = answers.get("name") or answers["hosts"].split(".")[0]
        return self.out / name, out

    @staticmethod
    def main_keys(text):
        return re.findall(r"^([A-Za-z_][A-Za-z0-9_]*):", text, re.M)


class TestGeneratedInventory(SetupTestCase):
    def test_lab_files_and_yaml(self):
        inv, _ = self.generate(LAB)
        for f in ("hosts.yml", "group_vars/all/main.yml", "group_vars/all/vault.yml", "setup-answers.json"):
            self.assertTrue((inv / f).is_file(), f)
        if yaml is None:
            self.skipTest("PyYAML not installed")
        hosts = yaml.safe_load((inv / "hosts.yml").read_text())
        group = hosts["all"]["children"]["rdp_servers"]
        self.assertEqual(list(group["hosts"]), ["rdp1.lab.example.com"])
        self.assertEqual(group["vars"], {"ansible_user": "admin"})
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertEqual(main["fastrdp_realm"], "LAB.EXAMPLE.COM")
        self.assertEqual(main["fastrdp_domain"], "lab.example.com")
        # Only what differs from the role defaults (roles/common): a lab with xfce, the
        # default ports and the vault-backed join password needs nothing else.
        for name in ("fastrdp_desktops", "fastrdp_allow_groups", "fastrdp_front_cert_src",
                     "fastrdp_backend_port_range", "fastrdp_default_geometry", "fastrdp_proc_hidepid",
                     "fastrdp_join_password"):
            self.assertNotIn(name, main)
        # build is the role default, so it is not written
        self.assertNotIn("fastrdp_install_method", main)
        self.assertNotIn("fastrdp_web_enabled", main)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_production_yaml(self):
        inv, out = self.generate(self.production(), env={"FASTRDP_JOIN_PASSWORD": "J0in-Secret!x"})
        self.assertEqual(inv.name, "corp")
        hosts = yaml.safe_load((inv / "hosts.yml").read_text())
        self.assertEqual(list(hosts["all"]["children"]["rdp_servers"]["hosts"]),
                         ["rdp1.corp.example.com", "rdp2.corp.example.com"])
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        expect = {
            "fastrdp_identity_provider": "ipa",
            "fastrdp_join_user": "admin",
            "fastrdp_allow_groups": ["rdp-users", "rdp-admins"],
            "fastrdp_desktops": ["xfce", "gnome", "plasma"],
            "fastrdp_default_desktop": "gnome",
            "fastrdp_gpu": "nvidia",
            "fastrdp_lan_networks": ["10.0.0.0/8", "2001:db8::/32"],
            "fastrdp_mfa_mode": "otp_or_push",
            "fastrdp_privacyidea_url": "https://pi.corp.example.com",
            "fastrdp_privacyidea_realm": "corp",
            "fastrdp_privacyidea_ca_src": str(self.ca),
            "fastrdp_privacyidea_service_user": "fastrdp-svc",
            "fastrdp_mfa_exempt_groups": ["breakglass"],
            "fastrdp_web_enabled": True,
            "fastrdp_web_oidc_issuer": "https://sso.corp.example.com/realms/corp",
            "fastrdp_web_oidc_client_id": "fastrdp",
            "fastrdp_install_method": "apt",
            "fastrdp_apt_key_checksum": "sha256:" + "ab" * 32,
            "fastrdp_front_cert_src": str(self.cert),
            "fastrdp_front_key_src": str(self.key),
        }
        for k, v in expect.items():
            self.assertEqual(main.get(k), v, k)
        # equal to the role defaults -> not written
        for k in ("fastrdp_apt_channel", "fastrdp_web_public_url", "fastrdp_web_oidc_ca_src",
                  "fastrdp_ad_gpo_access_control"):
            self.assertNotIn(k, main)
        self.assertIn("--ask-become-pass", out)
        # make needs the sudo prompt flag in ANSIBLE_ARGS (it passes it on to ansible-playbook)
        for target in ("preflight", "deploy"):
            self.assertIn(f"make {target} INVENTORY={self.out / 'corp'} VAULT_PASSWORD_FILE={self.pwfile} ANSIBLE_ARGS=-K", out)
        self.assertNotIn("ansible_become_exe", (self.out / "corp" / "hosts.yml").read_text())   # sudo
        _inv, lab_out = self.generate(LAB)                  # become_password defaults to no
        self.assertIn("make preflight INVENTORY=", lab_out)
        self.assertNotIn("ANSIBLE_ARGS", lab_out)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_fully_qualified_names(self):
        def main(answers, *extra, **kw):
            inv, _ = self.generate(answers, *extra, **kw)
            return yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        env = {"FASTRDP_JOIN_PASSWORD": "J0in-Secret!x"}
        self.assertNotIn("fastrdp_sssd_fully_qualified_names", main(self.production(), env=env))
        self.assertIs(main(self.production(sssd_fully_qualified_names="y"), "--force", env=env)
                      ["fastrdp_sssd_fully_qualified_names"], True)
        self.assertNotIn("fastrdp_sssd_fully_qualified_names", main(LAB))

    def test_only_known_variables(self):
        corpus = role_corpus()
        for answers, env in ((LAB, {}), (self.production(), {"FASTRDP_JOIN_PASSWORD": "x"}),
                             (dict(LAB, identity_provider="none", name="mit", join_password=None), {})):
            answers = {k: v for k, v in answers.items() if v is not None}
            inv, _ = self.generate(answers, "--force", env=env)
            text = (inv / "group_vars/all/main.yml").read_text()
            keys = self.main_keys(text)
            self.assertTrue(keys)
            for k in keys:
                self.assertIn(k, setup.VARIABLE_NAMES, k)
                self.assertRegex(corpus, r"\b" + k + r"\b", f"{k} is not used by any role")
            self.assertEqual(setup.check_known_variables(text), [])
            # every vault_* reference in main.yml is a key the assistant writes to vault.yml
            for ref in re.findall(r"\b(vault_[a-z0-9_]+)", text):
                self.assertIn(ref, setup.VAULT_KEYS.values())
            # hosts.yml carries only connection variables
            hosts_keys = set(re.findall(r"^\s+(ansible_[a-z_]+):", (inv / "hosts.yml").read_text(), re.M))
            self.assertLessEqual(hosts_keys, {"ansible_user", "ansible_connection"})

    def test_vault_keys_are_read_by_inventory_or_roles(self):
        corpus = role_corpus()
        lab_main = (REPO / "ansible/inventories/lab/group_vars/all/main.yml").read_text()
        for key in setup.VAULT_KEYS.values():
            self.assertTrue(re.search(r"\b" + key + r"\b", corpus + lab_main), key)

    def test_only_differences_from_role_defaults(self):
        inv, _ = self.generate(self.production(), env={"FASTRDP_JOIN_PASSWORD": "x"})
        values = setup.variables_for(setup.resolve(json.loads((inv / "setup-answers.json").read_text())
                                                   | SECRETS | {"join_password": "x"}, False))
        text = (inv / "group_vars/all/main.yml").read_text()
        for sec, name, default, _c in setup.VARIABLES:
            if default is setup.REQUIRED:
                if name in values:
                    self.assertIn(f"\n{name}:", text, name)
            elif name in self.main_keys(text):
                self.assertNotEqual(values[name], default, f"{name} equals the role default")

    def test_every_line_commented(self):
        inv, _ = self.generate(LAB)
        lines = (inv / "group_vars/all/main.yml").read_text().splitlines()
        for i, line in enumerate(lines):
            if re.match(r"^fastrdp_", line):
                self.assertTrue(lines[i - 1].startswith("#"), line)
                self.assertRegex(lines[i - 1], r"\((required|default: .*)\)$")

    def test_rerun_from_saved_answers_is_identical(self):
        inv, _ = self.generate(self.production(), env={"FASTRDP_JOIN_PASSWORD": "x"})
        first = (inv / "group_vars/all/main.yml").read_text()
        saved = json.loads((inv / "setup-answers.json").read_text())
        rc, _o, err = self.run_tool(saved, "--force", env={
            "FASTRDP_JOIN_PASSWORD": "x",
            "FASTRDP_PRIVACYIDEA_SERVICE_PASSWORD": "y",
            "FASTRDP_WEB_OIDC_CLIENT_SECRET": "z"})
        self.assertEqual(rc, 0, err)
        self.assertEqual((inv / "group_vars/all/main.yml").read_text(), first)

    def test_print_answers_writes_nothing(self):
        rc, out, err = self.run_tool(LAB, "--print-answers")
        self.assertEqual(rc, 0, err)
        self.assertFalse(self.out.exists())
        self.assertEqual(json.loads(out)["realm"], "LAB.EXAMPLE.COM")
        self.assertNotIn(SECRETS["join_password"], out)


class TestRoleConsistency(unittest.TestCase):
    """The assistant's view of the roles must match the roles."""

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_role_defaults_match(self):
        actual = role_defaults()
        for name, value in setup.ROLE_DEFAULTS.items():
            self.assertIn(name, actual, name)
            self.assertEqual(actual[name], value, name)
        for _s, name, default, _c in setup.VARIABLES:
            if default is setup.REQUIRED:
                # placeholder default that roles/common refuses
                self.assertEqual(actual.get(name), "", f"{name}: REQUIRED needs an empty role default")
            else:
                self.assertIn(name, actual, f"{name} has no role default (roles/common)")
                self.assertEqual(actual.get(name), default, name)

    def test_required_variables_cover_roles(self):
        """Every variable the roles use has a role default, and the assistant's REQUIRED set is
        exactly what roles/common insists on (non-empty checks)."""
        texts = [p.read_text(errors="replace") for p in ROLES.rglob("*") if p.is_file()]
        texts.append((REPO / "ansible/site.yml").read_text())
        used = set(re.findall(r"\bfastrdp_[a-z0-9_]+", "\n".join(texts)))
        defaults = set()
        for f in ROLES.glob("*/defaults/main.yml"):
            defaults |= set(re.findall(r"^(fastrdp_[a-z0-9_]+):", f.read_text(), re.M))
        produced = set()
        for f in list(ROLES.glob("*/tasks/*.yml")) + list(ROLES.glob("*/handlers/*.yml")):
            t = f.read_text()
            produced |= set(re.findall(r"register:\s*(fastrdp_[a-z0-9_]+)", t))
            produced |= set(re.findall(r"^\s+(fastrdp_[a-z0-9_]+):\s", t, re.M))   # set_fact keys
        # python packages, nft table; the error of the Keycloak code check's Deny access step
        not_variables = {"fastrdp_broker", "fastrdp_web", "fastrdp_webgate", "fastrdp_no_otp"}
        self.assertEqual(used - defaults - produced - not_variables, set(),
                         "roles use these without a default; add them to roles/common/defaults")
        checks = (ROLES / "common/tasks/main.yml").read_text()
        empty_defaults = set()
        for f in ROLES.glob("*/defaults/main.yml"):
            empty_defaults |= set(re.findall(r'^(fastrdp_[a-z0-9_]+): ""', f.read_text(), re.M))
        must_be_set = set(re.findall(r"- (fastrdp_[a-z0-9_]+) \| length > 0", checks)) & empty_defaults
        known_required = {n for _s, n, d, _c in setup.VARIABLES if d is setup.REQUIRED}
        self.assertEqual(known_required, must_be_set)

    def test_desktops_match_role(self):
        text = (ROLES / "desktops/defaults/main.yml").read_text()
        block = text.split("fastrdp_desktop_packages:", 1)[1].split("\n# ", 1)[0]
        role_desks = set(re.findall(r"^  ([a-z0-9-]+):", block, re.M))
        self.assertEqual(role_desks, set(setup.ALL_DESKTOPS))


class TestVault(SetupTestCase):
    def assert_no_cleartext(self, inv):
        for f in inv.rglob("*"):
            if f.is_file():
                data = f.read_text(errors="replace")
                for s in SECRETS.values():
                    self.assertNotIn(s, data, f"{s!r} in clear text in {f}")

    def test_stub_vault_encrypts(self):
        inv, out = self.generate(self.production(join_password=SECRETS["join_password"]))
        vault = inv / "group_vars/all/vault.yml"
        self.assertTrue(vault.read_text().startswith("$ANSIBLE_VAULT;"))
        self.assertEqual(stat.S_IMODE(vault.stat().st_mode), 0o600)
        self.assert_no_cleartext(inv)
        for s in SECRETS.values():
            self.assertNotIn(s, out)
        # what went into the vault
        plain = bytes.fromhex(vault.read_text().splitlines()[1]).decode()
        self.assertIn('vault_fastrdp_join_password: "J0in-Secret!x"', plain)
        self.assertIn("vault_fastrdp_privacyidea_service_password", plain)
        self.assertIn("vault_fastrdp_web_oidc_client_secret", plain)
        self.assertFalse(list(inv.rglob(".vault.yml.tmp")))

    @unittest.skipUnless(shutil.which("ansible-vault"), "ansible-vault not installed")
    def test_real_ansible_vault(self):
        a = self.production(join_password=SECRETS["join_password"])
        inv, _ = self.generate(a, vault=shutil.which("ansible-vault"))
        vault = inv / "group_vars/all/vault.yml"
        self.assertTrue(vault.read_text().startswith("$ANSIBLE_VAULT;1.1;AES256"))
        self.assert_no_cleartext(inv)
        r = subprocess.run(["ansible-vault", "view", "--vault-password-file", str(self.pwfile), str(vault)],
                           capture_output=True, text=True, check=True)
        if yaml is not None:
            data = yaml.safe_load(r.stdout)
            self.assertEqual(data, {setup.VAULT_KEYS[k]: v for k, v in SECRETS.items()})

    def test_vault_password_from_environment(self):
        path = self.tmp / "a.json"
        path.write_text(json.dumps(LAB))
        env = {"FASTRDP_ANSIBLE_VAULT": str(self.stub), "FASTRDP_VAULT_PASSWORD": "pw"}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
            rc = setup.main(["--non-interactive", "--answers", str(path), "--output-dir", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "rdp1/group_vars/all/vault.yml").read_text().startswith("$ANSIBLE_VAULT;"))

    def test_missing_ansible_vault_needs_opt_in(self):
        with mock.patch.object(setup, "find_ansible_vault", return_value=None):
            rc, _o, err = self.run_tool(LAB)
            self.assertEqual(rc, 2)
            self.assertIn("ansible-vault not found", err)
            self.assertFalse((self.out / "rdp1/group_vars/all/vault.yml").exists())
            rc, out, err = self.run_tool(LAB, "--plaintext-vault", "--force")
        self.assertEqual(rc, 0, err)
        vault = self.out / "rdp1/group_vars/all/vault.yml"
        self.assertEqual(stat.S_IMODE(vault.stat().st_mode), 0o600)
        self.assertIn("NOT encrypted", out)

    def test_failing_vault_leaves_no_file(self):
        bad = self.tmp / "bad-vault"
        bad.write_text("#!/bin/sh\necho boom >&2\nexit 1\n")
        bad.chmod(0o755)
        rc, _o, err = self.run_tool(LAB, vault=bad)
        self.assertEqual(rc, 2)
        self.assertIn("boom", err)
        self.assertFalse((self.out / "rdp1/group_vars/all/vault.yml").exists())

    def test_no_secrets_no_vault(self):
        a = dict(LAB, identity_provider="none")
        a.pop("join_password")
        inv, out = self.generate(a)
        self.assertFalse((inv / "group_vars/all/vault.yml").exists())
        self.assertNotIn("vault-pass", out)


class TestValidation(SetupTestCase):
    def assert_rejected(self, answers, fragment, *extra):
        rc, _o, err = self.run_tool(answers, *extra)
        self.assertEqual(rc, 2, err)
        self.assertIn(fragment, err)
        self.assertFalse(self.out.exists())

    def test_rejections(self):
        self.assert_rejected(dict(LAB, hosts="rdp1"), "not a fully qualified host name")
        self.assert_rejected(dict(LAB, desktops="xfce,kde"), "unknown desktop 'kde'")
        self.assert_rejected(dict(LAB, desktops="xfce", default_desktop="gnome"), "default desktop must be one of")
        self.assert_rejected(dict(LAB, realm="OTHER.EXAMPLE.COM"), "AD realm is the DNS domain")
        self.assert_rejected(dict(LAB, realm="lab.example.com"), "upper case")
        self.assert_rejected(dict(LAB, gpu="amd"), "choose one of")
        self.assert_rejected(dict(LAB, mfa_mode="otp", privacyidea_url="https://pi.example.com",
                                  allow_tls_logins=False), "needs TLS logins")
        self.assert_rejected(dict(LAB, mfa_mode="push", privacyidea_url="http://pi.example.com"), "use https://")
        self.assert_rejected(dict(LAB, mfa_mode="push"), "privacyidea_url: missing answer")
        self.assert_rejected(dict(LAB, tls="provided", tls_cert="/nonexistent.pem", tls_key=str(self.key)),
                             "does not exist")
        self.assert_rejected(dict(LAB, tls="provided", tls_cert=str(self.key), tls_key=str(self.key)),
                             "not a PEM certificate")
        self.assert_rejected(dict(LAB, install_method="apt", apt_key_checksum="md5:00"), "sha256:<64 hex digits>")
        self.assert_rejected(dict(LAB, name="lab"), "shipped example")
        self.assert_rejected(dict(LAB, lan_networks="10.1.2.3/8"), "invalid network '10.1.2.3/8'")
        self.assert_rejected(dict(LAB, lan_networks=["office"]), "invalid network 'office'")
        self.assert_rejected(dict(LAB, colour="blue"), "unknown answer key(s): colour")
        no_pw = dict(LAB)
        no_pw.pop("join_password")
        self.assert_rejected(no_pw, "FASTRDP_JOIN_PASSWORD")

    def test_become_exe_for_sudo_rs(self):
        inv, _ = self.generate(self.production(become_exe="sudo.ws"),
                               env={"FASTRDP_JOIN_PASSWORD": SECRETS["join_password"]})
        hosts = (inv / "hosts.yml").read_text()
        self.assertIn("ansible_become_exe: sudo.ws", hosts)
        if yaml:
            hv = yaml.safe_load(hosts)["all"]["children"]["rdp_servers"]["vars"]
            self.assertEqual(hv, {"ansible_user": "deploy", "ansible_become_exe": "sudo.ws"})
        rc, _o, err = self.run_tool(self.production(name="x", become_exe="sudo -n"),
                                    env={"FASTRDP_JOIN_PASSWORD": "x"})
        self.assertEqual(rc, 2, err)
        self.assertIn("program name", err)
        # only asked (and used) when sudo needs a password
        inv, _ = self.generate(dict(LAB, name="nopw", become_exe="sudo.ws"))
        self.assertNotIn("ansible_become_exe", (inv / "hosts.yml").read_text())

    def test_existing_inventory_needs_force(self):
        self.generate(LAB)
        rc, _o, err = self.run_tool(LAB)
        self.assertEqual(rc, 2)
        self.assertIn("--force", err)

    def test_existing_inventory_asked_at_once(self):
        # interactive: right after the name, not after all other questions; Enter overwrites,
        # n asks for another name
        given = {k: v for k, v in setup.resolve(dict(LAB), False, env={}).items() if v is not None}
        existing = lambda name: Path("/inv") / name if name == "rdp1" else None
        out = io.StringIO()
        a = setup.resolve(given, True, env={}, stream_in=io.StringIO("\n"), stream_out=out,
                          existing=existing)
        self.assertEqual((a["name"], a.get("_overwrite")), ("rdp1", True))
        self.assertIn("/inv/rdp1 exists. Overwrite its hosts.yml, group_vars/all/main.yml and vault.yml "
                      "(other files stay)? (y/n) [y]: ", out.getvalue())
        a = setup.resolve(given, True, env={}, stream_in=io.StringIO("n\nrdp2\n"),
                          stream_out=io.StringIO(), existing=existing)
        self.assertEqual((a["name"], a.get("_overwrite")), ("rdp2", None))
        # without an inventory of that name, or without the callable (--force): no question
        a = setup.resolve(dict(given, name="rdp3"), True, env={}, stream_in=io.StringIO(""),
                          stream_out=io.StringIO(), existing=existing)
        self.assertEqual(a["name"], "rdp3")
        a = setup.resolve(given, True, env={}, stream_in=io.StringIO(""), stream_out=io.StringIO())
        self.assertNotIn("_overwrite", a)

    def test_relative_paths_become_absolute(self):
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)
        inv, _ = self.generate(dict(LAB, tls="provided", tls_cert="rdp.crt", tls_key="rdp.key"))
        text = (inv / "group_vars/all/main.yml").read_text()
        self.assertIn(f"fastrdp_front_cert_src: {self.cert}", text)

    def test_interactive_reasks_until_valid(self):
        q = next(q for q in setup.QUESTIONS if q.key == "gpu")
        out = io.StringIO()
        value = setup.ask_interactive(q, {}, stream_in=io.StringIO("amd\n\n"), stream_out=out)
        self.assertEqual(value, "auto")          # Enter takes the default after the error
        self.assertIn("choose one of", out.getvalue())

    def test_yaml_scalar_quoting(self):
        self.assertEqual(setup.yaml_scalar("xfce"), "xfce")
        for s in ("yes", "on", "1920x1080", "a: b", "{{ x }}", "", "#x", "x y"):
            q = setup.yaml_scalar(s)
            self.assertTrue(q.startswith('"'), (s, q))
            self.assertEqual(json.loads(q), s)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestMfaAndAudioOptions(SetupTestCase):
    """MFA modes web/push_or_web, web approval settings, KDC evidence and audio."""

    ENV = {"FASTRDP_JOIN_PASSWORD": "x", "FASTRDP_WEB_OIDC_CLIENT_SECRET": "z"}
    WEB = {"web_oidc_issuer": "https://sso.lab.example.com/realms/lab"}

    def main(self, answers):
        inv, _ = self.generate(answers, "--force", env=self.ENV)
        return yaml.safe_load((inv / "group_vars/all/main.yml").read_text())

    def assert_rejected(self, answers, fragment):
        rc, _o, err = self.run_tool(answers, env=self.ENV)
        self.assertEqual(rc, 2, err)
        self.assertIn(fragment, err)

    def test_web_approval(self):
        main = self.main(dict(LAB, mfa_mode="web", **self.WEB))
        self.assertEqual(main["fastrdp_mfa_mode"], "web")
        self.assertIs(main["fastrdp_web_enabled"], True)        # default with web approval
        # no privacyIDEA in mode web; approval settings at their role defaults are not written
        for k in ("fastrdp_privacyidea_url", "fastrdp_mfa_web_approval_timeout",
                  "fastrdp_mfa_web_approval_max_auth_age", "fastrdp_mfa_web_approval_single_pending"):
            self.assertNotIn(k, main)
        # the proxy waits for the approval plus the session start
        need = 90 + setup.SESSION_START_TIMEOUT
        if need > setup.ROLE_DEFAULTS["fastrdp_proxy_broker_timeout"]:
            self.assertEqual(main["fastrdp_proxy_broker_timeout"], need)
        else:
            self.assertNotIn("fastrdp_proxy_broker_timeout", main)
        main = self.main(dict(LAB, mfa_mode="web", mfa_web_approval_timeout="300",
                              mfa_web_approval_max_auth_age=60, mfa_web_approval_single_pending="n", **self.WEB))
        self.assertEqual(main["fastrdp_mfa_web_approval_timeout"], 300)
        self.assertEqual(main["fastrdp_proxy_broker_timeout"], 300 + setup.SESSION_START_TIMEOUT)
        self.assertEqual(main["fastrdp_mfa_web_approval_max_auth_age"], 60)
        self.assertIs(main["fastrdp_mfa_web_approval_single_pending"], False)
        main = self.main(dict(LAB, mfa_mode="web", mfa_web_approval_timeout=510, **self.WEB))
        self.assertEqual(main["fastrdp_proxy_broker_timeout"], 600)        # the proxy's maximum
        # push_or_web: privacyIDEA as for push, plus the approval page
        main = self.main(dict(LAB, mfa_mode="push_or_web", privacyidea_url="https://pi.lab.example.com",
                              privacyidea_service_user="svc", privacyidea_service_password="pw", **self.WEB))
        self.assertEqual(main["fastrdp_privacyidea_url"], "https://pi.lab.example.com")
        self.assertEqual(main["fastrdp_privacyidea_service_user"], "svc")
        self.assertIs(main["fastrdp_web_enabled"], True)
        # other modes: the approval settings are neither asked nor written
        main = self.main(dict(LAB, mfa_mode="push", privacyidea_url="https://pi.lab.example.com",
                              mfa_web_approval_timeout=300))
        self.assertNotIn("fastrdp_mfa_web_approval_timeout", main)
        self.assertNotIn("fastrdp_proxy_broker_timeout", main)

    def test_notifications(self):
        # W1 follow-up: asked with web approval; ntfy's token goes to the vault, its CA is copied
        main = self.main(dict(LAB, mfa_mode="web", **self.WEB))
        for k in ("fastrdp_web_notify_backends", "fastrdp_web_notify_ntfy_url", "fastrdp_web_notify_ntfy_ca_src"):
            self.assertNotIn(k, main)                                   # "none": the role default
        ca = self.tmp / "ntfy-ca.pem"
        ca.write_text(self.cert.read_text())
        inv, out = self.generate(dict(LAB, mfa_mode="code_or_web", notify_backends="both",
                                      notify_ntfy_url="https://ntfy.lab.example.com", notify_ntfy_ca=str(ca),
                                      **self.WEB), "--force",
                                 env=dict(self.ENV, FASTRDP_MFA_KEYCLOAK_CLIENT_SECRET="c",
                                          FASTRDP_WEB_NOTIFY_NTFY_TOKEN="tk_Secret-7"))
        text = (inv / "group_vars/all/main.yml").read_text()
        main = yaml.safe_load(text)
        self.assertEqual((main["fastrdp_web_notify_backends"], main["fastrdp_web_notify_ntfy_url"],
                          main["fastrdp_web_notify_ntfy_ca_src"]),
                         (["ntfy", "webpush"], "https://ntfy.lab.example.com", str(ca)))
        self.assertNotIn("fastrdp_web_notify_ntfy_token", main)        # the role default reads the vault
        self.assertIn('vault_fastrdp_web_notify_ntfy_token: "tk_Secret-7"', self.vault(inv))
        self.assertNotIn("tk_Secret-7", text + (inv / "setup-answers.json").read_text() + out)
        self.assertIn("users turn them on at https://rdp1.lab.example.com/web/notify", out)
        self.assertIn("The ntfy token needs write access to the topics fastrdp-*", out)
        # web push only: no ntfy settings; without a token a note
        main = self.main(dict(LAB, mfa_mode="web", notify_backends=["webpush"], notify_ntfy_url="https://x",
                              **self.WEB))
        self.assertEqual(main["fastrdp_web_notify_backends"], ["webpush"])
        self.assertNotIn("fastrdp_web_notify_ntfy_url", main)
        inv, out = self.generate(dict(LAB, mfa_mode="web", notify_backends="ntfy",
                                      notify_ntfy_url="https://ntfy.sh", **self.WEB), "--force", env=self.ENV)
        self.assertIn("No ntfy token: the ntfy server must let anyone publish", out)
        self.assertNotIn("vault_fastrdp_web_notify_ntfy_token", self.vault(inv))
        # not asked without web approval (push) or without browser access
        main = self.main(dict(LAB, mfa_mode="push", privacyidea_url="https://pi.lab.example.com",
                              web_enabled=True, notify_backends="ntfy", **self.WEB))
        self.assertNotIn("fastrdp_web_notify_backends", main)
        # the prompt shows a remembered answer as "ntfy,webpush"; answers files may give the list
        for value, backends in (("both", ["ntfy", "webpush"]), ("ntfy,webpush", ["ntfy", "webpush"]),
                                (["ntfy", "webpush"], ["ntfy", "webpush"]), ("NTFY", ["ntfy"]), ("none", []),
                                ([], []), ("", [])):
            with self.subTest(value=value):
                self.assertEqual(setup.v_notify_backends(value), backends)

    def test_notification_rejections(self):
        for answers, fragment in (
                ({"notify_backends": "sms"}, "notify_backends: choose one of: none, ntfy, webpush, both"),
                ({"notify_backends": ["webpush", "ntfy"]}, "notify_backends: choose one of"),
                ({"notify_backends": "ntfy"}, "notify_ntfy_url: missing answer"),
                ({"notify_backends": "ntfy", "notify_ntfy_url": "http://ntfy.example.com"}, "notify_ntfy_url"),
                ({"notify_backends": "ntfy", "notify_ntfy_url": "https://ntfy.example.com",
                  "notify_ntfy_ca": "/nonexistent/ca.pem"}, "notify_ntfy_ca: /nonexistent/ca.pem does not exist")):
            with self.subTest(answers=answers):
                self.assert_rejected(dict(LAB, mfa_mode="web", **answers, **self.WEB), fragment)

    def test_web_approval_rejections(self):
        self.assert_rejected(dict(LAB, mfa_mode="web", web_enabled=False),
                             "web_enabled: MFA mode 'web' needs browser access")
        self.assert_rejected(dict(LAB, mfa_mode="push_or_web", **self.WEB), "privacyidea_url: missing answer")
        for value, fragment in (("5", "from 10 to 510"), (511, "from 10 to 510"), ("1m", "from 10 to 510"),
                                (True, "from 10 to 510")):
            with self.subTest(value=value):
                self.assert_rejected(dict(LAB, mfa_mode="web", mfa_web_approval_timeout=value, **self.WEB), fragment)
        self.assert_rejected(dict(LAB, mfa_mode="web", mfa_web_approval_max_auth_age=301, **self.WEB),
                             "from 0 to 300")

    def vault(self, inv):
        return bytes.fromhex((inv / "group_vars/all/vault.yml").read_text().splitlines()[1]).decode()

    def test_keycloak_mfa(self):
        # Field report: web mode without fastrdp_web_passkeys and without a step-up flow in
        # Keycloak refused every sign-in (acr '1'); the assistant never mentioned it.
        inv, out = self.generate(dict(LAB, mfa_mode="web", **self.WEB), "--force", env=self.ENV)
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertNotIn("fastrdp_web_passkeys", main)                  # role default false
        self.assertIn("Make sure Keycloak enforces MFA for acr=mfa (a level-2 step, "
                      "docs/web-access.md#keycloak-setup), otherwise every web sign-in is refused.", out)
        self.assertNotIn("vault_fastrdp_keycloak", self.vault(inv))
        # service-account client (the default login), secret in the vault
        inv, out = self.generate(dict(LAB, mfa_mode="web", web_passkeys="y", keycloak_admin_realm="ops",
                                      keycloak_admin_client_id="fastrdp-admin", **self.WEB), "--force",
                                 env=dict(self.ENV, FASTRDP_KEYCLOAK_ADMIN_CLIENT_SECRET="kc-Secret-9"))
        text = (inv / "group_vars/all/main.yml").read_text()
        main = yaml.safe_load(text)
        self.assertIs(main["fastrdp_web_passkeys"], True)
        self.assertEqual((main["fastrdp_keycloak_admin_realm"], main["fastrdp_keycloak_admin_client_id"]),
                         ("ops", "fastrdp-admin"))
        self.assertNotIn("fastrdp_keycloak_admin_user", main)
        self.assertNotIn("kc-Secret-9", text + (inv / "setup-answers.json").read_text() + out)
        self.assertIn('vault_fastrdp_keycloak_admin_client_secret: "kc-Secret-9"', self.vault(inv))
        self.assertNotIn("Make sure Keycloak enforces MFA", out)
        # admin user instead; realm master is the role default (not written)
        inv, _ = self.generate(dict(LAB, mfa_mode="push_or_web", privacyidea_url="https://pi.lab.example.com",
                                    web_passkeys=True, keycloak_admin_auth="user", keycloak_admin_user="kcadmin",
                                    keycloak_admin_password="kc-Pw-1", **self.WEB), "--force", env=self.ENV)
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertEqual(main["fastrdp_keycloak_admin_user"], "kcadmin")
        for k in ("fastrdp_keycloak_admin_realm", "fastrdp_keycloak_admin_client_id"):
            self.assertNotIn(k, main)
        self.assertIn('vault_fastrdp_keycloak_admin_password: "kc-Pw-1"', self.vault(inv))
        self.assertNotIn("vault_fastrdp_keycloak_admin_client_secret", self.vault(inv))
        # plain browser access (MFA none) asks it too; without browser access nothing is written
        main = self.main(dict(LAB, web_enabled=True, web_passkeys=True, keycloak_admin_auth="user",
                              keycloak_admin_user="kcadmin", keycloak_admin_password="pw", **self.WEB))
        self.assertIs(main["fastrdp_web_passkeys"], True)
        main = self.main(dict(LAB, web_passkeys=True, keycloak_admin_user="kcadmin"))
        self.assertNotIn("fastrdp_web_passkeys", main)
        self.assertNotIn("fastrdp_keycloak_admin_user", main)

    def test_keycloak_account_console(self):
        # W4: opt-in, asked only when Ansible configures Keycloak; the closing notes name the gap
        inv, out = self.generate(dict(LAB, mfa_mode="web", web_passkeys=True, keycloak_admin_auth="user",
                                      keycloak_admin_user="kcadmin", keycloak_admin_password="pw",
                                      keycloak_account_console_mfa="y", **self.WEB), "--force", env=self.ENV)
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertIs(main["fastrdp_keycloak_account_console_mfa"], True)
        self.assertNotIn("Keycloak, enrolment gap", out)
        inv, out = self.generate(dict(LAB, mfa_mode="web", web_passkeys=True, keycloak_admin_auth="user",
                                      keycloak_admin_user="kcadmin", keycloak_admin_password="pw", **self.WEB),
                                 "--force", env=self.ENV)
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertNotIn("fastrdp_keycloak_account_console_mfa", main)   # role default false
        self.assertIn("Keycloak, enrolment gap", out)
        self.assertIn("or answer keycloak_account_console_mfa=y.", out)
        # without web_passkeys the question is not asked, the note points at the manual step
        inv, out = self.generate(dict(LAB, mfa_mode="web", keycloak_account_console_mfa="y", **self.WEB),
                                 "--force", env=self.ENV)
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertNotIn("fastrdp_keycloak_account_console_mfa", main)
        self.assertIn("account-console at the MFA flow (docs/passkeys.md#close-the-enrolment-gap-enrolling-a-factor-needs-mfa).", out)

    def test_keycloak_mfa_rejections(self):
        web = dict(LAB, mfa_mode="web", web_passkeys=True, **self.WEB)
        self.assert_rejected(dict(web, keycloak_admin_client_id="fastrdp-admin"),
                             "keycloak_admin_client_secret: missing answer (or environment variable "
                             "FASTRDP_KEYCLOAK_ADMIN_CLIENT_SECRET)")
        self.assert_rejected(dict(web, keycloak_admin_client_id="fastrdp-admin", keycloak_admin_client_secret=""),
                             "keycloak_admin_client_secret: a value is needed")
        self.assert_rejected(dict(web, keycloak_admin_client_secret="s"), "keycloak_admin_client_id: missing answer")
        self.assert_rejected(dict(web, keycloak_admin_client_id="a b", keycloak_admin_client_secret="s"),
                             "a client id is needed")
        self.assert_rejected(dict(web, keycloak_admin_realm="", keycloak_admin_client_id="c",
                                  keycloak_admin_client_secret="s"), "keycloak_admin_realm: a realm is needed")
        self.assert_rejected(dict(web, keycloak_admin_auth="token"), "choose one of: client, user")
        self.assert_rejected(dict(web, keycloak_admin_auth="user", keycloak_admin_password="pw"),
                             "keycloak_admin_user: missing answer")
        self.assert_rejected(dict(web, keycloak_admin_auth="user", keycloak_admin_user="kcadmin"),
                             "FASTRDP_KEYCLOAK_ADMIN_PASSWORD")
        self.assert_rejected(dict(web, web_passkeys="maybe"), "web_passkeys: answer yes or no")

    def test_keycloak_mfa_help(self):
        qs = {q.key: q for q in setup.QUESTIONS}
        q = qs["web_passkeys"]
        self.assertEqual(q.prompt, "Let Ansible configure Keycloak's MFA flow (incl. passkeys)? (y/n)")
        for fragment in ("only sign-ins that Keycloak marks as MFA (acr=mfa", "fastrdp_web_required_acr",
                         "ACR map (mfa -> 2", "is not enough", "level-2 (MFA) step",
                         "docs/web-access.md#keycloak-setup", "second factor", "registered"):
            self.assertIn(fragment, q.help)
        self.assertFalse(q.default_for({}))      # answers files without the key: as before
        self.assertTrue(q.when({"web_enabled": True}))
        self.assertFalse(q.when({"web_enabled": False}))
        self.assertTrue(q.ask({"profile": "lab"}))
        self.assertIn("otherwise every web sign-in is refused", q.warn({"web_enabled": True, "web_passkeys": False}))
        self.assertIsNone(q.warn({"web_enabled": True, "web_passkeys": True}))
        self.assertFalse(qs["keycloak_admin_client_id"].when({"web_enabled": True, "web_passkeys": False}))
        self.assertTrue(qs["keycloak_admin_client_secret"].secret)
        self.assertTrue(qs["keycloak_admin_password"].secret)
        self.assertNotIn("keycloak_admin_client_secret", setup.REMEMBERED_KEYS)

    def test_keycloak_mfa_interactive(self):
        # every answer given except web_passkeys, which is asked (Enter: the default)
        given = dict(LAB, mfa_mode="web", web_oidc_client_secret="z", name="rdp1", become_password=False,
                     domain="lab.example.com", realm="LAB.EXAMPLE.COM", join_user="Administrator", allow_groups=[],
                     default_desktop="xfce", web_enabled=True, tls="self-signed", **self.WEB)
        given.update({q.key: q.default for q in setup.QUESTIONS if q.key not in given and q.key != "web_passkeys"
                      and q.default is not None and not callable(q.default)})
        out = io.StringIO()
        a = setup.resolve(given, True, env={}, stream_in=io.StringIO("\n"), stream_out=out)
        self.assertIs(a["web_passkeys"], False)
        text = out.getvalue()
        self.assertIn("The web gateway accepts only sign-ins that Keycloak marks as MFA", text)
        self.assertIn("Let Ansible configure Keycloak's MFA flow (incl. passkeys)? (y/n) [n]: ", text)
        self.assertIn("  NOTE: Make sure Keycloak enforces MFA for acr=mfa", text)

    CODE_ENV = dict(ENV, FASTRDP_MFA_KEYCLOAK_CLIENT_SECRET="otp-Secret-7")

    def test_code_or_web(self):
        # the web gateway's realm, flow by hand: only the mode (and browser access) is written
        inv, out = self.generate(dict(LAB, mfa_mode="code_or_web", **self.WEB), "--force", env=self.CODE_ENV)
        text = (inv / "group_vars/all/main.yml").read_text()
        main = yaml.safe_load(text)
        self.assertEqual(main["fastrdp_mfa_mode"], "code_or_web")
        self.assertIs(main["fastrdp_web_enabled"], True)                # default with the approval page
        for k in ("fastrdp_mfa_keycloak_issuer", "fastrdp_mfa_keycloak_client_id",
                  "fastrdp_mfa_keycloak_client_secret", "fastrdp_mfa_keycloak_ca_src", "fastrdp_privacyidea_url"):
            self.assertNotIn(k, main)                                   # role defaults
        self.assertIn('vault_fastrdp_mfa_keycloak_client_secret: "otp-Secret-7"', self.vault(inv))
        self.assertNotIn("otp-Secret-7", text + (inv / "setup-answers.json").read_text() + out)
        for fragment in ("create the client fastrdp-otp-check from docs/examples/keycloak-fastrdp-otp-check-client.json",
                         "brute force detection on", "reusable token off",
                         "set up the code check's direct grant flow, its amr mapper and the flow binding of the "
                         "client by hand (docs/examples/keycloak-mfa/README.md#code-in-the-rdp-window-code_or_web);",
                         "users need TOTP in Keycloak for the code, or a passkey for the approval page."):
            self.assertIn(fragment, out)
        # web_passkeys: the role sets up the flow in the web gateway's realm
        inv, out = self.generate(dict(LAB, mfa_mode="code_or_web", web_passkeys=True, keycloak_admin_client_id="adm",
                                      mfa_keycloak_client_id="otp", **self.WEB), "--force",
                                 env=dict(self.CODE_ENV, FASTRDP_KEYCLOAK_ADMIN_CLIENT_SECRET="k"))
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertEqual(main["fastrdp_mfa_keycloak_client_id"], "otp")
        self.assertNotIn("fastrdp_mfa_keycloak_issuer", main)
        self.assertIn("create the client otp from", out)
        self.assertNotIn("by hand", out)
        # another realm (production asks): issuer and its CA written, flow by hand anyway
        inv, out = self.generate(self.production(mfa_mode="code_or_web", web_passkeys=True,
                                                 keycloak_admin_client_id="adm",
                                                 mfa_keycloak_issuer="https://otp.corp.example.com/realms/otp/",
                                                 mfa_keycloak_ca=str(self.ca)), "--force",
                                 env=dict(self.CODE_ENV, FASTRDP_KEYCLOAK_ADMIN_CLIENT_SECRET="k"))
        main = yaml.safe_load((inv / "group_vars/all/main.yml").read_text())
        self.assertEqual(main["fastrdp_mfa_keycloak_issuer"], "https://otp.corp.example.com/realms/otp")
        self.assertEqual(main["fastrdp_mfa_keycloak_ca_src"], str(self.ca))
        self.assertNotIn("fastrdp_privacyidea_url", main)
        self.assertIn("flow binding of the client by hand", out)
        # the approval wait applies (it bounds the code checks too)
        main = self.main(dict(LAB, mfa_mode="code_or_web", mfa_web_approval_timeout=300,
                              mfa_keycloak_client_secret="s", **self.WEB))
        self.assertEqual(main["fastrdp_proxy_broker_timeout"], 300 + setup.SESSION_START_TIMEOUT)

    def test_code_or_web_rejections(self):
        code = dict(LAB, mfa_mode="code_or_web", **self.WEB)
        self.assert_rejected(code, "mfa_keycloak_client_secret: missing answer (or environment variable "
                                   "FASTRDP_MFA_KEYCLOAK_CLIENT_SECRET)")
        self.assert_rejected(dict(code, web_enabled=False, mfa_keycloak_client_secret="s"),
                             "web_enabled: MFA mode 'code_or_web' needs browser access")
        self.assert_rejected(dict(code, mfa_keycloak_client_secret="s", mfa_keycloak_client_id="a b"),
                             "a client id is needed")
        for issuer, fragment in (("http://kc.example.com/realms/r", "use https://"),
                                 ("https://kc.example.com/auth", "expected a Keycloak realm URL"),
                                 ("https://kc.example.com/realms/r/extra", "expected a Keycloak realm URL")):
            with self.subTest(issuer=issuer):
                self.assert_rejected(dict(code, mfa_keycloak_client_secret="s", mfa_keycloak_issuer=issuer),
                                     fragment)

    def test_code_or_web_questions(self):
        qs = {q.key: q for q in setup.QUESTIONS}
        self.assertIn("code_or_web", qs["mfa_mode"].prompt)
        self.assertIn("code_or_web  the user types the code from the authenticator app into the RDP window",
                      qs["mfa_mode"].help)
        code = {"mfa_mode": "code_or_web", "web_enabled": True, "web_oidc_issuer": "https://kc/realms/a"}
        for key in ("mfa_keycloak_issuer", "mfa_keycloak_client_id", "mfa_keycloak_client_secret",
                    "mfa_web_approval_timeout"):
            self.assertTrue(qs[key].when(code), key)
            self.assertFalse(qs[key].when({"mfa_mode": "push_or_web"}) and key != "mfa_web_approval_timeout", key)
        self.assertTrue(qs["web_enabled"].default_for(code))
        self.assertEqual(qs["mfa_keycloak_issuer"].default_for(code), "https://kc/realms/a")
        self.assertFalse(qs["mfa_keycloak_issuer"].ask({"profile": "lab"}))
        self.assertTrue(qs["mfa_keycloak_issuer"].ask({"profile": "production"}))
        self.assertFalse(qs["mfa_keycloak_ca"].when(code))
        self.assertTrue(qs["mfa_keycloak_ca"].when(dict(code, mfa_keycloak_issuer="https://kc/realms/b")))
        self.assertTrue(qs["mfa_keycloak_client_secret"].secret)
        self.assertNotIn("mfa_keycloak_client_secret", setup.REMEMBERED_KEYS)
        self.assertIn("code check's direct grant flow", qs["web_passkeys"].warn(dict(code, web_passkeys=False)))
        self.assertIsNone(qs["web_passkeys"].warn(dict(code, web_passkeys=True)))
        self.assertIn("by hand", qs["web_passkeys"].warn(dict(code, web_passkeys=True,
                                                               mfa_keycloak_issuer="https://kc/realms/b")))

    def test_keycloak_issuer_rule_matches_roles_common(self):
        # the assistant's issuer shape is the role's, minus plain http on loopback
        checks = (ROLES / "common/tasks/main.yml").read_text()
        rule = re.search(r"fastrdp_mfa_keycloak_issuer \| string\s+is match\('([^']+)'\)", checks).group(1)
        for issuer in ("https://kc.example.com/realms/r", "https://kc.example.com:8443/auth/realms/r-1",
                       "https://kc.example.com/realms/r/", "https://kc.example.com/realms/r/x",
                       "https://kc.example.com/r", "https://kc_x.example.com/realms/r"):
            with self.subTest(issuer=issuer):
                role_ok = bool(re.match(rule, issuer))
                try:
                    setup.v_keycloak_issuer(issuer)
                    ours = True
                except setup.SetupError:
                    ours = False
                self.assertEqual(ours, role_ok)

    def test_kdc_evidence(self):
        pi = {"mfa_mode": "push", "privacyidea_url": "https://pi.lab.example.com"}
        main = self.main(dict(LAB, mfa_kdc_evidence_as_mfa="sid:S-1-18-4, sid:S-1-5-21-1-2-3-1300 sid:S-1-18-4",
                              **pi))
        self.assertEqual(main["fastrdp_mfa_kdc_evidence_as_mfa"], ["sid:S-1-18-4", "sid:S-1-5-21-1-2-3-1300"])
        main = self.main(dict(LAB, mfa_kdc_evidence_as_mfa=["ind:pkinit", "ind:passkey"], **pi))
        self.assertEqual(main["fastrdp_mfa_kdc_evidence_as_mfa"], ["ind:pkinit", "ind:passkey"])
        self.assertNotIn("fastrdp_mfa_kdc_evidence_as_mfa", self.main(dict(LAB, **pi)))
        # no effect without MFA: not written
        self.assertNotIn("fastrdp_mfa_kdc_evidence_as_mfa", self.main(dict(LAB, mfa_kdc_evidence_as_mfa="ind:pkinit")))
        for item in ("ind:hardened", "sid:S-1-18-1", "sid:S-1-18-2", "sid:S-1-1-0", "sid:S-1-5-11",
                     "sid:S-1-5-32-545", "sid:S-1-5-21-1111-2222-3333-513"):
            with self.subTest(item=item):
                self.assert_rejected(dict(LAB, mfa_kdc_evidence_as_mfa=["ind:pkinit", item], **pi),
                                     "it is no second factor")
        for item in ("pkinit", "sid:X-1-18-4", "SID:S-1-18-4", "sid:S-1-18-4x", "ind:" + "x" * 65):
            with self.subTest(item=item):
                self.assert_rejected(dict(LAB, mfa_kdc_evidence_as_mfa=[item], **pi), "invalid item")

    def test_kdc_evidence_rules_match_roles_common(self):
        checks = (ROLES / "common/tasks/main.yml").read_text()
        block = checks.split("fastrdp_mfa_kdc_evidence_as_mfa | map('string')", 1)[1]
        item = re.search(r"reject\('match', '([^']+)'\)", block).group(1)
        refused = re.search(r"select\('match', '([^']+)'\)", block).group(1)
        self.assertEqual(setup.KDC_EVIDENCE_ITEM_RE.pattern, item)
        self.assertEqual(setup.KDC_EVIDENCE_NOT_MFA_RE.pattern, refused)

    def test_audio(self):
        main = self.main(LAB)
        self.assertNotIn("fastrdp_audio", main)
        self.assertNotIn("fastrdp_audio_input", main)
        main = self.main(dict(LAB, audio_input="n"))
        self.assertIs(main["fastrdp_audio_input"], False)
        self.assertNotIn("fastrdp_audio", main)
        # no audio: the microphone question does not apply
        main = self.main(dict(LAB, audio="no", audio_input="n"))
        self.assertIs(main["fastrdp_audio"], False)
        self.assertNotIn("fastrdp_audio_input", main)

    def test_advanced_questions_only_in_production(self):
        qs = {q.key: q for q in setup.QUESTIONS}
        lab, prod = {"profile": "lab"}, {"profile": "production"}
        for key in ("audio_input", "mfa_kdc_evidence_as_mfa", "mfa_web_approval_timeout",
                    "mfa_web_approval_max_auth_age", "mfa_web_approval_single_pending"):
            self.assertFalse(qs[key].ask(lab), key)
            self.assertTrue(qs[key].ask(prod), key)
        self.assertTrue(qs["audio"].ask(lab))
        web = {"mfa_mode": "web"}
        self.assertTrue(qs["mfa_web_approval_timeout"].when(web))
        self.assertFalse(qs["privacyidea_url"].when(web))
        self.assertTrue(qs["privacyidea_url"].when({"mfa_mode": "push_or_web"}))
        self.assertTrue(qs["web_enabled"].default_for(web))
        self.assertFalse(qs["mfa_kdc_evidence_as_mfa"].when({"mfa_mode": "none"}))


class FakeTTY(io.StringIO):
    """stdin of an interactive run: these lines, then Ctrl-D (or Ctrl-C with interrupt=True)."""

    def __init__(self, lines, interrupt=False):
        super().__init__("".join(line + "\n" for line in lines))
        self.interrupt = interrupt

    def isatty(self):
        return True

    def readline(self, *a):
        line = super().readline(*a)
        if not line and self.interrupt:
            raise KeyboardInterrupt
        return line


class TestRememberedAnswers(SetupTestCase):
    """Interactive answers are saved after every question and offered as defaults next time."""

    def interactive(self, lines, *extra, interrupt=False):
        out, err = io.StringIO(), io.StringIO()
        environ = {k: v for k, v in os.environ.items() if not k.startswith("FASTRDP_")}
        environ["FASTRDP_ANSIBLE_VAULT"] = str(self.stub)
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(setup.sys, "stdin", FakeTTY(lines, interrupt)), \
                mock.patch.object(setup, "probe_apt_repo", return_value=False), \
                mock.patch.object(setup.getpass, "getpass", return_value=SECRETS["join_password"]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = setup.main(["--output-dir", str(self.out), "--vault-password-file", str(self.pwfile), *extra])
        return rc, out.getvalue(), err.getvalue()

    @property
    def memory(self):
        return self.out / setup.LAST_ANSWERS

    def remembered(self):
        return json.loads(self.memory.read_text())

    # profile, hosts, name, ssh_user: then cancelled
    FIRST = ["production", "rdp1.corp.example.com", "corp", "deploy"]

    def test_cancelled_run_keeps_answers(self):
        for interrupt in (True, False):         # Ctrl-C, Ctrl-D
            with self.subTest(interrupt=interrupt):
                shutil.rmtree(self.out, ignore_errors=True)
                rc, _o, err = self.interactive(self.FIRST, interrupt=interrupt)
                self.assertEqual(rc, 130 if interrupt else 2, err)
                self.assertEqual(self.remembered(), {"profile": "production",
                                                     "hosts": ["rdp1.corp.example.com"],
                                                     "name": "corp", "ssh_user": "deploy"})
                self.assertEqual(stat.S_IMODE(self.memory.stat().st_mode), 0o600)
                self.assertFalse((self.out / "corp").exists())     # no inventory yet

    def test_next_run_offers_them_as_defaults(self):
        self.interactive(self.FIRST, interrupt=True)
        rc, _o, err = self.interactive([], interrupt=True)          # only Ctrl-C at the first question
        self.assertEqual(rc, 130)
        self.assertIn("Defaults include your answers from the last run", err)
        self.assertIn("Deployment type (lab / production) [production]:", err)
        rc, _o, err = self.interactive(["", ""], interrupt=True)    # Enter, Enter
        self.assertIn("RDP server(s), fully qualified, comma-separated [rdp1.corp.example.com]:", err)
        self.assertIn("Inventory name (ansible/inventories/<name>) [corp]:", err)
        # answers not reached in this run are kept
        self.assertEqual(self.remembered()["ssh_user"], "deploy")

    def test_complete_run_and_secrets(self):
        lab = ["lab", "rdp1.lab.example.com", "mylab", "admin"]
        rc, _o, err = self.interactive(lab + [""] * 60)
        self.assertEqual(rc, 0, err)
        mem = self.remembered()
        self.assertEqual(mem["hosts"], ["rdp1.lab.example.com"])
        self.assertEqual(mem["identity_provider"], "ad")
        self.assertNotIn("join_password", mem)
        self.assertNotIn(SECRETS["join_password"], self.memory.read_text())
        written = json.loads((self.out / "mylab" / "setup-answers.json").read_text())
        self.assertEqual({k: mem[k] for k in written if k in setup.REMEMBERED_KEYS},
                         {k: v for k, v in written.items() if k in setup.REMEMBERED_KEYS})
        # all defaults now: the same inventory again
        rc, _o, err = self.interactive([""] * 60, "--force")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads((self.out / "mylab" / "setup-answers.json").read_text()), written)
        # without --force: asked right after the name, not at the end; Enter overwrites
        rc, _o, err = self.interactive([""] * 60)
        self.assertEqual(rc, 0, err)
        self.assertIn(f"{self.out / 'mylab'} exists. Overwrite its hosts.yml", err)
        self.assertLess(err.index("exists. Overwrite"), err.index("SSH user on the host(s)"))
        self.assertEqual(json.loads((self.out / "mylab" / "setup-answers.json").read_text()), written)
        # n: another name, the existing inventory stays as it is
        before = (self.out / "mylab" / "hosts.yml").stat().st_mtime_ns
        rc, _o, err = self.interactive(["", "", "", "n", "otherlab"] + [""] * 60)
        self.assertEqual(rc, 0, err)
        self.assertTrue((self.out / "otherlab" / "setup-answers.json").exists())
        self.assertEqual((self.out / "mylab" / "hosts.yml").stat().st_mtime_ns, before)

    def test_fresh_ignores_and_replaces(self):
        self.interactive(self.FIRST, interrupt=True)
        rc, _o, err = self.interactive(["lab"], "--fresh", interrupt=True)
        self.assertNotIn("Defaults include", err)
        self.assertIn("Deployment type (lab / production) [lab]:", err)
        self.assertEqual(self.remembered(), {"profile": "lab"})

    def test_invalid_or_broken_memory(self):
        self.out.mkdir(parents=True)
        self.memory.write_text(json.dumps({"profile": "staging", "join_password": "x", "colour": 1}))
        rc, _o, err = self.interactive([], interrupt=True)
        self.assertIn("Deployment type (lab / production) [lab]:", err)    # invalid: question default
        self.memory.write_text("{not json")
        rc, _o, err = self.interactive([], interrupt=True)
        self.assertEqual(rc, 130)
        self.assertIn("ignoring", err)

    def test_non_interactive_neither_reads_nor_writes(self):
        self.out.mkdir(parents=True)
        self.memory.write_text(json.dumps({"ssh_user": "someone-else"}))
        inv, _ = self.generate(LAB)
        self.assertEqual(json.loads((inv / "setup-answers.json").read_text())["ssh_user"], "admin")
        self.assertEqual(self.remembered(), {"ssh_user": "someone-else"})


if __name__ == "__main__":
    unittest.main()
