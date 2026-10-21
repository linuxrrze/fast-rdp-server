# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Static checks of ansible/preflight.yml (make test-setup).

- the bash snippets it runs pass shellcheck (when shellcheck is installed);
- ansible-playbook --syntax-check (when ansible-core is installed);
- its list of required inventory variables matches scripts/fastrdp-setup;
- it contains only read-only modules.
"""

import importlib.machinery
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO / "ansible" / "preflight.yml"

try:
    import yaml
except ImportError:
    yaml = None


def load_setup():
    loader = importlib.machinery.SourceFileLoader("fastrdp_setup_pf", str(REPO / "scripts" / "fastrdp-setup"))
    spec = importlib.util.spec_from_loader("fastrdp_setup_pf", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def tasks():
    play = yaml.safe_load(PLAYBOOK.read_text())[0]
    out = []
    for t in play["tasks"]:
        out.append(t)
        for key in ("block", "rescue", "always"):
            out.extend(t.get(key, []))
    return play, out


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestPreflight(unittest.TestCase):
    def test_shell_snippets_pass_shellcheck(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck not installed")
        _play, ts = tasks()
        snippets = [t["ansible.builtin.shell"]["cmd"] for t in ts if "ansible.builtin.shell" in t]
        self.assertGreaterEqual(len(snippets), 3)
        for i, cmd in enumerate(snippets):
            self.assertNotIn("{{", cmd, "pass values via environment, not Jinja inside shell code")
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
                f.write("#!/bin/bash\n" + cmd)
            try:
                r = subprocess.run(["shellcheck", "-s", "bash", f.name], capture_output=True, text=True,
                                   check=False)
            finally:
                os.unlink(f.name)
            self.assertEqual(r.returncode, 0, f"snippet {i}:\n{cmd}\n{r.stdout}")

    def test_read_only_modules(self):
        play, ts = tasks()
        self.assertIs(play["become"], False)
        allowed = {"ansible.builtin.set_fact", "ansible.builtin.command", "ansible.builtin.shell",
                   "ansible.builtin.uri", "ansible.builtin.stat", "ansible.builtin.debug",
                   "ansible.builtin.assert", "ansible.builtin.service_facts"}
        for t in ts:
            if "block" in t:
                continue
            mods = [k for k in t if k.startswith("ansible.")]
            self.assertEqual(len(mods), 1, t.get("name"))
            self.assertIn(mods[0], allowed, t.get("name"))
            if mods[0] in ("ansible.builtin.command", "ansible.builtin.shell"):
                self.assertIs(t.get("changed_when"), False, t.get("name"))
            if mods[0] == "ansible.builtin.uri":
                self.assertEqual(t[mods[0]].get("method"), "GET", t.get("name"))
            if t.get("become"):
                # only a no-op and stat may run as root
                self.assertIn(mods[0], ("ansible.builtin.command", "ansible.builtin.stat"), t.get("name"))
                if mods[0] == "ansible.builtin.command":
                    self.assertEqual(t[mods[0]], "/usr/bin/true")

    def test_required_vars_match_setup(self):
        setup = load_setup()
        play, _ = tasks()
        expected = {n for _s, n, d, _c in setup.VARIABLES if d is setup.REQUIRED}
        self.assertEqual(set(play["vars"]["preflight_required_vars"]), expected)
        text = PLAYBOOK.read_text()
        # conditionally required: the MFA server and the join password (vault)
        self.assertIn("'fastrdp_privacyidea_url'", text)
        self.assertIn("vault_fastrdp_join_password", text)

    def test_fqdn_rule_matches_common_default(self):
        # preflight checks the name the roles will use: same rule (inventory name if an FQDN)
        common = (REPO / "ansible" / "roles" / "common" / "defaults" / "main.yml").read_text()
        rule = re.search(r"inventory_hostname is match\('([^']+)'\)", common).group(1)
        self.assertIn(f"inventory_hostname is match('{rule}')", PLAYBOOK.read_text())
        fqdn = re.compile(rule)
        for name in ("rdp1.example.com", "RDP1.Example.COM", "a-b.c-d.example"):
            self.assertTrue(fqdn.match(name), name)
        for name in ("localhost", "rdp1", "192.0.2.10", "2001:db8::1", "rdp1.example.com:2222"):
            self.assertFalse(fqdn.match(name), name)

    def test_fallbacks_match_role_defaults(self):
        # scripts/fastrdp-setup leaves out variables equal to their role default, and this play
        # does not load role defaults: every `fastrdp_x | default(...)` must mean what the role does
        defaults = {}
        for f in sorted((REPO / "ansible" / "roles").glob("*/defaults/main.yml")):
            defaults.update(yaml.safe_load(f.read_text()) or {})
        text = PLAYBOOK.read_text()
        checked = 0
        for m in re.finditer(r"\b(fastrdp_[a-z0-9_]+) \| default\(", text):
            name, depth, i = m.group(1), 1, m.end()
            while depth:
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            arg = text[m.end():i - 1].strip()
            if name not in defaults:
                continue
            role = defaults[name]
            with self.subTest(name=name, fallback=arg):
                literal = re.fullmatch(r"'[^']*'|\[[^]]*\]|\d+", arg)
                if isinstance(role, str) and "{{" in role:
                    # templated role default (vault_*, other variables): never a constant here
                    self.assertFalse(literal, f"role default is {role!r}")
                    vault = set(re.findall(r"\bvault_fastrdp_[a-z0-9_]+", role))
                    self.assertTrue(vault <= set(re.findall(r"\bvault_fastrdp_[a-z0-9_]+", arg)),
                                    f"role default is {role!r}")
                elif not literal:
                    pass        # read from preflight_role_defaults, or an equivalent expression
                else:
                    self.assertEqual(yaml.safe_load(arg.replace("'", '"')), role)
                checked += 1
        self.assertGreater(checked, 15)

    def test_syntax_check(self):
        exe = shutil.which("ansible-playbook")
        if not exe:
            self.skipTest("ansible-core not installed")
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "hosts.yml"
            inv.write_text("all:\n  children:\n    rdp_servers:\n      hosts:\n        localhost: {}\n")
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=tmp, ANSIBLE_HOME=tmp)
            r = subprocess.run([exe, "-i", str(inv), "--syntax-check", str(PLAYBOOK)], cwd=PLAYBOOK.parent,
                               capture_output=True, text=True, env=env, check=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_ansible_fact_injection(self):
        # INJECT_FACTS_AS_VARS is deprecated: facts via ansible_facts.* only
        text = PLAYBOOK.read_text()
        allowed = {"ansible_facts", "ansible_failed_result", "ansible_host", "ansible_check_mode",
                   "ansible_become_exe"}   # connection variable (sudo.ws with sudo-rs), not a fact
        used = set(re.findall(r"\b(ansible_[a-z0-9_]+)", text))
        self.assertEqual(used - allowed, set())


if __name__ == "__main__":
    unittest.main()
