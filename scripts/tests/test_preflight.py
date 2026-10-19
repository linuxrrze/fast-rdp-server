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
        allowed = {"ansible_facts", "ansible_failed_result", "ansible_host", "ansible_check_mode"}
        used = set(re.findall(r"\b(ansible_[a-z0-9_]+)", text))
        self.assertEqual(used - allowed, set())


if __name__ == "__main__":
    unittest.main()
