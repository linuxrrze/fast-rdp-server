# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Static checks of the roles that need no Ansible (make test-ansible).

- ansible_managed only in templates: ansible-core 2.19+ defines it for the template
  module alone, so `copy: content: "# {{ ansible_managed }}"` fails at deploy time;
- no top-level fact variables (ansible_fqdn, ansible_distribution, ...): with
  INJECT_FACTS_AS_VARS deprecated (removed in ansible-core 2.24) facts are read as
  ansible_facts.* (host names through fastrdp_fqdn / fastrdp_hostname from common).
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ANSIBLE = REPO / "ansible"
# ansible_* names that are not injected facts
ALLOWED = {"ansible_facts", "ansible_managed", "ansible_check_mode", "ansible_failed_result",
           "ansible_host", "ansible_user", "ansible_become_exe", "ansible_play_hosts"}


def role_files():
    files = sorted(p for p in (ANSIBLE / "roles").rglob("*") if p.is_file() and p.suffix in (".yml", ".j2"))
    return files + [ANSIBLE / "site.yml"]


class RolesStatic(unittest.TestCase):
    def test_ansible_managed_only_in_templates(self):
        for p in role_files():
            if p.suffix == ".j2":
                continue
            with self.subTest(file=str(p.relative_to(REPO))):
                self.assertNotIn("ansible_managed", p.read_text())

    def test_no_top_level_facts(self):
        for p in role_files():
            used = set(re.findall(r"\b(ansible_[a-z0-9_]+)", p.read_text())) - ALLOWED
            with self.subTest(file=str(p.relative_to(REPO))):
                self.assertEqual(used, set(), "use ansible_facts.<name> (or fastrdp_fqdn / fastrdp_hostname)")

    def test_host_name_defaults(self):
        text = (ANSIBLE / "roles" / "common" / "defaults" / "main.yml").read_text()
        self.assertIn('fastrdp_fqdn: "{{ ansible_facts.fqdn }}"', text)
        self.assertIn('fastrdp_hostname: "{{ ansible_facts.hostname }}"', text)


if __name__ == "__main__":
    unittest.main()
