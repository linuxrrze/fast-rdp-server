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

    def test_gnome_dconf_database_is_read(self):
        # copy does not create /etc/dconf/db/local.d, and without a user profile naming
        # system-db:local the settings in it are ignored (neither exists on Ubuntu/Debian)
        role = ANSIBLE / "roles" / "gnome_rd"
        tasks = (role / "tasks" / "main.yml").read_text()
        self.assertLess(tasks.index("/etc/dconf/db/local.d]"), tasks.index("dest: /etc/dconf/db/local.d/50-fastrdp"))
        self.assertIn("system-db:local", tasks)
        self.assertIn("dest: /etc/dconf/profile/user", tasks)
        self.assertIn("dconf-cli", (role / "defaults" / "main.yml").read_text())

    def test_restarts_survive_a_failed_run(self):
        # Handlers run at the end of a play and not at all when it fails; the next run finds
        # the files unchanged and never restarts (sssd kept realm join's config: GPO denied).
        self.assertRegex((ANSIBLE / "ansible.cfg").read_text(), r"(?m)^force_handlers = True$")
        self.assertRegex((ANSIBLE / "site.yml").read_text(), r"(?m)^  force_handlers: true\b")
        identity = (ANSIBLE / "roles" / "identity" / "tasks" / "main.yml").read_text()
        self.assertIn("ansible.builtin.meta: flush_handlers", identity)
        self.assertIn("sss_cache -E", (ANSIBLE / "roles" / "identity" / "handlers" / "main.yml").read_text())

    def test_broker_config_validated_before_install(self):
        # a broker.toml the installed broker rejects must never replace the working one
        # (force_handlers would restart into it), and older packages than these roles stop early
        tasks = (ANSIBLE / "roles" / "broker" / "tasks" / "main.yml").read_text()
        self.assertIn("validate: env PYTHONPATH=/usr/lib/fastrdp/python /usr/bin/python3 -m fastrdp_broker"
                      " --check --config %s", tasks)
        self.assertIn("Installed packages are not older than these roles", tasks)
        # ...and the base role upgrades fastrdp packages older than the roles before that
        repo = (ANSIBLE / "roles" / "base" / "tasks" / "apt_repo.yml").read_text()
        self.assertIn("Upgrade fastrdp packages older than these roles", repo)
        self.assertIn("only_upgrade: true", repo)
        # vendored FreeRDP/xrdp: own versions from packaging/*/debian/changelog
        self.assertIn("Upgrade vendored packages older than these roles", repo)
        # the comparison is the script's (tests/ansible/test_outdated_packages.sh), run before and
        # after the upgrade; still older afterwards stops the play here, not in a later role
        self.assertEqual(repo.count("ansible.builtin.script: \"{{ fastrdp_outdated_cmd }}\""), 2)
        self.assertTrue((ANSIBLE / "roles" / "base" / "files" / "fastrdp-outdated-packages.sh").is_file())
        self.assertIn("Installed fastrdp packages are not older than these roles", repo)
        self.assertIn("Versions of these roles are well-formed", repo)
        common = (ANSIBLE / "roles" / "common" / "defaults" / "main.yml").read_text()
        for f in ("packaging/freerdp/debian/changelog", "packaging/xrdp/debian/changelog"):
            self.assertIn(f, common)
        self.assertIn("fastrdp_roles_version:", (ANSIBLE / "roles" / "common" / "defaults" / "main.yml").read_text())
        self.assertNotIn("name: Validate broker configuration", tasks)

    def test_roles_notify_only_their_own_handlers(self):
        # base runs first and the identity role flushes handlers (meta: flush_handlers) before
        # broker/freerdp_proxy/web_gateway install their units; a handler of a later role run
        # from there fails on a host where the unit does not exist yet (0.6.1 deploy failure)
        roles = ANSIBLE / "roles"
        owner = {}
        for f in roles.glob("*/handlers/main.yml"):
            for name in re.findall(r"(?m)^- name: (.+)$", f.read_text()):
                owner[name] = f.parent.parent.name
        for f in sorted(roles.glob("*/tasks/*.yml")):
            role = f.parent.parent.name
            text = f.read_text()
            self.assertNotRegex(text, r"(?m)^\s*notify:\s*$", f"{f}: multi-line notify (not checked)")
            for m in re.finditer(r"(?m)^\s*notify: (.+)$", text):
                value = m.group(1).strip()
                names = [n.strip() for n in value.strip("[]").split(",")] if value.startswith("[") else [value]
                for name in names:
                    self.assertEqual(owner.get(name), role, f"{f}: notify {name!r} is not a {role} handler")
        handlers = (roles / "base" / "handlers" / "main.yml").read_text()
        for name in ("Try-restart fastrdp services after an upgrade",
                     "Try-restart vendored services after an upgrade", "Try-restart fastrdp-proxy"):
            block = handlers.split(f"- name: {name}", 1)[1].split("\n- name:", 1)[0]
            self.assertIn("try-restart", block)
            self.assertIn("failed_when: fastrdp_try_restart.rc not in [0, 5]", block)

    def test_handler_names_unique_across_roles(self):
        # with two handlers of the same name only the last loaded one runs (base's tolerant
        # "Restart fastrdp-proxy" was silently replaced by freerdp_proxy's)
        seen = {}
        for f in sorted((ANSIBLE / "roles").glob("*/handlers/main.yml")):
            for name in re.findall(r"(?m)^- name: (.+)$", f.read_text()):
                self.assertNotIn(name, seen, f"handler {name!r} in {f.parent.parent.name} and {seen.get(name)}")
                seen[name] = f.parent.parent.name

    def test_join_passwords_never_on_a_command_line(self):
        # /proc/<pid>/cmdline is world-readable: join passwords go on stdin or into the
        # environment of the task, never into the command (security review)
        tasks = ANSIBLE / "roles" / "identity" / "tasks"
        ipa = (tasks / "ipa.yml").read_text()
        self.assertNotIn("--password=", ipa)
        self.assertIn('stdin: "{{ fastrdp_join_password }}"', ipa)
        self.assertIn('stdin: "{{ fastrdp_join_password }}"', (tasks / "ad.yml").read_text())
        for f in sorted(tasks.glob("*.yml")):
            for line in f.read_text().splitlines():
                if "fastrdp_join_password" in line:
                    self.assertRegex(line.strip(), r"^(stdin|JOIN_PW|fastrdp_join_password):|^- |^#",
                                     f"{f.name}: {line.strip()}")

    def test_gdm_headless_static_user(self):
        # dbus-daemon (Ubuntu 26.04) drops the unit's DynamicUser client; static gdm user,
        # with the sandboxing DynamicUser implied, and not root (root bypasses GDM's polkit rule)
        tasks = (ANSIBLE / "roles" / "gnome_rd" / "tasks" / "main.yml").read_text()
        for line in ("DynamicUser=no", "User=gdm", "Group=gdm", "ProtectSystem=strict", "ProtectHome=yes",
                     "PrivateTmp=yes"):
            self.assertIn(line, tasks)
        self.assertNotIn("User=root", tasks)
        self.assertIn("gnome-headless-session@.service.d/fastrdp.conf", tasks)
        self.assertIn("daemon_reload: true", (ANSIBLE / "roles" / "gnome_rd" / "handlers" / "main.yml").read_text())

    def test_host_name_defaults(self):
        text = (ANSIBLE / "roles" / "common" / "defaults" / "main.yml").read_text()
        # the inventory name first (reverse DNS can give the bare domain), the fact as fallback
        self.assertRegex(text, r"fastrdp_fqdn: >-\n  \{\{ \(inventory_hostname if inventory_hostname is match\(")
        self.assertIn("else ansible_facts.fqdn) | lower }}", text)
        self.assertIn('fastrdp_hostname: "{{ ansible_facts.hostname }}"', text)


if __name__ == "__main__":
    unittest.main()
