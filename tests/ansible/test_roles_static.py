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

    def test_proxy_logs_to_the_journal(self):
        # WLog's console appender block-buffers stdout in the pipe to journald: late, torn
        # lines (backlog A4). The unit is used by the package and by build installs alike.
        unit = (REPO / "broker" / "session" / "systemd" / "fastrdp-proxy.service").read_text()
        self.assertIn("\nEnvironment=WLOG_APPENDER=JOURNALD\n", unit)
        self.assertIn("\nEnvironment=WLOG_JOURNALD_ID=fastrdp-proxy\n", unit)
        self.assertIn("AF_UNIX", unit)   # sd_journal_stream_fd() connects to journald's socket
        build = (REPO / "third_party" / "build-freerdp.sh").read_text()
        self.assertIn("-DWITH_SYSTEMD=ON", build)
        self.assertNotIn("WITH_LIBSYSTEMD", build)
        self.assertIn("WINPR_HAVE_JOURNALD_H", build)
        series = (REPO / "patches" / "freerdp" / "series").read_text()
        self.assertIn("0009-winpr-wlog-make-WITH_SYSTEMD-reach-config.h-journald-appender.patch", series)

    def test_host_name_defaults(self):
        text = (ANSIBLE / "roles" / "common" / "defaults" / "main.yml").read_text()
        # the inventory name first (reverse DNS can give the bare domain), the fact as fallback
        self.assertRegex(text, r"fastrdp_fqdn: >-\n  \{\{ \(inventory_hostname if inventory_hostname is match\(")
        self.assertIn("else ansible_facts.fqdn) | lower }}", text)
        self.assertIn('fastrdp_hostname: "{{ ansible_facts.hostname }}"', text)

    def test_service_accounts_before_the_broker(self):
        # broker.toml names _fastrdp-proxy and, with [web] enabled, _fastrdp-web; the broker
        # resolves both at start (pwd.getpwnam), so they exist before the broker role runs
        # (0.7.0: a fresh host with the web path had a broker that did not start)
        site = (ANSIBLE / "site.yml").read_text()
        self.assertLess(site.index("- role: base\n"), site.index("- role: broker\n"))
        base = (ANSIBLE / "roles" / "base" / "tasks" / "main.yml").read_text()
        web = (ANSIBLE / "roles" / "web_gateway" / "tasks" / "web.yml").read_text()
        for user, sysusers, when in (("_fastrdp-proxy", "fastrdp-proxy-module", None),
                                     ("_fastrdp-web", "fastrdp-webgate", "fastrdp_web_enabled | bool")):
            with self.subTest(user=user):
                # same account as the package's sysusers.d entry (u NAME - "GECOS" HOME SHELL)
                line = next(x for x in (REPO / "debian" / f"{sysusers}.sysusers").read_text().splitlines()
                            if x.startswith("u "))
                m = re.fullmatch(r'u (\S+) - "([^"]*)" (\S+) (\S+)', line)
                self.assertEqual(m.group(1), user)
                task = (f"  ansible.builtin.user:\n    name: {user}\n    comment: {m.group(2)}\n"
                        f"    system: true\n    shell: {m.group(4)}\n    home: {m.group(3)}\n"
                        "    create_home: false\n")
                self.assertIn(task + (f"  when: {when}\n" if when else ""), base)
        self.assertIn(task, web)          # web_gateway keeps the same account for --tags web
        self.assertIn('gateway_user = "_fastrdp-web"',
                      (ANSIBLE / "roles" / "broker" / "templates" / "broker.toml.j2").read_text())

    def test_xsessions_directory_before_wlroots_entries(self):
        # only the X11 desktops' packages create /usr/share/xsessions; copy does not
        tasks = (ANSIBLE / "roles" / "desktops" / "tasks" / "main.yml").read_text()
        self.assertLess(tasks.index("    path: /usr/share/xsessions\n    state: directory"),
                        tasks.index('dest: "/usr/share/xsessions/fastrdp-{{ item }}.desktop"'))

    def test_web_gateway_removed_when_disabled(self):
        # fastrdp_web_enabled true -> false stops the gateway; a "when" on the role in site.yml
        # would skip the teardown and the role's handlers
        site = (ANSIBLE / "site.yml").read_text()
        entry = site.split("- role: web_gateway", 1)[1].split("\n    - role:", 1)[0]
        self.assertNotIn("when:", entry)
        role = ANSIBLE / "roles" / "web_gateway"
        main = (role / "tasks" / "main.yml").read_text()
        self.assertIn("import_tasks: web.yml\n  when: fastrdp_web_enabled | bool\n", main)
        self.assertIn("import_tasks: web_absent.yml\n  when: not fastrdp_web_enabled | bool\n", main)
        absent = (role / "tasks" / "web_absent.yml").read_text()
        for path in ("/etc/nginx/sites-enabled/fastrdp-web.conf", "/etc/nftables.d/fastrdp-web.nft",
                     '"/etc/containers/systemd/{{ item }}"'):
            self.assertIn(f"    path: {path}\n    state: absent\n", absent)
        self.assertIn("import_tasks: kdcproxy_absent.yml", absent)
        self.assertIn("name: fastrdp-webgate.service\n    state: stopped\n    enabled: false\n", absent)
        # units only if installed: a no-op on hosts that never had the web path
        self.assertEqual(absent.count("in ansible_facts.services"), 2)
        # packages and data stay
        self.assertNotIn("ansible.builtin.apt", absent)
        self.assertNotRegex(absent, r"path: \"?/etc/fastrdp/")
        # the reload copes with nginx stopped or not installed
        handlers = (role / "handlers" / "main.yml").read_text()
        block = handlers.split("- name: Reload nginx\n", 1)[1].split("\n- name:", 1)[0]
        self.assertIn("argv: [systemctl, try-reload-or-restart, nginx.service]", block)
        self.assertIn("failed_when: fastrdp_nginx_reload.rc not in [0, 5]", block)

    def test_restarts_for_changed_certificates(self):
        role = ANSIBLE / "roles" / "web_gateway"
        web = (role / "tasks" / "web.yml").read_text()
        # nginx serves the front certificate the fingerprint is taken from
        self.assertIn("dest: /etc/fastrdp/front.fingerprint", web.split("notify: [Restart fastrdp-webgate, Reload nginx]")[0]
                      .rsplit("- name:", 1)[1])
        # the webgate reads the IdP CA once
        idp = web.split("dest: /etc/fastrdp/webgate-idp-ca.pem", 1)[1].split("\n- name:", 1)[0]
        self.assertIn("notify: Restart fastrdp-webgate", idp)
        # the broker reads the privacyIDEA CA once: its checksum is in broker.toml
        broker = (ANSIBLE / "roles" / "broker" / "tasks" / "main.yml").read_text()
        self.assertLess(broker.index("path: /etc/fastrdp/privacyidea-ca.pem"), broker.index("src: broker.toml.j2"))
        self.assertIn("fastrdp_broker_pi_ca.stat.checksum",
                      (ANSIBLE / "roles" / "broker" / "templates" / "broker.toml.j2").read_text())
        # first start of a container pulls the image
        for quadlet in ("fastrdp-guacd.container.j2", "fastrdp-guacamole.container.j2"):
            text = (role / "templates" / quadlet).read_text()
            self.assertIn("TimeoutStartSec=900\n", text.split("[Service]", 1)[1].split("\n[", 1)[0])


if __name__ == "__main__":
    unittest.main()
