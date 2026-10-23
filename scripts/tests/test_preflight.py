# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Static checks of ansible/preflight.yml (make test-setup).

- the bash snippets it runs pass shellcheck (when shellcheck is installed);
- ansible-playbook --syntax-check (when ansible-core is installed);
- its list of required inventory variables matches scripts/fastrdp-setup;
- it contains only read-only modules;
- the KDC proxy and KDC evidence probes with stub tools; the KDC evidence result with
  ansible-playbook on localhost (when ansible-core is installed);
- the Keycloak MFA check against a stub discovery document (ansible-playbook on localhost).
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestPreflightKdcProxy(unittest.TestCase):
    """The KDC proxy probe (fastrdp_web_kdcproxy) with stub apt-cache/dig and local TCP ports."""

    NAME = "Look at the KDC proxy packages and probe the KDCs from the host"

    def setUp(self):
        _play, ts = tasks()
        task = next(t for t in ts if t.get("name") == self.NAME)
        self.cmd = task["ansible.builtin.shell"]["cmd"]
        self.assertEqual(set(task["environment"]), {"REALM", "KDCS", "KPASSWD"})
        self.assertIn("preflight_kdcproxy", task["when"])
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.open = f"127.0.0.1:{self.listener.getsockname()[1]}"
        with socket.socket() as s:      # a port nobody listens on
            s.bind(("127.0.0.1", 0))
            self.closed = f"127.0.0.1:{s.getsockname()[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        stubs = {
            # apt-cache policy <package>
            "apt-cache": 'case " $NOPKG " in *" $2 "*) echo "  Candidate: (none)";; *) echo "  Candidate: 1.0";; esac',
            # dig +short +time=3 +tries=1 SRV <name>: "<prio> <weight> <port> <target>." lines,
            # from "0_0_<port>_<host>." words in $SRV_KRB / $SRV_KP
            "dig": 'case "$5" in _kerberos.*) v=$SRV_KRB;; _kpasswd.*) v=$SRV_KP;; *) v=;; esac\n'
                   'for w in $v; do echo "${w//_/ }"; done',
        }
        for name, body in stubs.items():
            p = Path(self.tmp.name) / name
            p.write_text(f"#!/bin/bash\n{body}\n")
            p.chmod(0o755)

    def tearDown(self):
        self.listener.close()
        self.tmp.cleanup()

    def run_probe(self, kdcs="", kpasswd="false", nopkg="", srv_krb="", srv_kp=""):
        env = {"PATH": f"{self.tmp.name}:/usr/bin:/bin", "REALM": "lab.example.com", "KDCS": kdcs,
               "KPASSWD": kpasswd, "NOPKG": nopkg, "SRV_KRB": srv_krb, "SRV_KP": srv_kp}
        r = subprocess.run(["bash", "-c", self.cmd], env=env, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.splitlines()

    @staticmethod
    def srv(*hostports):
        return " ".join(f"0_0_{hp.split(':')[1]}_{hp.split(':')[0]}." for hp in hostports)

    def test_listed_kdcs(self):
        out = self.run_probe(kdcs=f"{self.open} {self.closed}")
        self.assertIn(f"INFO KDC {self.open}", out)
        self.assertIn(f"WARN KDC {self.closed} not reachable on TCP", out)
        self.assertFalse([line for line in out if line.startswith("FAIL")], out)
        out = self.run_probe(kdcs=self.closed)
        self.assertIn("FAIL none of the KDCs is reachable on TCP from the host", out)

    def test_packages(self):
        out = self.run_probe(kdcs=self.open, nopkg="gunicorn")
        self.assertEqual([line for line in out if line.startswith("FAIL")],
                         ["FAIL gunicorn not available from the configured APT sources (Ubuntu: universe)"])

    def test_srv_records_and_kpasswd(self):
        out = self.run_probe(kpasswd="true", srv_krb=self.srv(self.open))
        self.assertIn(f"INFO KDC {self.open}", out)
        # no _kpasswd records: port 464 of the KDC hosts
        self.assertIn("WARN kpasswd 127.0.0.1:464 not reachable on TCP (password changes through the proxy)", out)
        out = self.run_probe(kpasswd="true", srv_krb=self.srv(self.open), srv_kp=self.srv(self.open))
        self.assertFalse([line for line in out if not line.startswith("INFO")], out)
        out = self.run_probe()
        self.assertIn("FAIL no _kerberos._tcp.lab.example.com SRV records on the host: set fastrdp_web_kdcproxy_kdcs",
                      out)


STUB_TOOLS = {
    # per host: files <dir>/<DOMAIN>.inst (dpkg status line), .cand (APT candidate), .ldap
    # (samba | windows; missing: ldapsearch fails)
    "dpkg-query": 'f="$(dirname "$0")/$DOMAIN.inst"; [ -r "$f" ] || exit 1; echo "$(cat "$f")"',
    "apt-cache": 'f="$(dirname "$0")/$DOMAIN.cand"; echo "fastrdp-freerdp3:"\n'
                 'if [ -r "$f" ]; then echo "  Candidate: $(cat "$f")"; else echo "  Candidate: (none)"; fi',
    "ldapsearch": 'f="$(dirname "$0")/$DOMAIN.ldap"; [ -r "$f" ] || exit 255; echo "dn:"\n'
                  '[ "$(cat "$f")" = samba ] && echo "vendorName: Samba Team (https://www.samba.org)"; exit 0',
}


def write_stubs(directory, tools=STUB_TOOLS):
    for name, body in tools.items():
        p = Path(directory) / name
        p.write_text(f"#!/bin/bash\n{body}\n")
        p.chmod(0o755)


@unittest.skipIf(yaml is None, "PyYAML not installed")
@unittest.skipUnless(shutil.which("dpkg"), "dpkg not installed (dpkg --compare-versions)")
class TestPreflightKdcEvidence(unittest.TestCase):
    """fastrdp_mfa_kdc_evidence_as_mfa: FreeRDP version and DC software probe (stub tools)."""

    NAME = "Read the FreeRDP version and the DC software (KDC evidence)"

    def setUp(self):
        play, ts = tasks()
        self.task = next(t for t in ts if t.get("name") == self.NAME)
        self.cmd = self.task["ansible.builtin.shell"]["cmd"]
        self.min = str(play["vars"]["preflight_kdc_evidence_min_freerdp"])
        self.tmp = tempfile.TemporaryDirectory()
        self.stubs = Path(self.tmp.name) / "stubs"
        self.stubs.mkdir()
        write_stubs(self.stubs)
        # only these tools: a host without ldapsearch is a PATH without the stub
        self.tools = Path(self.tmp.name) / "tools"
        self.tools.mkdir()
        for tool in ("awk", "cat", "dirname", "dpkg", "grep", "timeout"):
            (self.tools / tool).symlink_to(shutil.which(tool))

    def tearDown(self):
        self.tmp.cleanup()

    def host(self, domain, inst=None, cand=None, ldap=None):
        for ext, value in (("inst", inst), ("cand", cand), ("ldap", ldap)):
            if value is not None:
                (self.stubs / f"{domain}.{ext}").write_text(value + "\n")

    def run_probe(self, method="apt", idp="ipa", domain="lab.example.com", ldapsearch=True):
        stubs = self.stubs
        if not ldapsearch:
            stubs = Path(self.tmp.name) / "stubs-no-ldap"
            stubs.mkdir(exist_ok=True)
            write_stubs(stubs, {k: v for k, v in STUB_TOOLS.items() if k != "ldapsearch"})
            for f in self.stubs.glob(domain + ".*"):
                shutil.copy(f, stubs)
        env = {"PATH": f"{stubs}:{self.tools}", "METHOD": method, "MIN": self.min, "IDP": idp, "DOMAIN": domain}
        r = subprocess.run(["/bin/bash", "-c", self.cmd], env=env, capture_output=True, text=True, timeout=60,
                           check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.splitlines()

    def test_task(self):
        self.assertEqual(set(self.task["environment"]), {"METHOD", "MIN", "IDP", "DOMAIN"})
        self.assertIn("preflight_kdc_evidence", self.task["when"])

    def test_min_version_is_the_freerdp_package_with_patch_0005(self):
        changelog = (REPO / "packaging/freerdp/debian/changelog").read_text()
        entries = re.split(r"\n(?=fastrdp-freerdp3 \()", changelog)
        first = [e for e in entries if "kdc_evidence_as_mfa" in e][-1]
        self.assertEqual(re.match(r"fastrdp-freerdp3 \(([^)]+)\)", first).group(1), self.min)
        self.assertIn("0005-winpr-kerberos-acceptor-keep-the-KDC-evidence", (REPO / "patches/freerdp/series").read_text())

    def test_freerdp_version(self):
        d = "lab.example.com"
        self.host(d, inst=f"install ok installed {self.min}")
        self.assertEqual(self.run_probe(), [f"PASS fastrdp-freerdp3 {self.min} installed"])
        self.host(d, inst="install ok installed 3.32.2-3", cand="3.32.2-5")
        self.assertEqual(self.run_probe(),
                         ["PASS fastrdp-freerdp3 3.32.2-5 available (installed: 3.32.2-3), deploy installs it"])
        self.host(d, cand="3.32.2-3")
        out = self.run_probe()
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("FAIL fastrdp-freerdp3 installed 3.32.2-3, available 3.32.2-3: older than"),
                        out)
        self.assertIn("never reaches the broker", out[0])
        # removed, configuration files left: not installed
        self.host(d, inst=f"deinstall ok config-files {self.min}")
        (self.stubs / f"{d}.cand").unlink()
        out = self.run_probe()
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("WARN fastrdp-freerdp3 neither installed nor in the host's APT sources"), out)
        # build: compiled from this checkout, nothing to read on the host
        self.assertEqual(self.run_probe(method="build"), [])

    def test_dc_software(self):
        self.host("samba.example.com", ldap="samba")
        self.host("win.example.com", ldap="windows")
        self.assertEqual(self.run_probe(method="build", idp="ad", domain="samba.example.com"), ["DC samba"])
        self.assertEqual(self.run_probe(method="build", idp="ad", domain="win.example.com"), ["DC windows"])
        self.assertEqual(self.run_probe(method="build", idp="ad", domain="down.example.com"), ["DC unknown"])
        self.assertEqual(self.run_probe(method="build", idp="ad", domain="win.example.com", ldapsearch=False),
                         ["DC unknown"])
        self.assertEqual(self.run_probe(method="build", idp="ipa", domain="win.example.com"), [])


@unittest.skipIf(yaml is None, "PyYAML not installed")
@unittest.skipUnless(shutil.which("dpkg"), "dpkg not installed (dpkg --compare-versions)")
@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-core not installed")
class TestPreflightKdcEvidenceResult(unittest.TestCase):
    """The 'MFA from KDC evidence' result, run by ansible-playbook on localhost per scenario."""

    TASKS = ("Read the FreeRDP version and the DC software (KDC evidence)", "Result - MFA from KDC evidence")
    BASE = {"fastrdp_realm": "LAB.EXAMPLE.COM", "fastrdp_identity_provider": "ipa", "fastrdp_mfa_mode": "push",
            "fastrdp_install_method": "apt"}

    def run_play(self, hosts, series="0005-winpr-kerberos-acceptor-keep-the-KDC-evidence-from-the-ticket.patch\n",
                 names=None):
        """hosts: name -> (inventory vars, stub files {ext: content}); names: the tasks to run
        (default TASKS). Returns name -> result."""
        play, ts = tasks()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "ansible").mkdir()
            (tmp / "patches/freerdp").mkdir(parents=True)
            (tmp / "patches/freerdp/series").write_text(series)
            stubs = tmp / "stubs"
            stubs.mkdir()
            write_stubs(stubs)
            defaults = {}
            for f in sorted((REPO / "ansible/roles").glob("*/defaults/main.yml")):
                defaults.update(yaml.safe_load(f.read_text()) or {})
            pvars = dict(play["vars"])
            pvars["preflight_role_defaults"] = {k: v for k, v in defaults.items()
                                                if not (isinstance(v, str) and "{{" in v)}
            inv = {}
            for name, (hvars, files) in hosts.items():
                hv = dict(self.BASE, fastrdp_domain=f"{name}.example.com", **hvars)
                hv.update(ansible_connection="local", ansible_python_interpreter="{{ ansible_playbook_python }}")
                inv[name] = hv
                for ext, content in files.items():
                    (stubs / f"{hv['fastrdp_domain']}.{ext}").write_text(content + "\n")
            pb = [{"name": "KDC evidence", "hosts": "rdp_servers", "gather_facts": False, "vars": pvars,
                   "tasks": [{"name": "Start", "ansible.builtin.set_fact": {"preflight_results": []}}]
                   + [t for t in ts if t.get("name") in (names or self.TASKS)]
                   + [{"name": "Save", "delegate_to": "localhost", "ansible.builtin.copy": {
                       "content": "{{ preflight_results | to_json }}", "dest": str(tmp) + "/{{ inventory_hostname }}.json",
                       "mode": "0644"}}]}]
            (tmp / "ansible/pf.yml").write_text(yaml.safe_dump(pb, sort_keys=False))
            (tmp / "hosts.yml").write_text(yaml.safe_dump({"all": {"children": {"rdp_servers": {"hosts": inv}}}}))
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", ANSIBLE_LOCAL_TEMP=str(tmp),
                       ANSIBLE_HOME=str(tmp), ANSIBLE_NOCOLOR="1")
            r = subprocess.run(["ansible-playbook", "-i", str(tmp / "hosts.yml"), str(tmp / "ansible/pf.yml")],
                               capture_output=True, text=True, env=env, timeout=300, check=False)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = {}
            for name in hosts:
                results = json.loads((tmp / f"{name}.json").read_text())
                self.assertEqual(len(results), 1, results)
                out[name] = results[0]
        return out

    def test_scenarios(self):
        new = "install ok installed 3.32.2-4"
        r = self.run_play({
            "off": ({}, {}),
            "ipa": ({"fastrdp_mfa_kdc_evidence_as_mfa": ["ind:pkinit", "ind:passkey"]}, {"inst": new}),
            "old": ({"fastrdp_mfa_kdc_evidence_as_mfa": ["ind:pkinit"]},
                    {"inst": "install ok installed 3.32.2-3", "cand": "3.32.2-3"}),
            "samba": ({"fastrdp_identity_provider": "ad", "fastrdp_realm": "SAMBA.EXAMPLE.COM",
                       "fastrdp_mfa_kdc_evidence_as_mfa": ["sid:S-1-18-3"]}, {"inst": new, "ldap": "samba"}),
            "win": ({"fastrdp_identity_provider": "ad", "fastrdp_realm": "WIN.EXAMPLE.COM",
                     "fastrdp_mfa_kdc_evidence_as_mfa": ["sid:S-1-18-3", "ind:pkinit"]}, {"inst": new, "ldap": "windows"}),
            "whfb": ({"fastrdp_identity_provider": "ad", "fastrdp_realm": "WHFB.EXAMPLE.COM",
                      "fastrdp_mfa_kdc_evidence_as_mfa": ["sid:S-1-18-4"]}, {"inst": new, "ldap": "windows"}),
            "unknown": ({"fastrdp_identity_provider": "ad", "fastrdp_realm": "UNKNOWN.EXAMPLE.COM",
                         "fastrdp_mfa_kdc_evidence_as_mfa": ["sid:S-1-18-4"]}, {"inst": new}),
            "bad": ({"fastrdp_realm": "", "fastrdp_mfa_mode": "none",
                     "fastrdp_mfa_kdc_evidence_as_mfa": ["ind:hardened", "sid:S-1-5-21-1-2-3-513", "pkinit"]},
                    {"inst": new}),
            "string": ({"fastrdp_mfa_kdc_evidence_as_mfa": "ind:pkinit"}, {"inst": new}),
            "build": ({"fastrdp_install_method": "build", "fastrdp_mfa_kdc_evidence_as_mfa": ["ind:pkinit"]}, {}),
        })
        for name, res in r.items():
            self.assertEqual(res["check"], "MFA from KDC evidence", name)
        self.assertEqual((r["off"]["status"], r["off"]["detail"]),
                         ("INFO", "not used (fastrdp_mfa_kdc_evidence_as_mfa empty)"))
        self.assertEqual(r["ipa"]["status"], "PASS", r["ipa"])
        self.assertIn("ind:pkinit or ind:passkey skip the second factor; fastrdp-freerdp3 3.32.2-4 installed",
                      r["ipa"]["detail"])
        self.assertEqual(r["old"]["status"], "FAIL", r["old"])
        self.assertIn("never reaches the broker", r["old"]["detail"])
        self.assertEqual(r["samba"]["status"], "WARN", r["samba"])
        self.assertIn("Samba AD DC: only sid:S-1-18-3 can appear", r["samba"]["detail"])
        self.assertIn("not hardware-bound", r["samba"]["detail"])
        self.assertEqual(r["win"]["status"], "WARN", r["win"])
        self.assertIn("KDC support for PKInit Freshness Extension", r["win"]["detail"])
        self.assertIn("AD KDCs issue no authentication indicators: ind:pkinit never match", r["win"]["detail"])
        self.assertEqual(r["whfb"]["status"], "PASS", r["whfb"])
        self.assertEqual(r["unknown"]["status"], "WARN", r["unknown"])
        self.assertIn("DC software not detected", r["unknown"]["detail"])
        self.assertEqual(r["bad"]["status"], "FAIL", r["bad"])
        for fragment in ("malformed: pkinit", "no second factor: ind:hardened, sid:S-1-5-21-1-2-3-513",
                         "fastrdp_realm is empty", "fastrdp_mfa_mode is none"):
            self.assertIn(fragment, r["bad"]["detail"])
        self.assertEqual(r["string"]["status"], "FAIL", r["string"])
        self.assertIn("must be a list", r["string"]["detail"])
        self.assertEqual(r["build"]["status"], "PASS", r["build"])
        self.assertIn("built from this checkout with patches/freerdp/0005", r["build"]["detail"])

    def test_web_approval_timeouts(self):
        """Same rule as roles/common: approval timeout 10..510, plus the broker's 90 s session
        start at most fastrdp_proxy_broker_timeout (1..600)."""
        web = {"fastrdp_mfa_mode": "web", "fastrdp_web_enabled": True}
        r = self.run_play({
            "fits": (dict(web, fastrdp_mfa_web_approval_timeout=90, fastrdp_proxy_broker_timeout=180), {}),
            "max": (dict(web, fastrdp_mfa_web_approval_timeout=510, fastrdp_proxy_broker_timeout=600), {}),
            "tight": (dict(web, fastrdp_mfa_web_approval_timeout=91, fastrdp_proxy_broker_timeout=180), {}),
            "range": (dict(web, fastrdp_mfa_web_approval_timeout=520, fastrdp_proxy_broker_timeout=600), {}),
            "proxy": (dict(web, fastrdp_proxy_broker_timeout=700), {}),
            "noweb": ({"fastrdp_mfa_mode": "push_or_web", "fastrdp_mfa_web_approval_timeout": 30,
                       "fastrdp_proxy_broker_timeout": 120}, {}),
        }, names=("Result - MFA web approval",))
        self.assertEqual(r["fits"]["status"], "PASS", r["fits"])
        self.assertIn("RDP logins wait up to 90 s", r["fits"]["detail"])
        self.assertEqual(r["max"]["status"], "PASS", r["max"])
        self.assertEqual(r["tight"]["status"], "FAIL", r["tight"])
        self.assertIn("(91 s) + 90 s session start exceeds fastrdp_proxy_broker_timeout (180 s)", r["tight"]["detail"])
        self.assertEqual(r["range"]["status"], "FAIL", r["range"])
        self.assertIn("is not whole seconds 10..510", r["range"]["detail"])
        self.assertEqual(r["proxy"]["status"], "FAIL", r["proxy"])
        self.assertIn("fastrdp_proxy_broker_timeout (700) is not whole seconds 1..600", r["proxy"]["detail"])
        self.assertEqual(r["noweb"]["status"], "FAIL", r["noweb"])
        self.assertIn("fastrdp_web_enabled is false", r["noweb"]["detail"])
        self.assertNotIn("exceeds", r["noweb"]["detail"])

    def test_build_without_patch_0005(self):
        r = self.run_play({"build": ({"fastrdp_install_method": "build",
                                      "fastrdp_mfa_kdc_evidence_as_mfa": ["ind:pkinit"]}, {})},
                          series="0004-winpr-kerberos-U2U-acceptor-answer-with-the-machine-account-TGT.patch\n")
        self.assertEqual(r["build"]["status"], "FAIL", r["build"])
        self.assertIn("has no 0005", r["build"]["detail"])


class StubDiscovery(BaseHTTPRequestHandler):
    """/realms/<realm>/.well-known/openid-configuration with acr_values_supported per realm
    (None: HTTP 500); realms in no_token have no token_endpoint."""
    acr = {}
    no_token = set()

    def log_message(self, *a):
        pass

    def do_GET(self):
        realm = self.path.split("/")[2]
        values = self.acr.get(realm)
        issuer = f"http://127.0.0.1:{self.server.server_port}/realms/{realm}"
        doc = {"issuer": issuer, "acr_values_supported": values}
        if realm not in self.no_token:
            doc["token_endpoint"] = issuer + "/protocol/openid-connect/token"
        body = b"" if values is None else json.dumps(doc).encode()
        self.send_response(500 if values is None else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipIf(yaml is None or not shutil.which("ansible-playbook"), "PyYAML or ansible-core not installed")
class TestPreflightKeycloakMfa(unittest.TestCase):
    """'Keycloak MFA for acr=mfa': discovery's acr_values_supported (realm ACR map + LoA levels of
    the realm's browser flow; Keycloak lists "0", "1" without step-up) and fastrdp_web_passkeys."""

    TASKS = ("Probe the OIDC issuer from the host", "Result - Keycloak MFA for acr=mfa")
    BASE = TestPreflightKdcEvidenceResult.BASE
    run_play = TestPreflightKdcEvidenceResult.run_play

    def test_scenarios(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), StubDiscovery)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        StubDiscovery.acr = {"plain": ["0", "1"], "stepup": ["0", "1", "2"], "realmmap": ["mfa", "0", "1"],
                             "broken": None}

        def web(realm="plain", **kw):
            return ({"fastrdp_web_enabled": True, "fastrdp_mfa_mode": "web",
                     "fastrdp_web_oidc_issuer": f"http://127.0.0.1:{srv.server_port}/realms/{realm}", **kw}, {})
        r = self.run_play({
            "plain": web(),
            "webonly": web(fastrdp_mfa_mode="none"),
            "stepup": web("stepup"),
            "realmmap": web("realmmap"),
            "broken": web("broken"),
            "amr": web(fastrdp_web_required_acr=[], fastrdp_web_required_amr_any=["otp"]),
            "passkeys": web(fastrdp_web_passkeys=True, vault_fastrdp_keycloak_admin_client_secret="s"),
            "adminuser": web(fastrdp_web_passkeys=True, fastrdp_keycloak_admin_user="admin",
                             vault_fastrdp_keycloak_admin_password="pw"),
            "nocreds": web(fastrdp_web_passkeys=True, fastrdp_keycloak_admin_user="admin"),
        })
        for name, res in r.items():
            self.assertEqual(res["check"], "Keycloak MFA for acr=mfa", name)
            self.assertIn("docs/web-access.md#keycloak-setup", res["fix"])
        self.assertEqual(r["plain"]["status"], "WARN", r["plain"])
        self.assertEqual(r["plain"]["detail"],
                         "fastrdp_web_passkeys is false and Keycloak advertises acr_values_supported [0, 1] only "
                         "(no level-2 step in the realm's browser flow; a client policy is not visible here): make "
                         "sure Keycloak enforces MFA for acr=mfa, otherwise every web sign-in and every RDP login "
                         "approval is refused (log: acr '1' does not prove MFA)")
        self.assertEqual(r["webonly"]["status"], "WARN", r["webonly"])
        self.assertIn("otherwise every web sign-in is refused", r["webonly"]["detail"])
        for name in ("stepup", "realmmap"):
            self.assertEqual(r[name]["status"], "PASS", r[name])
            self.assertIn("Keycloak advertises step-up", r[name]["detail"])
        self.assertEqual(r["broken"]["status"], "WARN", r["broken"])
        self.assertIn("cannot read acr_values_supported", r["broken"]["detail"])
        self.assertEqual(r["amr"]["status"], "INFO", r["amr"])
        for name in ("passkeys", "adminuser"):
            self.assertEqual(r[name]["status"], "PASS", r[name])
            self.assertIn("the deployment configures the MFA flow for acr=mfa", r[name]["detail"])
        self.assertEqual(r["nocreds"]["status"], "FAIL", r["nocreds"])
        self.assertIn("needs Keycloak admin credentials", r["nocreds"]["detail"])


@unittest.skipIf(yaml is None or not shutil.which("ansible-playbook"), "PyYAML or ansible-core not installed")
class TestPreflightCodeCheck(unittest.TestCase):
    """'MFA code check (Keycloak)' for code_or_web: discovery of the code check's realm, the
    client secret, the waiting screen, and whether the deployment sets up the flow."""

    TASKS = ("Probe the code check's Keycloak realm from the host", "Result - MFA code check (Keycloak)")
    BASE = TestPreflightKdcEvidenceResult.BASE
    run_play = TestPreflightKdcEvidenceResult.run_play

    def test_scenarios(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), StubDiscovery)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        StubDiscovery.acr = {"web": ["0", "1"], "other": ["0", "1"], "notoken": ["0", "1"], "broken": None}
        StubDiscovery.no_token = {"notoken"}
        self.addCleanup(setattr, StubDiscovery, "no_token", set())
        base = f"http://127.0.0.1:{srv.server_port}/realms/"

        def code(**kw):
            hv = {"fastrdp_web_enabled": True, "fastrdp_mfa_mode": "code_or_web",
                  "fastrdp_web_oidc_issuer": base + "web", "fastrdp_web_passkeys": True,
                  "vault_fastrdp_mfa_keycloak_client_secret": "s"}
            hv.update(kw)
            return ({k: v for k, v in hv.items() if v is not None}, {})
        r = self.run_play({
            "ok": code(),
            "byhand": code(fastrdp_web_passkeys=False),
            "other": code(fastrdp_mfa_keycloak_issuer=base + "other/"),
            "broken": code(fastrdp_mfa_keycloak_issuer=base + "broken"),
            "notoken": code(fastrdp_mfa_keycloak_issuer=base + "notoken"),
            "nosecret": code(vault_fastrdp_mfa_keycloak_client_secret=None),
            "noscreen": code(fastrdp_proxy_waiting_screen=False, fastrdp_mfa_keycloak_ca_src="/nonexistent/ca.pem"),
        })
        for name, res in r.items():
            self.assertEqual(res["check"], "MFA code check (Keycloak)", name)
        self.assertEqual(r["ok"]["status"], "PASS", r["ok"])
        self.assertEqual(r["ok"]["detail"], base + "web discovery ok; client fastrdp-otp-check: the deployment "
                         "sets up its direct grant flow and checks the client")
        self.assertEqual(r["byhand"]["status"], "WARN", r["byhand"])
        self.assertIn("by hand (fastrdp_web_passkeys is false)", r["byhand"]["detail"])
        self.assertEqual(r["other"]["status"], "WARN", r["other"])
        self.assertIn(base + "other discovery ok", r["other"]["detail"])
        self.assertIn("covers only the web gateway realm", r["other"]["detail"])
        self.assertEqual(r["broken"]["status"], "FAIL", r["broken"])
        self.assertIn("discovery answered 500", r["broken"]["detail"])
        self.assertEqual(r["notoken"]["status"], "FAIL", r["notoken"])
        self.assertIn("discovery has no token_endpoint", r["notoken"]["detail"])
        self.assertEqual(r["nosecret"]["status"], "FAIL", r["nosecret"])
        self.assertIn("client secret of fastrdp-otp-check empty", r["nosecret"]["detail"])
        self.assertEqual(r["noscreen"]["status"], "FAIL", r["noscreen"])
        self.assertIn("fastrdp_proxy_waiting_screen is false", r["noscreen"]["detail"])
        self.assertIn("CA file /nonexistent/ca.pem not found", r["noscreen"]["detail"])


if __name__ == "__main__":
    unittest.main()
