# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Role templates render to valid configuration with the expected values.

Renders render.yml through ansible-playbook (the real Jinja2 + filters), then parses
the results: gfx.toml/broker.toml/webgate.toml with tomllib, broker.toml and
webgate.toml also with the daemons' own config parsers, the INI files with
configparser. Skipped without ansible-playbook unless FASTRDP_TESTS_STRICT=1.
"""

import configparser
import ctypes
import ctypes.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path[:0] = [str(REPO / "broker/brokerd"), str(REPO / "broker/webgate")]

from fastrdp_broker import config as broker_config  # noqa: E402
from fastrdp_webgate import config as webgate_config  # noqa: E402

OUT: Path | None = None
_tmp: tempfile.TemporaryDirectory | None = None


def setUpModule():
    global OUT, _tmp
    playbook = shutil.which("ansible-playbook")
    if not playbook:
        if os.environ.get("FASTRDP_TESTS_STRICT") == "1":
            raise RuntimeError("ansible-playbook not found")
        raise unittest.SkipTest("ansible-playbook not found")
    _tmp = tempfile.TemporaryDirectory(prefix="fastrdp-render.")
    OUT = Path(_tmp.name)
    env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_INVENTORY_UNPARSED_WARNING="false",
               ANSIBLE_NOCOLOR="1", ANSIBLE_PYTHON_INTERPRETER=sys.executable)
    env.pop("ANSIBLE_CONFIG", None)  # cwd (tests/ansible) has no ansible.cfg: built-in defaults
    res = subprocess.run([playbook, "-i", "localhost,", str(HERE / "render.yml"), "-e", f"render_out={OUT}"],
                         env=env, capture_output=True, text=True, cwd=HERE)
    if res.returncode != 0:
        raise RuntimeError(f"render.yml failed:\n{res.stdout[-4000:]}\n{res.stderr[-2000:]}")


def tearDownModule():
    if _tmp:
        _tmp.cleanup()


def toml(name):
    with open(OUT / name, "rb") as fh:
        return tomllib.load(fh)


def ini(name, strict=True):
    """strict: no duplicate keys (sesman.ini repeats [Xorg] param= on purpose)."""
    cp = configparser.ConfigParser(interpolation=None, strict=strict, comment_prefixes=(";", "#"))
    cp.optionxform = str  # keys are case-sensitive for FreeRDP/xrdp
    cp.read(OUT / name)
    return cp


class GfxToml(unittest.TestCase):
    def check_ffmpeg(self, name, encoder):
        g = toml(name)
        self.assertEqual(g["codec"]["h264_encoder"], "ffmpeg")
        self.assertEqual(g["codec"]["order"], ["H.264", "RFX"])
        self.assertEqual(g["ffmpeg"]["encoder"], encoder)
        self.assertEqual(g["ffmpeg"]["device"], "/dev/dri/renderD128")
        self.assertEqual(g["ffmpeg"]["fallback"], "libx264")
        self.assertEqual(g["ffmpeg"]["default"], {"qp": 23, "gop": 300, "fps_num": 60, "fps_den": 1})
        self.assertEqual(g["ffmpeg"]["wan"], {"bitrate": 12000, "max_bitrate": 15000})
        for profile in ("lan", "wan", "broadband_high", "satellite", "broadband_low", "modem"):
            self.assertIn(profile, g["ffmpeg"])
        self.check_x264(g)

    def check_x264(self, g):
        # the software encoder is always configured (fallback and x264 mode)
        self.assertEqual(g["x264"]["default"]["preset"], "ultrafast")
        self.assertEqual(g["x264"]["default"]["fps_num"], 60)
        self.assertEqual(g["x264"]["default"]["threads"], 2)
        self.assertEqual(g["x264"]["modem"]["vbv_max_bitrate"], 1200)

    def test_explicit_hardware_encoders(self):
        for enc in ("vaapi", "nvenc", "qsv"):
            with self.subTest(enc):
                self.check_ffmpeg(f"gfx-{enc}.toml", f"h264_{enc}")

    def test_auto_follows_the_gpu(self):
        self.check_ffmpeg("gfx-auto-mesa.toml", "h264_vaapi")
        self.check_ffmpeg("gfx-auto-nvidia.toml", "h264_nvenc")

    def test_x264_has_no_ffmpeg_section(self):
        for name in ("gfx-x264.toml", "gfx-auto-none.toml"):
            with self.subTest(name):
                g = toml(name)
                self.assertEqual(g["codec"]["h264_encoder"], "x264")
                self.assertNotIn("ffmpeg", g)
                self.check_x264(g)

    def check_autodetect(self, g, profile, encoders):
        """[<enc>.autodetect] equals the chosen profile ({} for default and lan)."""
        for enc in encoders:
            with self.subTest(enc=enc, profile=profile):
                expect = {} if profile == "default" else g[enc][profile]
                self.assertEqual(g[enc]["autodetect"], expect)

    def test_autodetect_is_wan_by_default(self):
        for name in ("gfx-vaapi.toml", "gfx-nvenc.toml", "gfx-auto-mesa.toml"):
            g = toml(name)
            self.check_autodetect(g, "wan", ("ffmpeg", "x264"))
            self.assertEqual(g["ffmpeg"]["autodetect"], {"bitrate": 12000, "max_bitrate": 15000})
            self.assertEqual(g["x264"]["autodetect"], {"vbv_max_bitrate": 15000, "vbv_buffer_size": 1500})
        for name in ("gfx-x264.toml", "gfx-auto-none.toml", "gfx-minimal.toml"):
            self.check_autodetect(toml(name), "wan", ("x264",))

    def test_autodetect_other_profiles(self):
        g = toml("gfx-vaapi-satellite.toml")
        self.check_autodetect(g, "satellite", ("ffmpeg", "x264"))
        self.assertEqual(g["x264"]["autodetect"]["preset"], "superfast")
        self.assertEqual(g["ffmpeg"]["autodetect"]["bitrate"], 4000)
        g = toml("gfx-x264-modem.toml")
        self.check_autodetect(g, "modem", ("x264",))
        self.assertEqual(g["x264"]["autodetect"]["vbv_max_bitrate"], 1200)
        self.check_autodetect(toml("gfx-vaapi-default.toml"), "default", ("ffmpeg", "x264"))
        self.check_autodetect(toml("gfx-vaapi-lan.toml"), "lan", ("ffmpeg", "x264"))

    def test_profiles_unchanged_by_autodetect_choice(self):
        # the per-type sections come from one table; the choice only fills autodetect
        base = toml("gfx-vaapi.toml")
        for name in ("gfx-vaapi-satellite.toml", "gfx-vaapi-default.toml", "gfx-vaapi-lan.toml"):
            g = toml(name)
            for enc in ("ffmpeg", "x264"):
                self.assertEqual({k: v for k, v in g[enc].items() if k != "autodetect"},
                                 {k: v for k, v in base[enc].items() if k != "autodetect"})
        self.assertEqual(base["x264"]["broadband_low"],
                         {"preset": "veryfast", "vbv_max_bitrate": 1600, "vbv_buffer_size": 66})
        self.assertEqual(base["ffmpeg"]["lan"], {})
        self.assertEqual(base["x264"]["lan"], {})


class XrdpIni(unittest.TestCase):
    def test_xrdp_ini(self):
        x = ini("xrdp.ini")
        self.assertEqual(x["Globals"]["port"], "tcp://127.0.0.1:3390")
        self.assertEqual(x["Globals"]["security_layer"], "tls")
        self.assertEqual(x["Globals"]["require_credentials"], "true")
        self.assertEqual(x["Xorg"]["h264_frame_interval"], "16")  # 1000 / 60 fps
        self.assertEqual(x["Xorg"]["lib"], "libxup.so")

    def test_sesman_ini(self):
        s = ini("sesman.ini", strict=False)
        self.assertEqual(s["Sessions"]["MaxSessions"], "100")
        self.assertEqual(s["Sessions"]["DisconnectedTimeLimit"], "1800")  # minutes -> seconds

    def test_xorg_conf_glamor(self):
        text = (OUT / "xorg.conf").read_text()
        self.assertIn('Option "DRMDevice" "/dev/dri/renderD128"', text)
        self.assertIn("with glamor", text)


class ProxyIni(unittest.TestCase):
    def check(self, name, tls_allowed, tls_from="", remote_guard="false"):
        p = ini(name)
        self.assertEqual(p["Server"]["Port"], "3389")
        self.assertEqual(p["Target"]["FixedTarget"], "false")
        # the module pins back-end certificates and refuses to route with another policy
        self.assertEqual(p["Target"]["CertificatePolicy"], "deny")
        self.assertEqual(p["Security"]["ServerNlaSecurity"], "true")
        self.assertEqual(p["Security"]["ServerRdpSecurity"], "false")
        self.assertEqual(p["Security"]["ClientAllowFallbackToTls"], "false")
        self.assertEqual(p["Security"]["ServerTlsSecurity"], tls_allowed)
        self.assertEqual(p["FastRDP"]["AllowTls"], tls_allowed)
        # TLS logins from anywhere only when they are wanted; for the web path alone,
        # guacd on loopback (fastrdp_plugin.c tls_peer_allowed)
        self.assertEqual(p["FastRDP"]["AllowTlsFrom"], tls_from)
        self.assertEqual(p["Plugins"]["Modules"], "fastrdp")
        self.assertEqual(p["Plugins"]["Required"], "fastrdp")
        self.assertEqual(p["FastRDP"]["BrokerSocket"], "/run/fastrdp/broker.sock")
        self.assertEqual(p["FastRDP"]["Timeout"], "120")
        self.assertEqual(p["Channels"]["PassthroughIsBlacklist"], "true")
        # Remote Credential Guard: off unless fastrdp_accept_remote_guard (fastrdp_plugin.c)
        self.assertEqual(p["FastRDP"]["AcceptRemoteGuard"], remote_guard)

    def test_tls_logins(self):
        self.check("proxy-lab.ini", "true")

    def test_web_needs_tls(self):
        self.check("proxy-web-only.ini", "true", "127.0.0.1,::1")

    def test_tls_login_sources_override(self):
        self.check("proxy-sources.ini", "true", "127.0.0.1,::1,10.1.2.0/24,2001:db8::/32")

    def test_nla_only(self):
        self.check("proxy-nla-only.ini", "false")

    def test_remote_guard(self):
        self.check("proxy-rcg.ini", "true", remote_guard="true")


class GpuPackages(unittest.TestCase):
    """roles/gpu: GPU-specific packages only for the stack that uses them."""

    def stack(self, name):
        return json.loads((OUT / f"gpu-packages-{name}.json").read_text())

    def test_none_gets_only_software_gl(self):
        # llvmpipe (libgl1-mesa-dri) is the renderer of GPU-less sessions; nothing else
        self.assertEqual(self.stack("none"), {"packages": ["libgl1-mesa-dri"], "virtualgl": False})

    def test_mesa_gets_vaapi_and_vulkan(self):
        pkgs = self.stack("mesa")["packages"]
        self.assertEqual(pkgs[0], "libgl1-mesa-dri")
        for p in ("va-driver-all", "vainfo", "mesa-vulkan-drivers", "vulkan-tools", "mesa-utils"):
            self.assertIn(p, pkgs)
        self.assertFalse(self.stack("mesa")["virtualgl"])

    def test_nvidia_no_mesa_gpu_drivers(self):
        s = self.stack("nvidia")
        self.assertEqual(s["packages"], ["libgl1-mesa-dri", "vulkan-tools", "mesa-utils"])
        self.assertTrue(s["virtualgl"])


class BrokerToml(unittest.TestCase):
    def test_lab_defaults_accepted_by_broker(self):
        cfg = broker_config.parse(toml("broker-lab.toml"))
        self.assertEqual(cfg.auth.realms, ["LAB.EXAMPLE.COM"])
        self.assertEqual(cfg.auth.allow_groups, ["rdp-users"])
        self.assertTrue(cfg.auth.allow_tls_password_login)
        self.assertEqual(cfg.mfa.mode, "none")
        self.assertEqual(cfg.mfa.privacyidea.url, "")
        self.assertEqual(cfg.broker.port_range, (33900, 34899))
        self.assertEqual(cfg.broker.socket_group, "_fastrdp-broker")
        self.assertEqual(sorted(cfg.desktops), ["gnome", "mate", "plasma", "xfce"])
        self.assertEqual(cfg.desktops["xfce"].xsession, "xfce")
        self.assertEqual(cfg.desktops["gnome"].backend, "gnome")
        self.assertEqual(cfg.desktops["plasma"].backend, "plasma")
        self.assertEqual(cfg.default_desktop, "xfce")
        self.assertFalse(cfg.web.enabled)
        self.assertEqual(cfg.backends["xrdp"].port, 3390)
        self.assertEqual(cfg.backends["xrdp"].listener_user, "root")
        self.assertEqual(cfg.broker.session_tgt, "auto")

    def test_nla_kdc_enforced(self):
        self.assertFalse(broker_config.parse(toml("broker-lab.toml")).mfa.nla_kdc_enforced)
        self.assertFalse(broker_config.parse(toml("broker-minimal.toml")).mfa.nla_kdc_enforced)
        cfg = broker_config.parse(toml("broker-kdc.toml"))
        self.assertTrue(cfg.mfa.nla_kdc_enforced)
        self.assertEqual(cfg.mfa.mode, "push")
        self.assertEqual(cfg.auth.realms, ["LAB.EXAMPLE.COM"])

    def test_reconnect_grace(self):
        for name in ("broker-lab.toml", "broker-minimal.toml"):
            mfa = broker_config.parse(toml(name)).mfa
            self.assertEqual((mfa.reconnect_grace, mfa.reconnect_grace_same_address), (0, True), name)
        mfa = broker_config.parse(toml("broker-mfa.toml")).mfa
        self.assertEqual((mfa.reconnect_grace, mfa.reconnect_grace_same_address), (600, False))

    def test_web_approval(self):
        for name in ("broker-lab.toml", "broker-minimal.toml", "broker-mfa.toml"):
            mfa = broker_config.parse(toml(name)).mfa
            self.assertEqual((mfa.web_approval_timeout, mfa.web_approval_max_auth_age,
                              mfa.web_approval_single_pending), (90, 30, True), name)
        web = broker_config.parse(toml("broker-web.toml"))
        self.assertEqual(web.mfa.mode, "web")
        self.assertEqual(web.mfa.privacyidea.url, "")         # web approval alone needs no privacyIDEA
        self.assertTrue(web.web.enabled)
        self.assertEqual((web.mfa.web_approval_timeout, web.mfa.web_approval_max_auth_age,
                          web.mfa.web_approval_single_pending), (75, 0, False))
        both = broker_config.parse(toml("broker-push_or_web.toml")).mfa
        self.assertEqual(both.mode, "push_or_web")
        self.assertEqual(both.privacyidea.url, "https://privacyidea.lab.example.com")

    def test_session_tgt_required(self):
        self.assertEqual(broker_config.parse(toml("broker-tgt-required.toml")).broker.session_tgt, "required")

    def test_session_tgt_groups(self):
        self.assertEqual(broker_config.parse(toml("broker-lab.toml")).broker.session_tgt_groups, {})
        self.assertNotIn("session_tgt_groups", (OUT / "broker-lab.toml").read_text())  # empty: no table
        cfg = broker_config.parse(toml("broker-tgt-groups.toml"))
        self.assertEqual(cfg.broker.session_tgt, "auto")
        self.assertEqual(cfg.broker.session_tgt_groups, {
            "nfs-homes": "required", "kiosk": "off", "domain users@example.com": "auto",
            'grp "quoted"': "required"})
        self.assertEqual(cfg.broker.home_create_roots, ["/home"])  # [broker] keys before the table

    def test_mfa_variant_accepted_by_broker(self):
        cfg = broker_config.parse(toml("broker-mfa.toml"))
        self.assertEqual(cfg.auth.realms, ["LAB.EXAMPLE.COM"])
        self.assertFalse(cfg.auth.allow_tls_password_login)
        self.assertEqual(cfg.mfa.mode, "otp_or_push")
        self.assertEqual(cfg.mfa.exempt_groups, ["rdp-break-glass", "domain admins"])
        self.assertEqual(cfg.mfa.otp_lengths, [6, 8])
        pi = cfg.mfa.privacyidea
        self.assertEqual(pi.url, "https://privacyidea.lab.example.com")
        self.assertEqual(pi.ca_file, "/etc/fastrdp/privacyidea-ca.pem")
        self.assertFalse(pi.verify_tls)
        self.assertEqual(pi.service_user, "pi-service")
        self.assertEqual(cfg.desktops["plasma-x11"].xsession, "plasmax11")
        self.assertEqual(cfg.desktops["sway"].xsession, "fastrdp-sway")
        self.assertEqual(cfg.desktops["sway"].backend, "xrdp")
        self.assertEqual(cfg.default_desktop, "sway")
        self.assertEqual(cfg.default_geometry, "2560x1440")
        self.assertEqual(cfg.group_defaults, {"rdp-kde": "plasma", 'grp "quoted"': "gnome"})
        self.assertTrue(cfg.web.enabled)

    def test_network(self):
        for name in ("broker-lab.toml", "broker-minimal.toml"):
            net = broker_config.parse(toml(name)).network
            self.assertEqual((net.lan, net.xrdp_autodetect_profile), ((), "wan"))
        net = broker_config.parse(toml("broker-mfa.toml")).network
        self.assertEqual([str(n) for n in net.lan], ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"])
        self.assertEqual(net.xrdp_autodetect_profile, "broadband_high")

    def test_desktop_groups_and_labels(self):
        # Regression: per-desktop groups/labels could not be set through Ansible.
        cfg = broker_config.parse(toml("broker-mfa.toml"))
        self.assertEqual(cfg.desktops["plasma"].groups, ["rdp-kde"])
        self.assertEqual(cfg.desktops["gnome"].groups, ["rdp-gnome", "domain users"])
        self.assertEqual(cfg.desktops["sway"].groups, [])
        self.assertEqual(cfg.desktops["sway"].label, "Sway (tiling)")
        self.assertEqual(cfg.desktops["xfce"].label, 'XFCE "light"')

    def test_minimal_inventory(self):
        # Regression: roles used variables that only the lab inventory defined.
        cfg = broker_config.parse(toml("broker-minimal.toml"))
        self.assertEqual(cfg.auth.realms, ["EXAMPLE.COM"])
        self.assertEqual(cfg.auth.allow_groups, [])
        self.assertEqual(list(cfg.desktops), ["xfce"])
        self.assertEqual(cfg.default_desktop, "xfce")
        self.assertEqual(cfg.mfa.mode, "none")
        self.assertEqual(cfg.broker.session_tgt, "auto")
        self.assertEqual(cfg.backends["xrdp"].port, 3390)
        self.assertEqual(ini("proxy-minimal.ini")["Server"]["Port"], "3389")
        self.assertEqual(toml("gfx-minimal.toml")["codec"]["h264_encoder"], "x264")


class ResourceLimits(unittest.TestCase):
    def test_plasma_sessions_get_per_user_limits(self):
        # Regression: krdpserver (Plasma's H.264 encoder) runs in fastrdp-plasma@USER.service,
        # outside user-UID.slice, so the per-user limits did not cover it.
        for unit, section in (("user-.slice", "Slice"), ("fastrdp-plasma@.service", "Service")):
            with self.subTest(unit):
                p = ini(f"limits-{unit}.conf")
                self.assertEqual(p[section]["CPUQuota"], "400%")
                self.assertEqual(p[section]["MemoryMax"], "16G")
                self.assertEqual(p[section]["TasksMax"], "4096")

    def test_xrdp_daemon_aggregate_cap(self):
        p = ini("limits-xrdp.service.conf")
        self.assertEqual(p["Service"]["CPUQuota"], "800%")
        self.assertNotIn("MemoryMax", p["Service"])
        self.assertNotIn("TasksMax", p["Service"])


class SmokeTestPorts(unittest.TestCase):
    """tests/smoke/check-host.sh reads the ports from the deployed configuration."""

    def ports(self, proxy_ini, broker_toml):
        env = dict(os.environ, FASTRDP_PROXY_INI=str(proxy_ini), FASTRDP_BROKER_TOML=str(broker_toml))
        res = subprocess.run([str(REPO / "tests/smoke/check-host.sh"), "--ports"], env=env,
                             capture_output=True, text=True, check=True)
        return res.stdout.strip()

    def test_ports_from_rendered_config(self):
        # Regression: the smoke test hard-coded 3389/3390.
        self.assertEqual(self.ports(OUT / "proxy-ports.ini", OUT / "broker-ports.toml"), "proxy=3399 xrdp=3391")
        self.assertEqual(self.ports(OUT / "proxy-lab.ini", OUT / "broker-lab.toml"), "proxy=3389 xrdp=3390")

    def test_defaults_without_config(self):
        self.assertEqual(self.ports("/nonexistent/proxy.ini", "/nonexistent/broker.toml"), "proxy=3389 xrdp=3390")


class CommonChecks(unittest.TestCase):
    """roles/common/tasks/main.yml refuses inconsistent site settings."""

    def run_checks(self, host="rdp1.example.com", **extra):
        args = [shutil.which("ansible-playbook"), "-i", f"{host},", str(HERE / "check_common.yml")]
        for k, v in extra.items():
            args += ["-e", f"{k}={v}" if isinstance(v, (str, int)) else json.dumps({k: v})]
        env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_NOCOLOR="1",
                   ANSIBLE_PYTHON_INTERPRETER=sys.executable)
        env.pop("ANSIBLE_CONFIG", None)
        return subprocess.run(args, env=env, capture_output=True, text=True, cwd=HERE).returncode

    def test_minimal_passes(self):
        self.assertEqual(self.run_checks(fastrdp_realm="EXAMPLE.COM", fastrdp_domain="example.com"), 0)

    def test_rdp_file_name_and_port(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        self.assertEqual(self.run_checks(fastrdp_web_rdp_host="rdp.example.com", fastrdp_web_rdp_port=443, **ok), 0)
        self.assertEqual(self.run_checks(fastrdp_listen_port=3399, **ok), 0)

    def test_host_name(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        # the inventory name (an FQDN) is fastrdp_fqdn, whatever reverse DNS says
        self.assertEqual(self.run_checks(host="RDP1.Example.com", **ok), 0)
        # never the bare domain (a PTR record pointing at it gave TERMSRV/example.com)
        self.assertNotEqual(self.run_checks(host="example.com", **ok), 0)
        self.assertNotEqual(self.run_checks(fastrdp_fqdn="example.com", **ok), 0)
        self.assertNotEqual(self.run_checks(fastrdp_fqdn="rdp1", **ok), 0)
        self.assertEqual(self.run_checks(host="192.0.2.10", fastrdp_fqdn="rdp1.example.com", **ok), 0)

    def test_failures(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        cases = {
            "no realm": {"fastrdp_domain": "example.com"},
            "default desktop not offered": dict(ok, fastrdp_default_desktop="gnome"),
            "group default not offered": dict(ok, fastrdp_group_desktops='{"rdp-kde": "plasma"}'),
            "desktop groups for unknown desktop": dict(ok, fastrdp_desktop_groups='{"plasma": ["x"]}'),
            "mfa without url": dict(ok, fastrdp_mfa_mode="push"),
            "push_or_web without url": dict(ok, fastrdp_mfa_mode="push_or_web", fastrdp_web_enabled=True),
            "web approval without web access": dict(ok, fastrdp_mfa_mode="web"),
            "push_or_web without web access": dict(ok, fastrdp_mfa_mode="push_or_web",
                                                   fastrdp_privacyidea_url="https://pi"),
            "web approval timeout not below the proxy's": dict(
                ok, fastrdp_mfa_mode="web", fastrdp_web_enabled=True, fastrdp_mfa_web_approval_timeout=120),
            "web approval timeout above the proxy's": dict(
                ok, fastrdp_mfa_mode="web", fastrdp_web_enabled=True, fastrdp_mfa_web_approval_timeout=200,
                fastrdp_proxy_broker_timeout=150),
            "web approval timeout too short": dict(ok, fastrdp_mfa_web_approval_timeout=5),
            "web approval timeout over the limit": dict(ok, fastrdp_mfa_web_approval_timeout=541),
            "web approval timeout in minutes": dict(ok, fastrdp_mfa_web_approval_timeout="2m"),
            "proxy timeout over the module's limit": dict(ok, fastrdp_proxy_broker_timeout=601),
            "proxy timeout zero": dict(ok, fastrdp_proxy_broker_timeout=0),
            "web approval auth age negative": dict(ok, fastrdp_mfa_web_approval_max_auth_age=-1),
            "web approval auth age over the limit": dict(ok, fastrdp_mfa_web_approval_max_auth_age=301),
            "web approval single pending not a bool": dict(ok, fastrdp_mfa_web_approval_single_pending="maybe"),
            "unknown mfa mode": dict(ok, fastrdp_mfa_mode="sms", fastrdp_privacyidea_url="https://pi"),
            "unknown identity provider": dict(ok, fastrdp_identity_provider="ldap"),
            "xrdp port = front port": dict(ok, fastrdp_xrdp_port=3389),
            "unknown session_tgt": dict(ok, fastrdp_session_tgt="yes"),
            "session_tgt groups as a list": dict(ok, fastrdp_session_tgt_groups=["nfs-homes"]),
            "session_tgt group mode unknown": dict(ok, fastrdp_session_tgt_groups={"nfs-homes": "yes"}),
            "session_tgt group mode unquoted off": dict(ok, fastrdp_session_tgt_groups={"kiosk": False}),
            "session_tgt group name empty": dict(ok, fastrdp_session_tgt_groups={"": "required"}),
            "session_tgt group name with a newline": dict(ok, fastrdp_session_tgt_groups={"a\nb": "required"}),
            "unknown GPU stack": dict(ok, fastrdp_gpu="intel"),
            "alias not a DNS name": dict(ok, fastrdp_termsrv_aliases=["rdp;reboot"]),
            "alias list given as a string": dict(ok, fastrdp_termsrv_aliases="rdp.example.com"),
            "kdc-enforced with hardened (password) indicator": dict(
                ok, fastrdp_identity_provider="ipa", fastrdp_mfa_nla_kdc_enforced=True,
                fastrdp_mfa_nla_kdc_auth_indicators=["passkey", "hardened"]),
            "kdc-enforced without indicators": dict(
                ok, fastrdp_identity_provider="ipa", fastrdp_mfa_nla_kdc_enforced=True,
                fastrdp_mfa_nla_kdc_auth_indicators=[]),
            "kdc-enforced on AD without a policy": dict(ok, fastrdp_mfa_nla_kdc_enforced=True),
            "unknown autodetect profile": dict(ok, fastrdp_xrdp_autodetect_profile="autodetect"),
            "autodetect profile upper case": dict(ok, fastrdp_xrdp_autodetect_profile="WAN"),
            "lan networks as a string": dict(ok, fastrdp_lan_networks="10.0.0.0/8"),
            "lan network not a CIDR": dict(ok, fastrdp_lan_networks=["10.0.0.0/8", "office"]),
            "lan network with a shell character": dict(ok, fastrdp_lan_networks=["10.0.0.0/8;x"]),
            "TLS login sources as a string": dict(ok, fastrdp_tls_login_sources="127.0.0.1"),
            "TLS login source not an address": dict(ok, fastrdp_tls_login_sources=["127.0.0.1", "localhost"]),
            "TLS login source with a newline": dict(ok, fastrdp_tls_login_sources=["127.0.0.1\nAllowTls=true"]),
            "TLS login source with a trailing newline": dict(ok, fastrdp_tls_login_sources=["127.0.0.1\n"]),
            "reconnect grace negative": dict(ok, fastrdp_mfa_reconnect_grace=-1),
            "reconnect grace over an hour": dict(ok, fastrdp_mfa_reconnect_grace=3601),
            "reconnect grace in minutes": dict(ok, fastrdp_mfa_reconnect_grace="10m"),
            "reconnect grace same address not a bool": dict(ok, fastrdp_mfa_reconnect_grace_same_address="maybe"),
            "fully qualified names not a bool": dict(ok, fastrdp_sssd_fully_qualified_names="maybe"),
            "fully qualified names as a domain": dict(ok, fastrdp_sssd_fully_qualified_names="example.com"),
            "domain not a DNS name": dict(ok, fastrdp_domain="exa_mple.com"),
            "accept remote guard not a bool": dict(ok, fastrdp_accept_remote_guard="maybe"),
            "accept remote guard as a list": dict(ok, fastrdp_accept_remote_guard=["true"]),
            ".rdp file host an IP address": dict(ok, fastrdp_web_rdp_host="192.0.2.10"),
            ".rdp file host not a DNS name": dict(ok, fastrdp_web_rdp_host="rdp1.example.com;x"),
            ".rdp file host with a port": dict(ok, fastrdp_web_rdp_host="rdp1.example.com:3389"),
            ".rdp file port out of range": dict(ok, fastrdp_web_rdp_port=65536),
            ".rdp file port not a number": dict(ok, fastrdp_web_rdp_port="rdp"),
        }
        for name, extra in cases.items():
            with self.subTest(name):
                self.assertNotEqual(self.run_checks(**extra), 0)

    def test_kdc_enforced_passes(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com", "fastrdp_mfa_nla_kdc_enforced": True}
        self.assertEqual(self.run_checks(**ok, fastrdp_identity_provider="ipa"), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_mfa_nla_kdc_enforced_by_ad_policy=True), 0)

    def test_network_settings_pass(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for profile in ("lan", "wan", "broadband_high", "satellite", "broadband_low", "modem", "default"):
            with self.subTest(profile):
                self.assertEqual(self.run_checks(**ok, fastrdp_xrdp_autodetect_profile=profile), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_lan_networks=[
            "10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "::ffff:10.0.0.0/104"]), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_tls_login_sources=[
            "127.0.0.1", "::1", "10.0.0.0/8", "2001:db8::/32"]), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_tls_login_sources=[]), 0)

    def test_accept_remote_guard_passes(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for value in (True, False, "true", "False"):
            with self.subTest(value):
                self.assertEqual(self.run_checks(**ok, fastrdp_accept_remote_guard=value), 0)

    def test_reconnect_grace_passes(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for grace in (0, 600, 3600):
            with self.subTest(grace):
                self.assertEqual(self.run_checks(**ok, fastrdp_mfa_reconnect_grace=grace,
                                                 fastrdp_mfa_reconnect_grace_same_address=False), 0)

    def test_web_approval_passes(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com", "fastrdp_web_enabled": True}
        self.assertEqual(self.run_checks(**ok, fastrdp_mfa_mode="web"), 0)       # no privacyIDEA
        self.assertEqual(self.run_checks(**ok, fastrdp_mfa_mode="push_or_web",
                                         fastrdp_privacyidea_url="https://pi"), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_mfa_mode="web", fastrdp_mfa_web_approval_timeout=540,
                                         fastrdp_proxy_broker_timeout=600, fastrdp_mfa_web_approval_max_auth_age=0,
                                         fastrdp_mfa_web_approval_single_pending=False), 0)
        # without web approval the timeout is not compared with the proxy's
        self.assertEqual(self.run_checks(fastrdp_realm="EXAMPLE.COM", fastrdp_domain="example.com",
                                         fastrdp_mfa_web_approval_timeout=300), 0)

    def test_fully_qualified_names_pass(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for value in (True, False, "true", "false"):
            with self.subTest(value):
                self.assertEqual(self.run_checks(**ok, fastrdp_sssd_fully_qualified_names=value), 0)

    def test_session_tgt_groups_pass(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        self.assertEqual(self.run_checks(**ok, fastrdp_session_tgt_groups={
            "nfs-homes": "required", "kiosk": "off", "domain users@example.com": "auto"}), 0)

    def test_aliases_pass(self):
        self.assertEqual(self.run_checks(fastrdp_realm="EXAMPLE.COM", fastrdp_domain="example.com",
                                         fastrdp_termsrv_aliases=["rdp.example.com", "rdp"]), 0)


def names(variant):
    return json.loads((OUT / f"names-{variant}.json").read_text())


class TermsrvNames(unittest.TestCase):
    """TERMSRV principals (identity role) and front certificate SAN (base role)."""

    def test_default_principals(self):
        n = names("ad")
        self.assertEqual(n["spns"], ["TERMSRV/rdp1.lab.example.com", "TERMSRV/RDP1"])
        self.assertEqual(n["keytab_spns"], n["spns"])  # adcli writes an entry per SPN
        # Regression: the self-signed certificate named only the FQDN.
        self.assertEqual(n["san"], "DNS:rdp1.lab.example.com,DNS:rdp1")

    def test_aliases(self):
        n = names("ad-aliases")
        self.assertEqual(n["spns"], ["TERMSRV/rdp1.lab.example.com", "TERMSRV/RDP1",
                                     "TERMSRV/rdp.lab.example.com", "TERMSRV/rdp"])  # FQDN not twice
        self.assertEqual(n["keytab_spns"], n["spns"])
        self.assertEqual(n["san"], "DNS:rdp1.lab.example.com,DNS:rdp1,DNS:rdp.lab.example.com,DNS:rdp")

    def test_ipa_and_none_keytabs_carry_the_fqdn_principal(self):
        # FreeIPA aliases share the canonical principal's keys; "none" keytabs are provided.
        self.assertEqual(names("ipa-aliases")["keytab_spns"], ["TERMSRV/rdp1.lab.example.com"])
        self.assertEqual(names("none")["keytab_spns"], ["TERMSRV/rdp1.lab.example.com"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_san_accepted_by_openssl(self):
        # Same openssl options as roles/base/tasks/main.yml (self-signed certificate).
        san = names("ad-aliases")["san"]
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=rdp1.lab.example.com", "-addext", f"subjectAltName={san}",
                            "-addext", "extendedKeyUsage=serverAuth",
                            "-keyout", f"{tmp}/k", "-out", f"{tmp}/c"], check=True, capture_output=True)
            out = subprocess.run(["openssl", "x509", "-in", f"{tmp}/c", "-noout", "-ext", "subjectAltName"],
                                 check=True, capture_output=True, text=True).stdout
        self.assertIn("DNS:rdp1.lab.example.com, DNS:rdp1, DNS:rdp.lab.example.com, DNS:rdp", out)


class WebgateToml(unittest.TestCase):
    def test_accepted_by_webgate(self):
        cfg = webgate_config.parse(toml("webgate.toml"))
        self.assertEqual(cfg.webgate.public_url, "https://rdp1.lab.example.com")
        self.assertEqual(cfg.webgate.path_prefix, "/web")
        self.assertEqual(cfg.webgate.desktops, ["xfce", "mate", "gnome", "plasma"])
        # "Download .rdp file": the proxy's name and port (fastrdp_fqdn, fastrdp_listen_port)
        self.assertEqual((cfg.webgate.rdp_host, cfg.webgate.rdp_port), ("rdp1.lab.example.com", 3389))
        self.assertEqual(cfg.oidc.issuer, "https://keycloak.lab.example.com/realms/lab")
        self.assertEqual(cfg.oidc.strip_domains, ["lab.example.com"])
        self.assertEqual(cfg.oidc.required_acr, ["mfa"])
        self.assertEqual(cfg.oidc.ca_file, "/etc/fastrdp/webgate-idp-ca.pem")
        self.assertEqual(cfg.guacamole.connection_port, 3389)
        self.assertEqual(cfg.guacamole.cert_fingerprint_file, "/etc/fastrdp/front.fingerprint")
        # values are strings for Guacamole, whatever YAML type they had
        self.assertEqual(cfg.guacamole.rdp_parameters,
                         {"enable-font-smoothing": "true", "color-depth": "32", "resize-method": "display-update"})

    def test_rdp_port_follows_the_proxy_port(self):
        cfg = webgate_config.parse(toml("webgate-ports.toml"))
        self.assertEqual((cfg.webgate.rdp_host, cfg.webgate.rdp_port), ("rdp1.lab.example.com", 3399))
        self.assertEqual(cfg.guacamole.connection_port, 3399)


class NfsKrb5Homes(unittest.TestCase):
    """fastrdp_nfs_krb5_homes: gssproxy service for rpc.gssd + nfs.conf.d snippet."""

    def gssproxy(self, name):
        text = (OUT / name).read_text()
        pairs = [tuple(p.strip() for p in line.split("=", 1)) for line in text.splitlines()
                 if "=" in line and not line.lstrip().startswith("#")]
        sections = [line for line in text.splitlines() if line.startswith("[")]
        return sections, pairs

    def test_gssproxy_impersonation_service(self):
        sections, pairs = self.gssproxy("gssproxy-nfs-client.conf")
        self.assertEqual(sections, ["[service/fastrdp-nfs-client]"])
        opts = dict(pairs)
        self.assertEqual(opts["mechs"], "krb5")
        self.assertEqual(opts["cred_usage"], "initiate")  # never accept with the host keytab
        for flag in ("allow_any_uid", "impersonate", "trusted"):
            self.assertEqual(opts[flag], "yes", flag)
        self.assertEqual(opts["euid"], "0")
        self.assertEqual(opts["program"], "/usr/sbin/rpc.gssd")
        self.assertEqual([v for k, v in pairs if k == "cred_store"],
                         ["keytab:/etc/krb5.keytab", "ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U"])

    def test_own_keytab(self):
        _, pairs = self.gssproxy("gssproxy-nfs-client-own.conf")
        self.assertIn(("cred_store", "keytab:/etc/gssproxy/nfs.keytab"), pairs)

    def test_gssd_uses_gssproxy(self):
        cp = ini("nfs-gssd.conf")
        self.assertEqual(cp.sections(), ["gssd"])
        self.assertEqual(dict(cp["gssd"]), {"use-gss-proxy": "1"})


class SmbKrb5Homes(unittest.TestCase):
    """fastrdp_smb_krb5_homes: gssproxy service for cifs.upcall, request-key line,
    static multiuser mounts in /etc/fstab, and their common checks."""

    gssproxy = NfsKrb5Homes.gssproxy

    def test_gssproxy_impersonation_service(self):
        sections, pairs = self.gssproxy("gssproxy-smb-client.conf")
        self.assertEqual(sections, ["[service/fastrdp-smb-client]"])
        opts = dict(pairs)
        self.assertEqual(opts["mechs"], "krb5")
        self.assertEqual(opts["cred_usage"], "initiate")  # never accept with the host keytab
        # trusted: root (the mount) gets the host's own credential from the keytab
        for flag in ("allow_any_uid", "impersonate", "trusted"):
            self.assertEqual(opts[flag], "yes", flag)
        self.assertEqual(opts["euid"], "0")
        # default socket, like rpc.gssd's service: gssproxy refuses two allow_any_uid
        # services with the same socket and program, so the program must differ
        self.assertNotIn("socket", opts)
        self.assertEqual(opts["program"], "/usr/sbin/cifs.upcall")
        _, nfs = self.gssproxy("gssproxy-nfs-client.conf")
        self.assertNotEqual(dict(nfs)["program"], opts["program"])
        # own impersonated caches, not rpc.gssd's
        self.assertEqual([v for k, v in pairs if k == "cred_store"],
                         ["keytab:/etc/krb5.keytab", "ccache:FILE:/var/lib/gssproxy/clients/krb5cc_smb_%U"])
        self.assertNotIn(("cred_store", "ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U"), pairs)

    def test_own_keytab(self):
        _, pairs = self.gssproxy("gssproxy-smb-client-own.conf")
        self.assertIn(("cred_store", "keytab:/etc/gssproxy/smb.keytab"), pairs)

    def test_request_key_line(self):
        lines = [line for line in (OUT / "request-key-cifs-spnego.conf").read_text().splitlines()
                 if line.strip() and not line.startswith("#")]
        self.assertEqual(len(lines), 1)
        op, ktype, desc, callout, *cmd = lines[0].split()
        self.assertEqual((op, ktype, callout), ("create", "cifs.spnego", "*"))
        # less wild than cifs-utils' "*" (keyutils request-key.c match(): wildness is the
        # number of characters the "*" skips), and it matches the kernel's description
        self.assertEqual(desc, "ver=0x*")
        self.assertTrue("ver=0x2;host=fs1.lab.example.com;ip4=192.0.2.5;sec=krb5;uid=0x0;creduid=0x4e8;pid=0x1f"
                        .startswith(desc[:-1]))
        # request-key runs the program with execv: the variable needs env
        self.assertEqual(cmd, ["/usr/bin/env", "GSS_USE_PROXY=yes", "/usr/sbin/cifs.upcall", "%k"])

    def test_fstab(self):
        self.assertEqual((OUT / "fstab-smb-none").read_text().strip(), "")
        lines = (OUT / "fstab-smb").read_text().splitlines()
        self.assertEqual(len(lines), 2)
        what, where, fstype, opts, dump, passno = lines[0].split()
        self.assertEqual((what, where, fstype, dump, passno), ("//fs1.lab.example.com/users$", "/smb/users", "cifs", "0", "0"))
        self.assertEqual(opts.split(","), ["sec=krb5", "multiuser", "nosuid", "nodev", "_netdev", "nofail",
                                           "x-systemd.automount", "x-systemd.after=gssproxy.service"])
        opts = lines[1].split()[3].split(",")
        # sec from the options replaces the default, extra options come last
        self.assertEqual([o for o in opts if o.startswith("sec=")], ["sec=krb5i"])
        self.assertEqual(opts[-3:], ["vers=3.1.1", "seal", "sec=krb5i"])
        self.assertIn("multiuser", opts)

    def test_checks(self):
        run = HomeDirectories.run_checks
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        users = {"what": "//fs1.example.com/users$", "where": "/smb/users"}
        self.assertEqual(run(self, **ok, fastrdp_smb_krb5_homes=True), 0)
        self.assertEqual(run(self, **ok, fastrdp_smb_krb5_homes=True, fastrdp_smb_mounts=[
            users, {"what": "//FS1.Example.com/projects/it", "where": "/srv/smb/projects",
                    "options": "vers=3.1.1,seal,sec=krb5i"}]), 0)
        bad = {
            "mounts without the option": {"fastrdp_smb_mounts": [users]},
            "not a bool": {"fastrdp_smb_krb5_homes": "yes please"},
            "a mapping": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": users},
            "a string": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": "//fs1.example.com/users$"},
            "unknown key": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [dict(users, opts="seal")]},
            "short server name": {"fastrdp_smb_krb5_homes": True,
                                  "fastrdp_smb_mounts": [dict(users, what="//fs1/users$")]},
            "no share": {"fastrdp_smb_krb5_homes": True,
                         "fastrdp_smb_mounts": [dict(users, what="//fs1.example.com")]},
            "backslashes": {"fastrdp_smb_krb5_homes": True,
                            "fastrdp_smb_mounts": [dict(users, what="\\\\fs1.example.com\\users$")]},
            "space in share": {"fastrdp_smb_krb5_homes": True,
                               "fastrdp_smb_mounts": [dict(users, what="//fs1.example.com/my users")]},
            "relative where": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [dict(users, where="smb")]},
            "where /": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [dict(users, where="/")]},
            "where ..": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [dict(users, where="/smb/../etc")]},
            "where twice": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [users, users]},
            "no where": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [{"what": users["what"]}]},
            "space in options": {"fastrdp_smb_krb5_homes": True,
                                 "fastrdp_smb_mounts": [dict(users, options="seal 0 0\n/dev/sda1")]},
            "password sec": {"fastrdp_smb_krb5_homes": True, "fastrdp_smb_mounts": [dict(users, options="sec=ntlmssp")]},
        }
        for name, extra in bad.items():
            with self.subTest(name):
                self.assertNotEqual(run(self, **ok, **extra), 0)


class TicketRenewal(unittest.TestCase):
    """sssd-kcm renews every TGT in KCM (kinit in sessions too); FreeIPA's sssd.conf
    (written by ipa-client-install) gets the domain renewal options AD already has."""

    def test_kcm_renewal_for_every_provider(self):
        for provider in ("ad", "ipa", "none"):
            with self.subTest(provider):
                kcm = ini(f"sssd-fastrdp-{provider}.conf")["kcm"]
                self.assertEqual(dict(kcm), {"tgt_renewal": "true", "krb5_renew_interval": "1h",
                                             "krb5_renewable_lifetime": "7d"})

    def test_ipa_domain_renewal(self):
        cp = ini("sssd-fastrdp-ipa.conf")
        self.assertEqual(cp.sections(), ["kcm", "domain/lab.example.com"])
        self.assertEqual(dict(cp["domain/lab.example.com"]),
                         {"krb5_renewable_lifetime": "7d", "krb5_renew_interval": "1h",
                          "use_fully_qualified_names": "false"})
        # AD and "none": no domain section (AD has the options in its own sssd.conf)
        self.assertEqual(ini("sssd-fastrdp-ad.conf").sections(), ["kcm"])
        self.assertEqual(ini("sssd-fastrdp-none.conf").sections(), ["kcm"])

    def test_kcm_renewal_off(self):
        self.assertEqual(ini("sssd-fastrdp-ad-nokcm.conf").sections(), [])

    def test_ad_domain_renewal(self):
        dom = ini("sssd-ad.conf")["domain/lab.example.com"]
        self.assertEqual((dom["krb5_renewable_lifetime"], dom["krb5_renew_interval"]), ("7d", "1h"))

    def test_kinit_asks_for_renewable_tickets(self):
        k = ini("krb5-fastrdp.conf")["libdefaults"]
        self.assertEqual(k["renew_lifetime"], "7d")
        self.assertEqual(k["default_ccache_name"], "KCM:")


class SessionCredentialCache(unittest.TestCase):
    """pam_sss must store TGTs where the session's processes look (backlog K1): they
    get no KRB5CCNAME and use default_ccache_name = KCM:. sssd uses the same value
    when sssd.conf has no krb5_ccname_template (sssd-krb5(5); krb5_common.c reads
    [libdefaults] default_ccache_name, fallback FILE:%d/krb5cc_%U_XXXXXX)."""

    def test_no_ccname_template_in_sssd_files(self):
        files = sorted(OUT.glob("sssd*.conf"))
        self.assertTrue(files)
        for path in files:
            with self.subTest(path.name):
                cp = ini(path.name)
                for section in cp.sections():
                    self.assertNotIn("krb5_ccname_template", cp[section])

    def test_sssd_restarts_when_the_default_cache_changes(self):
        main = (REPO / "ansible/roles/identity/tasks/main.yml").read_text()
        for task in ("- name: Kerberos client settings of fastrdp (snippet)",
                     "- name: Kerberos client configuration (AD, none"):
            block = main[main.index(task):].split("\n\n", 1)[0]
            self.assertIn("notify: Restart sssd", block, task)


class FullyQualifiedNames(unittest.TestCase):
    """fastrdp_sssd_fully_qualified_names: SSSD names (AD sssd.conf, FreeIPA snippet,
    checked for provider "none") and the broker's name order come from one variable."""

    def test_ad(self):
        for name, fqn in (("sssd-ad.conf", "false"), ("sssd-ad-fqn.conf", "true")):
            with self.subTest(name):
                dom = ini(name)["domain/lab.example.com"]
                self.assertEqual(dom["use_fully_qualified_names"], fqn)
                # %u: the short name in both modes, the home directories stay
                self.assertEqual(dom["fallback_homedir"], "/home/%u")

    def test_ipa_snippet_overrides_the_enrolment(self):
        # conf.d snippets override sssd.conf, which ipa-client-install writes (sssd.conf(5))
        self.assertEqual(ini("sssd-fastrdp-ipa.conf")["domain/lab.example.com"]["use_fully_qualified_names"],
                         "false")
        cp = ini("sssd-fastrdp-ipa-fqn.conf")
        self.assertEqual(cp["domain/lab.example.com"]["use_fully_qualified_names"], "true")
        self.assertEqual(cp["domain/lab.example.com"]["krb5_renew_interval"], "1h")
        # provider "none": the admin's sssd.conf decides (checked, never written)
        self.assertEqual(ini("sssd-fastrdp-none-fqn.conf").sections(), ["kcm"])

    def test_broker_name_order(self):
        for name, realm, domain in (("broker-lab.toml", "LAB.EXAMPLE.COM", "lab.example.com"),
                                    ("broker-minimal.toml", "EXAMPLE.COM", "example.com")):
            with self.subTest(name):
                auth = broker_config.parse(toml(name)).auth
                self.assertEqual((auth.strip_realm, auth.realms, auth.domains), (True, [realm], [domain]))
        # FreeIPA whose domain is not the realm: the broker also qualifies with the domain
        auth = broker_config.parse(toml("broker-fqn.toml")).auth
        self.assertEqual((auth.strip_realm, auth.realms, auth.domains),
                         (False, ["IPA.LAB.EXAMPLE.ORG"], ["lab.example.com"]))

    def found(self, files, sssd_conf=True):
        """Run the identity role's check (tasks/sssd_names.yml) on files {name: text}."""
        with tempfile.TemporaryDirectory(prefix="fastrdp-sssd.") as d:
            os.mkdir(f"{d}/conf.d")
            if sssd_conf:
                Path(d, "sssd.conf").write_text(files.pop("sssd.conf", "[sssd]\nservices = nss, pam\n"))
            for name, text in files.items():
                Path(d, "conf.d", name).write_text(text)
            env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_NOCOLOR="1",
                       ANSIBLE_PYTHON_INTERPRETER=sys.executable)
            env.pop("ANSIBLE_CONFIG", None)
            res = subprocess.run([shutil.which("ansible-playbook"), "-i", "localhost,", str(HERE / "sssd_names.yml"),
                                  "-e", f"sssd_dir={d}", "-e", f"out={d}/out.json"],
                                 env=env, capture_output=True, text=True, cwd=HERE)
            self.assertEqual(res.returncode, 0, res.stdout[-3000:])
            r = json.loads(Path(d, "out.json").read_text())
        return r["fqn"] if r["found"] else None

    def test_admin_sssd_conf(self):
        dom = "[domain/example.com]\nid_provider = ldap\n"
        cases = {
            "nothing set: short names": ({}, False),
            "set in sssd.conf": ({"sssd.conf": dom + "use_fully_qualified_names = True\n"}, True),
            "commented out": ({"sssd.conf": dom + "# use_fully_qualified_names = true\n"
                                               "; use_fully_qualified_names = true\n"}, False),
            "snippet overrides sssd.conf": ({"sssd.conf": dom + "use_fully_qualified_names = true\n",
                                             "90-local.conf": dom + "use_fully_qualified_names=false\n"}, False),
            "later snippet wins": ({"10-a.conf": dom + "use_fully_qualified_names = false\n",
                                    "20-b.conf": dom + "  use_fully_qualified_names = TRUE\n"}, True),
            "not a snippet": ({"90-off.conf.disabled": dom + "use_fully_qualified_names = true\n"}, False),
            "default_domain_suffix qualifies names": (
                {"sssd.conf": "[sssd]\ndefault_domain_suffix = example.com\n" + dom}, True),
            "explicit value beats default_domain_suffix": (
                {"sssd.conf": "[sssd]\ndefault_domain_suffix = example.com\n" + dom
                              + "use_fully_qualified_names = false\n"}, False),
        }
        for name, (files, expected) in cases.items():
            with self.subTest(name):
                self.assertIs(self.found(dict(files)), expected)
        self.assertIsNone(self.found({}, sssd_conf=False))


def krb5_profile(conf, snippet_dir):
    """(default realm, default ccache, renew_lifetime, pkinit_anchors) as the real libkrb5
    reads conf, with /etc/krb5.conf.d/ pointed at snippet_dir. None without libkrb5."""
    try:
        k = ctypes.CDLL(ctypes.util.find_library("krb5") or "libkrb5.so.3")
    except OSError:
        return None
    P, S = ctypes.c_void_p, ctypes.c_char_p
    k.krb5_init_context.argtypes = [ctypes.POINTER(P)]
    k.krb5_free_context.argtypes = [P]
    k.krb5_cc_default_name.argtypes = [P]
    k.krb5_cc_default_name.restype = S
    k.krb5_get_profile.argtypes = [P, ctypes.POINTER(P)]
    k.profile_get_string.argtypes = [P, S, S, S, S, ctypes.POINTER(S)]
    k.profile_release.argtypes = [P]
    k.krb5_get_default_realm.argtypes = [P, ctypes.POINTER(S)]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "krb5.conf"
        path.write_text(Path(conf).read_text().replace("/etc/krb5.conf.d/", f"{snippet_dir}/"))
        old = os.environ.get("KRB5_CONFIG")
        os.environ["KRB5_CONFIG"] = str(path)
        try:
            ctx = P()
            rc = k.krb5_init_context(ctypes.byref(ctx))
            if rc:
                raise AssertionError(f"libkrb5 refuses {conf}: error {rc}")
            realm, prof = S(), P()
            k.krb5_get_default_realm(ctx, ctypes.byref(realm))
            k.krb5_get_profile(ctx, ctypes.byref(prof))
            values = [realm.value.decode(), k.krb5_cc_default_name(ctx).decode()]
            for args in ((b"libdefaults", b"renew_lifetime", None),
                         (b"realms", realm.value, b"pkinit_anchors")):
                out = S()
                k.profile_get_string(prof, *args, None, ctypes.byref(out))
                values.append(out.value.decode() if out.value else None)
            k.profile_release(prof)
            k.krb5_free_context(ctx)
        finally:
            if old is None:
                os.environ.pop("KRB5_CONFIG", None)
            else:
                os.environ["KRB5_CONFIG"] = old
    return tuple(values)


# What ipa-client-install 4.12 writes (DNS discovery, sssd); keyring ccache on purpose.
IPA_KRB5_CONF = """#File modified by ipa-client-install

{includedir}includedir {sss}/

[libdefaults]
  default_realm = LAB.EXAMPLE.COM
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
  dns_lookup_kdc = true
  ticket_lifetime = 24h
  forwardable = true
  udp_preference_limit = 0
  default_ccache_name = KEYRING:persistent:%{{uid}}


[realms]
  LAB.EXAMPLE.COM = {{
    pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem
    pkinit_pool = FILE:/var/lib/ipa-client/pki/ca-bundle.pem

  }}


[domain_realm]
  .lab.example.com = LAB.EXAMPLE.COM
  lab.example.com = LAB.EXAMPLE.COM
  rdp1.lab.example.com = LAB.EXAMPLE.COM
"""


class Krb5Conf(unittest.TestCase):
    """fastrdp's Kerberos settings are /etc/krb5.conf.d/fastrdp for every provider; FreeIPA
    keeps ipa-client-install's krb5.conf. Regression: the role wrote the AD krb5.conf over
    FreeIPA's on every run after the first (no PKINIT anchors, no sssd include)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.snippets = self.dir / "krb5.conf.d"
        self.snippets.mkdir()
        shutil.copy(OUT / "krb5-fastrdp.conf", self.snippets / "fastrdp")
        self.sss = self.dir / "krb5.include.d"
        self.sss.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_ad_and_none_file(self):
        text = (OUT / "krb5.conf").read_text()
        self.assertIn("\nincludedir /etc/krb5.conf.d/\n", text)
        self.assertLess(text.index("includedir"), text.index("[libdefaults]"))
        k = configparser.ConfigParser(interpolation=None, comment_prefixes=("#",))
        k.read_string("\n".join(line for line in text.splitlines() if not line.startswith("includedir")))
        self.assertEqual(k["libdefaults"]["default_realm"], "LAB.EXAMPLE.COM")
        self.assertEqual(k["libdefaults"]["dns_lookup_kdc"], "true")
        self.assertNotIn("default_ccache_name", k["libdefaults"])   # snippet
        self.assertEqual(dict(k["domain_realm"]), {".lab.example.com": "LAB.EXAMPLE.COM",
                                                   "lab.example.com": "LAB.EXAMPLE.COM"})

    def test_snippet(self):
        self.assertEqual(ini("krb5-fastrdp.conf").sections(), ["libdefaults"])

    def test_role_order(self):
        import yaml   # ansible-core's dependency
        tasks = REPO / "ansible/roles/identity/tasks"
        main = yaml.safe_load((tasks / "main.yml").read_text())
        writers = [t for t in main if (t.get("ansible.builtin.template") or {}).get("dest") == "/etc/krb5.conf"]
        self.assertEqual(len(writers), 1)
        self.assertEqual(writers[0]["when"], "fastrdp_identity_provider != 'ipa'")
        names = [t["name"] for t in main]
        snippet = names.index("Kerberos client settings of fastrdp (snippet)")
        self.assertLess(names.index("Kerberos snippet directory"), snippet)
        self.assertLess(snippet, names.index("Join directory"))   # before ipa-client-install
        ipa = yaml.safe_load((tasks / "ipa.yml").read_text())
        steps = [next(iter(k for k in t if k.startswith("ansible.builtin."))) for t in ipa]
        enrol = [t["name"] for t in ipa].index("Enrol in FreeIPA")
        self.assertEqual(steps[enrol + 1], "ansible.builtin.include_tasks")
        self.assertEqual(ipa[enrol + 1]["ansible.builtin.include_tasks"], "ipa_krb5.yml")

    def profile(self, conf):
        p = krb5_profile(conf, self.snippets)
        if p is None:
            self.skipTest("libkrb5 not installed")
        return p

    def test_ad_file_with_snippet_through_libkrb5(self):
        self.assertEqual(self.profile(OUT / "krb5.conf"), ("LAB.EXAMPLE.COM", "KCM:", "7d", None))

    def test_snippet_wins_over_freeipa_file(self):
        conf = self.dir / "ipa.conf"
        conf.write_text(IPA_KRB5_CONF.format(includedir="includedir /etc/krb5.conf.d/\n", sss=self.sss))
        self.assertEqual(self.profile(conf), ("LAB.EXAMPLE.COM", "KCM:", "7d",
                                              "FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem"))

    def test_restored_freeipa_file(self):
        for variant in ("sss", "nosss"):
            with self.subTest(variant):
                text = (OUT / f"krb5-ipa-{variant}.conf").read_text()
                self.assertEqual("includedir /var/lib/sss/pubconf/krb5.include.d/" in text, variant == "sss")
                conf = self.dir / "restored.conf"
                conf.write_text(text.replace("/var/lib/sss/pubconf/krb5.include.d", str(self.sss)))
                self.assertEqual(self.profile(conf), ("LAB.EXAMPLE.COM", "KCM:", "7d",
                                                      "FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem"))
                self.assertIn("rdp1.lab.example.com = LAB.EXAMPLE.COM", text)

    def run_ipa_tasks(self, conf, sss=None):
        """tasks/ipa_krb5.yml on conf; returns the number of changed tasks."""
        args = [shutil.which("ansible-playbook"), "-i", "localhost,", str(HERE / "ipa_krb5.yml"),
                "-e", f"krb5_conf={conf}"]
        if sss:
            args += ["-e", f"sss_dir={sss}"]
        env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_NOCOLOR="1",
                   ANSIBLE_PYTHON_INTERPRETER=sys.executable, ANSIBLE_ROLES_PATH=str(REPO / "ansible/roles"))
        env.pop("ANSIBLE_CONFIG", None)
        res = subprocess.run(args, env=env, capture_output=True, text=True, cwd=HERE)
        self.assertEqual(res.returncode, 0, res.stdout[-3000:])
        recap = [line for line in res.stdout.splitlines() if line.startswith("localhost")][-1]
        return int(recap.split("changed=")[1].split()[0])

    def test_ipa_file_kept_and_stable(self):
        conf = self.dir / "krb5.conf"
        original = IPA_KRB5_CONF.format(includedir="includedir /etc/krb5.conf.d/\n\n", sss=self.sss)
        conf.write_text(original)
        self.assertEqual(self.run_ipa_tasks(conf), 0)
        self.assertEqual(conf.read_text(), original)

    def test_ipa_file_gets_the_includedir_once(self):
        # enrolled while /etc/krb5.conf.d did not exist: ipa-client-install left the line out
        conf = self.dir / "krb5.conf"
        conf.write_text(IPA_KRB5_CONF.format(includedir="", sss=self.sss))
        self.assertEqual(self.run_ipa_tasks(conf), 1)
        first = conf.read_text()
        self.assertTrue(first.startswith("includedir /etc/krb5.conf.d/\n"))
        self.assertEqual(first.count("includedir /etc/krb5.conf.d/"), 1)
        self.assertEqual(self.run_ipa_tasks(conf), 0)
        self.assertEqual(conf.read_text(), first)
        self.assertEqual(self.profile(conf)[1:3], ("KCM:", "7d"))

    def test_file_of_an_older_role_restored_once(self):
        # the old role wrote the AD-style krb5.conf (with the settings inline) over FreeIPA's
        conf = self.dir / "krb5.conf"
        conf.write_text("# Ansible managed\n[libdefaults]\n    default_realm = LAB.EXAMPLE.COM\n"
                        "    default_ccache_name = KCM:\n    renew_lifetime = 7d\n")
        self.assertEqual(self.run_ipa_tasks(conf, sss=self.sss), 1)
        first = conf.read_text()
        self.assertIn("pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem", first)
        self.assertIn("includedir /var/lib/sss/pubconf/krb5.include.d/", first)
        self.assertEqual(self.run_ipa_tasks(conf, sss=self.sss), 0)
        self.assertEqual(conf.read_text(), first)


class TermsrvUnits(unittest.TestCase):
    """Keytab watcher: packaged units run /usr/sbin/fastrdp-termsrv-keytab, the build
    install method's copies the one in /usr/local/sbin."""

    def test_helper_directory(self):
        self.assertEqual((OUT / "termsrv-sbin-apt.txt").read_text(), "/usr/sbin")
        self.assertEqual((OUT / "termsrv-sbin-build.txt").read_text(), "/usr/local/sbin")

    def test_units(self):
        packaged = REPO / "broker/session/systemd/fastrdp-termsrv-keytab.service"
        self.assertIn("ExecStart=/usr/sbin/fastrdp-termsrv-keytab\n", packaged.read_text())
        svc = ini("build-fastrdp-termsrv-keytab.service")["Service"]
        self.assertEqual(svc["ExecStart"], "/usr/local/sbin/fastrdp-termsrv-keytab")
        self.assertEqual(svc["ExecStartPost"], "-/usr/bin/systemctl try-restart fastrdp-proxy.service")
        self.assertEqual(svc["Type"], "oneshot")
        path = ini("build-fastrdp-termsrv-keytab.path")
        self.assertEqual(path["Path"]["PathChanged"], "/etc/krb5.keytab")
        self.assertEqual(path["Install"]["WantedBy"], "multi-user.target")


class HomeDirectories(unittest.TestCase):
    """fastrdp_sssd_override_homedir (local homes) and fastrdp_autofs (directory automount
    maps through sssd). Defaults change nothing."""

    DOMAIN = "domain/lab.example.com"

    def run_checks(self, **extra):
        # all values as one JSON -e: "k=v" would cut "/home/%u x" at the space
        args = [shutil.which("ansible-playbook"), "-i", "rdp1.example.com,", str(HERE / "check_common.yml"),
                "-e", json.dumps(extra)]
        env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_NOCOLOR="1",
                   ANSIBLE_PYTHON_INTERPRETER=sys.executable)
        env.pop("ANSIBLE_CONFIG", None)
        return subprocess.run(args, env=env, capture_output=True, text=True, cwd=HERE).returncode

    def test_defaults_unchanged(self):
        ad = ini("sssd-ad.conf")
        self.assertEqual(ad["sssd"]["services"], "nss, pam")
        self.assertEqual(ad[self.DOMAIN]["fallback_homedir"], "/home/%u")
        # GDM's headless session (GNOME) is an RDP logon, not denied as unmapped
        self.assertEqual(ad[self.DOMAIN]["ad_gpo_map_remote_interactive"],
                         "+fastrdp, +xrdp-sesman, +fastrdp-session, +gdm-autologin")
        for key in ("override_homedir", "autofs_provider"):
            self.assertNotIn(key, ad[self.DOMAIN])
            self.assertNotIn(key, ini("sssd-fastrdp-ipa.conf")[self.DOMAIN])

    def test_ad_local_homes_and_automount_maps(self):
        ad = ini("sssd-ad-homes.conf")
        self.assertEqual(ad["sssd"]["services"], "nss, pam, autofs")
        self.assertEqual(ad[self.DOMAIN]["override_homedir"], "/home/%u")
        self.assertEqual(ad[self.DOMAIN]["autofs_provider"], "ad")
        # autofs with the admin's own maps: sssd untouched
        files = ini("sssd-ad-autofs-files.conf")
        self.assertEqual(files["sssd"]["services"], "nss, pam")
        self.assertNotIn("autofs_provider", files[self.DOMAIN])

    def test_ipa_snippet(self):
        dom = ini("sssd-fastrdp-ipa-homes.conf")[self.DOMAIN]
        self.assertEqual(dom["override_homedir"], "/home/%d/%u")
        self.assertEqual(dom["autofs_provider"], "ipa")
        self.assertEqual(dom["ipa_automount_location"], "default")
        self.assertEqual(dom["krb5_renew_interval"], "1h")
        # AD has them in its own sssd.conf: the snippet keeps only [kcm]
        self.assertEqual(ini("sssd-fastrdp-ad-homes.conf").sections(), ["kcm"])

    def test_checks(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for good in ("/home/%u", "/home/%d/%u", "/srv/home/%l/%u", "/home/users/%f", "/home/%%x%u"):
            with self.subTest(good=good):
                self.assertEqual(self.run_checks(**ok, fastrdp_sssd_override_homedir=good, fastrdp_autofs="sssd"), 0)
        self.assertEqual(self.run_checks(**ok, fastrdp_autofs="files"), 0)
        for bad in ("home/%u", "/home/%u/", "/home/%x", "/home/../%u", "/home/./%u", "/home/%u\n",
                    "/home/%u x", "/", "//home/%u", "/home/%u;reboot"):
            with self.subTest(bad=bad):
                self.assertNotEqual(self.run_checks(**ok, fastrdp_sssd_override_homedir=bad), 0)
        self.assertNotEqual(self.run_checks(**ok, fastrdp_sssd_override_homedir=["/home/%u"]), 0)
        self.assertNotEqual(self.run_checks(**ok, fastrdp_autofs="ldap"), 0)

    def test_home_create_roots_rendered(self):
        for name, roots in (("broker-lab.toml", ["/home"]), ("broker-minimal.toml", ["/home"]),
                            ("broker-homes-several.toml", ["/home", "/srv/home"]),
                            ("broker-homes-none.toml", [])):
            with self.subTest(name):
                self.assertEqual(toml(name)["broker"]["home_create_roots"], roots)
                cfg = broker_config.parse(toml(name))  # the broker accepts it
                self.assertEqual(cfg.broker.home_create_roots, roots)

    def test_home_create_roots_checks(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for good in ([], ["/home"], ["/home", "/srv/home"]):
            with self.subTest(good=good):
                self.assertEqual(self.run_checks(**ok, fastrdp_home_create_roots=good), 0)
        for bad in ("/home", ["home"], ["/"], ["/home/"], ["/home/../etc"], ["/home/./x"], ["//home"],
                    ["/home\n"], ["/home dir"], ['/home"]\nx = ["']):
            with self.subTest(bad=bad):
                self.assertNotEqual(self.run_checks(**ok, fastrdp_home_create_roots=bad), 0)

    def test_autofs_tasks(self):
        # the responder line is appended once (idempotent) and sssd restarts before autofs
        tasks = (REPO / "ansible/roles/identity/tasks/autofs.yml").read_text()
        self.assertIn("(?!.*\\bautofs\\b)", tasks)
        self.assertLess(tasks.index("flush_handlers"), tasks.index("name: autofs\n    enabled: true"))
        self.assertIn("line: 'automount:      files sss'", tasks)
        main = (REPO / "ansible/roles/identity/tasks/main.yml").read_text()
        self.assertIn("include_tasks: autofs.yml", main)


class PowerRule(unittest.TestCase):
    """Polkit rule against power off/reboot/suspend/hibernate/halt from RDP sessions
    (base role, fastrdp_block_power_actions; backlog H1). The rule runs in node with
    polkit's rule semantics (tests/ansible/polkit_rule_eval.js)."""

    PREFIX = "org.freedesktop.login1."
    # logind's actions for these operations (systemd 257-259 org.freedesktop.login1.policy,
    # logind-action.c): kexec/soft-reboot -> reboot, hybrid-sleep/suspend-then-hibernate ->
    # hibernate; set-reboot-* imply reboot.
    REFUSED = [f"{op}{variant}" for op in ("power-off", "reboot", "halt", "suspend", "hibernate")
               for variant in ("", "-multiple-sessions", "-ignore-inhibit")] + [
        "set-reboot-parameter", "set-reboot-to-firmware-setup",
        "set-reboot-to-boot-loader-menu", "set-reboot-to-boot-loader-entry"]
    UNTOUCHED = ["inhibit-block-shutdown", "inhibit-delay-shutdown", "inhibit-block-sleep",
                 "inhibit-delay-sleep", "inhibit-block-idle", "inhibit-handle-power-key",
                 "lock-sessions", "set-self-linger", "set-wall-message", "chvt", "manage"]
    RDP = {"local": False, "active": True}          # RDP sessions have no seat
    CONSOLE = {"local": True, "active": True}       # active session on seat0

    def evaluate(self, rules, cases):
        node = shutil.which("node") or shutil.which("nodejs")
        if not node:
            if os.environ.get("FASTRDP_TESTS_STRICT") == "1":
                self.fail("node (nodejs) not found")
            self.skipTest("node (nodejs) not found")
        res = subprocess.run([node, str(HERE / "polkit_rule_eval.js"), str(OUT / rules)],
                             input=json.dumps(cases), capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(res.stdout)

    def results(self, rules, actions, user, groups, session):
        cases = [dict(session, action=self.PREFIX + a, user=user, groups=groups) for a in actions]
        return dict(zip(actions, self.evaluate(rules, cases)))

    def test_action_list(self):
        text = (OUT / "power-default.rules").read_text()
        actions = json.loads(re.search(r"var actions = (\[.*?\]);", text, re.S).group(1))
        self.assertEqual(sorted(actions), sorted(self.PREFIX + a for a in self.REFUSED))

    def test_es5_only(self):
        # polkitd's duktape is ES5.1: no let/const, arrow functions or template strings
        for name in ("power-default.rules", "power-groups-console.rules", "power-root-only.rules"):
            with self.subTest(name):
                code = "\n".join(line for line in (OUT / name).read_text().splitlines()
                                 if not line.lstrip().startswith("//"))
                self.assertNotRegex(code, r"\b(let|const|class)\s|=>|`")
                self.assertIn("polkit.addRule(function (action, subject) {", code)

    def test_users_refused_admins_authenticate(self):
        for session in (self.RDP, self.CONSOLE):
            with self.subTest(session=session):
                user = self.results("power-default.rules", self.REFUSED, "alice", ["alice", "users"], session)
                self.assertEqual(set(user.values()), {"no"})
                admin = self.results("power-default.rules", self.REFUSED, "bob", ["bob", "sudo"], session)
                self.assertEqual(set(admin.values()), {"auth_admin_keep"})

    def test_other_actions_and_root_untouched(self):
        other = self.results("power-default.rules", self.UNTOUCHED, "alice", ["alice"], self.RDP)
        self.assertEqual(set(other.values()), {None})
        root = self.results("power-default.rules", self.REFUSED, "root", ["root"], self.RDP)
        self.assertEqual(set(root.values()), {None})
        foreign = self.evaluate("power-default.rules", [dict(self.RDP, action="org.freedesktop.systemd1.manage-units",
                                                             user="alice", groups=["alice"])])
        self.assertEqual(foreign, [None])

    def test_local_console_and_group_names(self):
        rules = "power-groups-console.rules"
        console = self.results(rules, self.REFUSED, "alice", ["alice"], self.CONSOLE)
        self.assertEqual(set(console.values()), {None})            # upstream defaults
        inactive = self.results(rules, ["power-off"], "alice", ["alice"], {"local": True, "active": False})
        self.assertEqual(inactive, {"power-off": "no"})
        rdp = self.results(rules, self.REFUSED, "alice", ["alice"], self.RDP)
        self.assertEqual(set(rdp.values()), {"no"})
        ad_admin = self.results(rules, ["reboot-multiple-sessions"], "carol@example.com",
                                ["rdp admins@example.com"], self.RDP)
        self.assertEqual(ad_admin, {"reboot-multiple-sessions": "auth_admin_keep"})

    def test_root_only(self):
        admin = self.results("power-root-only.rules", self.REFUSED, "bob", ["bob", "sudo"], self.RDP)
        self.assertEqual(set(admin.values()), {"no"})

    def test_smoke_script(self):
        """tests/smoke/check-power-actions.sh (user mode) with stub busctl/pkcheck/loginctl."""
        script = REPO / "tests/smoke/check-power-actions.sh"
        text = script.read_text()
        for a in self.REFUSED:  # its action list follows the role's
            self.assertRegex(text, rf"(?m)(^|[ \"]){re.escape(a)}( |$|\")")
        if os.geteuid() == 0:
            self.skipTest("user mode only (as root the script needs a host with logind)")
        with tempfile.TemporaryDirectory() as stubs:
            for name, body in (("busctl", 'echo "s \\"$STUB_CAN\\""'), ("pkcheck", 'exit "$STUB_PK"'),
                               ("loginctl", "exit 0")):
                p = Path(stubs) / name
                p.write_text(f"#!/bin/sh\n{body}\n")
                p.chmod(0o755)
            for can, pk, rc in (("no", 1, 0), ("na", 1, 0), ("challenge", 2, 1), ("yes", 0, 1), ("no", 127, 1)):
                with self.subTest(can=can, pkcheck=pk):
                    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", STUB_CAN=can, STUB_PK=str(pk),
                               FASTRDP_POWER_RULE=str(OUT / "power-root-only.rules"))
                    res = subprocess.run([str(script)], env=env, capture_output=True, text=True)
                    self.assertEqual(res.returncode, rc, res.stdout + res.stderr)
                    self.assertIn("ok   power rule present", res.stdout)

    def test_tasks_and_checks(self):
        tasks = (REPO / "ansible/roles/base/tasks/main.yml").read_text()
        self.assertIn("dest: /etc/polkit-1/rules.d/40-fastrdp-power.rules", tasks)
        self.assertIn("when: not fastrdp_block_power_actions | bool", tasks)
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        checks = CommonChecks()
        for good in ({}, {"fastrdp_power_admin_groups": []},
                     {"fastrdp_power_admin_groups": ["sudo", "rdp admins@example.com", "wheel"]},
                     {"fastrdp_block_power_actions": False, "fastrdp_power_allow_local_console": True}):
            with self.subTest(good=good):
                self.assertEqual(checks.run_checks(**ok, **good), 0)
        for bad in ({"fastrdp_power_admin_groups": "sudo"}, {"fastrdp_power_admin_groups": ['sudo"]; x = ["']},
                    {"fastrdp_power_admin_groups": ["sudo\n"]}, {"fastrdp_power_admin_groups": ["-sudo"]},
                    {"fastrdp_block_power_actions": "maybe"}, {"fastrdp_power_allow_local_console": "yes please"}):
            with self.subTest(bad=bad):
                self.assertNotEqual(checks.run_checks(**ok, **bad), 0)


class KdcProxy(unittest.TestCase):
    """KDC proxy (MS-KKDCP) on the web gateway (fastrdp_web_kdcproxy; backlog K6):
    python3-kdcproxy under gunicorn behind nginx, only for fastrdp_realm and its KDCs."""

    ROLE = REPO / "ansible/roles/web_gateway"
    REALM = "LAB.EXAMPLE.COM"     # lab inventory

    def kdcproxy_conf(self, name):
        """Read like kdcproxy 1.0 does (KDCProxyConfig: ConfigParser defaults, servers split on " ")."""
        cp = configparser.ConfigParser()
        cp.read(OUT / f"kdcproxy-{name}.conf")
        return cp

    @staticmethod
    def servers(cp, realm, service):
        try:
            return cp.get(realm, service).strip().split(" ")
        except configparser.Error:
            return []

    @staticmethod
    def block(text, start):
        """The {...} block that starts at the first line containing start."""
        i = text.index(start)
        depth, j = 0, text.index("{", i)
        while True:
            depth += {"{": 1, "}": -1}.get(text[j], 0)
            j += 1
            if depth == 0:
                return text[i:j]

    def test_nginx_off_by_default(self):
        text = (OUT / "nginx-web.conf").read_text()
        self.assertNotIn("KdcProxy", text)
        self.assertNotIn("limit_req", text)
        self.assertNotIn("fastrdp-kdcproxy", text)

    def test_nginx_location(self):
        text = (OUT / "nginx-web-kdcproxy.conf").read_text()
        servers = text.split("\nserver {")
        self.assertEqual(len(servers), 3)            # http-level directives, 443, 80
        http_level, tls, plain = servers
        # the zone is defined at http level (the site file is included inside http {})
        self.assertIn("limit_req_zone $binary_remote_addr zone=fastrdp-kdcproxy:10m rate=30r/m;", http_level)
        # HTTPS only: the port-80 server only redirects
        self.assertIn("listen 443 ssl;", tls)
        self.assertNotIn("KdcProxy", plain)
        self.assertIn("return 301 https://$host$request_uri;", plain)
        loc = self.block(tls, "location = /KdcProxy")       # exact match; FreeRDP appends /KdcProxy
        lines = [line.split("#")[0].strip() for line in loc.splitlines()]
        for want in ("limit_except POST { deny all; }",
                     "limit_req zone=fastrdp-kdcproxy burst=10 nodelay;",
                     "limit_req_status 429;",
                     "client_max_body_size 128k;",
                     "proxy_pass http://unix:/run/fastrdp-kdcproxy.sock;"):
            self.assertIn(want, lines)
        # the socket nginx uses is the one systemd listens on
        sock = ini("fastrdp-kdcproxy.socket")["Socket"]
        self.assertEqual(sock["ListenStream"], "/run/fastrdp-kdcproxy.sock")
        self.assertEqual((sock["SocketUser"], sock["SocketGroup"], sock["SocketMode"]), ("root", "www-data", "0660"))

    def test_only_the_realm_and_no_dns(self):
        for name in ("list", "srv", "srv-no-kpasswd-records", "no-kpasswd", "local"):
            with self.subTest(name):
                cp = self.kdcproxy_conf(name)
                # the realm also in lower case (section names are case-sensitive), same servers
                self.assertEqual(cp.sections(), ["global", self.REALM, self.REALM.lower()])
                self.assertEqual(dict(cp[self.REALM]), dict(cp[self.REALM.lower()]))
                self.assertEqual(dict(cp["global"]), {"use_dns": "false"})   # no "configs = mit"
                self.assertIs(cp.getboolean("global", "use_dns"), False)
                # the unit's ExecStartPre looks for exactly this line
                self.assertIn("\nuse_dns = false\n", (OUT / f"kdcproxy-{name}.conf").read_text())
                self.assertEqual(self.servers(cp, "OTHER.EXAMPLE.NET", "kerberos"), [])
                self.assertEqual(self.servers(cp, "Lab.Example.Com", "kerberos"), [])

    def test_servers(self):
        cp = self.kdcproxy_conf("list")
        self.assertEqual(self.servers(cp, self.REALM, "kerberos"),
                         ["kerberos+tcp://dc1.lab.example.com:88", "kerberos+tcp://dc2.lab.example.com:1088",
                          "kerberos+tcp://192.0.2.10:88", "kerberos+tcp://dc1.lab.example.com:750"])
        self.assertEqual(self.servers(cp, self.REALM, "kpasswd"),
                         ["kpasswd+tcp://dc1.lab.example.com:464", "kpasswd+tcp://dc2.lab.example.com:464",
                          "kpasswd+tcp://192.0.2.10:464"])
        # kdcproxy takes scheme, host and port from each URL
        from urllib.parse import urlparse
        url = urlparse("kerberos+tcp://dc2.lab.example.com:1088")
        self.assertEqual((url.scheme, url.hostname, url.port), ("kerberos+tcp", "dc2.lab.example.com", 1088))
        # from SRV records, in their order; kpasswd records, else port 464 of the KDCs
        cp = self.kdcproxy_conf("srv")
        self.assertEqual(self.servers(cp, self.REALM, "kerberos"),
                         ["kerberos+tcp://dc2.lab.example.com:88", "kerberos+tcp://dc1.lab.example.com:88"])
        self.assertEqual(self.servers(cp, self.REALM, "kpasswd"), ["kpasswd+tcp://dc1.lab.example.com:464"])
        cp = self.kdcproxy_conf("srv-no-kpasswd-records")
        self.assertEqual(self.servers(cp, self.REALM, "kpasswd"),
                         ["kpasswd+tcp://dc1.lab.example.com:464", "kpasswd+tcp://dc2.lab.example.com:464"])
        self.assertEqual(self.servers(self.kdcproxy_conf("no-kpasswd"), self.REALM, "kpasswd"), [])

    def test_units_and_gunicorn(self):
        unit = (OUT / "fastrdp-kdcproxy.service").read_text()
        for line in ("Type=notify", "DynamicUser=yes", "Requires=fastrdp-kdcproxy.socket",
                     "Environment=KDCPROXY_CONFIG=/etc/fastrdp/kdcproxy.conf",
                     'ExecStartPre=/usr/bin/grep -qxF "use_dns = false" /etc/fastrdp/kdcproxy.conf',
                     "ExecStart=/usr/bin/gunicorn --config /etc/fastrdp/kdcproxy-gunicorn.conf.py",
                     "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectHome=yes"):
            self.assertIn(line + "\n", unit)
        self.assertNotRegex(unit, r"(?m)^User=|^--bind")
        tasks = (self.ROLE / "tasks/kdcproxy.yml").read_text()
        for dest in ("/etc/fastrdp/kdcproxy.conf", "/etc/fastrdp/kdcproxy-gunicorn.conf.py",
                     '"/etc/systemd/system/{{ item }}"'):
            self.assertIn(f"dest: {dest}\n", tasks)
        self.assertIn("name: [python3-kdcproxy, gunicorn]", tasks)
        # the settings file is Python; no bind (systemd's socket), the WSGI app of python3-kdcproxy
        settings = {}
        exec(compile((OUT / "kdcproxy-gunicorn.conf.py").read_text(), "kdcproxy-gunicorn.conf.py", "exec"), settings)
        settings = {k: v for k, v in settings.items() if not k.startswith("__")}
        self.assertEqual(settings["wsgi_app"], "kdcproxy:application")
        self.assertEqual(settings["worker_class"], "gthread")
        self.assertIs(settings["control_socket_disable"], True)
        self.assertNotIn("bind", settings)
        self.assertGreater(settings["timeout"], 30)

    def test_role_wiring(self):
        main = (self.ROLE / "tasks/main.yml").read_text()
        self.assertIn("include_tasks: kdcproxy.yml\n  when: fastrdp_web_kdcproxy | bool", main)
        self.assertIn("include_tasks: kdcproxy_absent.yml\n  when: not fastrdp_web_kdcproxy | bool", main)
        self.assertLess(main.index("include_tasks: kdcproxy.yml"), main.index("src: nginx-fastrdp-web.conf.j2"))
        handlers = (self.ROLE / "handlers/main.yml").read_text()
        self.assertIn("loop: [fastrdp-kdcproxy.socket, fastrdp-kdcproxy.service]", handlers)
        defaults = (self.ROLE / "defaults/main.yml").read_text()
        self.assertIn("\nfastrdp_web_kdcproxy: false\n", defaults)
        self.assertIn("\nfastrdp_web_kdcproxy_kdcs: []\n", defaults)

    def test_srv_lookup_script(self):
        """files/fastrdp_kdcproxy_srv.py with a stub dnspython."""
        stub = textwrap.dedent("""
            import sys, types
            class NXDOMAIN(Exception): pass
            class NoAnswer(Exception): pass
            class DNSException(Exception): pass
            class Rec:
                def __init__(self, p, w, port, t): self.priority, self.weight, self.port, self.target = p, w, port, t
            ANSWERS = {
                "_kerberos._tcp.lab.example.com": [Rec(10, 0, 88, "DC2.lab.example.com."), Rec(0, 50, 88, "dc3.lab.example.com."),
                                                   Rec(0, 100, 88, "dc1.lab.example.com."), Rec(20, 0, 88, ".")],
            }
            def resolve(name, rdtype):
                assert rdtype == "SRV"
                if name.startswith("_kpasswd"): raise NoAnswer()
                if name not in ANSWERS: raise NXDOMAIN()
                return ANSWERS[name]
            dns = types.ModuleType("dns"); dns.exception = types.ModuleType("dns.exception")
            dns.resolver = types.ModuleType("dns.resolver")
            dns.exception.DNSException = DNSException
            dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.resolve = NXDOMAIN, NoAnswer, resolve
            sys.modules.update({"dns": dns, "dns.exception": dns.exception, "dns.resolver": dns.resolver})
            exec(compile(open(SCRIPT).read(), SCRIPT, "exec"), {"__name__": "__main__"})
        """)
        code = f"SCRIPT = {str(self.ROLE / 'files/fastrdp_kdcproxy_srv.py')!r}\n" + stub
        res = subprocess.run([sys.executable, "-I", "-c", code, "LAB.Example.COM"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout), {
            "kerberos": ["dc1.lab.example.com:88", "dc3.lab.example.com:88", "dc2.lab.example.com:88"],
            "kpasswd": []})
        res = subprocess.run([sys.executable, "-I", "-c", code, "OTHER.TEST"], capture_output=True, text=True)
        self.assertEqual(json.loads(res.stdout), {"kerberos": [], "kpasswd": []})

    def test_real_kdcproxy(self):
        """The rendered files with the real kdcproxy (+ gunicorn, socket-activated) and a fake KDC:
        the realm is forwarded, other realms get 503. Needs an interpreter with kdcproxy:
        python3 (python3-kdcproxy, gunicorn) or FASTRDP_KDCPROXY_PYTHON (a venv with
        pip install kdcproxy gunicorn); skipped otherwise."""
        python = os.environ.get("FASTRDP_KDCPROXY_PYTHON", sys.executable)
        if subprocess.run([python, "-c", "import kdcproxy"], capture_output=True).returncode != 0:
            self.skipTest(f"kdcproxy not importable by {python}")
        res = subprocess.run([python, "-I", str(HERE / "kdcproxy_check.py"), str(OUT / "kdcproxy-local.conf"),
                              self.REALM, "18088", str(OUT / "kdcproxy-gunicorn.conf.py")],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr)
        r = json.loads(res.stdout)
        self.assertEqual(r["resolvers"], ["KDCProxyConfig"])            # no DNSResolver
        self.assertEqual(r["own"], {"status": "200 OK", "reply": "7e023000", "kdc_got": ["6a023000"]})
        self.assertEqual(r["lower"], {"status": "200 OK", "kdc_got": ["6a023000"]})
        for name in ("other", "mixed", "none"):
            self.assertEqual(r[name], {"status": "503 Service Unavailable", "kdc_got": []}, name)
        self.assertEqual(r["get"], "405 Method Not Allowed")
        self.assertEqual(r["kpasswd"], ["kpasswd+tcp://127.0.0.1:464"])
        # why the unit refuses to start without the file: kdcproxy then asks DNS for any realm
        self.assertIn("DNSResolver", r["resolvers_without_file"])
        if r["gunicorn"] is not None:
            g = r["gunicorn"]
            self.assertEqual((g.get("own"), g.get("other")), ("HTTP/1.1 200 OK", "HTTP/1.1 503 Service Unavailable"),
                             g)
            self.assertEqual(g["files"], [])            # no gunicorn.ctl (gunicorn 25.1+)

    def test_checks(self):
        run = HomeDirectories.run_checks
        ok = {"fastrdp_realm": "LAB.EXAMPLE.COM", "fastrdp_domain": "lab.example.com"}
        web = dict(ok, fastrdp_web_enabled=True, fastrdp_web_kdcproxy=True)
        for good in ({}, {"fastrdp_web_kdcproxy_kdcs": ["dc1.lab.example.com", "dc2.lab.example.com:88", "192.0.2.10"]},
                     {"fastrdp_web_kdcproxy_kpasswd": False, "fastrdp_web_kdcproxy_rate_per_minute": 120,
                      "fastrdp_web_kdcproxy_burst": 0}):
            with self.subTest(good=good):
                self.assertEqual(run(self, **web, **good), 0)
        self.assertEqual(run(self, **ok, fastrdp_web_kdcproxy=False), 0)
        bad = {
            "without the web gateway": dict(ok, fastrdp_web_kdcproxy=True),
            "not a bool": dict(web, fastrdp_web_kdcproxy="yes please"),
            "kpasswd not a bool": dict(web, fastrdp_web_kdcproxy_kpasswd="maybe"),
            "kdcs as a string": dict(web, fastrdp_web_kdcproxy_kdcs="dc1.lab.example.com"),
            "kdc as a URL": dict(web, fastrdp_web_kdcproxy_kdcs=["kerberos://dc1.lab.example.com"]),
            "two kdcs in one entry": dict(web, fastrdp_web_kdcproxy_kdcs=["dc1.lab.example.com dc2.lab.example.com"]),
            "kdc with a newline": dict(web, fastrdp_web_kdcproxy_kdcs=["dc1.lab.example.com\n[EVIL.TEST]"]),
            "port 0": dict(web, fastrdp_web_kdcproxy_kdcs=["dc1.lab.example.com:0"]),
            "port too big": dict(web, fastrdp_web_kdcproxy_kdcs=["dc1.lab.example.com:88888"]),
            "rate 0": dict(web, fastrdp_web_kdcproxy_rate_per_minute=0),
            "rate with a unit": dict(web, fastrdp_web_kdcproxy_rate_per_minute="10r/s"),
            "burst negative": dict(web, fastrdp_web_kdcproxy_burst=-1),
            "realm not a section name": dict(web, fastrdp_realm="LAB.EXAMPLE.COM]\n[global"),
            "realm named like kdcproxy's own section": dict(web, fastrdp_realm="GLOBAL"),
        }
        for name, extra in bad.items():
            with self.subTest(name):
                self.assertNotEqual(run(self, **extra), 0)


class TgtNotify(unittest.TestCase):
    """Kerberos login reminder (desktops role, fastrdp_tgt_notify*; backlog K4): the
    rendered /etc/fastrdp/tgt-notify.conf is read by tgt-notify's own parser, and the
    common checks refuse what it would reject in every session."""

    ROLE = REPO / "ansible/roles/desktops"

    def test_defaults(self):
        from fastrdp_broker import tgtnotify
        s = tgtnotify.load(OUT / "tgt-notify-default.conf")
        self.assertTrue(s.enabled)
        self.assertEqual(s.thresholds, (86400, 7200))
        self.assertEqual(s.interval, 600)
        self.assertTrue(s.notify_expired)
        self.assertEqual(s.texts, tgtnotify.Settings().texts)   # built-in texts

    def test_custom(self):
        from fastrdp_broker import tgtnotify
        s = tgtnotify.load(OUT / "tgt-notify-custom.conf")
        self.assertFalse(s.enabled)
        self.assertEqual(s.thresholds, (172800, 5400, 3600))
        self.assertEqual(s.interval, 300)
        self.assertFalse(s.notify_expired)
        self.assertEqual(s.texts["summary"], "Kerberos-Anmeldung endet in {left}")
        self.assertEqual(s.texts["body"], 'Ab {deadline} kein Zugriff auf "H:\\" ({principal}).\nNeu verbinden: Ä')
        self.assertEqual(s.texts["expired_body"], tgtnotify.EXPIRED_BODY)

    def test_tasks(self):
        tasks = (self.ROLE / "tasks/tgt_notify.yml").read_text()
        self.assertIn("import_tasks: tgt_notify.yml", (self.ROLE / "tasks/main.yml").read_text())
        for text in ("dest: /etc/fastrdp/tgt-notify.conf", "dest: /usr/libexec/fastrdp/tgt-notify",
                     "dest: /etc/xdg/autostart/fastrdp-tgt-notify.desktop", "name: libnotify-bin",
                     "name: fastrdp-session"):
            self.assertIn(text, tasks)
        # the packaged files are the ones the build install copies
        install = (REPO / "debian/fastrdp-session.install").read_text()
        self.assertIn("broker/session/autostart/fastrdp-tgt-notify.desktop etc/xdg/autostart/", install)
        self.assertIn("broker/session/libexec/* usr/libexec/fastrdp/", install)
        desktop = configparser.ConfigParser(interpolation=None)
        desktop.read(REPO / "broker/session/autostart/fastrdp-tgt-notify.desktop")
        self.assertEqual(desktop["Desktop Entry"]["Exec"], "/usr/libexec/fastrdp/tgt-notify")
        self.assertNotIn("OnlyShowIn", desktop["Desktop Entry"])   # every desktop
        # wlroots compositors run no XDG autostart: wlroots-in-x starts it
        self.assertIn("/tgt-notify\" &", (REPO / "broker/session/libexec/wlroots-in-x").read_text())

class BrowserSso(unittest.TestCase):
    """Browsers that reach the session TGT in KCM and their SPNEGO policies (desktops role,
    fastrdp_firefox_deb, fastrdp_browser_spnego_domains; backlog K9)."""

    ROLE = REPO / "ansible/roles/desktops"
    MOZILLA_FPR = "35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3"

    def policies(self, name):
        return json.loads((OUT / name).read_text())["policies"]

    def test_firefox_spnego(self):
        p = self.policies("firefox-policies-spnego.json")
        # https only, lower case; Firefox matches the name and hosts below it with a dot boundary
        self.assertEqual(p, {"Authentication": {"SPNEGO": ["https://lab.example.com", "https://intranet.example.org"]}})

    def test_firefox_extra_policies_merged(self):
        p = self.policies("firefox-policies-merged.json")
        self.assertIs(p["DisableTelemetry"], True)
        self.assertIs(p["Authentication"]["Locked"], False)
        self.assertEqual(p["Authentication"]["SPNEGO"], ["https://lab.example.com"])   # the domains win
        self.assertEqual(self.policies("firefox-policies-extra.json"), {"DisableTelemetry": True})

    def test_chromium_allowlist(self):
        data = json.loads((OUT / "chromium-spnego.json").read_text())
        self.assertEqual(data, {"AuthServerAllowlist":
                                "lab.example.com,*.lab.example.com,intranet.example.org,*.intranet.example.org"})

    def test_defaults_off(self):
        text = (self.ROLE / "defaults/main.yml").read_text()
        self.assertRegex(text, r"(?m)^fastrdp_firefox_deb: false$")
        self.assertRegex(text, r"(?m)^fastrdp_browser_spnego_domains: \[\]$")
        self.assertRegex(text, r"(?m)^fastrdp_firefox_policies: \{\}$")
        self.assertRegex(text, rf"(?m)^fastrdp_firefox_mozilla_key_fingerprint: {self.MOZILLA_FPR}$")
        self.assertIn("ansible.builtin.include_tasks: browsers.yml", (self.ROLE / "tasks/main.yml").read_text())

    def test_mozilla_repository_tasks(self):
        tasks = (self.ROLE / "tasks/browsers.yml").read_text()
        # the downloaded key is checked before it becomes an APT keyring
        self.assertLess(tasks.index("name: Browsers - the key is Mozilla's"),
                        tasks.index("dest: /etc/apt/keyrings/packages.mozilla.org.asc"))
        self.assertIn("Signed-By: /etc/apt/keyrings/packages.mozilla.org.asc", tasks)
        self.assertIn("URIs: https://packages.mozilla.org/apt", tasks)
        # pinned: only Firefox, above Ubuntu's 1:1snap1 transitional package
        pin = re.search(r"Package: (.*)\n\s*Pin: (.*)\n\s*Pin-Priority: (\d+)", tasks)
        self.assertEqual(pin.groups(), ("firefox firefox-l10n-*", "origin packages.mozilla.org", "1000"))
        self.assertIn('Unattended-Upgrade::Origins-Pattern:: "site=packages.mozilla.org";', tasks)
        self.assertIn("allow_downgrade: true", tasks)
        # Ubuntu only; Debian gets its own firefox-esr
        self.assertIn("ansible_facts.distribution == 'Ubuntu'", tasks)
        self.assertIn("name: firefox-esr", tasks)
        # snaps are never removed by the role
        self.assertNotRegex(tasks, r"argv: \[snap, remove")
        self.assertNotIn("community.general.snap", tasks)

    def test_key_fingerprint_record(self):
        """The role takes the first fpr record of `gpg --with-colons --show-keys` as the
        primary key's fingerprint and refuses files with more than one primary key."""
        gpg = shutil.which("gpg")
        if not gpg:
            if os.environ.get("FASTRDP_TESTS_STRICT") == "1":
                self.fail("gpg not found")
            self.skipTest("gpg not found")
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, GNUPGHOME=home)

            def gpg_run(*args, **kw):
                return subprocess.run([gpg, "--batch", *args], env=env, capture_output=True, text=True,
                                      check=True, **kw).stdout

            fprs = []
            for uid in ("signer@example.com", "other@example.com"):
                gpg_run("--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "never")
                fpr = re.search(r"(?m)^fpr:+([0-9A-F]{40}):", gpg_run("--with-colons", "--list-keys", uid)).group(1)
                gpg_run("--passphrase", "", "--quick-add-key", fpr, "cv25519", "encr", "never")   # a subkey with its own fpr
                fprs.append(fpr)
            one = Path(home) / "one.asc"
            one.write_text(gpg_run("--armor", "--export", fprs[0]))
            both = Path(home) / "both.asc"
            both.write_text(gpg_run("--armor", "--export", *fprs))
            lines = gpg_run("--with-colons", "--show-keys", str(one)).splitlines()
            self.assertEqual(len([s for s in lines if s.startswith("pub:")]), 1)
            self.assertEqual([s for s in lines if s.startswith("fpr:")][0].split(":")[9], fprs[0])
            self.assertEqual(len([s for s in lines if s.startswith("fpr:")]), 2)   # the subkey's comes later
            lines = gpg_run("--with-colons", "--show-keys", str(both)).splitlines()
            self.assertEqual(len([s for s in lines if s.startswith("pub:")]), 2)

    def test_checks(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        checks = CommonChecks()
        for good in ({"fastrdp_tgt_notify": False}, {"fastrdp_tgt_notify_thresholds": []},
                     {"fastrdp_tgt_notify_thresholds": ["7d", "36h", "90m", 3600]},
                     {"fastrdp_tgt_notify_interval": "1h", "fastrdp_tgt_notify_expired": False},
                     {"fastrdp_tgt_notify_texts": {"summary": "Noch {left}", "body": "Ab {deadline} ({principal})"}}):
            with self.subTest(good=good):
                self.assertEqual(checks.run_checks(**ok, **good), 0)
        for bad in ({"fastrdp_tgt_notify": "maybe"}, {"fastrdp_tgt_notify_thresholds": "24h"},
                    {"fastrdp_tgt_notify_thresholds": ["24 h"]}, {"fastrdp_tgt_notify_thresholds": ["0h"]},
                    {"fastrdp_tgt_notify_thresholds": ["1w"]}, {"fastrdp_tgt_notify_interval": "0"},
                    {"fastrdp_tgt_notify_interval": "soon"}, {"fastrdp_tgt_notify_texts": "hello"},
                    {"fastrdp_tgt_notify_texts": {"title": "x"}}, {"fastrdp_tgt_notify_texts": {"body": ""}},
                    {"fastrdp_tgt_notify_texts": {"body": "{user}"}}, {"fastrdp_tgt_notify_texts": {"body": "{left"}},
                    {"fastrdp_tgt_notify_texts": {"summary": ["x"]}}):
            with self.subTest(bad=bad):
                self.assertNotEqual(checks.run_checks(**ok, **bad), 0)

        for good in ({}, {"fastrdp_firefox_deb": True},
                     {"fastrdp_browser_spnego_domains": ["example.com", "intranet.lab-1.example.org"]},
                     {"fastrdp_firefox_policies": {"DisableTelemetry": True}},
                     {"fastrdp_firefox_mozilla_key_fingerprint": self.MOZILLA_FPR.lower()}):
            with self.subTest(good=good):
                self.assertEqual(checks.run_checks(**ok, **good), 0)
        bad = {
            "deb not a bool": {"fastrdp_firefox_deb": "snap"},
            "domains as a string": {"fastrdp_browser_spnego_domains": "example.com"},
            "domains as a mapping": {"fastrdp_browser_spnego_domains": {"example.com": True}},
            "bare TLD": {"fastrdp_browser_spnego_domains": ["com"]},
            "wildcard": {"fastrdp_browser_spnego_domains": ["*.example.com"]},
            "leading dot": {"fastrdp_browser_spnego_domains": [".example.com"]},
            "URL": {"fastrdp_browser_spnego_domains": ["https://intranet.example.com"]},
            "IP address": {"fastrdp_browser_spnego_domains": ["10.0.0.1"]},
            "JSON injection": {"fastrdp_browser_spnego_domains": ['example.com","evil.test']},
            "trailing newline": {"fastrdp_browser_spnego_domains": ["example.com\n"]},
            "comma list": {"fastrdp_browser_spnego_domains": ["example.com,evil.test"]},
            "policies as a list": {"fastrdp_firefox_policies": ["DisableTelemetry"]},
            "short fingerprint": {"fastrdp_firefox_mozilla_key_fingerprint": "DC6315A3"},
        }
        for name, extra in bad.items():
            with self.subTest(name):
                self.assertNotEqual(checks.run_checks(**ok, **extra), 0)

    def test_smoke_script_hints(self):
        text = (REPO / "tests/smoke/check-session-tgt.sh").read_text()
        self.assertIn("fastrdp_firefox_deb: true", text)
        self.assertIn("fastrdp_browser_spnego_domains", text)
        self.assertIn("heim_org.h5l.kcm-socket", text)


if __name__ == "__main__":
    unittest.main()
