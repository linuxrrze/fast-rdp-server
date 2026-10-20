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
import shutil
import subprocess
import sys
import tempfile
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
    def check(self, name, tls_allowed, tls_from=""):
        p = ini(name)
        self.assertEqual(p["Server"]["Port"], "3389")
        self.assertEqual(p["Target"]["FixedTarget"], "false")
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

    def test_tls_logins(self):
        self.check("proxy-lab.ini", "true")

    def test_web_needs_tls(self):
        self.check("proxy-web-only.ini", "true", "127.0.0.1,::1")

    def test_tls_login_sources_override(self):
        self.check("proxy-sources.ini", "true", "127.0.0.1,::1,10.1.2.0/24,2001:db8::/32")

    def test_nla_only(self):
        self.check("proxy-nla-only.ini", "false")


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

    def test_session_tgt_required(self):
        self.assertEqual(broker_config.parse(toml("broker-tgt-required.toml")).broker.session_tgt, "required")

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

    def run_checks(self, **extra):
        args = [shutil.which("ansible-playbook"), "-i", "localhost,", str(HERE / "check_common.yml")]
        for k, v in extra.items():
            args += ["-e", f"{k}={v}" if isinstance(v, (str, int)) else json.dumps({k: v})]
        env = dict(os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_NOCOLOR="1",
                   ANSIBLE_PYTHON_INTERPRETER=sys.executable)
        env.pop("ANSIBLE_CONFIG", None)
        return subprocess.run(args, env=env, capture_output=True, text=True, cwd=HERE).returncode

    def test_minimal_passes(self):
        self.assertEqual(self.run_checks(fastrdp_realm="EXAMPLE.COM", fastrdp_domain="example.com"), 0)

    def test_failures(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        cases = {
            "no realm": {"fastrdp_domain": "example.com"},
            "default desktop not offered": dict(ok, fastrdp_default_desktop="gnome"),
            "group default not offered": dict(ok, fastrdp_group_desktops='{"rdp-kde": "plasma"}'),
            "desktop groups for unknown desktop": dict(ok, fastrdp_desktop_groups='{"plasma": ["x"]}'),
            "mfa without url": dict(ok, fastrdp_mfa_mode="push"),
            "unknown mfa mode": dict(ok, fastrdp_mfa_mode="sms", fastrdp_privacyidea_url="https://pi"),
            "unknown identity provider": dict(ok, fastrdp_identity_provider="ldap"),
            "xrdp port = front port": dict(ok, fastrdp_xrdp_port=3389),
            "unknown session_tgt": dict(ok, fastrdp_session_tgt="yes"),
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

    def test_reconnect_grace_passes(self):
        ok = {"fastrdp_realm": "EXAMPLE.COM", "fastrdp_domain": "example.com"}
        for grace in (0, 600, 3600):
            with self.subTest(grace):
                self.assertEqual(self.run_checks(**ok, fastrdp_mfa_reconnect_grace=grace,
                                                 fastrdp_mfa_reconnect_grace_same_address=False), 0)

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
        self.assertEqual(cfg.oidc.issuer, "https://keycloak.lab.example.com/realms/lab")
        self.assertEqual(cfg.oidc.strip_domains, ["lab.example.com"])
        self.assertEqual(cfg.oidc.required_acr, ["mfa"])
        self.assertEqual(cfg.oidc.ca_file, "/etc/fastrdp/webgate-idp-ca.pem")
        self.assertEqual(cfg.guacamole.connection_port, 3389)
        self.assertEqual(cfg.guacamole.cert_fingerprint_file, "/etc/fastrdp/front.fingerprint")
        # values are strings for Guacamole, whatever YAML type they had
        self.assertEqual(cfg.guacamole.rdp_parameters,
                         {"enable-font-smoothing": "true", "color-depth": "32", "resize-method": "display-update"})


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
                         {"krb5_renewable_lifetime": "7d", "krb5_renew_interval": "1h"})
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


if __name__ == "__main__":
    unittest.main()
