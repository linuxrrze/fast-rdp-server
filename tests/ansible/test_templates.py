# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Role templates render to valid configuration with the expected values.

Renders render.yml through ansible-playbook (the real Jinja2 + filters), then parses
the results: gfx.toml/broker.toml/webgate.toml with tomllib, broker.toml and
webgate.toml also with the daemons' own config parsers, the INI files with
configparser. Skipped without ansible-playbook unless FASTRDP_TESTS_STRICT=1.
"""

import configparser
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
    def check(self, name, tls_allowed):
        p = ini(name)
        self.assertEqual(p["Server"]["Port"], "3389")
        self.assertEqual(p["Target"]["FixedTarget"], "false")
        self.assertEqual(p["Security"]["ServerNlaSecurity"], "true")
        self.assertEqual(p["Security"]["ServerRdpSecurity"], "false")
        self.assertEqual(p["Security"]["ClientAllowFallbackToTls"], "false")
        self.assertEqual(p["Security"]["ServerTlsSecurity"], tls_allowed)
        self.assertEqual(p["FastRDP"]["AllowTls"], tls_allowed)
        self.assertEqual(p["Plugins"]["Modules"], "fastrdp")
        self.assertEqual(p["Plugins"]["Required"], "fastrdp")
        self.assertEqual(p["FastRDP"]["BrokerSocket"], "/run/fastrdp/broker.sock")
        self.assertEqual(p["FastRDP"]["Timeout"], "120")
        self.assertEqual(p["Channels"]["PassthroughIsBlacklist"], "true")

    def test_tls_logins(self):
        self.check("proxy-lab.ini", "true")

    def test_web_needs_tls(self):
        self.check("proxy-web-only.ini", "true")

    def test_nla_only(self):
        self.check("proxy-nla-only.ini", "false")


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
            args += ["-e", f"{k}={v}"]
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
        }
        for name, extra in cases.items():
            with self.subTest(name):
                self.assertNotEqual(self.run_checks(**extra), 0)


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


if __name__ == "__main__":
    unittest.main()
