import os
import pwd
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, identity, netcheck
from fastrdp_broker.config import ConfigError, MfaSection
from fastrdp_broker.identity import LocalUser
from fastrdp_broker.mfa import split_otp
from fastrdp_broker.tokens import TOKEN_PREFIX, TokenStore

EXAMPLE = Path(__file__).parent.parent / "config" / "broker.toml.example"


def load_example() -> dict:
    with open(EXAMPLE, "rb") as fh:
        return tomllib.load(fh)


class ConfigTests(unittest.TestCase):
    def test_example_parses(self):
        cfg = config.parse(load_example())
        self.assertEqual(cfg.default_desktop, "xfce")
        self.assertEqual(cfg.desktops["gnome"].backend, "gnome")
        self.assertEqual(cfg.backends["xrdp"].port, 3390)
        self.assertEqual(cfg.backends["plasma"].security, "nla")
        self.assertEqual(cfg.auth.realms, ["EXAMPLE.COM"])
        self.assertEqual(cfg.group_defaults["rdp-kde"], "plasma")

    def test_unknown_key_rejected(self):
        raw = load_example()
        raw["auth"]["typo"] = 1
        with self.assertRaises(ConfigError):
            config.parse(raw)

    def test_xrdp_desktop_needs_xsession(self):
        raw = load_example()
        del raw["desktops"]["xfce"]["xsession"]
        with self.assertRaises(ConfigError):
            config.parse(raw)

    def test_mfa_requires_url(self):
        raw = load_example()
        raw["mfa"]["privacyidea"]["url"] = ""
        with self.assertRaises(ConfigError):
            config.parse(raw)

    def test_default_desktop_must_exist(self):
        raw = load_example()
        raw["defaults"]["desktop"] = "nope"
        with self.assertRaises(ConfigError):
            config.parse(raw)


class OtpSplitTests(unittest.TestCase):
    def setUp(self):
        self.cfg = MfaSection(otp_lengths=[6], yubikey_otp=True)

    def test_totp(self):
        self.assertEqual(split_otp("secret123456", self.cfg), ("secret", "123456"))

    def test_yubikey(self):
        yk = "cccccbhuinjd" + "ghvtkjdrkbbrelidcerbjcuuetfngj"[:32].ljust(32, "c")
        self.assertEqual(len(yk), 44)
        self.assertEqual(split_otp("pw" + yk, self.cfg), ("pw", yk))

    def test_no_otp(self):
        self.assertIsNone(split_otp("justapassword", self.cfg))
        self.assertIsNone(split_otp("123456", self.cfg))  # nothing left for the password


class TokenTests(unittest.TestCase):
    def test_one_time(self):
        store = TokenStore(ttl=60)
        tok = store.issue("alice", "pw")
        self.assertTrue(tok.startswith(TOKEN_PREFIX))
        self.assertEqual(store.redeem("bob", tok), (False, None))
        self.assertEqual(store.redeem("alice", tok), (True, "pw"))
        self.assertEqual(store.redeem("alice", tok), (False, None))

    def test_expiry(self):
        store = TokenStore(ttl=1)
        tok = store.issue("alice", None)
        with mock.patch("fastrdp_broker.tokens.time.monotonic", return_value=time.monotonic() + 5):
            self.assertEqual(store.redeem("alice", tok), (False, None))


class NetcheckTests(unittest.TestCase):
    def test_parse_proc(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(f"{root}/net")
            header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            with open(f"{root}/net/tcp", "w") as fh:
                fh.write(header)
                # 127.0.0.1:3390 LISTEN uid 998; 10.0.0.5:3389 LISTEN (ignored); 127.0.0.1:33900 ESTABLISHED
                fh.write("   0: 0100007F:0D3E 00000000:0000 0A 0:0 00:0 0 998 0 1 1\n")
                fh.write("   1: 0500000A:0D3D 00000000:0000 0A 0:0 00:0 0 0 0 2 1\n")
                fh.write("   2: 0100007F:846C 0100007F:9000 01 0:0 00:0 0 1000 0 3 1\n")
            with open(f"{root}/net/tcp6", "w") as fh:
                fh.write(header)
                fh.write("   0: 00000000000000000000000000000000:846C 00000000000000000000000000000000:0000 0A 0:0 00:0 0 1000 0 4 1\n")
            self.assertEqual(netcheck.listener_uids(3390, root), {998})
            self.assertEqual(netcheck.listener_uids(3389, root), set())
            self.assertEqual(netcheck.listener_uids(33900, root), {1000})


class IdentityTests(unittest.TestCase):
    def test_principal(self):
        self.assertEqual(identity.split_principal("alice@example.com"), ("alice", "EXAMPLE.COM"))
        with self.assertRaises(identity.IdentityError):
            identity.split_principal("alice")

    def test_normalize(self):
        self.assertEqual(identity.normalize_rdp_user("EXAMPLE\\alice"), "alice")
        self.assertEqual(identity.normalize_rdp_user("alice@example.com"), "alice")
        self.assertEqual(identity.normalize_rdp_user("alice"), "alice")

    def test_choose_desktop(self):
        cfg = config.parse(load_example())
        me = pwd.getpwuid(os.getuid())
        with tempfile.TemporaryDirectory() as home:
            user = LocalUser(me.pw_name, me.pw_uid, me.pw_gid, home, frozenset({"rdp-kde"}))
            # group default
            self.assertEqual(identity.choose_desktop(cfg, user, None), "plasma")
            # user preference beats group default
            os.makedirs(f"{home}/.config/fastrdp")
            Path(f"{home}/.config/fastrdp/desktop").write_text("mate\n")
            self.assertEqual(identity.choose_desktop(cfg, user, None), "mate")
            # client hint beats preference; unknown hints are ignored
            self.assertEqual(identity.choose_desktop(cfg, user, "fastrdp:gnome"), "gnome")
            self.assertEqual(identity.choose_desktop(cfg, user, "bogus"), "mate")

    def test_pref_symlink_ignored(self):
        me = pwd.getpwuid(os.getuid())
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(f"{home}/.config/fastrdp")
            Path(f"{home}/target").write_text("gnome\n")
            os.symlink(f"{home}/target", f"{home}/.config/fastrdp/desktop")
            user = LocalUser(me.pw_name, me.pw_uid, me.pw_gid, home, frozenset())
            self.assertIsNone(identity.read_desktop_pref(user))

    def test_restricted_desktop(self):
        raw = load_example()
        raw["desktops"]["gnome"]["groups"] = ["gnome-pilot"]
        cfg = config.parse(raw)
        me = pwd.getpwuid(os.getuid())
        user = LocalUser(me.pw_name, me.pw_uid, me.pw_gid, "/nonexistent", frozenset())
        self.assertEqual(identity.choose_desktop(cfg, user, "gnome"), "xfce")


if __name__ == "__main__":
    unittest.main()


class BackendHelperTests(unittest.TestCase):
    def test_xrdp_listener_defaults_to_root(self):
        raw = load_example()
        del raw["backends"]["xrdp"]["listener_user"]
        self.assertEqual(config.parse(raw).backends["xrdp"].listener_user, "root")

    def test_port_reserved_until_released(self):
        from fastrdp_broker.backends.gnome import GnomeBackend
        from fastrdp_broker.state import StateStore
        from fastrdp_broker.tokens import TokenStore

        raw = load_example()
        raw["broker"]["port_range"] = [41000, 41002]
        cfg = config.parse(raw)
        with tempfile.TemporaryDirectory() as d:
            state = StateStore(d)
            backend = GnomeBackend(cfg, state, TokenStore(60))
            with mock.patch("fastrdp_broker.netcheck.listeners", return_value=[]), \
                    mock.patch("fastrdp_broker.netcheck.port_in_use", return_value=False):
                a = backend.allocate_port()
                b = backend.allocate_port()  # concurrent start of another user
                self.assertNotEqual(a, b)
                backend.release_port(a)
                self.assertEqual(backend.allocate_port(), a)
            self.assertEqual(oct(os.stat(d).st_mode & 0o777), "0o711")
