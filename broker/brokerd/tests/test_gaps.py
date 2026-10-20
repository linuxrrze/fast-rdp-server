# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Regression tests for branches the other broker tests do not reach: config
validation, wire protocol limits, MFA modes and exempt groups, login policy,
root-only operations, back-end start/stop error paths, state, privacyIDEA client."""

import asyncio
import io
import json
import os
import pwd
import socket
import tempfile
import tomllib
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from fastrdp_broker import __main__ as cli
from fastrdp_broker import config, identity, mfa, netcheck, protocol, sysutil
from fastrdp_broker.backends import BackendError, LoginRequest, Target
from fastrdp_broker.backends.gnome import GnomeBackend
from fastrdp_broker.backends.plasma import PlasmaBackend
from fastrdp_broker.backends.xrdp import XrdpBackend
from fastrdp_broker.config import ConfigError, MfaSection, PrivacyIdeaSection
from fastrdp_broker.identity import IdentityError, LocalUser
from fastrdp_broker.privacyidea import PrivacyIdea, PrivacyIdeaError
from fastrdp_broker.state import Session, StateStore
from fastrdp_broker.tokens import TokenStore
from test_server import ME, make_cfg, request

EXAMPLE = Path(__file__).parent.parent / "config" / "broker.toml.example"


def raw_example() -> dict:
    with open(EXAMPLE, "rb") as fh:
        return tomllib.load(fh)


def user(name="alice", groups=("rdp-users",), uid=1500, home="/nonexistent"):
    return LocalUser(name, uid, uid, home, frozenset(groups))


# ------------------------------------------------------------------ config
class ConfigValidationTests(unittest.TestCase):
    def rejects(self, mutate):
        raw = raw_example()
        mutate(raw)
        with self.assertRaises(ConfigError):
            config.parse(raw)

    def test_port_range(self):
        for rng in ([80, 90], [40000, 40000], [40000, 39000], [40000, 70000]):
            with self.subTest(rng=rng):
                self.rejects(lambda r, rng=rng: r["broker"].__setitem__("port_range", rng))

    def test_mfa_mode(self):
        self.rejects(lambda r: r["mfa"].__setitem__("mode", "sms"))

    def test_mfa_none_needs_no_url(self):
        raw = raw_example()
        raw["mfa"]["mode"] = "none"
        raw["mfa"]["privacyidea"]["url"] = ""
        self.assertEqual(config.parse(raw).mfa.mode, "none")

    def test_desktop_backend(self):
        self.rejects(lambda r: r["desktops"]["xfce"].__setitem__("backend", "vnc"))

    def test_no_desktops(self):
        def drop(r):
            r["desktops"] = {}
            r["defaults"] = {}
        self.rejects(drop)

    def test_unknown_backend_section(self):
        self.rejects(lambda r: r["backends"].__setitem__("vnc", {}))

    def test_backend_security(self):
        self.rejects(lambda r: r["backends"]["xrdp"].__setitem__("security", "rdp"))

    def test_geometry(self):
        for g in ("1920", "100x100", "1920x99999", "axb"):
            with self.subTest(g=g):
                self.rejects(lambda r, g=g: r["defaults"].__setitem__("geometry", g))
        raw = raw_example()
        raw["defaults"]["geometry"] = "1280X720"
        self.assertEqual(config.parse(raw).default_geometry, "1280x720")

    def test_unknown_sections_and_keys(self):
        self.rejects(lambda r: r.__setitem__("typo", {}))
        self.rejects(lambda r: r["defaults"].__setitem__("typo", 1))
        self.rejects(lambda r: r["mfa"]["privacyidea"].__setitem__("typo", 1))
        self.rejects(lambda r: r["desktops"]["xfce"].__setitem__("typo", 1))

    def test_group_default_must_exist(self):
        self.rejects(lambda r: r["defaults"]["groups"].__setitem__("rdp-x", "nope"))

    def test_realms_upper_and_default_desktop(self):
        raw = raw_example()
        raw["auth"]["realms"] = ["example.com"]
        del raw["defaults"]["desktop"]
        cfg = config.parse(raw)
        self.assertEqual(cfg.auth.realms, ["EXAMPLE.COM"])
        self.assertEqual(cfg.default_desktop, "xfce")  # first desktop
        self.assertEqual(cfg.backends["gnome"].security, "nla")


class CliTests(unittest.TestCase):
    def test_check(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(cli.daemon_main(["--check", "-c", str(EXAMPLE)]), 0)
        self.assertIn("config ok", out.getvalue())

    def test_bad_config_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fh:
            fh.write("[typo]\n")
            fh.flush()
            with self.assertLogs(level="ERROR"):
                self.assertEqual(cli.daemon_main(["--check", "-c", fh.name]), 2)
        with self.assertLogs(level="ERROR"):
            self.assertEqual(cli.daemon_main(["--check", "-c", "/nonexistent/broker.toml"]), 2)


# ---------------------------------------------------------------- protocol
class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def read(self, data: bytes, limit=protocol.MAX_LINE):
        r = asyncio.StreamReader(limit=limit)
        r.feed_data(data)
        r.feed_eof()
        return await protocol.read_message(r)

    async def test_eof_is_none(self):
        self.assertIsNone(await self.read(b""))

    async def test_rejected_messages(self):
        for data in (b'{"op":"x"}', b"nojson\n", b"[1]\n", b'{"x":1}\n', b'{"op":1}\n'):
            with self.subTest(data=data), self.assertRaises(protocol.ProtocolError):
                await self.read(data)

    async def test_too_large(self):
        with self.assertRaises(protocol.ProtocolError):
            await self.read(b'{"op":"' + b"a" * 200 + b'"}\n', limit=64)

    def test_str_field(self):
        f = protocol.str_field
        self.assertIsNone(f({"a": ""}, "a"))
        with self.assertRaises(protocol.ProtocolError):
            f({"a": ""}, "a", required=True)
        with self.assertRaises(protocol.ProtocolError):
            f({"a": 5}, "a")
        with self.assertRaises(protocol.ProtocolError):
            f({"a": "x" * 65}, "a", max_len=64)

    def test_int_field(self):
        f = protocol.int_field
        self.assertIsNone(f({}, "w", 1, 10))
        self.assertEqual(f({"w": 10}, "w", 1, 10), 10)
        for v in (True, 11, 0, "5", 5.0):
            with self.subTest(v=v), self.assertRaises(protocol.ProtocolError):
                f({"w": v}, "w", 1, 10)


# --------------------------------------------------------------------- MFA
class SplitOtpTests(unittest.TestCase):
    def test_length_order(self):
        cfg = MfaSection(otp_lengths=[8, 6], yubikey_otp=False)
        self.assertEqual(mfa.split_otp("pw12345678", cfg), ("pw", "12345678"))
        self.assertEqual(mfa.split_otp("pw123456", cfg), ("pw", "123456"))

    def test_yubikey_disabled(self):
        yk = "c" * 44
        self.assertIsNone(mfa.split_otp("pw" + yk, MfaSection(yubikey_otp=False)))
        self.assertEqual(mfa.split_otp("pw" + yk, MfaSection(yubikey_otp=True)), ("pw", yk))
        self.assertIsNone(mfa.split_otp("pw" + "a" * 44, MfaSection(yubikey_otp=True)))  # not modhex


class SecondFactorTests(unittest.IsolatedAsyncioTestCase):
    def factor(self, mode, **kw):
        sf = mfa.SecondFactor(MfaSection(mode=mode, privacyidea=PrivacyIdeaSection(url="https://pi"), **kw))
        sf.pi = mock.Mock()
        return sf

    def test_exempt(self):
        self.assertTrue(mfa.SecondFactor(MfaSection(mode="none")).exempt(frozenset()))
        sf = self.factor("otp", exempt_groups=["svc"])
        self.assertTrue(sf.exempt(frozenset({"svc", "x"})))
        self.assertFalse(sf.exempt(frozenset({"x"})))

    async def test_otp_rejected(self):
        sf = self.factor("otp")
        sf.pi.check_otp.return_value = False
        with self.assertRaises(mfa.MfaDenied):
            await sf.verify("alice", "123456", "pw")

    async def test_otp_missing(self):
        with self.assertRaises(mfa.MfaDenied):
            await self.factor("otp").verify("alice", None, "pw")

    async def test_service_error_denies(self):
        sf = self.factor("otp")
        sf.pi.check_otp.side_effect = PrivacyIdeaError("down")
        with self.assertRaisesRegex(mfa.MfaDenied, "unavailable"):
            await sf.verify("alice", "123456", "pw")

    async def test_otp_or_push_without_otp_pushes(self):
        sf = self.factor("otp_or_push")
        sf.pi.trigger_challenge.return_value = "tx"
        sf.pi.wait_for_push.return_value = True
        self.assertEqual(await sf.verify("alice", None, "pw"), "push")
        sf.pi.trigger_challenge.assert_called_with("alice", "pw")
        sf.pi.check_otp.assert_not_called()

    async def test_push_mode_ignores_otp(self):
        sf = self.factor("push")
        sf.pi.trigger_challenge.return_value = "tx"
        sf.pi.wait_for_push.return_value = True
        self.assertEqual(await sf.verify("alice", "123456", "pw"), "push")
        sf.pi.check_otp.assert_not_called()

    async def test_push_no_token_or_timeout(self):
        sf = self.factor("push")
        sf.pi.trigger_challenge.return_value = None
        with self.assertRaises(mfa.MfaDenied):
            await sf.verify("alice", None, "pw")
        sf.pi.trigger_challenge.return_value = "tx"
        sf.pi.wait_for_push.return_value = False
        with self.assertRaises(mfa.MfaDenied):
            await sf.verify("alice", None, "pw")


# --------------------------------------------------------------- privacyIDEA
class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def pi_reply(value=True, status=True, **extra):
    return FakeResp(json.dumps({"result": {"status": status, "value": value}, **extra}).encode())


class PrivacyIdeaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = PrivacyIdeaSection(url="https://pi/", realm="lab", push_timeout=5, poll_interval=0)

    def tearDown(self):
        self.tmp.cleanup()

    def urlopen(self, *replies):
        self.calls = []

        def fake(req, timeout, context):
            self.calls.append(req)
            r = replies[len(self.calls) - 1]
            if isinstance(r, Exception):
                raise r
            return r
        return mock.patch("urllib.request.urlopen", side_effect=fake)

    def test_check_otp(self):
        pi = PrivacyIdea(self.cfg)
        with self.urlopen(pi_reply(True), pi_reply(False)):
            self.assertTrue(pi.check_otp("alice", "123456"))
            self.assertFalse(pi.check_otp("alice", "000000"))
        self.assertEqual(self.calls[0].full_url, "https://pi/validate/check")
        self.assertIn(b"realm=lab", self.calls[0].data)

    def test_errors(self):
        pi = PrivacyIdea(self.cfg)
        bad = {"result": {"status": False, "error": {"message": "user unknown"}}}
        http_json = urllib.error.HTTPError("u", 400, "x", {}, io.BytesIO(json.dumps(bad).encode()))
        http_raw = urllib.error.HTTPError("u", 500, "x", {}, io.BytesIO(b"<html>"))
        self.addCleanup(http_json.close)
        self.addCleanup(http_raw.close)
        for r, msg in ((FakeResp(json.dumps(bad).encode()), "user unknown"), (http_json, "user unknown"),
                       (http_raw, "HTTP 500"), (urllib.error.URLError("refused"), "refused"),
                       (FakeResp(b"not json"), "")):
            with self.subTest(msg=msg), self.urlopen(r), self.assertRaisesRegex(PrivacyIdeaError, msg):
                pi.check_otp("alice", "1")

    def test_trigger_without_service_user(self):
        pi = PrivacyIdea(self.cfg)
        with self.assertRaises(PrivacyIdeaError):
            pi.trigger_challenge("alice", None)
        with self.urlopen(pi_reply(False, detail={"transaction_id": "tx9"})):
            self.assertEqual(pi.trigger_challenge("alice", "pw"), "tx9")
        self.assertTrue(self.calls[0].full_url.endswith("/validate/check"))

    def test_service_user_jwt_cached(self):
        secret = Path(self.tmp.name) / "s"
        secret.write_text("svcpw\n")
        self.cfg.service_user = "svc"
        self.cfg.service_password_file = str(secret)
        pi = PrivacyIdea(self.cfg)
        tx = {"detail": {"transaction_id": "tx1"}}
        with self.urlopen(pi_reply({"token": "JWT"}), pi_reply(False, **tx), pi_reply(False, **tx)):
            self.assertEqual(pi.trigger_challenge("alice", None), "tx1")
            self.assertEqual(pi.trigger_challenge("alice", None), "tx1")
        self.assertEqual([c.full_url.rsplit("/", 1)[1] for c in self.calls],
                         ["auth", "triggerchallenge", "triggerchallenge"])
        self.assertIn(b"password=svcpw", self.calls[0].data)
        self.assertEqual(self.calls[1].get_header("Authorization"), "JWT")

    def test_wait_for_push(self):
        pi = PrivacyIdea(self.cfg)
        with self.urlopen(pi_reply(False), pi_reply(True), pi_reply(True)):
            self.assertTrue(pi.wait_for_push("alice", "tx1"))
        self.assertIn("polltransaction?transaction_id=tx1", self.calls[0].full_url)
        self.assertIn(b"transaction_id=tx1", self.calls[2].data)
        self.cfg.push_timeout = 0
        self.assertFalse(PrivacyIdea(self.cfg).wait_for_push("alice", "tx1"))


# ---------------------------------------------------------------- identity
def pw(name, uid, home="/home/x"):
    return pwd.struct_passwd((name, "x", uid, uid, "", home, "/bin/sh"))


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.auth = config.AuthSection()

    def test_invalid_names(self):
        for n in ("", "a b", "a/b", "x" * 300, "al\nice"):
            with self.subTest(n=n), self.assertRaises(IdentityError):
                identity.resolve(n, None, self.auth)

    def test_root_refused(self):
        with mock.patch("pwd.getpwnam", return_value=pw("root", 0)), self.assertRaises(IdentityError):
            identity.resolve("root", None, self.auth)

    def test_unknown(self):
        with mock.patch("pwd.getpwnam", side_effect=KeyError), self.assertRaises(IdentityError):
            identity.resolve("ghost", "EXAMPLE.COM", self.auth)

    def test_candidates_and_groups(self):
        tried = []

        def getpwnam(n):
            tried.append(n)
            if n == "alice@example.com":
                return pw(n, 1500)
            raise KeyError(n)
        with mock.patch("pwd.getpwnam", side_effect=getpwnam), \
                mock.patch("os.getgrouplist", return_value=[os.getgid(), 987654]):
            u = identity.resolve("alice", "EXAMPLE.COM", config.AuthSection(strip_realm=False))
        self.assertEqual(tried, ["alice@example.com"])
        self.assertEqual(u.name, "alice@example.com")
        self.assertEqual(len(u.groups), 1)  # unknown gid skipped

    def test_user_allowed(self):
        self.assertTrue(identity.user_allowed(user(groups=()), config.AuthSection()))
        a = config.AuthSection(allow_groups=["rdp-users"])
        self.assertTrue(identity.user_allowed(user(), a))
        self.assertFalse(identity.user_allowed(user(groups=("other",)), a))

    def test_desktop_pref_edge_cases(self):
        with tempfile.TemporaryDirectory() as home:
            u = LocalUser(ME.pw_name, ME.pw_uid, ME.pw_gid, home, frozenset())
            os.makedirs(f"{home}/.config/fastrdp/desktop")  # a directory, not a file
            self.assertIsNone(identity.read_desktop_pref(u))
            os.rmdir(f"{home}/.config/fastrdp/desktop")
            Path(f"{home}/.config/fastrdp/desktop").write_text("")
            self.assertIsNone(identity.read_desktop_pref(u))
            other = LocalUser(ME.pw_name, ME.pw_uid + 1, ME.pw_gid, home, frozenset())
            Path(f"{home}/.config/fastrdp/desktop").write_text("gnome\n")
            self.assertIsNone(identity.read_desktop_pref(other))  # file not owned by the user

    def test_no_desktop_permitted(self):
        raw = raw_example()
        for d in raw["desktops"].values():
            d["groups"] = ["nobody-has-this"]
        cfg = config.parse(raw)
        with self.assertRaises(IdentityError):
            identity.choose_desktop(cfg, user(), "gnome")


# ------------------------------------------------------------------- state
class StateTests(unittest.TestCase):
    def test_roundtrip_and_privacy(self):
        with tempfile.TemporaryDirectory() as d:
            s = StateStore(d)
            s.put(Session("alice", "gnome", "gnome", port=34000, rdp_user="fastrdp", rdp_password="sec"))
            self.assertEqual(oct(os.stat(s.path).st_mode & 0o777), "0o600")
            s2 = StateStore(d)
            self.assertEqual(s2.get("alice", "gnome").rdp_password, "sec")
            self.assertNotIn("rdp_password", s2.get("alice", "gnome").public())
            s2.reserved_ports.add(34001)
            self.assertEqual(s2.ports_in_use(), {34000, 34001})
            s2.drop("alice", "gnome")
            s2.drop("alice", "gnome")  # idempotent
            self.assertEqual(StateStore(d).sessions, {})

    def test_corrupt_state_starts_fresh(self):
        with tempfile.TemporaryDirectory() as d:
            for content in ("{not json", '[{"bogus": 1}]'):
                Path(d, "sessions.json").write_text(content)
                self.assertEqual(StateStore(d).sessions, {})


class NetcheckGapTests(unittest.TestCase):
    def test_missing_proc_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(netcheck.listeners(root), [])

    def test_port_in_use(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen()
            self.assertTrue(netcheck.port_in_use(s.getsockname()[1]))


# ----------------------------------------------------------------- sysutil
class SysutilTests(unittest.IsolatedAsyncioTestCase):
    async def test_run(self):
        res = await sysutil.run("cat", input="hello")
        self.assertEqual((res.rc, res.stdout), (0, "hello"))
        self.assertEqual((await sysutil.run("false", check=False)).rc, 1)
        with self.assertRaises(sysutil.CommandError):
            await sysutil.run("sh", "-c", "echo boom >&2; exit 3")
        with self.assertRaisesRegex(sysutil.CommandError, "timeout"):
            await sysutil.run("sleep", "5", timeout=0.2)

    async def test_wait_for_listener(self):
        with mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={1500}):
            await sysutil.wait_for_listener(34000, 1500, 1)
            with self.assertRaisesRegex(sysutil.CommandError, "unexpected uid"):
                await sysutil.wait_for_listener(34000, 1600, 1)
        with mock.patch("fastrdp_broker.netcheck.listener_uids", return_value=set()), \
                self.assertRaisesRegex(sysutil.CommandError, "no listener"):
            await sysutil.wait_for_listener(34000, 1500, 0)

    def test_valid_user_file(self):
        with tempfile.TemporaryDirectory() as d:
            u = LocalUser(ME.pw_name, ME.pw_uid, ME.pw_gid, d, frozenset())
            f = Path(d, "f")
            f.write_text("x")
            os.symlink(f, Path(d, "l"))
            self.assertTrue(sysutil._valid_user_file(str(f), u))
            self.assertFalse(sysutil._valid_user_file(str(Path(d, "l")), u))
            self.assertFalse(sysutil._valid_user_file(str(Path(d, "missing")), u))

    @unittest.skipIf(os.getuid() == 0, "needs a non-root-owned directory")
    async def test_backend_cert_refuses_user_owned_state_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(sysutil.CommandError, "root-owned"):
                await sysutil.ensure_backend_cert(user(), d)


# ---------------------------------------------------------------- backends
class BackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name)
        self.cfg.broker.port_range = (41000, 41001)
        self.state = StateStore(self.cfg.broker.state_dir)
        self.tokens = TokenStore(60)
        self.user = user()
        self.free_ports = [
            mock.patch("fastrdp_broker.netcheck.listeners", return_value=[]),
            mock.patch("fastrdp_broker.netcheck.port_in_use", return_value=False),
        ]
        for p in self.free_ports:
            p.start()

    def tearDown(self):
        for p in self.free_ports:
            p.stop()
        self.tmp.cleanup()

    def req(self, desktop):
        return LoginRequest(self.user, self.cfg.desktops[desktop], "pw", 1280, 720)

    # xrdp
    async def test_xrdp_wrong_listener_refused(self):
        b = XrdpBackend(self.cfg, self.state, self.tokens)
        with mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={1500}), \
                self.assertRaisesRegex(BackendError, "not owned"):
            await b.ensure(self.req("xfce"))
        self.assertEqual(len(self.tokens), 0)

    async def test_xrdp_login(self):
        b = XrdpBackend(self.cfg, self.state, self.tokens)
        with mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={0}):
            t = await b.ensure(self.req("mate"))
        self.assertEqual((t.port, t.username, t.security), (3390, "alice", "tls"))
        self.assertEqual(self.tokens.redeem("alice", t.password), (True, "pw"))
        choice = Path(self.cfg.broker.runtime_dir, "desktop", "alice")
        self.assertEqual(choice.read_text(), "mate\n")
        self.assertEqual(oct(choice.stat().st_mode & 0o777), "0o644")
        self.assertIsNotNone(self.state.get("alice", "xrdp"))

    async def test_xrdp_logout(self):
        b = XrdpBackend(self.cfg, self.state, self.tokens)
        self.state.put(Session("alice", "xrdp", "xfce"))
        # Only the user's xrdp logind sessions are ended, never terminate-user (it would
        # also end SSH logins); see test_regressions.XrdpSessionTests for the session match.
        empty = sysutil.Result(0, "", "")
        with mock.patch("fastrdp_broker.sysutil.run", new=mock.AsyncMock(return_value=empty)) as run:
            await b.logout(self.user)
        run.assert_awaited_with("loginctl", "list-sessions", "--no-legend", check=False)
        self.assertNotIn("terminate-user", [a for c in run.await_args_list for a in c.args])
        self.assertIsNone(self.state.get("alice", "xrdp"))

    def test_listener_user(self):
        b = XrdpBackend(self.cfg, self.state, self.tokens)
        self.assertEqual(b.expected_listener_uid(self.user), 0)
        b.bcfg.listener_user = ""
        self.assertEqual(b.expected_listener_uid(self.user), 1500)
        b.bcfg.listener_user = "no-such-user-fastrdp"
        with self.assertRaises(BackendError):
            b.expected_listener_uid(self.user)

    def test_ports_exhausted(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        b.allocate_port()
        b.allocate_port()
        with self.assertRaisesRegex(BackendError, "no free"):
            b.allocate_port()

    # gnome
    def gnome_mocks(self, unit_active=False, fail=None):
        m = {
            "ensure_backend_cert": mock.AsyncMock(return_value=("/c.crt", "/c.key")),
            "run_as_user": mock.AsyncMock(),
            "unit_active": mock.AsyncMock(return_value=unit_active),
            "start_unit": mock.AsyncMock(),
            "stop_unit": mock.AsyncMock(),
            "wait_for_listener": mock.AsyncMock(),
        }
        if fail:
            m[fail].side_effect = sysutil.CommandError("boom")
        return m, mock.patch.multiple("fastrdp_broker.sysutil", **m)

    async def test_gnome_start(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        m, p = self.gnome_mocks()
        with p:
            t = await b.ensure(self.req("gnome"))
        self.assertEqual((t.port, t.username, t.security), (41000, "fastrdp", "nla"))
        m["start_unit"].assert_awaited_with("gnome-headless-session@alice.service")
        # g-r-d is enabled in $XDG_RUNTIME_DIR, not ~/.config/systemd/user: a user manager
        # started without NFS credentials cannot read unit links in the home.
        argvs = [c.args[1:] for c in m["run_as_user"].await_args_list]
        self.assertIn(("systemctl", "--user", "--runtime", "enable", "gnome-remote-desktop-headless.service"), argvs)
        self.assertNotIn(("systemctl", "--user", "enable", "gnome-remote-desktop-headless.service"), argvs)
        cred = [c for c in m["run_as_user"].await_args_list if "set-credentials" in c.args]
        self.assertEqual(cred[0].kwargs["input"], t.password + "\n")  # secret via stdin, not argv
        self.assertNotIn(t.password, " ".join(str(a) for c in m["run_as_user"].await_args_list for a in c.args))
        self.assertEqual(self.state.reserved_ports, set())
        self.assertEqual(self.state.get("alice", "gnome").port, 41000)

    async def test_gnome_restarts_grd_in_live_session(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        m, p = self.gnome_mocks(unit_active=True)  # no state -> not "running"
        with p:
            await b.ensure(self.req("gnome"))
        m["start_unit"].assert_not_awaited()
        self.assertIn(("systemctl", "--user", "restart", "gnome-remote-desktop-headless.service"),
                      [c.args[1:] for c in m["run_as_user"].await_args_list])

    async def test_gnome_reuse(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        self.state.put(Session("alice", "gnome", "gnome", port=41001, rdp_user="fastrdp", rdp_password="old"))
        m, p = self.gnome_mocks(unit_active=True)
        with p, mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={1500}):
            t = await b.ensure(self.req("gnome"))
        self.assertEqual((t.port, t.password), (41001, "old"))
        m["run_as_user"].assert_not_awaited()

    async def test_gnome_hijacked_port_not_reused(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        self.state.put(Session("alice", "gnome", "gnome", port=41001, rdp_user="fastrdp", rdp_password="old"))
        m, p = self.gnome_mocks(unit_active=True)
        with p, mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={1600}):
            t = await b.ensure(self.req("gnome"))
        self.assertNotEqual(t.password, "old")

    async def test_gnome_errors_release_port(self):
        for fail in ("ensure_backend_cert", "run_as_user", "start_unit", "wait_for_listener"):
            with self.subTest(fail=fail):
                b = GnomeBackend(self.cfg, self.state, self.tokens)
                _, p = self.gnome_mocks(fail=fail)
                with p, self.assertRaises(BackendError):
                    await b.ensure(self.req("gnome"))
                self.assertEqual(self.state.reserved_ports, set())

    async def test_gnome_logout(self):
        b = GnomeBackend(self.cfg, self.state, self.tokens)
        self.state.put(Session("alice", "gnome", "gnome", port=41001))
        m, p = self.gnome_mocks()
        with p:
            await b.logout(self.user)
        m["stop_unit"].assert_awaited_with("gnome-headless-session@alice.service")
        self.assertIsNone(self.state.get("alice", "gnome"))

    # plasma
    async def test_plasma_start_writes_private_env(self):
        b = PlasmaBackend(self.cfg, self.state, self.tokens)
        m, p = self.gnome_mocks()
        with p, mock.patch("fastrdp_broker.sysutil.run", new=mock.AsyncMock()) as run:
            t = await b.ensure(self.req("plasma"))
        run.assert_awaited_with("systemctl", "restart", "--no-block", "fastrdp-plasma@alice.service")
        env = Path(b.env_path(self.user))
        self.assertEqual(oct(env.stat().st_mode & 0o777), "0o600")
        values = dict(line.split("=", 1) for line in env.read_text().splitlines())
        self.assertEqual(values["FASTRDP_RDP_PASSWORD"], t.password)
        self.assertEqual((values["FASTRDP_PORT"], values["FASTRDP_WIDTH"]), ("41000", "1280"))
        self.assertEqual(self.state.reserved_ports, set())

    async def test_plasma_errors_release_port(self):
        for fail in ("ensure_backend_cert", "wait_for_listener"):
            with self.subTest(fail=fail):
                b = PlasmaBackend(self.cfg, self.state, self.tokens)
                _, p = self.gnome_mocks(fail=fail)
                with p, mock.patch("fastrdp_broker.sysutil.run", new=mock.AsyncMock()), \
                        self.assertRaises(BackendError):
                    await b.ensure(self.req("plasma"))
                self.assertEqual(self.state.reserved_ports, set())


# ---------------------------------------------------------- server policy
class _BrokerHarness:
    """Broker on temporary sockets; identity, PAM and back-ends mocked."""
    web = True
    DENIED = {"ok": False, "error": "access denied", "reason": "denied"}

    @staticmethod
    def refused(reason):
        """Refusal reply: the error text is always generic, only `reason` differs."""
        return {"ok": False, "error": "access denied", "reason": reason}

    async def asyncSetUp(self):
        from fastrdp_broker import pamauth
        from fastrdp_broker.server import Broker

        self.pam = pamauth
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name, web=self.web)
        self.users = {"alice": user(), "carol": user("carol", ("rdp-users", "mfa-exempt")),
                      "eve": user("eve", ("other",))}
        self.patches = [
            mock.patch("fastrdp_broker.identity.resolve", side_effect=self.resolve),
            mock.patch("fastrdp_broker.pamauth.authenticate"),
            mock.patch("fastrdp_broker.pamauth.account_ok"),
        ]
        for p in self.patches:
            p.start()
        self.broker = Broker(self.cfg)
        self.ensure = mock.AsyncMock(return_value=Target("127.0.0.1", 3390, "alice", "t", "", "tls"))
        for b in self.broker.backends.values():
            b.ensure = self.ensure
        self.task = asyncio.create_task(self.broker.serve())
        for _ in range(50):
            if os.path.exists(self.cfg.broker.token_socket):
                break
            await asyncio.sleep(0.02)

    def resolve(self, name, realm, auth):
        if name not in self.users:
            raise IdentityError(f"unknown user {name!r}")
        return self.users[name]

    async def asyncTearDown(self):
        self.task.cancel()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def set_mfa(self, mode, exempt=()):
        self.broker.mfa.cfg.mode = mode
        self.broker.mfa.cfg.exempt_groups = list(exempt)
        self.broker.mfa.pi = mock.Mock()
        return self.broker.mfa.pi

    def login(self, **kw):
        msg = {"op": "login", "session_id": "s", "method": "tls", "user": "alice", "password": "pw"}
        msg.update(kw)
        return request(self.cfg.broker.socket, msg)

    def nla(self, **kw):
        return self.login(method="nla", principal=f"{kw.get('user', 'alice')}@EXAMPLE.COM", **kw)


class ServerPolicyTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def test_exempt_group_skips_otp(self):
        pi = self.set_mfa("otp", exempt=["mfa-exempt"])
        reply = await self.login(user="carol", password="pw123456")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.pam.authenticate.call_args.args[2], "pw123456")  # not split
        pi.check_otp.assert_not_called()
        self.assertEqual((await self.nla(user="carol"))["ok"], True)
        pi.trigger_challenge.assert_not_called()

    async def test_otp_mode_requires_otp(self):
        self.set_mfa("otp")
        self.assertEqual(await self.login(password="password"), self.refused("mfa_failed"))
        self.pam.authenticate.assert_not_called()

    async def test_otp_rejected(self):
        pi = self.set_mfa("otp")
        pi.check_otp.return_value = False
        self.assertEqual(await self.login(password="pw123456"), self.refused("mfa_failed"))
        self.ensure.assert_not_called()

    async def test_otp_or_push_falls_back_to_push(self):
        pi = self.set_mfa("otp_or_push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        self.assertTrue((await self.login(password="password"))["ok"])
        pi.trigger_challenge.assert_called_with("alice", "password")

    async def test_push_denied(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = False
        self.assertEqual(await self.nla(), self.refused("mfa_timeout"))
        self.ensure.assert_not_called()

    async def test_mfa_failures(self):
        pi = self.set_mfa("push")
        pi.trigger_challenge.return_value = None  # no push-capable token
        self.assertEqual(await self.nla(), self.refused("mfa_failed"))
        pi.trigger_challenge.side_effect = PrivacyIdeaError("down")
        self.assertEqual(await self.nla(), self.refused("mfa_failed"))
        self.ensure.assert_not_called()

    async def test_allow_groups(self):
        self.cfg.auth.allow_groups = ["rdp-users"]
        self.assertEqual(await self.login(user="eve"), self.refused("not_allowed"))
        self.assertEqual(await self.nla(user="eve"), self.refused("not_allowed"))
        for op in ("web_token", "web_desktops"):
            reply = await request(self.cfg.broker.socket, {"op": op, "user": "eve"})
            self.assertEqual(reply, self.refused("not_allowed"))
        self.ensure.assert_not_called()

    async def test_not_allowed_only_once_no_factor_is_owed(self):
        # A TLS password alone must not be confirmed while the second factor is still due;
        # NLA (CredSSP) and the web path (IdP) have confirmed the credentials already.
        self.cfg.auth.allow_groups = ["rdp-users"]
        self.users["eve"] = user("eve", ("other",))
        pi = self.set_mfa("otp_or_push")
        self.assertEqual(await self.login(user="eve"), self.DENIED)
        self.assertEqual(await self.nla(user="eve"), self.refused("not_allowed"))
        self.set_mfa("otp_or_push", exempt=["other"])
        self.assertEqual(await self.login(user="eve"), self.refused("not_allowed"))
        pi.trigger_challenge.assert_not_called()

    async def test_unknown_user(self):
        self.assertEqual(await self.login(user="mallory"), self.DENIED)

    async def test_unknown_user_and_wrong_password_look_the_same(self):
        for mode in ("none", "otp_or_push"):
            with self.subTest(mfa=mode):
                self.set_mfa(mode)
                self.pam.authenticate.side_effect = self.pam.PamError("authenticate", 7, "Authentication failure")
                wrong_password = await self.login(password="wrong")
                self.pam.authenticate.side_effect = None
                unknown = await self.login(user="mallory", password="wrong")
                self.assertEqual(wrong_password, unknown)
                self.assertEqual(unknown, self.DENIED)
                self.assertEqual(await self.nla(user="mallory"), self.DENIED)

    async def test_tls_account_check_failure(self):
        # pam_acct_mgmt after a correct password (expired, locked, pam_access)
        self.pam.authenticate.side_effect = self.pam.PamError("account", 13, "expired")
        self.assertEqual(await self.login(), self.refused("not_allowed"))
        self.set_mfa("push")
        self.assertEqual(await self.login(), self.DENIED)  # second factor still owed

    async def test_tls_policy(self):
        self.assertEqual(await self.login(password=None), self.DENIED)
        self.assertEqual(await self.login(method="rdp"), self.DENIED)
        self.cfg.auth.allow_tls_password_login = False
        self.assertEqual(await self.login(), self.DENIED)
        self.pam.authenticate.assert_not_called()

    async def test_nla_account_check_failure(self):
        self.pam.account_ok.side_effect = self.pam.PamError("account", 13, "expired")
        self.assertEqual(await self.nla(), self.refused("not_allowed"))
        reply = await request(self.cfg.broker.socket, {"op": "web_token", "user": "alice"})
        self.assertEqual(reply, self.refused("not_allowed"))

    async def test_backend_error_reported(self):
        self.ensure.side_effect = BackendError("xrdp down")
        self.assertEqual(await self.nla(),
                         {"ok": False, "error": "session could not be started", "reason": "backend"})

    async def test_geometry_default_and_invalid(self):
        self.assertTrue((await self.nla())["ok"])
        req = self.ensure.call_args.args[0]
        self.assertEqual((req.width, req.height), (1920, 1080))
        self.assertEqual(await self.nla(width=100000, height=10), {})  # protocol error: dropped
        self.assertEqual(await self.nla(session_id="x" * 65), {})

    async def test_desktop_restriction(self):
        self.cfg.desktops["gnome"].groups = ["gnome-pilot"]
        self.assertTrue((await self.nla(desktop_hint="fastrdp:gnome"))["ok"])
        self.assertEqual(self.ensure.call_args.args[0].desktop.name, "xfce")
        reply = await request(self.cfg.broker.socket, {"op": "web_token", "user": "alice"})
        self.assertNotIn("gnome", reply["desktops"])
        for d in self.cfg.desktops.values():
            d.groups = ["gnome-pilot"]
        self.assertEqual(await self.nla(), self.refused("not_allowed"))
        reply = await request(self.cfg.broker.socket, {"op": "web_desktops", "user": "alice"})
        self.assertEqual(reply, self.refused("not_allowed"))

    async def test_session_end(self):
        await self.nla(session_id="abc")
        self.assertEqual(self.broker.active, {"abc": "alice"})
        self.assertEqual(await request(self.cfg.broker.socket, {"op": "end", "session_id": "abc"}), {"ok": True})
        self.assertEqual(self.broker.active, {})

    async def test_root_operations(self):
        self.broker.state.put(Session("alice", "gnome", "gnome", port=41000, rdp_password="sec"))
        logout = mock.AsyncMock()
        self.broker.backends["gnome"].logout = logout
        self.broker.backends["xrdp"].logout = mock.AsyncMock()
        with mock.patch("fastrdp_broker.server.peer_uid", return_value=0):
            status = await request(self.cfg.broker.socket, {"op": "status"})
            self.assertTrue(status["ok"])
            self.assertNotIn("sec", json.dumps(status))
            self.assertEqual(await request(self.cfg.broker.socket, {"op": "logout", "user": "alice"}), {"ok": True})
            if ME.pw_uid != 0:  # root is not the proxy: no logins
                self.assertEqual((await self.nla())["error"], "not permitted")
        logout.assert_awaited_once()
        self.broker.backends["xrdp"].logout.assert_not_awaited()  # no xrdp session recorded

    async def test_token_socket_as_root(self):
        tok = self.broker.tokens.issue("alice", "pw")
        sock = self.cfg.broker.token_socket
        with mock.patch("fastrdp_broker.server.peer_uid", return_value=0):
            self.assertEqual(await request(sock, {"op": "redeem", "user": "bob", "token": tok}),
                             {"ok": False, "password": None})
            self.assertEqual(await request(sock, {"op": "redeem", "user": "alice", "token": tok}),
                             {"ok": True, "password": "pw"})
            self.assertEqual(await request(sock, {"op": "redeem", "user": "alice", "token": tok}),
                             {"ok": False, "password": None})
            self.assertEqual(await request(sock, {"op": "status"}), {})
            self.assertEqual(await request(sock, {"op": "redeem", "user": "alice"}), {})


class ServerWebDisabledTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    web = False

    async def test_web_token_login_refused_when_disabled(self):
        token = self.broker.web_tokens.issue("alice", None)
        self.assertEqual(await self.login(password=token, client_address="127.0.0.1"), self.DENIED)
        self.pam.authenticate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
