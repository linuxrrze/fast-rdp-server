# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Kerberos TGT for GNOME/Plasma sessions ([broker] session_tgt, docs/nfs-kerberos-homes.md).

Regressions: GNOME/Plasma sessions never got a TGT, so Kerberized NFS homes failed even
when the login carried the password; the password must never reach argv, the
environment, files or logs; "required" refuses logins that cannot get a TGT, before
MFA. (GNOME's runtime enable of g-r-d: test_gaps.BackendTests.test_gnome_start.)"""

import asyncio
import ctypes
import os
import unittest
from unittest import mock

from fastrdp_broker import config, pamauth, sysutil, tgt
from fastrdp_broker.config import ConfigError
from fastrdp_broker.state import Session
from test_gaps import _BrokerHarness, raw_example, user

PW = "S3cret-pw!"  # never allowed outside the PAM conversation


class SessionTgtTests(_BrokerHarness, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.calls = []  # order of TGT step and back-end start
        self.establish = mock.Mock(side_effect=lambda *a: self.calls.append("tgt") or "KCM:")
        self.klist = mock.AsyncMock(return_value=sysutil.Result(0, "", ""))
        self.ensure.side_effect = lambda req: self.calls.append("ensure") or self.ensure.return_value
        for p in (mock.patch("fastrdp_broker.pamauth.establish_credentials", self.establish),
                  mock.patch("fastrdp_broker.sysutil.run_dropped", self.klist)):
            p.start()
            self.patches.append(p)

    def gnome(self, password=PW, desktop="gnome", **kw):
        return self.nla(password=password, desktop_hint=f"fastrdp:{desktop}", **kw)

    async def test_gnome_and_plasma_get_tgt_before_start(self):
        for desktop in ("gnome", "plasma"):
            with self.subTest(desktop):
                self.calls.clear()
                self.assertTrue((await self.gnome(desktop=desktop))["ok"])
                self.establish.assert_called_with("fastrdp-tgt", "alice", PW)
                self.assertEqual(self.calls, ["tgt", "ensure"])
                # klist checks the cache pam_sss reported, as the user
                self.klist.assert_awaited_with(self.users["alice"], "klist", "-s", env={"KRB5CCNAME": "KCM:"})

    async def test_tls_login_gets_tgt(self):
        self.assertTrue((await self.login(password=PW, desktop_hint="fastrdp:plasma"))["ok"])
        self.establish.assert_called_once_with("fastrdp-tgt", "alice", PW)

    async def test_no_password_no_tgt_step(self):
        self.assertTrue((await self.gnome(password=None))["ok"])               # SSO, no delegation
        self.assertTrue((await self.gnome(smartcard=True))["ok"])              # PIN is not a password
        self.assertTrue((await self.gnome(password=None, remote_guard=True))["ok"])  # tickets discarded
        self.establish.assert_not_called()
        self.klist.assert_not_awaited()
        self.assertEqual(self.ensure.await_count, 3)

    async def test_xrdp_gets_tgt_itself(self):
        self.assertTrue((await self.nla(password=PW))["ok"])
        self.assertEqual(self.ensure.call_args.args[0].desktop.backend, "xrdp")
        self.establish.assert_not_called()

    async def test_off(self):
        self.cfg.broker.session_tgt = "off"
        self.assertTrue((await self.gnome())["ok"])
        self.establish.assert_not_called()

    async def test_auto_failure_is_only_a_warning(self):
        failures = {
            "pam": (pamauth.PamError("authenticate", 7, "Authentication failure"), 0),
            "no ticket (offline)": (None, 1),
        }
        for name, (exc, rc) in failures.items():
            with self.subTest(name):
                self.establish.side_effect = exc
                self.klist.return_value = sysutil.Result(rc, "", "")
                with self.assertLogs("fastrdp.broker", "WARNING") as logs:
                    reply = await self.gnome()
                self.assertTrue(reply["ok"], reply)
                self.assertIn("no Kerberos TGT", "\n".join(logs.output))
                self.assertNotIn(PW, "\n".join(logs.output))

    async def test_required_failure_refuses(self):
        self.cfg.broker.session_tgt = "required"
        for exc, rc in ((pamauth.PamError("authenticate", 7, "Authentication failure"), 0), (None, 1)):
            self.establish.side_effect = exc
            self.klist.return_value = sysutil.Result(rc, "", "")
            with self.assertLogs("fastrdp.broker", "WARNING") as logs:
                self.assertEqual(await self.gnome(), self.DENIED)
            self.assertNotIn(PW, "\n".join(logs.output))
        self.ensure.assert_not_called()

    async def test_required_refuses_logins_without_password_before_mfa(self):
        self.cfg.broker.session_tgt = "required"
        pi = self.set_mfa("push")
        self.assertEqual(await self.nla(password=None), self.DENIED)                # SSO, xrdp too
        self.assertEqual(await self.gnome(password=None), self.DENIED)
        self.assertEqual(await self.gnome(smartcard=True), self.DENIED)
        self.assertEqual(await self.nla(password=None, remote_guard=True), self.DENIED)  # RCG
        web = await self._request({"op": "web_token", "user": "alice"})
        self.assertFalse(web["ok"])
        pi.trigger_challenge.assert_not_called()   # no push for a login that will be refused
        self.ensure.assert_not_called()
        # with a password: xrdp (its own PAM stack) and GNOME (broker) go ahead
        pi.trigger_challenge.return_value = "tx"
        pi.wait_for_push.return_value = True
        self.assertTrue((await self.nla(password=PW))["ok"])
        self.assertTrue((await self.gnome())["ok"])

    async def test_reconnect_refreshes_tgt(self):
        """A reconnect to a running GNOME session (real back-end reuse path) with a
        password gets a new TGT first; one without a password reuses the session."""
        gnome = self.broker.backends["gnome"]
        del gnome.ensure  # the real GnomeBackend.ensure
        self.broker.state.put(Session("alice", "gnome", "gnome", port=41001, rdp_user="fastrdp",
                                      rdp_password="sess"))
        with mock.patch("fastrdp_broker.sysutil.unit_active", new=mock.AsyncMock(return_value=True)), \
                mock.patch("fastrdp_broker.netcheck.listener_uids", return_value={1500}), \
                mock.patch("fastrdp_broker.sysutil.run_as_user", new=mock.AsyncMock()) as run_as_user:
            for _ in range(2):
                reply = await self.gnome()
                self.assertTrue(reply["ok"], reply)
                self.assertEqual(reply["target"]["password"], "sess")  # same session
            self.assertTrue((await self.gnome(password=None))["ok"])
        self.assertEqual(self.establish.call_count, 2)
        run_as_user.assert_not_awaited()

    def _request(self, msg):
        from test_server import request
        return request(self.cfg.broker.socket, msg)


class TgtObtainTests(unittest.IsolatedAsyncioTestCase):
    """tgt.obtain with the real sysutil.run_dropped: what reaches the subprocess."""

    async def test_password_never_in_argv_or_env(self):
        u = user()
        captured = {}

        async def fake_exec(*argv, **kw):
            captured.update(argv=argv, **kw)
            proc = mock.Mock(returncode=0)
            proc.communicate = mock.AsyncMock(return_value=(b"", b""))
            return proc

        with mock.patch.dict(os.environ, {"KRB5CCNAME": "FILE:/tmp/root-cache", "KRB5_CONFIG": "/x",
                                          "FASTRDP_SECRET": PW}), \
                mock.patch("fastrdp_broker.pamauth.establish_credentials", return_value="KCM:") as pam, \
                mock.patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            await tgt.obtain(u, PW)
        pam.assert_called_once_with("fastrdp-tgt", "alice", PW)  # only PAM gets the password
        self.assertEqual(captured["argv"], ("klist", "-s"))
        self.assertNotIn(PW, " ".join(captured["argv"]))
        env = captured["env"]
        self.assertNotIn(PW, " ".join(f"{k}={v}" for k, v in env.items()))
        self.assertEqual(env["KRB5CCNAME"], "KCM:")             # from pam_sss, not the broker's
        self.assertNotIn("KRB5_CONFIG", env)
        self.assertEqual(env["HOME"], "/")                      # never the NFS home
        # privileges dropped completely: uid, gid and no supplementary groups (root's)
        self.assertEqual((captured["user"], captured["group"], captured["extra_groups"]), (1500, 1500, []))
        self.assertEqual(captured["cwd"], "/")
        self.assertEqual(captured["stdin"], asyncio.subprocess.DEVNULL)

    async def test_klist_failure(self):
        with mock.patch("fastrdp_broker.pamauth.establish_credentials", return_value=None), \
                mock.patch("fastrdp_broker.sysutil.run_dropped",
                           new=mock.AsyncMock(return_value=sysutil.Result(1, "", ""))) as klist, \
                self.assertRaisesRegex(tgt.TgtError, "no valid TGT"):
            await tgt.obtain(user(), PW)
        self.assertEqual(klist.await_args.kwargs["env"], None)  # no KRB5CCNAME from PAM: default
        with mock.patch("fastrdp_broker.pamauth.establish_credentials", return_value=None), \
                mock.patch("fastrdp_broker.sysutil.run_dropped",
                           new=mock.AsyncMock(side_effect=FileNotFoundError("klist"))), \
                self.assertRaisesRegex(tgt.TgtError, "klist"):
            await tgt.obtain(user(), PW)


class FakeLibpam:
    """Stands in for libpam: runs the conversation like pam_sss would."""

    def __init__(self, auth_rc=0, ccname=b"KCM:"):
        self.auth_rc, self.ccname = auth_rc, ccname
        self.answers, self.calls = [], []

    def pam_start(self, service, user, conv_ref, handle_ref):
        self.calls.append(("start", service, user))
        self.conv = conv_ref._obj
        return 0

    def pam_authenticate(self, handle, flags):
        msg = pamauth.PamMessage(pamauth.PAM_PROMPT_ECHO_OFF, b"Password: ")
        pmsg = ctypes.pointer(msg)
        resp = ctypes.POINTER(pamauth.PamResponse)()
        self.conv.conv(1, ctypes.pointer(pmsg), ctypes.byref(resp), None)
        self.answers.append(ctypes.string_at(resp[0].resp))
        self.calls.append(("authenticate",))
        return self.auth_rc

    def pam_setcred(self, handle, flags):
        self.calls.append(("setcred", flags))
        return 0

    def pam_getenv(self, handle, name):
        return self.ccname if name == b"KRB5CCNAME" else None

    def pam_acct_mgmt(self, handle, flags):
        self.calls.append(("account",))
        return 0

    def pam_strerror(self, handle, rc):
        return b"Authentication failure"

    def pam_end(self, handle, rc):
        self.calls.append(("end",))


class EstablishCredentialsTests(unittest.TestCase):
    def test_password_only_through_conversation(self):
        lib = FakeLibpam()
        with mock.patch("fastrdp_broker.pamauth._pam", return_value=lib):
            self.assertEqual(pamauth.establish_credentials("fastrdp-tgt", "alice", PW), "KCM:")
        self.assertEqual(lib.answers, [PW.encode()])
        self.assertEqual([c[0] for c in lib.calls], ["start", "authenticate", "setcred", "end"])
        self.assertEqual(lib.calls[0], ("start", b"fastrdp-tgt", b"alice"))
        self.assertTrue(lib.calls[2][1] & pamauth.PAM_ESTABLISH_CRED)

    def test_failure_raises_without_password(self):
        lib = FakeLibpam(auth_rc=7)
        with mock.patch("fastrdp_broker.pamauth._pam", return_value=lib), \
                self.assertRaises(pamauth.PamError) as cm:
            pamauth.establish_credentials("fastrdp-tgt", "alice", PW)
        self.assertNotIn(PW, str(cm.exception))
        self.assertEqual([c[0] for c in lib.calls], ["start", "authenticate", "end"])  # no setcred

    def test_no_ccname(self):
        with mock.patch("fastrdp_broker.pamauth._pam", return_value=FakeLibpam(ccname=None)):
            self.assertIsNone(pamauth.establish_credentials("fastrdp-tgt", "alice", PW))


class SessionTgtConfigTests(unittest.TestCase):
    def test_values(self):
        raw = raw_example()
        self.assertEqual(config.parse(raw).broker.session_tgt, "auto")
        for v in ("auto", "off", "required"):
            raw["broker"]["session_tgt"] = v
            self.assertEqual(config.parse(raw).broker.session_tgt, v)
        for bad in ("yes", True, ""):
            raw["broker"]["session_tgt"] = bad
            with self.subTest(bad), self.assertRaisesRegex(ConfigError, "session_tgt"):
                config.parse(raw)

    def test_pam_stack_has_no_faillock(self):
        # A stale delegated password must not lock the account for fastrdp logins.
        path = os.path.join(os.path.dirname(__file__), "../../session/pam/fastrdp-tgt")
        with open(path, encoding="utf-8") as fh:
            lines = [ln.split() for ln in fh if ln.strip() and not ln.startswith("#")]
        auth = [ln for ln in lines if ln[0] == "auth"]
        self.assertEqual(auth, [["auth", "required", "pam_sss.so"]])
        self.assertTrue(all(ln[2] == "pam_deny.so" for ln in lines if ln[0] != "auth"))


if __name__ == "__main__":
    unittest.main()
