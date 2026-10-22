# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Regression tests for bugs found in review (docs/backends/ cross-check, 2026-10-19)."""

import asyncio
import os
import pwd
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from fastrdp_broker import config, sysutil
from fastrdp_broker.backends.base import LoginRequest
from fastrdp_broker.backends.xrdp import XrdpBackend
from fastrdp_broker.identity import LocalUser
from fastrdp_broker.state import Session, StateStore
from fastrdp_broker.tokens import TokenStore

EXAMPLE = Path(__file__).parent.parent / "config" / "broker.toml.example"


class FakeLoginctl:
    """logind with sessions {id: (user, service, state)}; records terminate calls."""

    def __init__(self, sessions):
        self.sessions = dict(sessions)
        self.calls = []

    async def run(self, *argv, input=None, timeout=30, check=True):
        self.calls.append(argv)
        if argv[:2] == ("loginctl", "list-sessions"):
            out = "".join(f"{sid} 1000 {u} seat0 1 user - no -\n" for sid, (u, _, _) in self.sessions.items())
            return sysutil.Result(0, out, "")
        if argv[:2] == ("loginctl", "show-session"):
            _, service, state = self.sessions[argv[2]]
            return sysutil.Result(0, f"Service={service}\nState={state}\n", "")
        if argv[:2] in (("loginctl", "terminate-session"), ("loginctl", "terminate-user")):
            return sysutil.Result(0, "", "")
        raise AssertionError(f"unexpected command {argv}")


class XrdpSessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        with open(EXAMPLE, "rb") as fh:
            raw = tomllib.load(fh)
        raw["broker"]["runtime_dir"] = os.path.join(self.tmp.name, "run")
        raw["broker"]["state_dir"] = os.path.join(self.tmp.name, "state")
        self.cfg = config.parse(raw)
        self.state = StateStore(self.cfg.broker.state_dir)
        self.backend = XrdpBackend(self.cfg, self.state, TokenStore(60))
        me = pwd.getpwuid(os.getuid())
        self.user = LocalUser(me.pw_name, me.pw_uid, me.pw_gid, self.tmp.name, frozenset())

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, fake, desktop):
        req = LoginRequest(self.user, self.cfg.desktops[desktop], None, 1280, 800)
        uid = self.backend.expected_listener_uid(self.user)
        with mock.patch.object(sysutil, "run", fake.run), \
                mock.patch.object(sysutil, "cert_sha256", return_value="ab" * 32), \
                mock.patch("fastrdp_broker.backends.xrdp.netcheck.listener_uids", return_value={uid}):
            return asyncio.run(self.backend.ensure(req))

    def xrdp_desktops(self):
        return [n for n, d in self.cfg.desktops.items() if d.backend == "xrdp"]

    def test_logout_ends_only_xrdp_sessions(self):
        # Bug: logout ran `loginctl terminate-user`, ending the user's SSH sessions too.
        fake = FakeLoginctl({
            "3": (self.user.name, "xrdp-sesman", "active"),
            "4": (self.user.name, "sshd", "active"),
            "5": ("someone-else", "xrdp-sesman", "active"),
        })
        self.state.put(Session(user=self.user.name, backend="xrdp", desktop="xfce"))
        with mock.patch.object(sysutil, "run", fake.run):
            asyncio.run(self.backend.logout(self.user))
        terminated = [c for c in fake.calls if c[1].startswith("terminate")]
        self.assertEqual(terminated, [("loginctl", "terminate-session", "3")])
        self.assertIsNone(self.state.get(self.user.name, "xrdp"))

    def test_reconnect_keeps_running_desktop(self):
        # Bug: every login overwrote the recorded desktop although xrdp reconnects to
        # the desktop that is already running.
        first, second = self.xrdp_desktops()[:2]
        fake = FakeLoginctl({})
        self.login(fake, first)
        fake.sessions["7"] = (self.user.name, "xrdp-sesman", "active")
        self.login(fake, second)
        self.assertEqual(self.state.get(self.user.name, "xrdp").desktop, first)
        choice = Path(self.cfg.broker.runtime_dir, "desktop", self.user.name).read_text().strip()
        self.assertEqual(choice, self.cfg.desktops[first].xsession)

    def test_new_session_after_logout_uses_new_desktop(self):
        first, second = self.xrdp_desktops()[:2]
        fake = FakeLoginctl({})
        self.login(fake, first)
        fake.sessions["8"] = (self.user.name, "xrdp-sesman", "closing")  # ending, not reusable
        self.login(fake, second)
        self.assertEqual(self.state.get(self.user.name, "xrdp").desktop, second)

    def test_stale_record_is_reaped(self):
        # Bug: xrdp records were only removed by an explicit logout.
        from fastrdp_broker.server import Broker

        self.state.put(Session(user=self.user.name, backend="xrdp", desktop="xfce"))
        broker = Broker.__new__(Broker)
        broker.state = self.state
        broker.backends = {"xrdp": self.backend}
        with mock.patch.object(sysutil, "run", FakeLoginctl({}).run):
            asyncio.run(broker.reap())
        self.assertIsNone(self.state.get(self.user.name, "xrdp"))


if __name__ == "__main__":
    unittest.main()
