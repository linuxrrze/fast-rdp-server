# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of tests/lab/a5-collect.sh (LAB ONLY, backlog A5): argument handling, the
port from proxy.ini, the run folder, the key log (copied with mode 0600, never printed),
the journal and xrdp.log since the start, with id, tcpdump, ss and journalctl stubbed
through PATH."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "a5-collect.sh"
KEY_LINE = "CLIENT_TRAFFIC_SECRET_0 " + "ab" * 32 + " " + "cd" * 32

STUBS = {
    "id": '#!/bin/sh\necho "${A5T_UID:-0}"\n',
    # records its arguments, creates the -w file, then waits to be killed
    "tcpdump": '#!/bin/sh\necho "$@" > "$A5T_DIR/tcpdump.args"\n'
               'while [ $# -gt 0 ]; do [ "$1" = -w ] && : > "$2"; shift; done\nexec sleep 30\n',
    "ss": '#!/bin/sh\necho "ESTAB 0 0 192.0.2.1:3389 192.0.2.9:50000 args: $*"\n',
    "journalctl": '#!/bin/sh\necho "journalctl $*"\n',
}


def running(pid: int) -> bool:
    """Like a5-collect.sh's running(): a zombie counts as gone (CI containers whose PID 1
    never reaps keep a killed orphan as one)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][:1] != "Z"
    except OSError:
        return False


class A5Collect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        bindir = self.t / "bin"
        bindir.mkdir()
        for name, body in STUBS.items():
            p = bindir / name
            p.write_text(body)
            p.chmod(0o755)
        self.ini = self.t / "proxy.ini"
        self.ini.write_text("[Target]\nPort=1\n[Server]\nHost=0.0.0.0\nPort = 3390\n[Plugins]\n")
        self.keylog = self.t / "tls-keylog.txt"
        self.xrdp_log = self.t / "xrdp.log"
        self.env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", A5T_DIR=str(self.t),
                        A5_COLLECT_PROXY_INI=str(self.ini), A5_COLLECT_KEYLOG=str(self.keylog),
                        A5_COLLECT_XRDP_LOG=str(self.xrdp_log), A5_COLLECT_ROOT=str(self.t / "lab"),
                        A5_COLLECT_INTERVAL="0.1")

    def tearDown(self):
        for pidfile in (self.t / "lab").glob("*/*.pid") if (self.t / "lab").exists() else []:
            try:
                os.kill(int(pidfile.read_text()), 15)
            except (OSError, ValueError):
                pass
        self.tmp.cleanup()

    def run_script(self, *args, **env):
        return subprocess.run([str(SCRIPT), *args], env=dict(self.env, **env), capture_output=True,
                              text=True, timeout=60)

    def test_start_stop(self):
        r = self.run_script("start", "run1")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.t / "lab" / "run1"
        self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
        self.assertIn("port=3390", (d / "run.txt").read_text())  # [Server] Port, not [Target]
        self.assertEqual((self.t / "tcpdump.args").read_text().split(),
                         ["-i", "any", "-s", "0", "-U", "-w", str(d / "capture.pcap"), "tcp", "port", "3390"])
        pids = [int((d / f).read_text()) for f in ("tcpdump.pid", "ss.pid")]
        for pid in pids:
            self.assertTrue(running(pid), pid)
        time.sleep(0.5)
        self.assertIn("sport = :3390", (d / "ss.txt").read_text())
        self.keylog.write_text(KEY_LINE + "\n")
        since = (d / "run.txt").read_text().split("start=")[1].split("\n")[0]
        stamp = time.strftime("%Y%m%d-%H:%M:%S", time.strptime(since, "%Y-%m-%d %H:%M:%S"))
        self.xrdp_log.write_text("[20000101-00:00:00] [INFO ] old\n  old continuation\n"
                                 f"[{stamp}] [INFO ] new\n  new continuation\n")
        r = self.run_script("stop", "run1")
        self.assertEqual(r.returncode, 0, r.stderr)
        for pid in pids:
            for _ in range(50):
                if not running(pid):
                    break
                time.sleep(0.1)
            self.assertFalse(running(pid), pid)
        self.assertFalse(list(d.glob("*.pid")))
        k = d / "tls-keylog.txt"
        self.assertEqual(k.read_text(), KEY_LINE + "\n")
        self.assertEqual(stat.S_IMODE(k.stat().st_mode), 0o600)
        for secret in ("ab" * 32, "cd" * 32):
            self.assertNotIn(secret, r.stdout + r.stderr)
        j = (d / "journal.txt").read_text()
        for unit in ("fastrdp-proxy", "fastrdp-brokerd", "xrdp", "xrdp-sesman"):
            self.assertIn(f"-u {unit} ", j)
        self.assertIn("-o short-precise", j)
        self.assertIn(f"--since {since}", j)
        self.assertEqual((d / "xrdp.log").read_text(), f"[{stamp}] [INFO ] new\n  new continuation\n")
        self.assertIn("stop=", (d / "run.txt").read_text())
        self.assertIn("capture.pcap", r.stdout)
        self.assertIn("decode.py run1/capture.pcap run1/tls-keylog.txt --port 3390 --summary", r.stdout)
        self.assertNotIn("no key log", r.stderr)

    def test_existing_run_folder_refused(self):
        d = self.t / "own" / "x"
        d.mkdir(parents=True)
        r = self.run_script("start", "x", "--dir", str(d))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exists", r.stderr)
        self.assertFalse((self.t / "tcpdump.args").exists())

    def test_no_key_log_warns(self):
        d = self.t / "own" / "nokeys"
        self.assertEqual(self.run_script("start", "nokeys", "--dir", str(d), "--port", "3399").returncode, 0)
        self.assertIn("tcp port 3399", (self.t / "tcpdump.args").read_text())
        r = self.run_script("stop", "nokeys", "--dir", str(d))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no key log", r.stderr)
        self.assertIn("is fastrdp_proxy_tls_keylog on?", r.stderr)
        self.assertFalse((d / "tls-keylog.txt").exists())
        self.assertIn("not readable", r.stderr)  # no xrdp.log

    def test_default_port_without_proxy_ini(self):
        d = self.t / "own" / "def"
        r = self.run_script("start", "def", "--dir", str(d), A5_COLLECT_PROXY_INI=str(self.t / "none.ini"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("port=3389", (d / "run.txt").read_text())
        self.assertEqual(self.run_script("stop", "def", "--dir", str(d)).returncode, 0)

    def test_refusals(self):
        cases = {
            "not root": (["start", "r"], {"A5T_UID": "1000"}, "run as root"),
            "bad run name": (["start", "../x"], {}, "RUN must be"),
            "hidden run name": (["start", ".x"], {}, "RUN must be"),
            "bad port": (["start", "r", "--port", "70000"], {}, "bad port"),
            "port not a number": (["start", "r", "--port", "rdp"], {}, "bad port"),
            "unknown command": (["status", "r"], {}, "usage"),
            "unknown option": (["start", "r", "--if", "eth0"], {}, "usage"),
            "stop without start": (["stop", "never"], {}, "no run 'never'"),
        }
        for name, (args, env, msg) in cases.items():
            with self.subTest(name):
                r = self.run_script(*args, **env)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(msg, r.stderr)
        self.assertFalse((self.t / "tcpdump.args").exists())


if __name__ == "__main__":
    unittest.main()
