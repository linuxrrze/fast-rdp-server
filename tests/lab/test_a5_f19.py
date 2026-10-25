# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of tests/lab/a5_f19.py: the MCP client against a local fake server, the
PowerShell and journal plumbing, and the F19 sequence against a fake Windows box and host."""

from __future__ import annotations

import http.server
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_spec = importlib.util.spec_from_file_location("a5_f19", Path(__file__).resolve().parent / "a5_f19.py")
f19 = importlib.util.module_from_spec(_spec)
sys.modules["a5_f19"] = f19   # dataclasses look the module up
_spec.loader.exec_module(f19)

SID = ["A" * 32, "B" * 32, "C" * 32]
FRONT = ('front: client "WIN11-LAB" build 26100, 1280x800 32 bpp, monitors 0, scale 100/100, '
         'gfx yes, auto-reconnect cookie {cookie}, performance flags 0x00000006')


class Plumbing(unittest.TestCase):
    def test_sse(self):
        body = 'event: message\r\ndata: {"jsonrpc":"2.0","id":1,\r\ndata: "result":{}}\r\n\r\n: ping\n\ndata: x\n\n'
        self.assertEqual(f19.parse_sse(body), [{"jsonrpc": "2.0", "id": 1, "result": {}}])

    def test_ps_command(self):
        cmd = f19.ps_command(r"C:\lab\mstsc.ps1", {"Action": "watch", "Button": "^(Connect|Ver'binden)$",
                                                    "Timeout": 20.0, "Keys": ["Down", "Enter"],
                                                    "Save": None, "Trace": True, "List": False})
        self.assertEqual(cmd, r"& 'C:\lab\mstsc.ps1' -Action 'watch' -Button '^(Connect|Ver''binden)$' "
                              r"-Timeout 20.0 -Keys 'Down','Enter' -Trace; exit $LASTEXITCODE")

    def test_ps_result(self):
        out, status = f19.ps_result('Response: x\n@@JSON {"ok": true}\n\nStatus Code: 2')
        self.assertEqual(status, 2)
        self.assertEqual(f19.helper_json(out), {"ok": True})
        self.assertEqual(f19.ps_result("Command execution timed out"), ("Command execution timed out", -1))

    def test_journal_entry(self):
        e = f19.journal_entry(json.dumps({"__REALTIME_TIMESTAMP": "1792821302342000", "__CURSOR": "c1",
                                          "SYSLOG_IDENTIFIER": "fastrdp-proxy",
                                          "MESSAGE": list(f"[{SID[0]}] front: \xff".encode("latin-1"))}))
        self.assertEqual(e.session, SID[0])
        self.assertEqual(e.cursor, "c1")
        self.assertTrue(e.render().startswith("2026-10-24 05:55:02.342000Z fastrdp-proxy: ["))
        self.assertIsNone(f19.journal_entry("not json"))

    def test_front_diff(self):
        a, b = FRONT.format(cookie="no"), FRONT.format(cookie="yes")
        self.assertEqual(f19.front_diff(a, b), [("auto-reconnect cookie no", "auto-reconnect cookie yes")])
        self.assertEqual(f19.front_diff(a, a), [])

    def test_panel_timing(self):
        watch = {"window_ms": 400, "states": [["none", 0], ["black", 400], ["panel", 1300]]}
        self.assertEqual(f19.panel_after_window(watch), 900)
        self.assertEqual(f19.black_ms(watch), 900)
        black = {"window_ms": 400, "states": [["none", 0], ["black", 400]]}
        self.assertIsNone(f19.panel_after_window(black))
        self.assertEqual(f19.black_ms(black, 20000), 19600)

    def test_fingerprint(self):
        fp = "AB:" * 31 + "AB"
        self.assertEqual(f19.fingerprint("SHA256 Fingerprint=" + fp), "ab" * 32)
        with self.assertRaises(f19.SetupError):
            f19.fingerprint("AB:CD")


class FakeMcpHandler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((msg.get("method"), self.headers.get("Authorization"),
                                self.headers.get("Mcp-Session-Id")))
        if "id" not in msg:
            self.send_response(202)
            self.end_headers()
            return
        if msg["method"] == "initialize":
            body = ("event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result":
                    {"protocolVersion": "2025-03-26", "capabilities": {}}}) + "\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Mcp-Session-Id", "s-1")
        else:
            args = msg["params"]["arguments"]
            result = {"content": [{"type": "text", "text": f"Response: {args.get('command')}\nStatus Code: 0"}],
                      "isError": msg["params"]["name"] != "PowerShell"}
            body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class McpClient(unittest.TestCase):
    def test_session(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), FakeMcpHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            mcp = f19.Mcp(f"http://127.0.0.1:{srv.server_port}/mcp/", "tok")
            mcp.start()
            self.assertEqual(mcp.version, "2025-03-26")
            res = mcp.call("PowerShell", {"command": "Get-Date", "timeout": 5})
            self.assertEqual(f19.ps_result(f19.content_text(res)), ("Get-Date", 0))
            with self.assertRaises(f19.McpError):
                mcp.call("Screenshot", {})
        finally:
            srv.shutdown()
        self.assertEqual(FakeMcpHandler.seen[0], ("initialize", "Bearer tok", None))
        self.assertEqual(FakeMcpHandler.seen[1], ("notifications/initialized", "Bearer tok", "s-1"))
        self.assertEqual(FakeMcpHandler.seen[2], ("tools/call", "Bearer tok", "s-1"))

    def test_https_needs_a_pin(self):
        with self.assertRaises(f19.SetupError):
            f19.Mcp("https://box:8000/mcp/", "tok")


class FakeLab:
    """The Windows box and the fastrdp host in one: mstsc actions append journal lines."""

    def __init__(self, black_on: tuple[int, ...] = ()):
        self.entries: list = []
        self.black_on = black_on       # connections that show a black window (the A5 symptom)
        self.conn = 0
        self.connected = False
        self.waiting = False
        self.keys: list = []
        self.cleared = 0

    def log(self, ident: str, msg: str):
        self.entries.append(f19.Entry(1e9 + len(self.entries), ident, msg, str(len(self.entries))))

    def windows(self, session: bool, dialog: str | None = None) -> list:
        ws = [{"class": "#32770", "title": "Remote Desktop Connection", "hwnd": 1,
               "buttons": [{"name": "Connect", "id": "1"}], "texts": []}]
        if session:
            ws.append({"class": "TscShellContainerClass", "title": "rdp1 - Remote Desktop Connection", "hwnd": 42})
        if dialog:
            ws.append({"class": "#32770", "title": "Remote Desktop Connection", "hwnd": 7,
                       "buttons": [{"name": "OK", "id": "1"}, {"name": "Cancel", "id": "2"}], "texts": [dialog]})
        return ws

    # WinBox
    def mstsc(self, action, timeout=30, **p):
        if action in ("stop",):
            return {"ok": True}
        if action == "start":
            return {"ok": True, "pid": 4711, "windows": self.windows(False)}
        if action == "watch" and p.get("Button"):
            self.conn += 1
            sid = SID[self.conn - 1]
            self.log("fastrdp-proxy", f"[{sid}] " + FRONT.format(cookie="no"))
            self.log("fastrdp-proxy", f"[{sid}] code field shown (6 digits)")
            self.waiting = True
            if self.conn in self.black_on:
                return {"ok": True, "reached": False, "state": "black", "window_ms": 300,
                        "states": [["none", 0], ["black", 300]], "rect": [0, 0, 1280, 800],
                        "windows": self.windows(True)}
            return {"ok": True, "reached": True, "state": "panel", "window_ms": 300,
                    "states": [["none", 0], ["black", 300], ["panel", 700]], "rect": [0, 0, 1280, 800],
                    "windows": self.windows(True)}
        if action == "watch" and p.get("Until") == "desktop":
            return {"ok": True, "reached": True, "state": "other", "windows": self.windows(True)}
        if action == "close":
            self.closing = True
            return {"ok": True}
        if action == "windows":
            return {"ok": True, "windows": self.windows(True, "Your remote session will be disconnected.")}
        if action == "invoke":
            sid = SID[self.conn - 1]
            if self.waiting:
                self.log("fastrdp-brokerd", f"login of session {sid} abandoned: the proxy closed the connection")
            else:
                self.log("fastrdp-brokerd", f"session end {sid} user=labuser1")
            return {"ok": True}
        if action == "watch" and p.get("Until") == "gone":
            return {"ok": True, "reached": True, "state": "none", "windows": self.windows(False)}
        if action == "events":
            return {"ok": True, "events": []}
        raise AssertionError(action)

    def send_keys(self, hwnd, mode, text=None, keys=None):
        self.keys.append((hwnd, mode, keys or "<code>"))
        sid = SID[self.conn - 1]
        if text is not None:
            self.waiting = False
            self.log("fastrdp-brokerd", "labuser1: code from the waiting screen accepted by Keycloak")
            self.log("fastrdp-proxy", f"[{sid}] desktop picker: 2 desktops, default xfce, 30 s")
        else:
            self.log("fastrdp-proxy", f"[{sid}] back-end connection type 6 (client sent 6)")

    def screenshot(self, rect, path):
        return False

    # Server
    def out(self, argv, root=False):
        return {"dpkg-query": "3.32.2-7", "sed": "false\n", "date": "1000000000.0\n"}[argv[0]]

    def run(self, argv, root=False, timeout=30):
        if argv[0] == "fastrdpctl":
            self.cleared += 1
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def journal(self, since, cursor):
        start = int(cursor) + 1 if cursor else 0
        return self.entries[start:]


class Sequence(unittest.TestCase):
    def run_f19(self, lab: FakeLab):
        cfg = {"windows": {"client_name": "WIN11-LAB", "rdp_file": r"C:\lab\fastrdp.rdp", "helper_dir": r"C:\lab"},
               "user": {"name": "labuser1", "totp_secret_file": "/nonexistent"},
               "timing": {"login_timeout": 1, "close_timeout": 1}}
        report = f19.Report()
        with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
            test = f19.F19(cfg, Path(d), lab, lab, report)
            test.code = lambda: "123456"
            try:
                test.run()
            except f19.StepFailed as exc:
                report.check("run", False, str(exc))
            test.finish("2026-10-25T00:00:00Z")
        return {c["id"]: c["status"] for c in report.checks}, test

    def test_pass(self):
        lab = FakeLab()
        checks, test = self.run_f19(lab)
        self.assertNotIn("fail", checks.values(), checks)
        for cid in ("c1.panel", "c1.code", "c1.session", "x1.dialog", "x1.closed", "x1.dialog_back",
                    "x1.session_end", "x1.no_ultimatum", "c2.panel", "c2.session", "x3.abandoned", "x3.no_keycloak"):
            self.assertEqual(checks.get(cid), "pass", cid)
        self.assertEqual(lab.cleared, 3)
        self.assertEqual(lab.keys[0], (42, "Scancode", "<code>"))
        self.assertEqual(lab.keys[1], (42, "Scancode", ["Enter"]))     # the picker
        self.assertEqual(test.conns[1]["panel_ms"], 400)
        self.assertTrue(any("front: " in line for line in test.conns[0]["diagnostics"]))

    def test_black_window_on_the_second_connect(self):
        checks, test = self.run_f19(FakeLab(black_on=(2,)))
        self.assertEqual(checks["c2.panel"], "fail")
        self.assertEqual(checks["run"], "fail")
        self.assertNotIn("c3.front", checks)

    def test_ultimatum_fails(self):
        lab = FakeLab()
        real = lab.mstsc

        def mstsc(action, timeout=30, **p):
            if action == "invoke" and lab.conn == 1:
                lab.log("fastrdp-proxy", "disconnect provider ultimatum sent to peer, closing connection")
            return real(action, timeout, **p)
        lab.mstsc = mstsc
        checks, _ = self.run_f19(lab)
        self.assertEqual(checks["x1.no_ultimatum"], "fail")


if __name__ == "__main__":
    unittest.main()
