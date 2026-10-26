#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (drives a Windows lab client and logs in lab users with their TOTP seeds).
# Backlog A5, lab test F19 (docs/lab-waiting-screen-input.md), automated: mstsc's X, then
# *Connect* again in the SAME mstsc process; once more with the X while the panel waits.
# Set-up: docs/lab-windows-mcp.md (Windows-MCP, tests/lab/windows/*.ps1 in helper_dir).
#
#   tests/lab/a5_f19.py --config a5-f19.toml [--out DIR] [--no-x-while-waiting]
#                       [--connection2 code|web]
#
# Steps (the connection number is the one in the report):
#   1  restart mstsc (/edit rdp_file), Connect, the panel, the code (tests/lab/totp.py),
#      the desktop (picker: picker_keys)
#   X  WM_CLOSE to the session window, OK in mstsc's dialog; mstsc must return to its
#      connection dialog, the proxy must not log "disconnect provider ultimatum sent to
#      peer" (patch 0008), the broker logs "session end"
#   2  Connect in the same process: the panel within panel_limit seconds of the session
#      window, then the code and the desktop again (the A5 symptom: a black window);
#      connection2 = "web": instead of the code, the panel still shown, then the login
#      approved like a phone after its QR code (tests/lab/approve.py: Keycloak password +
#      TOTP or [user] passkey_file, Approve on <approve_url>?login=<id>), the broker's
#      "approved via the login-bound link"
#   X  as above
#   3  Connect, the X while the panel waits: the broker abandons the login at once
# Before each connection the user's reconnect grace is cleared (fastrdpctl clear-grace),
# so every login shows the waiting screen. Per connection the report keeps the proxy's
# diagnostics (front:, Save Session Info, Refresh Rect, Suppress Output, unread bytes) and
# the differences of the front: lines; WaitingScreenObserve is read from proxy.ini (F19c
# run 1 or 2: switch it with the role, then run this again).
#
# Output in --out (default ./a5-f19-<time>): summary.txt, results.json, journal.txt (the
# proxy's and broker's lines since the start), mstsc-events.json, screenshots *.png. Codes
# are never written; the PNGs may show the panel (lab data, docs/lab-windows-mcp.md §8).
# Exit: 0 every check passed (warnings allowed), 1 a check failed, 2 set-up error.
"""LAB ONLY: backlog A5 / lab test F19 against a Windows client driven over MCP (see header)."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOTP = HERE / "totp.py"
BROKER_TOML = "/etc/fastrdp/broker.toml"
WEB_APPROVAL_MODES = ("web", "push_or_web", "code_or_web")   # fastrdp_broker/config.py
PROTOCOL = "2025-06-18"
SESSION_ID = re.compile(r"\b[0-9A-F]{32}\b")
FREERDP_MIN = "3.32.2-7"   # patches/freerdp/0008: Shutdown Request Denied


class SetupError(Exception):
    pass


def approve_module():
    """tests/lab/approve.py (the approval page like a phone), loaded for connection2 = "web" only."""
    import importlib.util
    if "fastrdp_lab_approve" not in sys.modules:
        spec = importlib.util.spec_from_file_location("fastrdp_lab_approve", HERE / "approve.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["fastrdp_lab_approve"] = mod   # dataclasses look the module up
        spec.loader.exec_module(mod)
    return sys.modules["fastrdp_lab_approve"]


class StepFailed(Exception):
    """A step the later steps depend on failed; the run stops and saves what it has."""


# --- MCP (streamable HTTP) ----------------------------------------------------------------

class McpError(Exception):
    pass


def parse_sse(text: str) -> list[dict]:
    """JSON-RPC messages from a text/event-stream body (data: lines, blank-line separated)."""
    out, data = [], []
    for line in text.replace("\r\n", "\n").split("\n") + [""]:
        if line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif line == "" and data:
            try:
                out.append(json.loads("\n".join(data)))
            except ValueError:
                pass
            data = []
    return out


def fingerprint(text: str) -> str:
    fp = re.sub(r"[^0-9a-f]", "", text.lower().removeprefix("sha256 fingerprint="))
    if len(fp) != 64:
        raise SetupError("mcp.cert_sha256: 64 hex digits (openssl x509 -noout -fingerprint -sha256)")
    return fp


class Mcp:
    """Minimal MCP client: initialize, then tools/call; TLS pinned to one certificate."""

    def __init__(self, url: str, token: str, cert_sha256: str | None = None):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise SetupError(f"mcp.url: http or https, not {u.scheme!r}")
        if u.scheme == "https" and not cert_sha256:
            raise SetupError("mcp.cert_sha256 is needed for https (the server's certificate is self-signed)")
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.path = u.path or "/mcp/"
        self.token = token
        self.fp = fingerprint(cert_sha256) if self.https else None
        self.session: str | None = None
        self.version = PROTOCOL
        self.ids = 0

    def _connect(self, timeout: float) -> http.client.HTTPConnection:
        if not self.https:
            return http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # replaced by the fingerprint check below
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ctx)
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if hashlib.sha256(der).hexdigest() != self.fp:
            conn.close()
            raise McpError("the server's certificate does not match mcp.cert_sha256")
        return conn

    def _post(self, msg: dict, timeout: float) -> dict | None:
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {self.token}"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
            headers["MCP-Protocol-Version"] = self.version
        try:
            conn = self._connect(timeout)
            try:
                conn.request("POST", self.path, json.dumps(msg).encode(), headers)
                resp = conn.getresponse()
                body = resp.read().decode("utf-8", "replace")
                if resp.getheader("Mcp-Session-Id"):
                    self.session = resp.getheader("Mcp-Session-Id")
                ctype = resp.getheader("Content-Type", "")
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as exc:
            raise McpError(f"{msg.get('method')}: {type(exc).__name__}: {exc}") from None
        if "id" not in msg and resp.status in (200, 202):   # a notification
            return None
        if resp.status != 200:
            raise McpError(f"HTTP {resp.status} for {msg.get('method')}: {body[:200]}")
        msgs = parse_sse(body) if ctype.startswith("text/event-stream") else [json.loads(body)]
        for m in msgs:
            if m.get("id") == msg.get("id"):
                if "error" in m:
                    raise McpError(f"{msg.get('method')}: {m['error'].get('message', m['error'])}")
                return m.get("result", {})
        raise McpError(f"no reply to {msg.get('method')}")

    def request(self, method: str, params: dict, timeout: float = 60) -> dict:
        self.ids += 1
        return self._post({"jsonrpc": "2.0", "id": self.ids, "method": method, "params": params}, timeout)

    def start(self) -> dict:
        res = self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                          "clientInfo": {"name": "fastrdp-a5-f19", "version": "1"}})
        self.version = res.get("protocolVersion", PROTOCOL)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 30)
        return res

    def call(self, tool: str, args: dict, timeout: float = 60) -> dict:
        res = self.request("tools/call", {"name": tool, "arguments": args}, timeout)
        if res.get("isError"):
            raise McpError(f"{tool}: {content_text(res)[:300]}")
        return res


def content_text(res: dict) -> str:
    return "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")


# --- the Windows box ----------------------------------------------------------------------

def ps_quote(value) -> str:
    """A PowerShell argument: numbers as they are, everything else single-quoted."""
    if isinstance(value, bool):
        raise TypeError("switches are passed by name")
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ",".join(ps_quote(v) for v in value)
    return "'" + str(value).replace("'", "''") + "'"


def ps_command(script: str, params: dict) -> str:
    parts = ["&", ps_quote(script)]
    for name, value in params.items():
        if value is None or value is False:
            continue
        parts.append(f"-{name}" if value is True else f"-{name} {ps_quote(value)}")
    return " ".join(parts) + "; exit $LASTEXITCODE"


def ps_result(text: str) -> tuple[str, int]:
    """Windows-MCP's PowerShell tool answers "Response: <output>\\nStatus Code: <n>"."""
    m = re.search(r"\nStatus Code: (-?\d+)\s*$", text)
    status = int(m.group(1)) if m else -1
    body = text[:m.start()] if m else text
    return body.removeprefix("Response: "), status


def helper_json(output: str) -> dict | None:
    for line in output.splitlines():
        if line.startswith("@@JSON "):
            return json.loads(line[7:])
    return None


class WinBox:
    def __init__(self, mcp: Mcp, helper_dir: str):
        self.mcp = mcp
        self.dir = helper_dir.rstrip("\\")

    def _ps(self, script: str, params: dict, timeout: float) -> tuple[str, int]:
        res = self.mcp.call("PowerShell", {"command": ps_command(f"{self.dir}\\{script}", params),
                                           "timeout": int(timeout)}, timeout + 20)
        return ps_result(content_text(res))

    def mstsc(self, action: str, timeout: float = 30, **params) -> dict:
        out, status = self._ps("mstsc.ps1", {"Action": action, **params}, timeout)
        data = helper_json(out)
        if data is None:
            raise McpError(f"mstsc.ps1 -Action {action}: no result (status {status}): {out[:300]}")
        data["status"] = status
        return data

    def send_keys(self, hwnd: int, mode: str, text: str | None = None, keys: list[str] | None = None) -> None:
        params = {"Mode": mode, "Hwnd": hwnd}
        params.update({"Text": text} if text is not None else {"Keys": keys})
        try:
            out, status = self._ps("send-keys.ps1", params, 30)
        except McpError:
            raise McpError("send-keys.ps1 failed (details left out: the call carried a code)") from None
        if status != 0:
            raise McpError(f"send-keys.ps1 exit {status}")   # its output never has the characters

    def screenshot(self, rect: list[int] | None, path: Path) -> bool:
        args = {"region": rect} if rect else {}
        try:
            res = self.mcp.call("Screenshot", args, 60)
        except McpError:
            return False
        for c in res.get("content", []):
            if c.get("type") == "image" and c.get("data"):
                path.write_bytes(base64.b64decode(c["data"]))
                return True
        return False


# --- the fastrdp host ---------------------------------------------------------------------

@dataclasses.dataclass
class Entry:
    t: float            # journal time, seconds since the epoch
    ident: str          # SYSLOG_IDENTIFIER or the unit
    msg: str
    cursor: str

    @property
    def session(self) -> str | None:
        m = SESSION_ID.search(self.msg)
        return m.group(0) if m else None

    def render(self) -> str:
        secs, us = divmod(round(self.t * 1e6), 1_000_000)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(secs)) + f".{us:06d}Z"
        return f"{stamp} {self.ident}: {self.msg}"


def journal_entry(line: str) -> Entry | None:
    try:
        j = json.loads(line)
    except ValueError:
        return None
    msg = j.get("MESSAGE", "")
    if isinstance(msg, list):   # journalctl -o json: bytes that are not UTF-8
        msg = bytes(msg).decode("utf-8", "replace")
    ident = j.get("SYSLOG_IDENTIFIER") or j.get("_SYSTEMD_UNIT") or "?"
    return Entry(int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6, ident, msg or "", j.get("__CURSOR", ""))


class Server:
    def __init__(self, ssh: str, sudo: bool, units: list[str]):
        self.ssh, self.sudo, self.units = ssh, sudo, units
        # one ssh connection for the many journal polls (%C: a short hash, socket paths are limited)
        control = Path(tempfile.gettempdir()) / "fastrdp-a5f19-%C"
        self.opts = ["-o", "BatchMode=yes", "-o", "ControlMaster=auto",
                     "-o", f"ControlPath={control}", "-o", "ControlPersist=120"]

    def close(self) -> None:
        subprocess.run(["ssh", *self.opts, "-O", "exit", self.ssh], capture_output=True, timeout=10)

    def run(self, argv: list[str], root: bool = False, timeout: float = 30) -> subprocess.CompletedProcess:
        cmd = (["sudo", "-n"] if root and self.sudo else []) + argv
        return subprocess.run(["ssh", *self.opts, self.ssh, "--", shlex.join(cmd)],
                              capture_output=True, text=True, timeout=timeout)

    def out(self, argv: list[str], root: bool = False) -> str:
        r = self.run(argv, root)
        if r.returncode != 0:
            raise SetupError(f"{shlex.join(argv)} on {self.ssh}: {r.stderr.strip() or r.returncode}")
        return r.stdout

    def journal(self, since: float, cursor: str | None) -> list[Entry]:
        argv = ["journalctl", "--no-pager", "-o", "json",
                "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT"]
        for u in self.units:
            argv += ["-u", u]
        argv += ["--after-cursor", cursor] if cursor else ["--since", f"@{int(since)}"]
        return [e for e in map(journal_entry, self.out(argv, root=True).splitlines())
                if e and e.t >= since]


class Journal:
    def __init__(self, server: Server, since: float):
        self.server, self.since = server, since
        self.cursor: str | None = None
        self.entries: list[Entry] = []

    def poll(self) -> None:
        new = self.server.journal(self.since, self.cursor)
        if new:
            self.cursor = new[-1].cursor
            self.entries += new

    def mark(self) -> int:
        self.poll()
        return len(self.entries)

    def find(self, pred, start: int = 0) -> Entry | None:
        return next((e for e in self.entries[start:] if pred(e)), None)

    def wait(self, pred, timeout: float, start: int = 0) -> Entry | None:
        deadline = time.monotonic() + timeout
        while True:
            self.poll()
            hit = self.find(pred, start)
            if hit or time.monotonic() >= deadline:
                return hit
            time.sleep(0.4)


# --- evaluation helpers -------------------------------------------------------------------

def front_parts(msg: str) -> list[str]:
    i = msg.find("front: ")
    return [p.strip() for p in msg[i + 7:].split(", ")] if i >= 0 else []


def front_diff(a: str, b: str) -> list[tuple[str, str]]:
    pa, pb = front_parts(a), front_parts(b)
    n = max(len(pa), len(pb))
    pa += [""] * (n - len(pa))
    pb += [""] * (n - len(pb))
    return [(x, y) for x, y in zip(pa, pb) if x != y]


DIAGNOSTICS = ("front: ", "Save Session Info", "Refresh Rect", "Suppress Output", "were not read",
               "waiting screen", "front connection closed", "request abandoned", "ErrorInfo",
               "code field shown", "desktop picker", "back-end connection")


def diagnostics(entries: list[Entry], sid: str) -> list[str]:
    return [e.render() for e in entries if e.session == sid and any(k in e.msg for k in DIAGNOSTICS)]


def panel_after_window(watch: dict) -> int | None:
    """Milliseconds from the session window to the first panel state, from mstsc.ps1 watch."""
    if watch.get("window_ms") is None:
        return None
    for state, ms in watch.get("states") or []:
        if state == "panel":
            return ms - watch["window_ms"]
    return None


def black_ms(watch: dict, end_ms: int | None = None) -> int:
    """How long the session window was black before the watch ended (or end_ms)."""
    states = list(watch.get("states") or [])
    total = 0
    for i, (state, ms) in enumerate(states):
        nxt = states[i + 1][1] if i + 1 < len(states) else end_ms
        if state == "black" and nxt is not None:
            total += nxt - ms
    return total


class Report:
    def __init__(self):
        self.checks: list[dict] = []
        self.info: dict = {}

    def check(self, cid: str, ok: bool, detail: str, warn_only: bool = False) -> bool:
        status = "pass" if ok else ("warn" if warn_only else "fail")
        self.checks.append({"id": cid, "status": status, "detail": detail})
        print(f"{status.upper():4} {cid}: {detail}", flush=True)
        return ok

    @property
    def failed(self) -> bool:
        return any(c["status"] == "fail" for c in self.checks)


# --- the test -----------------------------------------------------------------------------

class F19:
    def __init__(self, cfg: dict, out: Path, win: WinBox, server: Server, report: Report):
        self.cfg, self.out, self.win, self.server, self.r = cfg, out, win, server, report
        w, u, t = cfg["windows"], cfg["user"], cfg.get("timing", {})
        self.client = w["client_name"]
        self.connect_re = w.get("connect_button", "^(Connect|Verbinden)$")
        self.ok_re = w.get("ok_button", "^OK$")
        self.mode = w.get("key_mode", "Scancode")
        self.shots = w.get("shots_dir")
        self.user = u["name"]
        self.connection2 = u.get("connection2", "code")
        self.approve_url: str | None = None   # web: [web] approve_url or the broker's [ui] approve_url
        self.picker_keys = u.get("picker_keys", ["Enter"])
        self.panel_limit = float(t.get("panel_limit", 1.0))
        self.panel_timeout = float(t.get("panel_timeout", 20))
        self.login_timeout = float(t.get("login_timeout", 60))
        self.close_timeout = float(t.get("close_timeout", 15))
        self.approve_timeout = float(t.get("approve_timeout", 15))
        self.pid: int | None = None
        self.journal: Journal | None = None
        self.conns: list[dict] = []

    # TOTP from the lab user's seed; the code goes to send-keys only
    def code(self) -> str:
        u = self.cfg["user"]
        argv = [sys.executable, "-I", str(TOTP), "--secret-file", os.path.expanduser(u["totp_secret_file"]),
                "--min-left", "8"]
        if u.get("totp_state"):
            argv += ["--state", os.path.expanduser(u["totp_state"])]
        argv += [f"--{k}={u[k]}" for k in ("algorithm", "digits", "period") if k in u]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise StepFailed(f"totp.py exit {r.returncode}: {r.stderr.strip()}")
        return r.stdout.split()[0]

    def shot(self, name: str, rect) -> str | None:
        path = self.out / f"{name}.png"
        return path.name if self.win.screenshot(rect, path) else None

    def preconditions(self) -> None:
        ver = self.server.out(["dpkg-query", "-W", "-f=${Version}", "fastrdp-freerdp3"]).strip()
        ge = self.server.run(["dpkg", "--compare-versions", ver, "ge", FREERDP_MIN]).returncode == 0
        self.r.check("pre.freerdp", ge, f"fastrdp-freerdp3 {ver} (needs >= {FREERDP_MIN})")
        observe = self.server.out(["sed", "-n", "s/^WaitingScreenObserve=//p", "/etc/fastrdp/proxy.ini"],
                                  root=True).strip() or "false"
        self.r.info["waiting_screen_observe"] = observe
        print(f"INFO WaitingScreenObserve={observe} (F19c run {'2' if observe == 'true' else '1'})")
        if self.connection2 == "web":
            self.web_preconditions()

    def web_preconditions(self) -> None:
        """The approval page needs a web approval mode; its URL is the QR code's."""
        try:
            broker = tomllib.loads(self.server.out(["cat", BROKER_TOML], root=True))
        except tomllib.TOMLDecodeError as exc:
            raise SetupError(f"{BROKER_TOML}: {exc}") from None
        mode = broker.get("mfa", {}).get("mode", "none")
        ok = mode in WEB_APPROVAL_MODES
        self.r.check("pre.web", ok, f"[mfa] mode = {mode!r}" + ("" if ok else
                     f": no approval page (connection2 = \"web\" needs one of {', '.join(WEB_APPROVAL_MODES)})"))
        if not ok:
            raise SetupError(f"connection2 = \"web\": [mfa] mode {mode!r} in {BROKER_TOML} has no approval page")
        self.approve_url = self.cfg.get("web", {}).get("approve_url") or broker.get("ui", {}).get("approve_url")
        if not self.approve_url:
            raise SetupError(f"connection2 = \"web\": no approval URL ([ui] approve_url in {BROKER_TOML} "
                             "is empty; set [web] approve_url)")
        self.r.info["approve_url"] = self.approve_url

    def start_mstsc(self) -> None:
        self.win.mstsc("stop")
        res = self.win.mstsc("start", RdpFile=self.cfg["windows"]["rdp_file"])
        if not res.get("ok"):
            raise StepFailed(f"mstsc did not start: {res.get('error')}")
        self.pid = res["pid"]
        self.r.info["mstsc_pid"] = self.pid

    def session_window(self, watch: dict) -> dict | None:
        return next((w for w in watch.get("windows") or [] if w["class"] == "TscShellContainerClass"), None)

    def connect(self, n: int) -> dict:
        cleared = self.server.run(["fastrdpctl", "clear-grace", self.user], root=True)
        if cleared.returncode != 0:
            self.r.check(f"c{n}.grace", False, f"fastrdpctl clear-grace: {cleared.stderr.strip()}", warn_only=True)
        mark = self.journal.mark()
        save = f"{self.shots}\\a5-f19-c{n}-panel.png" if self.shots else None
        watch = self.win.mstsc("watch", timeout=self.panel_timeout + 15, Button=self.connect_re,
                               Timeout=self.panel_timeout, Until="panel", ProcessId=self.pid, Save=save)
        conn = {"n": n, "pid": self.pid, "watch": watch, "mark": mark}
        self.conns.append(conn)
        if not watch.get("ok"):
            raise StepFailed(f"connection {n}: {watch.get('error')}")
        front = self.journal.wait(lambda e: e.msg.find(f'front: client "{self.client}"') >= 0, 10, mark)
        conn["sid"] = front.session if front else None
        conn["front"] = front.msg if front else None
        self.r.check(f"c{n}.front", front is not None,
                     f"session {conn['sid']}" if front else f'no "front: client \\"{self.client}\\"" line')
        sw = self.session_window(watch)
        conn["hwnd"] = sw["hwnd"] if sw else None
        conn["rect"] = watch.get("rect")
        conn["panel_ms"] = panel_after_window(watch)
        conn["shot_panel"] = self.shot(f"c{n}-panel", conn["rect"])
        if conn["sid"]:
            grace = self.journal.find(lambda e: "second factor skipped" in e.msg and self.user in e.msg, mark)
            if grace:
                self.r.check(f"c{n}.mfa", False, f"the second factor was skipped: {grace.msg}")
        return conn

    def check_panel(self, conn: dict, limit: float | None) -> bool:
        n, watch, ms = conn["n"], conn["watch"], conn["panel_ms"]
        states = " -> ".join(f"{s}@{t}ms" for s, t in watch.get("states") or [])
        if ms is None:
            return self.r.check(f"c{n}.panel", False, f"no panel within {self.panel_timeout:.0f} s; states {states}; "
                                f"black {black_ms(watch, int(self.panel_timeout * 1000))} ms")
        if limit is not None and ms > limit * 1000:
            return self.r.check(f"c{n}.panel", False, f"panel {ms} ms after the session window "
                                f"(limit {limit * 1000:.0f} ms); states {states}", warn_only=True)
        return self.r.check(f"c{n}.panel", True, f"panel {ms} ms after the session window; states {states}")

    def login(self, conn: dict) -> None:
        n, sid = conn["n"], conn["sid"]
        if not (sid and conn["hwnd"]):
            raise StepFailed(f"connection {n}: no session to log in")
        field = self.journal.wait(lambda e: e.session == sid and "code field shown" in e.msg, 10, conn["mark"])
        if not self.r.check(f"c{n}.field", field is not None, "code field shown" if field else "no code field"):
            raise StepFailed("no code field: is [mfa] mode code_or_web?")
        mark = self.journal.mark()
        self.win.send_keys(conn["hwnd"], self.mode, text=self.code())
        accepted = self.journal.wait(lambda e: "code from the waiting screen accepted" in e.msg and self.user in e.msg,
                                     30, mark)
        if not self.r.check(f"c{n}.code", accepted is not None,
                            "code accepted by Keycloak" if accepted else "the code was not accepted"):
            raise StepFailed(f"connection {n}: login failed")
        self.desktop(conn, mark)

    def web_decide(self):
        """Approve the user's one waiting login on the approval page (no journal line names
        its id: approve.py takes it from the page's list, then opens <url>?login=<id>)."""
        approve = approve_module()
        u, w = self.cfg["user"], self.cfg.get("web", {})
        pins = w.get("cert_sha256") or []
        code = approve.code_source(u["totp_secret_file"], u.get("totp_state"), 8, False,
                                   u.get("algorithm"), u.get("digits"), u.get("period"))
        password = approve.read_password(u["password_file"]) if "password_file" in u else None
        passkeys = approve.Passkeys(u["passkey_file"]) if "passkey_file" in u else None
        browser = approve.Browser(w.get("ca_file") and os.path.expanduser(w["ca_file"]),
                                  tuple([pins] if isinstance(pins, str) else pins))
        return approve.Approver(self.approve_url, u.get("idp_user", self.user), password, code, browser,
                                passkeys=passkeys).run()

    def login_web(self, conn: dict) -> None:
        """Connection 2 approved on the approval page instead of the code (connection2 = "web")."""
        approve = approve_module()
        n, sid = conn["n"], conn["sid"]
        if not (sid and conn["hwnd"]):
            raise StepFailed(f"connection {n}: no session to log in")
        pending = self.journal.wait(lambda e: "web approval pending for" in e.msg and self.user in e.msg,
                                    10, conn["mark"])
        if not self.r.check(f"c{n}.pending", pending is not None,
                            "broker: web approval pending" if pending else "no 'web approval pending' line"):
            raise StepFailed(f"connection {n}: the login does not wait for web approval")
        still = self.win.mstsc("watch", timeout=20, Timeout=3, Until="panel", ProcessId=self.pid)
        self.r.check(f"c{n}.panel_shown", bool(still.get("reached")),
                     "panel still shown" if still.get("reached") else f"window state {still.get('state')}")
        mark = self.journal.mark()
        try:
            res = self.web_decide()
        except approve.SetupError as exc:
            raise SetupError(f"approve.py: {exc}") from None
        except approve.Failed as exc:
            self.r.check(f"c{n}.web", False, f"approval page: {exc}")
            raise StepFailed(f"connection {n}: not approved") from None
        conn["login_id"] = res.login
        self.r.check(f"c{n}.web", True, f"approval page: {res.message}")
        line = self.journal.wait(lambda e: f"web approval for {self.user} from" in e.msg
                                 and "approved via the login-bound link" in e.msg, self.approve_timeout, mark)
        if not self.r.check(f"c{n}.approved", line is not None,
                            "broker: approved via the login-bound link" if line
                            else "no 'web approval for … approved via the login-bound link' line"):
            raise StepFailed(f"connection {n}: login failed")
        self.desktop(conn, mark)

    def desktop(self, conn: dict, mark: int) -> None:
        """After the second factor: the picker (picker_keys), the back-end, the desktop."""
        n, sid = conn["n"], conn["sid"]
        picker = self.journal.wait(lambda e: e.session == sid and "desktop picker:" in e.msg, 3, mark)
        if picker and self.picker_keys:
            self.win.send_keys(conn["hwnd"], "Scancode", keys=self.picker_keys)
        backend = self.journal.wait(lambda e: e.session == sid and "back-end connection type" in e.msg,
                                    self.login_timeout, mark)
        if not self.r.check(f"c{n}.session", backend is not None,
                            "back-end connected" if backend else f"no back-end within {self.login_timeout:.0f} s"):
            raise StepFailed(f"connection {n}: no session")
        desk = self.win.mstsc("watch", timeout=45, Timeout=30, Until="desktop", ProcessId=self.pid)
        self.r.check(f"c{n}.desktop", bool(desk.get("reached")),
                     "desktop drawn" if desk.get("reached") else f"window state {desk.get('state')}", warn_only=True)
        conn["shot_desktop"] = self.shot(f"c{n}-desktop", desk.get("rect"))

    def connection_dialog(self, w: dict) -> bool:
        return any(re.search(self.connect_re, b.get("name") or "") for b in w.get("buttons") or [])

    def close_x(self, conn: dict, label: str, waiting: bool = False) -> dict:
        """The X: WM_CLOSE to the session window, then OK in mstsc's dialog."""
        n, sid = conn["n"], conn["sid"]
        mark = self.journal.mark()
        closed = self.win.mstsc("close", ProcessId=self.pid)
        if not closed.get("ok"):
            raise StepFailed(f"{label}: {closed.get('error')}")
        dialog = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and dialog is None:
            ws = self.win.mstsc("windows", ProcessId=self.pid).get("windows") or []
            dialog = next((w for w in ws if w["class"] == "#32770" and not self.connection_dialog(w)), None)
        x = {"label": label, "dialog": dialog}
        if dialog:
            x["dialog_shot"] = self.shot(f"{label}-dialog", None)
            self.win.mstsc("invoke", Button=self.ok_re, ProcessId=self.pid)
        self.r.check(f"{label}.dialog", dialog is not None,
                     f"mstsc asked: {' / '.join(dialog.get('texts') or [dialog['title']])}" if dialog
                     else "no confirmation dialog (mstsc set not to ask?)", warn_only=True)
        gone = self.win.mstsc("watch", timeout=self.close_timeout + 15, Timeout=self.close_timeout,
                              Until="gone", ProcessId=self.pid)
        self.r.check(f"{label}.closed", bool(gone.get("reached")),
                     "session window closed" if gone.get("reached") else "the session window stayed")
        back = [w for w in gone.get("windows") or [] if w["class"] == "#32770"]
        x["windows_after"] = back
        main = any(self.connection_dialog(w) for w in back)
        self.r.check(f"{label}.dialog_back", main,
                     f"mstsc {self.pid} shows its connection dialog again" if main
                     else f"no connection dialog in mstsc {self.pid}: {[w['title'] for w in back]}")
        if waiting:
            ab = self.journal.wait(lambda e: f"login of session {sid} abandoned" in e.msg, 5, mark)
            self.r.check(f"{label}.abandoned", ab is not None,
                         "the broker abandoned the login" if ab else "no 'login ... abandoned' within 5 s")
            kc = self.journal.find(lambda e: "code from the waiting screen" in e.msg and self.user in e.msg, mark)
            self.r.check(f"{label}.no_keycloak", kc is None, "no code check" if kc is None else kc.msg)
        else:
            end = self.journal.wait(lambda e: f"session end {sid}" in e.msg, self.close_timeout, mark)
            self.r.check(f"{label}.session_end", end is not None,
                         "broker: session end" if end else "no 'session end' from the broker", warn_only=True)
        self.journal.poll()
        ult = self.journal.find(lambda e: "disconnect provider ultimatum sent to peer" in e.msg, mark)
        if not waiting:
            self.r.check(f"{label}.no_ultimatum", ult is None,
                         "no provider-initiated disconnect" if ult is None else f"proxy: {ult.msg}")
        x["other_dialogs"] = [w.get("texts") or w["title"] for w in back if not self.connection_dialog(w)]
        conn.setdefault("x", []).append(x)
        return x

    def run(self, x_while_waiting: bool = True) -> None:
        self.preconditions()
        self.journal = Journal(self.server, float(self.server.out(["date", "+%s.%N"])))
        self.start_mstsc()
        c1 = self.connect(1)
        self.check_panel(c1, None)
        self.login(c1)
        self.close_x(c1, "x1")

        c2 = self.connect(2)   # Connect in the same mstsc process: watch presses its button
        if c1.get("front") and c2.get("front"):
            diff = front_diff(c1["front"], c2["front"])
            self.r.info["front_diff_c1_c2"] = diff
            print("INFO front: c1 -> c2: " + ("; ".join(f"{a} -> {b}" for a, b in diff) or "no difference"))
        if not self.check_panel(c2, self.panel_limit):
            # the A5 symptom: keep the connection until the proxy gives up, for the journal
            self.journal.wait(lambda e: e.session == c2["sid"] and ("waiting screen:" in e.msg or
                              "front connection closed" in e.msg), self.login_timeout, c2["mark"])
            raise StepFailed("connection 2 showed no panel (backlog A5)")
        if self.connection2 == "web":
            self.login_web(c2)
        else:
            self.login(c2)
        self.close_x(c2, "x2")

        if x_while_waiting:
            c3 = self.connect(3)
            if self.check_panel(c3, None):
                self.close_x(c3, "x3", waiting=True)

    def finish(self, started_iso: str) -> None:
        if self.journal:
            self.journal.poll()
            (self.out / "journal.txt").write_text("".join(e.render() + "\n" for e in self.journal.entries))
            for c in self.conns:
                c["diagnostics"] = diagnostics(self.journal.entries, c.get("sid")) if c.get("sid") else []
        try:
            ev = self.win.mstsc("events", timeout=60, Since=started_iso)
            (self.out / "mstsc-events.json").write_text(json.dumps(ev, indent=2))
        except McpError as exc:
            print(f"WARN mstsc events: {exc}")


def load_config(path: Path) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    for section, keys in {"mcp": ["url", "auth_key_file"], "windows": ["rdp_file", "client_name", "helper_dir"],
                          "server": ["ssh"], "user": ["name", "totp_secret_file"]}.items():
        for k in keys:
            if k not in cfg.get(section, {}):
                raise SetupError(f"{path}: [{section}] {k} missing")
    check_user(cfg["user"], path)
    return cfg


def check_user(u: dict, path: Path) -> None:
    if u.get("connection2", "code") not in ("code", "web"):
        raise SetupError(f'{path}: [user] connection2 is "code" or "web"')
    if u.get("connection2") == "web" and not ({"password_file", "passkey_file"} & set(u)):
        raise SetupError(f'{path}: [user] password_file or passkey_file missing (connection2 = "web")')


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="LAB ONLY: backlog A5 / lab test F19, automated")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--no-x-while-waiting", action="store_true", help="skip connection 3")
    ap.add_argument("--connection2", choices=("code", "web"),
                    help="connection 2: the code (default) or the approval page ([user] connection2)")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
        if args.connection2:
            cfg["user"]["connection2"] = args.connection2
            check_user(cfg["user"], args.config)
        out = args.out or Path(f"a5-f19-{time.strftime('%Y%m%d-%H%M%S')}")
        out.mkdir(parents=True, exist_ok=True)
        token = Path(os.path.expanduser(cfg["mcp"]["auth_key_file"])).read_text().strip()
        mcp = Mcp(cfg["mcp"]["url"], token, cfg["mcp"].get("cert_sha256"))
        mcp.start()
        srv = cfg["server"]
        server = Server(srv["ssh"], bool(srv.get("sudo", False)),
                        [srv.get("proxy_unit", "fastrdp-proxy.service"), srv.get("broker_unit", "fastrdp-brokerd.service")])
    except (SetupError, McpError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"a5_f19: {exc}", file=sys.stderr)
        return 2
    report = Report()
    test = F19(cfg, out, WinBox(mcp, cfg["windows"]["helper_dir"]), server, report)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
    try:
        test.run(x_while_waiting=not args.no_x_while_waiting)
    except StepFailed as exc:
        report.check("run", False, f"stopped: {exc}")
    except (SetupError, McpError, subprocess.TimeoutExpired) as exc:
        report.check("run", False, f"stopped: {type(exc).__name__}: {exc}")
    finally:
        test.finish(started)
        conns = [{k: v for k, v in c.items() if k != "mark"} for c in test.conns]
        (out / "results.json").write_text(json.dumps({"checks": report.checks, "info": report.info,
                                                      "connections": conns}, indent=2))
        lines = [f"{c['status'].upper():4} {c['id']}: {c['detail']}" for c in report.checks]
        (out / "summary.txt").write_text("\n".join(lines) + "\n")
        server.close()
    print(f"results in {out}/")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
