# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Records broker requests; accepts password 'good' and routes to 127.0.0.1:<port>.

Other passwords: 'deadport' -> accepted but routed to a closed port; a password listed in
REFUSALS -> that refusal (reasons: broker/brokerd/fastrdp_broker/protocol.py); anything
else -> "access denied" with reason "denied".
Users 'lanuser' / 'bogususer' get target connection_type "lan" / "bogus" (the module
must apply the first and ignore the second).
Targets carry cert_sha256 from $E2E_CERT_SHA256 (the certificate the next proxy presents;
default: 64 zeros); user 'badcert' gets another fingerprint, user 'nocert' none (the module
must refuse both: back-end certificate pin).
User 'pushwait' stands for a pending MFA push: the reply comes after PUSH_WAIT seconds
unless the proxy closes the connection first; either way a "pushwait" record with the
seconds waited and whether the peer closed goes to the log.
Progress lines (protocol.py; only when the login asks with "progress": 1):
  'progress'      an "mfa" message (push_or_web, approval URL, QR code of the login-bound
                  URL <approval URL>?login=$E2E_LOGIN_ID from the broker's ui.py and
                  qrcode.py, PROGRESS_TIMEOUT s countdown) at once, a "session_start"
                  message after PROGRESS_WAIT s, then the reply
  'pushwait'      the "mfa" message, then waits as above
  'oldbroker'     none (a broker from before progress messages), the reply after 2 s
  'badprogress'   a malformed QR code and non-string lines, then the reply
  'floodprogress' more progress messages than the module accepts
A "progresswait" record says whether the login asked and whether the peer closed.
Desktop picker (protocol.py "choose_desktop"; users whose name starts with 'picker'):
after PICKER_DELAY s (the MFA wait) a choose_desktop prompt with PICKER_OPTIONS, default
xfce, PICKER_TIMEOUT s, if the login announced "picker": 1; then it waits up to
PICKER_TIMEOUT + 5 s for the module's one line. A "pickerchoice" record holds whether a
prompt went out, the line received (null: none), whether the peer closed and the seconds
waited; the reply names the chosen desktop.
Connections are served in threads, so a waiting request does not hold up others."""
import json
import os
import select
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "broker", "brokerd"))
from fastrdp_broker import qrcode, ui  # noqa: E402

DENIED = "access denied"
REFUSALS = {
    "nogroup": {"error": DENIED, "reason": "not_allowed"},
    "mfafail": {"error": DENIED, "reason": "mfa_failed"},
    "mfatimeout": {"error": DENIED, "reason": "mfa_timeout"},
    "newreason": {"error": DENIED, "reason": "from_a_newer_broker"},
    "nobackend": {"error": "session could not be started", "reason": "backend"},
    "oldbackend": {"error": "session could not be started"},  # broker without "reason"
}

CONNECTION_TYPES = {"lanuser": "lan", "bogususer": "bogus"}
CERT_SHA256 = os.environ.get("E2E_CERT_SHA256", "0" * 64)
PUSH_WAIT = 8.0
PROGRESS_WAIT = 3.5
PROGRESS_TIMEOUT = 5
APPROVE_URL = "https://rdp1.lab.example.com/web/approve"
LOGIN_ID = os.environ.get("E2E_LOGIN_ID", "A" * 22)   # the pending login's id (mfa.WebApprovals)
PICKER_DELAY = 1.5
PICKER_TIMEOUT = 6
PICKER_OPTIONS = [{"name": "xfce", "label": "Xfce", "running": False},
                  {"name": "gnome", "label": "GNOME (running)", "running": True},
                  {"name": "plasma", "label": "KDE Plasma", "running": False}]
MFA_PROGRESS = {"progress": "mfa", "method": "push_or_web", "timeout_s": PROGRESS_TIMEOUT,
                "approve_url": APPROVE_URL, "countdown": "Time left:",
                "lines": ["Approve your sign-in", "Confirm the push on your phone, or sign in at",
                          APPROVE_URL, "Gr\u00fc\u00dfe \u2013 \u65e5\u672c"],
                "qr": qrcode.encode(ui.login_url(APPROVE_URL, LOGIN_ID).encode())}

path, log, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
log_lock = threading.Lock()


def record(rec: dict) -> None:
    with log_lock, open(log, "a") as fh:
        fh.write(json.dumps(rec) + "\n")


def wait_push(conn: socket.socket, asked: bool) -> bool:
    """Waits like a broker for a push approval; False if the peer closed first."""
    start = time.monotonic()
    closed = False
    while (left := PUSH_WAIT - (time.monotonic() - start)) > 0:
        if select.select([conn], [], [], left)[0]:
            closed = conn.recv(1) == b""  # the module never sends while it waits
            break
    record({"op": "pushwait", "asked": asked, "closed": closed,
            "waited": round(time.monotonic() - start, 2)})
    return not closed


def send(conn: socket.socket, msg: dict) -> None:
    conn.sendall((json.dumps(msg) + "\n").encode())


def wait_closed(conn: socket.socket, seconds: float) -> bool:
    """Waits; True if the peer closed the connection meanwhile."""
    return bool(select.select([conn], [], [], seconds)[0]) and conn.recv(1) == b""


def progress(conn: socket.socket, req: dict) -> bool:
    """The progress lines of the users above; False if the peer closed meanwhile."""
    asked, user, start = req.get("progress") == 1, req["user"], time.monotonic()
    closed = False
    if user == "oldbroker":
        closed = wait_closed(conn, 2)
    elif asked and user == "progress":
        send(conn, MFA_PROGRESS)
        closed = wait_closed(conn, PROGRESS_WAIT)
        if not closed:
            send(conn, {"progress": "session_start", "lines": ["Starting your desktop\u2026"]})
            closed = wait_closed(conn, 0.3)
    elif asked and user == "badprogress":
        send(conn, {**MFA_PROGRESS, "qr": ["01x", "0"], "lines": ["fine", 42, None, {"a": 1}]})
    elif asked and user == "floodprogress":
        for _ in range(40):
            send(conn, {"progress": "session_start", "lines": ["again"]})
    elif user == "progress":
        closed = wait_closed(conn, PROGRESS_WAIT)
    record({"op": "progresswait", "user": user, "asked": asked, "closed": closed,
            "waited": round(time.monotonic() - start, 2)})
    return not closed


def picker(conn: socket.socket, req: dict) -> tuple[bool, str]:
    """The desktop picker of the 'picker*' users; (peer still there, chosen desktop)."""
    asked = req.get("picker") == 1
    if wait_closed(conn, PICKER_DELAY):
        record({"op": "pickerchoice", "user": req["user"], "asked": asked, "closed": True})
        return False, "xfce"
    if not asked:
        record({"op": "pickerchoice", "user": req["user"], "asked": False, "closed": False})
        return True, "xfce"
    send(conn, {"progress": "choose_desktop", "options": PICKER_OPTIONS, "default": "xfce",
                "timeout_s": PICKER_TIMEOUT, "lines": ["Choose your desktop"],
                "countdown": "Starting in", "hint": "1-3, arrows and Enter, or click. Esc: Xfce"})
    start, line, closed = time.monotonic(), None, False
    buf = b""
    while (left := PICKER_TIMEOUT + 5 - (time.monotonic() - start)) > 0 and b"\n" not in buf:
        if not select.select([conn], [], [], left)[0]:
            break
        data = conn.recv(4096)
        if not data:
            closed = True
            break
        buf += data
    if b"\n" in buf:
        line = json.loads(buf.split(b"\n", 1)[0])
    record({"op": "pickerchoice", "user": req["user"], "asked": True, "line": line,
            "closed": closed, "waited": round(time.monotonic() - start, 2)})
    chosen = (line or {}).get("desktop") or "xfce"
    if not closed:
        send(conn, {"progress": "session_start", "lines": [f"Starting {chosen}\u2026"]})
    return not closed, chosen


def serve(conn: socket.socket) -> None:
    with conn:
        for line in conn.makefile():
            req = json.loads(line)
            record(req)
            if req["op"] == "login" and req["user"] == "pushwait":
                if req.get("progress") == 1:
                    send(conn, MFA_PROGRESS)
                if not wait_push(conn, req.get("progress") == 1):
                    return
            if req["op"] == "login" and req["user"] in ("progress", "oldbroker", "badprogress",
                                                         "floodprogress") and not progress(conn, req):
                return
            desktop = "xfce"
            if req["op"] == "login" and req["user"].startswith("picker"):
                there, desktop = picker(conn, req)
                if not there:
                    return
            if req["op"] != "login":
                rep = {"ok": True}
            elif req.get("password") in ("good", "fastrdp1:TOKEN", "deadport"):
                rep = {"ok": True, "user": req["user"], "desktop": desktop, "target": {
                    "host": "127.0.0.1", "port": 1 if req["password"] == "deadport" else port,
                    "username": req["user"], "password": "fastrdp1:TOKEN", "domain": "",
                    "security": "tls", "cert_sha256": CERT_SHA256}}
                if req["user"] == "badcert":
                    rep["target"]["cert_sha256"] = "f" * 64
                elif req["user"] == "nocert":
                    del rep["target"]["cert_sha256"]
                ct = CONNECTION_TYPES.get(req["user"])
                if ct:
                    rep["target"]["connection_type"] = ct
            else:
                rep = {"ok": False, **REFUSALS.get(req.get("password"), {"error": DENIED, "reason": "denied"})}
            try:
                send(conn, rep)
            except OSError:
                return


if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(5)
print("ready", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
