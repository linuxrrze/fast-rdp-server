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
Connections are served in threads, so a waiting request does not hold up others."""
import json
import os
import select
import socket
import sys
import threading
import time

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

path, log, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
log_lock = threading.Lock()


def record(rec: dict) -> None:
    with log_lock, open(log, "a") as fh:
        fh.write(json.dumps(rec) + "\n")


def wait_push(conn: socket.socket) -> bool:
    """Waits like a broker for a push approval; False if the peer closed first."""
    start = time.monotonic()
    closed = False
    while (left := PUSH_WAIT - (time.monotonic() - start)) > 0:
        if select.select([conn], [], [], left)[0]:
            closed = conn.recv(1) == b""  # the module never sends while it waits
            break
    record({"op": "pushwait", "closed": closed, "waited": round(time.monotonic() - start, 2)})
    return not closed


def serve(conn: socket.socket) -> None:
    with conn:
        for line in conn.makefile():
            req = json.loads(line)
            record(req)
            if req["op"] == "login" and req["user"] == "pushwait" and not wait_push(conn):
                return
            if req["op"] != "login":
                rep = {"ok": True}
            elif req.get("password") in ("good", "fastrdp1:TOKEN", "deadport"):
                rep = {"ok": True, "user": req["user"], "desktop": "xfce", "target": {
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
                conn.sendall((json.dumps(rep) + "\n").encode())
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
