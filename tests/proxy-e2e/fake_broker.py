# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Records broker requests; accepts password 'good' and routes to 127.0.0.1:<port>.

Other passwords: 'deadport' -> accepted but routed to a closed port; a password listed in
REFUSALS -> that refusal (reasons: broker/brokerd/fastrdp_broker/protocol.py); anything
else -> "access denied" with reason "denied".
Users 'lanuser' / 'bogususer' get target connection_type "lan" / "bogus" (the module
must apply the first and ignore the second)."""
import json
import os
import socket
import sys

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

path, log, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(5)
print("ready", flush=True)
while True:
    conn, _ = srv.accept()
    for line in conn.makefile():
        req = json.loads(line)
        with open(log, "a") as fh:
            fh.write(json.dumps(req) + "\n")
        if req["op"] != "login":
            rep = {"ok": True}
        elif req.get("password") in ("good", "fastrdp1:TOKEN", "deadport"):
            rep = {"ok": True, "user": req["user"], "desktop": "xfce", "target": {
                "host": "127.0.0.1", "port": 1 if req["password"] == "deadport" else port,
                "username": req["user"], "password": "fastrdp1:TOKEN", "domain": "",
                "security": "tls"}}
            ct = CONNECTION_TYPES.get(req["user"])
            if ct:
                rep["target"]["connection_type"] = ct
        else:
            rep = {"ok": False, **REFUSALS.get(req.get("password"), {"error": DENIED, "reason": "denied"})}
        conn.sendall((json.dumps(rep) + "\n").encode())
    conn.close()
