# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Records broker requests; accepts password 'good' and routes to 127.0.0.1:<port>.

Other passwords: 'nogroup' -> refused with reason not_allowed, 'nobackend' -> "session
could not be started", 'deadport' -> accepted but routed to a closed port."""
import json
import os
import socket
import sys

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
        elif req.get("password") == "nogroup":
            rep = {"ok": False, "error": "access denied", "reason": "not_allowed"}
        elif req.get("password") == "nobackend":
            rep = {"ok": False, "error": "session could not be started"}
        else:
            rep = {"ok": False, "error": "access denied"}
        conn.sendall((json.dumps(rep) + "\n").encode())
    conn.close()
