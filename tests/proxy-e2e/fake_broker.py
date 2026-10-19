"""Records broker requests; accepts password 'good' and routes to 127.0.0.1:<port>."""
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
        elif req.get("password") in ("good", "fastrdp1:TOKEN"):
            rep = {"ok": True, "user": req["user"], "desktop": "xfce", "target": {
                "host": "127.0.0.1", "port": port, "username": req["user"],
                "password": "fastrdp1:TOKEN", "domain": "", "security": "tls"}}
        else:
            rep = {"ok": False, "error": "access denied"}
        conn.sendall((json.dumps(rep) + "\n").encode())
    conn.close()
