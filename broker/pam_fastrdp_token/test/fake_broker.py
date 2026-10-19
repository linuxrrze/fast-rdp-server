"""Fake token socket: accepts token 'fastrdp1:good' for alice (returns a password)
and 'fastrdp1:nopw' for alice (no password); everything else is rejected."""
import json, os, socket, sys
path = sys.argv[1]
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(5)
print("ready", flush=True)
while True:
    c, _ = srv.accept()
    req = json.loads(c.makefile().readline())
    tokens = {"fastrdp1:good": "RealPassw0rd", "fastrdp1:nopw": None}
    ok = req.get("op") == "redeem" and req.get("user") == "alice" and req.get("token") in tokens
    c.sendall(json.dumps({"ok": ok, "password": tokens.get(req.get("token")) if ok else None}).encode() + b"\n")
    c.close()
