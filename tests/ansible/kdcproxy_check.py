# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Runs the real python3-kdcproxy against a rendered kdcproxy.conf (test_templates.py KdcProxy).

    kdcproxy_check.py <kdcproxy.conf> <realm> <kdc port> [<gunicorn.conf.py>]

A fake KDC listens on 127.0.0.1:<kdc port> (the rendered file must name it) and answers
every request. Sends MS-KKDCP messages through kdcproxy's WSGI application (and, with a
gunicorn config and gunicorn importable, through gunicorn on a unix socket) and prints
the results as JSON. Needs an interpreter with kdcproxy (python3-kdcproxy or pip).
"""

import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading

CONF, REALM, PORT = os.path.abspath(sys.argv[1]), sys.argv[2], int(sys.argv[3])
GUNICORN_CONF = os.path.abspath(sys.argv[4]) if len(sys.argv) > 4 else None
os.environ["KDCPROXY_CONFIG"] = CONF

import kdcproxy  # noqa: E402
from kdcproxy import config as kconfig  # noqa: E402
from kdcproxy.parse_pyasn1 import ProxyMessage  # noqa: E402
from pyasn1.codec.der import decoder, encoder  # noqa: E402

AS_REQ = bytes.fromhex("6a023000")       # [APPLICATION 10] SEQUENCE {}: parses as AS-REQ
KDC_REPLY = bytes.fromhex("7e023000")    # [APPLICATION 30] (KRB-ERROR shape)
received = []


def fake_kdc(listener):
    while True:
        conn, _ = listener.accept()
        with conn:
            data = b""
            while len(data) < 4 or len(data) < 4 + struct.unpack("!I", data[:4])[0]:
                part = conn.recv(65536)
                if not part:
                    break
                data += part
            received.append(data[4:].hex())
            conn.sendall(struct.pack("!I", len(KDC_REPLY)) + KDC_REPLY)


def message(realm, inner=AS_REQ):
    m = ProxyMessage()
    m.setComponentByName("message", struct.pack("!I", len(inner)) + inner)
    if realm is not None:
        m.setComponentByName("realm", realm)
    return encoder.encode(m)


def unwrap(body):
    m, _ = decoder.decode(body, asn1Spec=ProxyMessage())
    return m.getComponentByName("message").asOctets()[4:].hex()


def wsgi(app, body, method="POST"):
    env = {"REQUEST_METHOD": method, "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    status = []
    out = b"".join(app(env, lambda s, h: status.append(s)))
    return status[0], out


def resolvers():
    return [type(r).__name__ for r in kconfig.MetaResolver()._MetaResolver__resolvers]


def via_gunicorn(results):
    try:
        import gunicorn
    except ImportError:
        results["gunicorn"] = None
        return
    out = {"version": gunicorn.__version__}
    with tempfile.TemporaryDirectory() as tmp:
        # systemd socket activation as fastrdp-kdcproxy.socket does it: the listening socket
        # as fd 3, LISTEN_FDS=1 and LISTEN_PID of gunicorn itself; no --bind. close_fds=False:
        # Python opens everything else close-on-exec anyway
        sock = os.path.join(tmp, "kdcproxy.sock")
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(sock)
        listener.listen(16)
        fd = listener.fileno()
        exec_gunicorn = ("import os, sys; os.environ['LISTEN_PID'] = str(os.getpid()); "
                         "os.execv(sys.executable, [sys.executable, '-m', 'gunicorn'] + sys.argv[1:])")
        proc = subprocess.Popen([sys.executable, "-c", exec_gunicorn, "--config", GUNICORN_CONF],
                                cwd=tmp, env=dict(os.environ, LISTEN_FDS="1"), close_fds=False,
                                preexec_fn=lambda: os.dup2(fd, 3) if fd != 3 else os.set_inheritable(3, True),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        listener.close()
        try:
            for name, body in (("own", message(REALM)), ("other", message("OTHER.EXAMPLE.NET"))):
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(30)
                    s.connect(sock)
                    s.sendall(b"POST /KdcProxy HTTP/1.1\r\nHost: x\r\nContent-Type: application/kerberos\r\n"
                              b"Connection: close\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
                    reply = b""
                    while part := s.recv(65536):
                        reply += part
                out[name] = reply.split(b"\r\n", 1)[0].decode()
            out["files"] = sorted(f for f in os.listdir(tmp) if f != "kdcproxy.sock")
        except OSError as exc:
            out["error"] = str(exc)
        finally:
            proc.terminate()
            log = proc.communicate(timeout=20)[0].decode(errors="replace")
        out["log"] = log[-2000:]
        results["gunicorn"] = out


def main():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", PORT))
    listener.listen(8)
    threading.Thread(target=fake_kdc, args=(listener,), daemon=True).start()

    app = kdcproxy.Application()
    results = {"resolvers": resolvers()}
    status, body = wsgi(app, message(REALM))
    results["own"] = {"status": status, "reply": unwrap(body) if status.startswith("200") else None,
                      "kdc_got": list(received)}
    received.clear()
    for name, body in (("other", message("OTHER.EXAMPLE.NET")), ("lower", message(REALM.lower())),
                       ("mixed", message(REALM.title())),
                       ("none", message(None))):
        status, _ = wsgi(app, body)
        results[name] = {"status": status, "kdc_got": list(received)}
        received.clear()
    results["get"] = wsgi(app, b"", "GET")[0]
    results["kpasswd"] = list(kconfig.MetaResolver().lookup(REALM, kpasswd=True))
    # what kdcproxy does when it cannot read its file: DNS for any realm (fail-open)
    os.environ["KDCPROXY_CONFIG"] = os.path.join(os.path.dirname(CONF), "does-not-exist.conf")
    results["resolvers_without_file"] = resolvers()
    os.environ["KDCPROXY_CONFIG"] = CONF
    if GUNICORN_CONF:
        via_gunicorn(results)
    print(json.dumps(results))


if __name__ == "__main__":
    main()
