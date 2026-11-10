#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Fake journald stdout socket for run_journald.sh.

fake_journald.py SOCKET OUT: listens on SOCKET (AF_UNIX stream, as
/run/systemd/journal/stdout) and appends one JSON line per received log line to OUT:
{"conn": n, "t": arrival time (time.time()), "header": [...], "line": "..."}, and one
with "line": null when a stream's header is complete.
sd_journal_stream_fd() first sends seven header lines (identifier, unit id, priority,
level prefix, forward to syslog, kmsg, console), then the log lines.
"""
import json
import os
import socket
import sys
import threading
import time

HEADER_LINES = 7


def main():
    path, out = sys.argv[1], sys.argv[2]
    lock = threading.Lock()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o666)
    srv.listen(8)

    def record(rec):
        with lock, open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def serve(conn, n):
        f = conn.makefile("rb", buffering=0)
        header = []
        while len(header) < HEADER_LINES:
            line = f.readline()
            if not line:
                return
            header.append(line.decode(errors="replace").rstrip("\n"))
        record({"conn": n, "t": time.time(), "header": header, "line": None})
        while True:
            line = f.readline()
            if not line:
                return
            record({"conn": n, "t": time.time(), "header": header,
                    "line": line.decode(errors="replace").rstrip("\n")})

    n = 0
    while True:
        conn, _ = srv.accept()
        n += 1
        threading.Thread(target=serve, args=(conn, n), daemon=True).start()


if __name__ == "__main__":
    main()
