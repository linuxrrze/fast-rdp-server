#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# WLog's journald appender, as fastrdp-proxy.service uses it (WLOG_APPENDER=JOURNALD,
# WLOG_JOURNALD_ID; backlog A4): journald_log.c logs an INFO and a WARN message, keeps
# running for 2 s after each and then dies by SIGKILL. A fake journald (fake_journald.py) on
# /run/systemd/journal/stdout, the path libsystemd's sd_journal_stream_fd() connects to,
# records when each line arrives. Checks: the identifier, the priority prefixes (<6>, <4>),
# and that each line reaches journald within a second, while the process still runs.
# Without patches/freerdp/0010 (fastrdp-freerdp3 3.33.1-2) stdio buffers the stream and
# the lines arrive only with the process exit, here never (SIGKILL); a WinPR without the
# journald appender logs to the console and nothing arrives either.
#
# The socket path is fixed. As root without a running journald (the CI container) the
# fake listens there directly; otherwise the script re-runs itself in a user and mount
# namespace (unshare -rm) with its own /run/systemd/journal, so a real journald is never
# touched. Without either it skips (FASTRDP_TESTS_STRICT=1: fails).
# Needs gcc, python3, WinPR headers; FREERDP_PREFIX=/opt/fastrdp as in run.sh.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
JDIR=/run/systemd/journal

if [ "${E2E_JOURNALD_NS:-0}" = 1 ]; then
    # inside the namespace: an empty tmpfs hides the real journal socket (if any)
    if [ -d "$JDIR" ]; then mount -t tmpfs tmpfs "$JDIR"; else mount -t tmpfs tmpfs /run; fi
    mkdir -p "$JDIR"
elif [ -e "$JDIR/stdout" ] || [ "$(id -u)" != 0 ]; then
    if unshare --user --map-root-user --mount true 2>/dev/null; then
        exec env E2E_JOURNALD_NS=1 unshare --user --map-root-user --mount "$0" "$@"
    fi
    why="needs root without a running journald, or user namespaces (unshare -rm)"
    if [ "${FASTRDP_TESTS_STRICT:-0}" = 1 ]; then echo "FAIL $(basename "$0"): $why"; exit 1; fi
    echo "SKIP $(basename "$0"): $why"
    exit 0
fi

SYSROOT=${SYSROOT:-}
LIBDIR=$SYSROOT/usr/lib/$(gcc -print-multiarch)
W=$(mktemp -d /tmp/fastrdp-e2e.XXXXXX)
made_jdir=0
[ -d "$JDIR" ] || { mkdir -p "$JDIR"; made_jdir=1; }
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    rm -f "$JDIR/stdout"
    [ "$made_jdir" = 0 ] || rmdir "$JDIR" 2>/dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# shellcheck source=tests/proxy-e2e/freerdp-env.sh
. "$HERE/freerdp-env.sh"

gcc -std=c11 -D_GNU_SOURCE "${INC[@]}" "$HERE/journald_log.c" -o "$W/journald_log" "${LNK[@]}" -lwinpr3

python3 "$HERE/fake_journald.py" "$JDIR/stdout" "$W/journal.jsonl" &
for _ in $(seq 50); do [ -S "$JDIR/stdout" ] && break; sleep 0.1; done
[ -S "$JDIR/stdout" ] || { echo "FAIL fake journald did not start"; exit 1; }

rc=0
# in the background, wait's stderr discarded: the SIGKILL shows as 137, without bash's
# "Killed" job message
WLOG_APPENDER=JOURNALD WLOG_JOURNALD_ID=fastrdp-e2e WLOG_LEVEL=INFO \
    "$W/journald_log" >"$W/written.txt" 2>"$W/stderr.txt" &
{ wait $! || rc=$?; } 2>/dev/null
sleep 0.5

fail=0
if [ "$rc" = 137 ]; then
    echo "ok   the logging process ran 4 s and was killed (SIGKILL), as on a crash"
else
    echo "FAIL the logging process exited with $rc, expected 137 (SIGKILL)"; fail=1
fi
python3 - "$W/journal.jsonl" "$W/written.txt" <<'PY' || fail=1
import json, os, sys
journal, written = sys.argv[1], sys.argv[2]
recs = [json.loads(l) for l in open(journal)] if os.path.exists(journal) else []
sent = dict((w.split()[1], float(w.split()[0])) for w in open(written))
bad = 0
def check(ok, msg):
    global bad
    print(("ok   " if ok else "FAIL ") + msg)
    bad |= not ok
hdr = recs[0]["header"] if recs else []
check(hdr[:1] == ["fastrdp-e2e"] and hdr[3:4] == ["1"],
      f"journal stream with identifier fastrdp-e2e and level prefixes (header {hdr})")
for key, prio, text in (("info", "<6>", "e2e journald line 1 (info)"),
                        ("warn", "<4>", "e2e journald line 2 (warn)")):
    got = [r for r in recs if r["line"] is not None and text in r["line"]]
    if not got:
        check(False, f"{key} line reached journald (nothing arrived: buffered and lost, or no journald appender)")
        continue
    r = got[0]
    check(r["line"].startswith(prio), f"{key} line has priority {prio}: {r['line']!r}")
    delay = r["t"] - sent[key]
    check(delay < 1.0, f"{key} line reached journald {delay * 1000:.0f} ms after it was written, the process still running")
sys.exit(bad)
PY
if [ $fail -ne 0 ]; then
    echo "--- stderr of the logging process:"; tail -5 "$W/stderr.txt"
    echo "--- fake journald:"; tail -5 "$W/journal.jsonl" 2>/dev/null || true
fi
exit $fail
