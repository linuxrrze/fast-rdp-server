#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (records everything a lab client and the proxy say to each other; together
# with the proxy's TLS key log the capture decrypts the whole run, the code typed into
# the waiting screen and TLS passwords included: lab users only, delete the folder after
# the analysis). Backlog A5, docs/lab-checklist-0.7.6.md §1, "Before every run".
#
# On the proxy host, as root:
#   tests/lab/a5-collect.sh start RUN [--port N] [--dir D]
#       tcpdump of the RDP port (-i any -s 0) and the `ss -tinm` loop (every 0.5 s,
#       timestamped) in the background, pidfiles in the run folder.
#       Port: --port, else [Server] Port of /etc/fastrdp/proxy.ini, else 3389.
#       Folder: --dir, else /root/fastrdp-lab/RUN; an existing folder is never reused.
#   ... connections with the lab client ...
#   tests/lab/a5-collect.sh stop RUN [--dir D]
#       stops both, copies the TLS key log (mode 0600; never printed), exports the
#       journal of fastrdp-proxy, fastrdp-brokerd, xrdp and xrdp-sesman since the start,
#       the part of /var/log/xrdp.log since the start, and prints a summary.
#
# Environment (tests): A5_COLLECT_PROXY_INI, A5_COLLECT_KEYLOG, A5_COLLECT_XRDP_LOG,
# A5_COLLECT_ROOT (default /root/fastrdp-lab), A5_COLLECT_INTERVAL (ss loop, 0.5).
set -euo pipefail

PROXY_INI=${A5_COLLECT_PROXY_INI:-/etc/fastrdp/proxy.ini}
KEYLOG=${A5_COLLECT_KEYLOG:-/var/cache/fastrdp-proxy/tls-keylog.txt}
XRDP_LOG=${A5_COLLECT_XRDP_LOG:-/var/log/xrdp.log}
LAB_ROOT=${A5_COLLECT_ROOT:-/root/fastrdp-lab}
INTERVAL=${A5_COLLECT_INTERVAL:-0.5}

usage() {
    echo "usage: $0 start RUN [--port N] [--dir D] | stop RUN [--dir D]" >&2
    exit 2
}
die() { echo "a5-collect: $*" >&2; exit 1; }

[ $# -ge 2 ] || usage
cmd=$1 run=$2
shift 2
case $cmd in start|stop) ;; *) usage ;; esac
# a plain name: it becomes a directory name and appears in file names
[[ $run =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "RUN must be letters, digits, . _ - (got '$run')"
port='' dir='' dir_opt=''
while [ $# -gt 0 ]; do
    case $1 in
        --port) [ $# -ge 2 ] || usage; port=$2; shift 2 ;;
        --dir) [ $# -ge 2 ] || usage; dir=$2; dir_opt=" --dir $2"; shift 2 ;;
        *) usage ;;
    esac
done
[ "$(id -u)" = 0 ] || die "run as root (tcpdump, the key log and the journal need it)"
dir=${dir:-$LAB_ROOT/$run}

# [Server] Port of proxy.ini, empty if none
ini_port() {
    [ -r "$PROXY_INI" ] || return 0
    awk -F= '/^\[/ { s = ($0 ~ /^\[Server\][ \t]*$/) ; next }
             s && $1 ~ /^[ \t]*Port[ \t]*$/ { gsub(/[ \t\r]/, "", $2); print $2; exit }' "$PROXY_INI"
}

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

start() {
    if [ -z "$port" ]; then
        port=$(ini_port)
        port=${port:-3389}
    fi
    [[ $port =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "bad port '$port'"
    [ ! -e "$dir" ] || die "$dir exists: pick another RUN name (or remove the old run)"
    command -v tcpdump >/dev/null || die "tcpdump not installed"
    command -v ss >/dev/null || die "ss not installed (iproute2)"
    mkdir -p "$(dirname "$dir")"
    mkdir -m 0700 "$dir"
    local since
    since=$(date '+%Y-%m-%d %H:%M:%S')
    printf 'run=%s\nport=%s\nstart=%s\nhost=%s\n' "$run" "$port" "$since" "$(hostname)" > "$dir/run.txt"
    # -U: packets written as they come, so a capture of a killed tcpdump is complete
    nohup tcpdump -i any -s 0 -U -w "$dir/capture.pcap" "tcp port $port" > "$dir/tcpdump.log" 2>&1 &
    echo $! > "$dir/tcpdump.pid"
    # shellcheck disable=SC2016  # $1 and $2 are the inner shell's arguments
    nohup bash -c 'while :; do date "+%F %T.%N"; ss -tinm "sport = :$1"; sleep "$2"; done' \
        a5-collect-ss "$port" "$INTERVAL" > "$dir/ss.txt" 2>&1 &
    echo $! > "$dir/ss.pid"
    sleep 1
    alive "$dir/tcpdump.pid" || { stop_pids; die "tcpdump did not start: $(tail -3 "$dir/tcpdump.log")"; }
    alive "$dir/ss.pid" || { stop_pids; die "the ss loop did not start: $(tail -3 "$dir/ss.txt")"; }
    echo "a5-collect: run $run started $since, port $port, folder $dir"
    echo "  tcpdump (pid $(cat "$dir/tcpdump.pid")) -> capture.pcap, ss loop (pid $(cat "$dir/ss.pid")) -> ss.txt"
    echo "Now the connections (note per connection: button, what mstsc showed, the times)."
    echo "Then: $0 stop $run$dir_opt"
}

stop_pids() {
    local f pid
    for f in "$dir/tcpdump.pid" "$dir/ss.pid"; do
        [ -f "$f" ] || continue
        pid=$(cat "$f")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
            kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
            echo "a5-collect: stopped $(basename "$f" .pid) (pid $pid)"
        else
            echo "a5-collect: $(basename "$f" .pid) was not running (pid $pid)" >&2
        fi
        rm -f "$f"
    done
}

stop() {
    [ -f "$dir/run.txt" ] || die "$dir/run.txt not found: no run '$run' started there"
    local since
    since=$(sed -n 's/^start=//p' "$dir/run.txt")
    stop_pids
    echo "stop=$(date '+%Y-%m-%d %H:%M:%S')" >> "$dir/run.txt"
    local keys=no
    if [ -f "$KEYLOG" ]; then
        install -m 0600 "$KEYLOG" "$dir/tls-keylog.txt"
        keys=yes
    else
        echo "a5-collect: WARNING: no key log ($KEYLOG): is fastrdp_proxy_tls_keylog on?" \
             "Without it the capture cannot be decrypted." >&2
    fi
    if command -v journalctl >/dev/null; then
        journalctl -o short-precise -u fastrdp-proxy -u fastrdp-brokerd -u xrdp -u xrdp-sesman \
            --since "$since" --no-pager > "$dir/journal.txt" 2>&1 \
            || echo "a5-collect: journalctl failed, see journal.txt" >&2
    else
        echo "a5-collect: no journalctl, journal not exported" >&2
    fi
    if [ -r "$XRDP_LOG" ]; then
        # xrdp.log lines start with [YYYYMMDD-HH:MM:SS]; lines without a stamp follow the last one
        local from
        from=$(date -d "$since" '+%Y%m%d-%H:%M:%S')
        awk -v from="$from" '/^\[[0-9]{8}-[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\]/ { on = (substr($0, 2, 17) >= from) }
                             on' "$XRDP_LOG" > "$dir/xrdp.log"
    else
        echo "a5-collect: $XRDP_LOG not readable, not copied" >&2
    fi
    echo
    echo "a5-collect: run $run ($since to now) in $dir:"
    local f
    for f in "$dir"/*; do
        printf '  %10s  %s\n' "$(stat -c %s "$f")" "$(basename "$f")"
    done
    local port
    port=$(sed -n 's/^port=//p' "$dir/run.txt")
    echo
    echo "Next: copy the folder to the analysis machine, e.g."
    echo "  scp -r root@$(hostname):$dir ."
    if [ "$keys" = yes ]; then
        local d
        d=$(basename "$dir")
        echo "  tests/lab/rdpcapture/decode.py $d/capture.pcap $d/tls-keylog.txt --port $port --summary"
        echo "The key log and the capture together decrypt the whole run: delete both after the analysis."
    else
        echo "  (without a key log decode.py lists the connections only)"
    fi
    echo "Add mstsc's event log (tests/lab/windows/rdp-eventlog.ps1) and your notes."
}

case $cmd in
    start) start ;;
    stop) stop ;;
esac
