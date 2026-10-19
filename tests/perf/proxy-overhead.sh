#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Proxy overhead without a full deployment: FreeRDP's shadow server on Xvfb is the
# back-end, perfload generates screen changes, rdpbench measures direct vs. through
# freerdp-proxy + fastrdp module (with the test broker from tests/proxy-e2e).
#
# Needs: xvfb, freerdp-shadow-x11, freerdp-proxy, freerdp3-dev, libx11-dev, libcjson-dev.
# SYSROOT=/path uses binaries/libraries extracted from .debs instead of the system.
# Usage: proxy-overhead.sh [seconds-per-run] [runs]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SECS=${1:-15}
RUNS=${2:-3}
SYSROOT=${SYSROOT:-}
MA=$(gcc -print-multiarch)
LIBDIR=$SYSROOT/usr/lib/$MA
export LD_LIBRARY_PATH="$LIBDIR:$LIBDIR/pulseaudio${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
W=$(mktemp -d /tmp/fastrdp-perf.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
INC=(-I"$SYSROOT/usr/include/freerdp3" -I"$SYSROOT/usr/include/winpr3" -I"$SYSROOT/usr/include")
LNK=(-L"$LIBDIR" "-Wl,-rpath-link,$LIBDIR:$LIBDIR/pulseaudio")
CF=(-std=c11 -D_GNU_SOURCE -O2 -Wno-deprecated-declarations)

gcc "${CF[@]}" "${INC[@]}" "$HERE/rdpbench/rdpbench.c" -o "$W/rdpbench" "${LNK[@]}" -lfreerdp-client3 -lfreerdp3 -lwinpr3 -lm
gcc "${CF[@]}" "${INC[@]}" "$HERE/rdpbench/perfload.c" -o "$W/perfload" "${LNK[@]}" -l:libX11.so.6
gcc "${CF[@]}" -fPIC -shared -fvisibility=hidden "${INC[@]}" "$HERE/../proxy-e2e/shim.c" -o "$W/shim.so" \
    "${LNK[@]}" -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3 -lcjson
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=perf -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
cd "$W"

DISP=:$((90 + RANDOM % 9))
XVFB_ARGS=(-screen 0 1920x1080x24 -nolisten tcp)
[ -n "$SYSROOT" ] && XVFB_ARGS+=(-xkbdir "$SYSROOT/usr/share/X11/xkb")
LD_PRELOAD=${XVFB_LD_PRELOAD:-} "${XVFB:-$SYSROOT/usr/bin/Xvfb}" "$DISP" "${XVFB_ARGS[@]}" > xvfb.log 2>&1 &
export DISPLAY=$DISP
sleep 2
"$SYSROOT/usr/bin/freerdp-shadow-cli" /port:25000 /bind-address:127.0.0.1 -auth /sec:tls > shadow.log 2>&1 &
SHADOW=$!
cat > p.ini <<EOT
[Server]
Host=127.0.0.1
Port=25100
[Target]
FixedTarget=false
CertificatePolicy=allow
SmartcardAuth=false
[Channels]
GFX=true
DisplayControl=true
PassthroughIsBlacklist=true
Passthrough=
[Input]
Keyboard=true
Mouse=true
[Security]
ServerTlsSecurity=true
ServerNlaSecurity=false
ServerRdpSecurity=false
ClientTlsSecurity=true
ClientNlaSecurity=false
ClientRdpSecurity=false
ClientExtSecurity=false
ClientAllowFallbackToTls=false
[Plugins]
Modules=fastrdp
Required=fastrdp
[Certificates]
CertificateFile=$W/cert.pem
PrivateKeyFile=$W/key.pem
[FastRDP]
BrokerSocket=b.sock
Timeout=10
AllowTls=true
EOT
python3 "$HERE/../proxy-e2e/fake_broker.py" b.sock b.log 25000 > b.out 2>&1 &
LD_PRELOAD="$W/shim.so" "$SYSROOT/usr/bin/freerdp-proxy" p.ini > proxy.log 2>&1 &
PROXY=$!
sleep 2

TCK=$(getconf CLK_TCK)
cpu() { awk '{print $14+$15}' "/proc/$1/stat"; }
printf "%-6s %-7s %-4s %8s %8s %9s %9s %s\n" path load run fps gfxMbit serverCPU proxyCPU codec
for load in video scroll; do
    if [ "$load" = video ]; then ./perfload video 1280x720 60 & else ./perfload scroll 60 & fi
    PL=$!
    sleep 1
    for run in $(seq "$RUNS"); do
        for path in direct:25000 proxy:25100; do
            s0=$(cpu $SHADOW); p0=$(cpu $PROXY)
            out=$(./rdpbench --host 127.0.0.1 --port "${path#*:}" --user alice --password good \
                  --sec tls --seconds "$SECS" --no-decode 2>/dev/null | tail -1)
            s1=$(cpu $SHADOW); p1=$(cpu $PROXY)
            python3 - "$out" "${path%:*}" "$load" "$run" $(( (s1 - s0) * 100 / TCK / SECS )) \
                $(( (p1 - p0) * 100 / TCK / SECS )) <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print("%-6s %-7s %-4s %8.1f %8.1f %8s%% %8s%% %s" % (sys.argv[2], sys.argv[3], sys.argv[4],
      d["fps_avg"], d["gfx_mbit_avg"], sys.argv[5], sys.argv[6], d["main_codec"]))
PY
        done
    done
    kill $PL
    wait $PL 2>/dev/null || true
done

# Input-to-frame latency: perfload repaints a square on each key press.
./perfload latency &
PL=$!
sleep 1
printf "\n%-6s %8s %8s %8s\n" path samples p50ms p95ms
for path in direct:25000 proxy:25100; do
    out=$(./rdpbench --host 127.0.0.1 --port "${path#*:}" --user alice --password good \
          --sec tls --seconds "$SECS" --no-decode --latency 2>/dev/null | tail -1)
    python3 - "$out" "${path%:*}" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print("%-6s %8d %8.1f %8.1f" % (sys.argv[2], d["latency_samples"], d["latency_ms_p50"], d["latency_ms_p95"]))
PY
done
kill $PL
