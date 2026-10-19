#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# End-to-end test of the fastrdp proxy module inside the real freerdp-proxy:
#
#   client --TLS--> proxy A (+fastrdp) --broker A--> proxy B (+fastrdp) --broker B--> (nowhere)
#
# Proxy B stands in for a back-end, so broker B records exactly what proxy A sent
# to the back-end: it must be the broker token, never the user's password.
#
# Needs: freerdp-proxy, freerdp3-dev, libcjson-dev, openssl, python3, gcc.
# SYSROOT=/path runs against FreeRDP extracted from .debs instead of the system;
# FREERDP_PREFIX=/opt/fastrdp against fastrdp's patched build (see freerdp-env.sh).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=${SYSROOT:-}
LIBDIR=$SYSROOT/usr/lib/$(gcc -print-multiarch)
W=$(mktemp -d /tmp/fastrdp-e2e.XXXXXX)   # short path: AF_UNIX limit
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
export LD_LIBRARY_PATH="$LIBDIR:$LIBDIR/pulseaudio${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# shellcheck source=tests/proxy-e2e/freerdp-env.sh
. "$HERE/freerdp-env.sh"

gcc -std=c11 -D_GNU_SOURCE -fPIC -shared -fvisibility=hidden -Wno-deprecated-declarations \
    "${INC[@]}" "$HERE/shim.c" -o "$W/shim.so" "${LNK[@]}" -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3 -lcjson
gcc -std=c11 -D_GNU_SOURCE -Wno-deprecated-declarations "${INC[@]}" "$HERE/client.c" -o "$W/client" \
    "${LNK[@]}" -lfreerdp3 -lwinpr3
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=e2e -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null

cd "$W"
mkproxy() { # name port broker-socket
cat > "$1.ini" <<EOT
[Server]
Host=127.0.0.1
Port=$2
[Target]
FixedTarget=false
CertificatePolicy=allow
SmartcardAuth=false
[Channels]
GFX=true
; like production: pass every channel (incl. drdynvc/GFX) through
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
BrokerSocket=$3
Timeout=10
AllowTls=true
EOT
}
mkproxy a 23389 a.sock
mkproxy b 23390 b.sock
python3 "$HERE/fake_broker.py" a.sock a.log 23390 > a.out 2>&1 &
python3 "$HERE/fake_broker.py" b.sock b.log 23391 > b.out 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" a.ini > proxy-a.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" b.ini > proxy-b.log 2>&1 &
for _ in $(seq 50); do grep -q ready a.out b.out 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23390) 2>/dev/null && break; sleep 0.2; done

E2E_CLIENT_ADDRESS=203.0.113.7 timeout 20 ./client 127.0.0.1 23389 alice good fastrdp:gnome >/dev/null 2>&1 || true
timeout 20 ./client 127.0.0.1 23389 mallory bad "" >/dev/null 2>&1 || true
# certificate pinning in the format fastrdp-webgate gives guacd (sha256:aa:bb:...)
FP="sha256:$(openssl x509 -in cert.pem -noout -fingerprint -sha256 | sed 's/^.*=//' | tr 'A-F' 'a-f')"
E2E_CERT_FP="$FP" timeout 20 ./client 127.0.0.1 23389 pinned good "" >/dev/null 2>&1 || true
E2E_CERT_FP="sha256:00:11:22" timeout 20 ./client 127.0.0.1 23389 wrongpin good "" >/dev/null 2>&1 || true
sleep 1

fail=0
expect() { # description python-expression-over(a,b)
    if python3 - "$2" <<'PY'
import json, sys
load = lambda f: [json.loads(l) for l in open(f)] if __import__("os").path.exists(f) else []
a, b = load("a.log"), load("b.log")
la = [r for r in a if r["op"] == "login"]
lb = [r for r in b if r["op"] == "login"]
sys.exit(0 if eval(sys.argv[1]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
expect "front broker saw the expected logins"         'len(la) == 3'
expect "pinned certificate accepted, wrong pin refused" '[r["user"] for r in la] == ["alice", "mallory", "pinned"]'
expect "front login carries TLS credentials + hints"   'la[0]["method"] == "tls" and la[0]["user"] == "alice" and la[0]["password"] == "good" and la[0]["desktop_hint"] == "fastrdp:gnome" and (la[0]["width"], la[0]["height"]) == (2560, 1440)'
expect "client address is the socket peer, not the claimed one" 'la[0]["client_address"] == "127.0.0.1"'
expect "back-end received the token, not the password" 'len(lb) == 2 and all(r["password"] == "fastrdp1:TOKEN" for r in lb) and lb[0]["user"] == "alice"'
expect "client shell request not forwarded"            'lb[0]["desktop_hint"] is None'
expect "refused login never reached the back-end"      'all(r["user"] != "mallory" for r in lb)'
expect "session end reported to the broker"            'any(r["op"] == "end" and r["session_id"] == la[0]["session_id"] for r in a)'
if [ $fail -ne 0 ]; then
    echo "--- proxy A log:"; grep -E "fastrdp|ERROR" proxy-a.log | tail -20
fi
exit $fail
