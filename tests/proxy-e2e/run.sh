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
# The desktop picker checks need patches/freerdp/0007 (fastrdp-freerdp3 3.32.2-6); without
# it the module does not offer the picker and they fail. The Shutdown Request Denied checks
# need patches/freerdp/0008 (3.32.2-7).
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
mkproxy() { # name port broker-socket [AllowTlsFrom [CertificatePolicy [more [FastRDP] lines]]]
cat > "$1.ini" <<EOT
[Server]
Host=127.0.0.1
Port=$2
[Target]
FixedTarget=false
CertificatePolicy=${5:-deny}
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
AllowTlsFrom=${4:-}
${6:-}
EOT
}
# A to D without the waiting screen (the module's default is WaitingScreen=true)
mkproxy a 23389 a.sock '127.0.0.0/8, ::1' deny WaitingScreen=false
mkproxy b 23390 b.sock '' deny WaitingScreen=false
# TLS logins only from addresses the e2e client does not have (web-only TLS, R3)
mkproxy c 23392 a.sock '192.0.2.0/24, 2001:db8::/32' deny WaitingScreen=false
# the module pins the back-end certificate itself and needs CertificatePolicy=deny
mkproxy d 23393 a.sock '127.0.0.0/8' allow WaitingScreen=false
# like A, with the waiting screen by default (no WaitingScreen key) and Status Info PDUs
# for clients that ask
mkproxy e 23394 a.sock '127.0.0.0/8' deny StatusInfo=true
# proxy B is proxy A's back-end and presents cert.pem: its fingerprint goes into the targets
E2E_CERT_SHA256=$(openssl x509 -in cert.pem -outform DER | sha256sum | cut -d' ' -f1)
export E2E_CERT_SHA256
# the pending login's id the fake broker puts into the QR code (<approval URL>?login=<id>)
export E2E_LOGIN_ID=k3Jq9vX2-PzR7wLm0aTb_Q
python3 "$HERE/fake_broker.py" a.sock a.log 23390 > a.out 2>&1 &
python3 "$HERE/fake_broker.py" b.sock b.log 23391 > b.out 2>&1 &
# connection state transitions (core.rdp DEBUG) show whether multitransport was offered
WLOG_FILTER="com.freerdp.core.rdp:DEBUG" LD_PRELOAD="$W/shim.so" "$PROXY" a.ini > proxy-a.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" b.ini > proxy-b.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" c.ini > proxy-c.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" d.ini > proxy-d.log 2>&1 &
WLOG_FILTER="proxy.modules.fastrdp:DEBUG" LD_PRELOAD="$W/shim.so" "$PROXY" e.ini > proxy-e.log 2>&1 &
for _ in $(seq 50); do grep -q ready a.out b.out 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23390) 2>/dev/null &&
    (exec 3<>/dev/tcp/127.0.0.1/23392) 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23393) 2>/dev/null &&
    (exec 3<>/dev/tcp/127.0.0.1/23394) 2>/dev/null && break; sleep 0.2; done

E2E_CLIENT_ADDRESS=203.0.113.7 timeout 20 ./client 127.0.0.1 23389 alice good fastrdp:gnome >/dev/null 2>&1 || true
timeout 20 ./client 127.0.0.1 23389 mallory bad "" > mallory.out 2>&1 || true
# certificate pinning in the format fastrdp-webgate gives guacd (sha256:aa:bb:...)
FP="sha256:$(openssl x509 -in cert.pem -noout -fingerprint -sha256 | sed 's/^.*=//' | tr 'A-F' 'a-f')"
E2E_CERT_FP="$FP" timeout 20 ./client 127.0.0.1 23389 pinned good "" >/dev/null 2>&1 || true
E2E_CERT_FP="sha256:00:11:22" timeout 20 ./client 127.0.0.1 23389 wrongpin good "" >/dev/null 2>&1 || true
# refusals: Set Error Info codes ([MS-RDPBCGR] 2.2.5.1.1) the client receives
for r in nogroup mfafail mfatimeout newreason nobackend oldbackend; do
    timeout 20 ./client 127.0.0.1 23389 "$r" "$r" "" > "$r.out" 2>&1 || true
done
timeout 20 ./client 127.0.0.1 23389 deadport deadport "" > deadport.out 2>&1 || true
# back-end certificate pin: another certificate than the broker's, or none from the broker
timeout 20 ./client 127.0.0.1 23389 badcert good "" > badcert.out 2>&1 || true
timeout 20 ./client 127.0.0.1 23389 nocert good "" > nocert.out 2>&1 || true
# a proxy.ini with CertificatePolicy=allow would accept what the pin refused: no routing
timeout 20 ./client 127.0.0.1 23393 allowpolicy good "" > allowpolicy.out 2>&1 || true
# RemoteApp (INFO_RAIL) is not offered; a smartcard PIN on the TLS path is never forwarded
E2E_RAIL=1 timeout 20 ./client 127.0.0.1 23389 railuser good "" > rail.out 2>&1 || true
E2E_SC_PIN=1 timeout 20 ./client 127.0.0.1 23389 pinuser 1234 "" > pin.out 2>&1 || true
# connection type towards the back-end (xrdp's encoder profile): the broker's choice, or
# the client's when the broker sends none or an unknown one
timeout 20 ./client 127.0.0.1 23389 lanuser good "" >/dev/null 2>&1 || true
timeout 20 ./client 127.0.0.1 23389 bogususer good "" >/dev/null 2>&1 || true
E2E_CONNECTION_TYPE=2 timeout 20 ./client 127.0.0.1 23389 slowuser good "" >/dev/null 2>&1 || true
# Remote Credential Guard required (mstsc /remoteGuard) but not offered: the proxy answers
# with a negotiation response without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED instead of
# dropping the TCP connection (patches/freerdp/0002), the client gives up on its own
E2E_REMOTE_GUARD=1 timeout 20 ./client 127.0.0.1 23389 rcguser good "" > rcg.out 2>&1 || true
# TLS login from an address outside AllowTlsFrom: refused before the broker
timeout 20 ./client 127.0.0.1 23392 outsider good "" > outsider.out 2>&1 || true
# The user closes the client while the broker waits for an MFA push (fake broker: 8 s).
# The proxy must drop the broker request at once, not when the broker answers.
E2E_GIVE_UP_S=1 timeout 20 ./client 127.0.0.1 23389 pushwait good "" > pushwait.out 2>&1 || true
for _ in $(seq 50); do grep -q '"pushwait"' a.log 2>/dev/null && break; sleep 0.2; done
# The user clicks the X in mstsc's connection bar during the session: mstsc sends a Shutdown
# Request ([MS-RDPBCGR] 1.3.1.4.1). The fake brokers hold 'holdsession' for 3 s each, so
# proxy A has accepted the client (its broker answered) while proxy B still holds the login;
# 4.5 s in, proxy A must deny the request and leave the disconnect to the client.
E2E_KEEP_S=10 E2E_SHUTDOWN_AT_MS=4500 timeout 30 ./client 127.0.0.1 23389 holdsession good "" > shutdown.out 2>&1 || true
# The back-end ends a running session (GNOME logout: gnome-remote-desktop sends Set Error
# Info and closes). Here proxy B accepts proxy A's client, then fails to reach its own
# back-end and closes with 0x400: proxy A forwards the code, then ends the front with
# Deactivate All, Set Error Info and a Disconnect Provider Ultimatum, not a bare close.
E2E_KEEP_S=6 timeout 30 ./client 127.0.0.1 23389 backendend good "" > backendend.out 2>&1 || true
# Waiting screen (proxy E): the broker's progress messages as Bitmap Updates while the
# login waits; the screen is dumped 1.5 s in (MFA panel with the QR code)
E2E_KEEP_S=10 E2E_STATUS_INFO=1 E2E_DUMP="$W/panel32.ppm" timeout 30 ./client 127.0.0.1 23394 progress good "" > ws32.out 2>&1 || true
E2E_KEEP_S=10 E2E_BPP=16 E2E_DUMP="$W/panel16.ppm" timeout 30 ./client 127.0.0.1 23394 progress good "" > ws16.out 2>&1 || true
E2E_KEEP_S=10 E2E_BPP=24 timeout 30 ./client 127.0.0.1 23394 progress good "" > ws24.out 2>&1 || true
E2E_KEEP_S=10 E2E_BPP=15 timeout 30 ./client 127.0.0.1 23394 progress good "" > ws15.out 2>&1 || true
# the same login through proxy A (WaitingScreen=false): no progress asked, no graphics
E2E_KEEP_S=10 E2E_STATUS_INFO=1 timeout 30 ./client 127.0.0.1 23389 progress good "" > ws-off.out 2>&1 || true
# a broker without progress messages, malformed and too many progress messages
E2E_KEEP_S=10 timeout 30 ./client 127.0.0.1 23394 oldbroker good "" > ws-old.out 2>&1 || true
E2E_KEEP_S=10 timeout 30 ./client 127.0.0.1 23394 badprogress good "" > ws-bad.out 2>&1 || true
E2E_KEEP_S=10 timeout 30 ./client 127.0.0.1 23394 floodprogress good "" > ws-flood.out 2>&1 || true
# the client gives up while the waiting screen shows the push
E2E_GIVE_UP_S=1 timeout 20 ./client 127.0.0.1 23394 pushwait good "" > ws-giveup.out 2>&1 || true
for _ in $(seq 50); do [ "$(grep -c '"pushwait"' a.log)" -ge 2 ] && break; sleep 0.2; done
# Desktop picker (proxy E): the fake broker prompts 1.5 s after the login (the MFA wait),
# the clients answer 2.5 s after connecting, in parallel. Keys typed before the prompt and
# a key released that went down before it do not count.
picker() { # user [VAR=value ...]
    local u=$1; shift
    env E2E_KEEP_S=12 "$@" timeout 30 ./client 127.0.0.1 23394 "$u" good "" > "$u.out" 2>&1 || true
}
pids=()
picker pickerdigit E2E_KEYS=2 & pids+=($!)
picker pickerkeys E2E_KEYS=down,down,enter & pids+=($!)
picker pickeresc E2E_KEYS=down,esc & pids+=($!)
picker pickertimeout & pids+=($!)
picker pickermoved E2E_KEYS=down & pids+=($!)
picker pickerclick E2E_CLICK=+1 & pids+=($!)
picker pickerearly E2E_EARLY_KEYS=3,enter,d4 E2E_KEYS=r4,u2 & pids+=($!)
picker pickerkeypad E2E_NUMLOCK=1 E2E_KEYS=kp3 & pids+=($!)
picker pickergone E2E_GIVE_UP_S=3 & pids+=($!)
# a Shutdown Request while the picker shows (no session yet): the proxy closes at once
picker pickershutdown E2E_SHUTDOWN_AT_MS=2500 & pids+=($!)
# static channel data read during the picker: passed on below the module's cap (4 MiB),
# the login abandoned above it (the proxy's queue for the back-end has no limit)
picker pickerchan E2E_CHANNEL_DATA=65536 E2E_KEYS=2 & pids+=($!)
picker pickerflood E2E_CHANNEL_DATA=6291456 & pids+=($!)
# proxy A has the waiting screen switched off: no picker offered, the login goes on as before
E2E_KEEP_S=6 timeout 30 ./client 127.0.0.1 23389 pickeroff good "" > pickeroff.out 2>&1 & pids+=($!)
wait "${pids[@]}"
sleep 1

fail=0
expect() { # description python-expression-over(a,b)
    if python3 - "$2" <<'PY'
import json, sys
load = lambda f: [json.loads(l) for l in open(f)] if __import__("os").path.exists(f) else []
a, b = load("a.log"), load("b.log")
la = [r for r in a if r["op"] == "login"]
lb = [r for r in b if r["op"] == "login"]
ct = lambda logins, user: [r.get("connection_type") for r in logins if r["user"] == user]
pw = [r for r in a if r["op"] == "pushwait"]
pr = lambda user: [r for r in a if r["op"] == "progresswait" and r["user"] == user]
pc = {r["user"]: r for r in a if r["op"] == "pickerchoice"}
hold = lambda log: [r for r in log if r["op"] == "holdwait"]
sid = lambda user: [r["session_id"] for r in la if r["user"] == user]
chose = lambda user: (pc[user].get("line") or {}).get("desktop", "none") if pc.get(user, {}).get("line") else "none"
sys.exit(0 if eval(sys.argv[1]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
expect "front broker saw the expected logins"         'len(la) == 40'
expect "pinned certificate accepted, wrong pin refused" '[r["user"] for r in la][:3] == ["alice", "mallory", "pinned"]'
expect "RemoteApp and TLS smartcard-PIN logins never reached the broker" 'not any(r["user"] in ("railuser", "pinuser") for r in la)'
expect "front login carries TLS credentials + hints"   'la[0]["method"] == "tls" and la[0]["user"] == "alice" and la[0]["password"] == "good" and la[0]["desktop_hint"] == "fastrdp:gnome" and (la[0]["width"], la[0]["height"]) == (2560, 1440)'
expect "client address is the socket peer, not the claimed one" 'la[0]["client_address"] == "127.0.0.1"'
expect "TLS logins carry no KDC evidence"              'not any("kdc_evidence" in r for r in la + lb)'
expect "back-end received the token, not the password" 'len(lb) == 24 and all(r["password"] == "fastrdp1:TOKEN" for r in lb) and lb[0]["user"] == "alice"'
expect "client shell request not forwarded"            'lb[0]["desktop_hint"] is None'
expect "refused login never reached the back-end"      'all(r["user"] != "mallory" for r in lb)'
expect "back-end with the broker's certificate reached (pin matched)" 'any(r["user"] == "alice" for r in lb)'
expect "back-end certificate not the broker's, or no fingerprint: back-end never got the login" \
    'any(r["user"] == "badcert" for r in la) and any(r["user"] == "nocert" for r in la) and not any(r["user"] in ("badcert", "nocert") for r in lb)'
expect "CertificatePolicy=allow: login never reached the broker" 'not any(r["user"] == "allowpolicy" for r in la)'
expect "front login carries the client's connection type" 'ct(la, "alice") == [7] and ct(la, "slowuser") == [2]'
expect "connection type from the broker reaches the back-end" 'ct(lb, "lanuser") == [6]'
expect "no or unknown broker connection type: client's kept" 'ct(lb, "alice") == [7] and ct(lb, "bogususer") == [7] and ct(lb, "slowuser") == [2]'
expect "session end reported to the broker"           'any(r["op"] == "end" and r["session_id"] == la[0]["session_id"] for r in a)'
expect "TLS login outside AllowTlsFrom never reached the broker" 'not any(r["user"] == "outsider" for r in la)'
expect "Remote Credential Guard required: login never reached the broker" 'not any(r["user"] == "rcguser" for r in la)'
expect "client gone during the MFA wait: broker connection closed early" \
    'len(pw) == 2 and pw[0]["closed"] and pw[0]["waited"] < 4 and not pw[0]["asked"]'
expect "... also while the waiting screen shows the push"  'pw[1]["asked"] and pw[1]["closed"] and pw[1]["waited"] < 4'
expect "WaitingScreen (default): login asks for progress and sends the keyboard layout" \
    'all(r.get("progress") == 1 and isinstance(r.get("keyboard_layout"), int) for r in la if r["user"] in ("oldbroker", "badprogress", "floodprogress"))'
expect "WaitingScreen=false: no progress asked"          '[r["asked"] for r in pr("progress")] == [True] * 4 + [False] and ["progress" in r for r in la if r["user"] == "progress"] == [True] * 4 + [False] and "progress" not in la[0]'
expect "waiting screen logins reached the back-end (old broker, malformed progress too)" \
    '[r["user"] for r in lb].count("progress") == 5 and any(r["user"] == "oldbroker" for r in lb) and any(r["user"] == "badprogress" for r in lb)'
expect "too many progress messages: login refused, back-end never reached" 'not any(r["user"] == "floodprogress" for r in lb)'
expect "picker offered with the waiting screen, not without" \
    'all(r.get("picker") == 1 for r in la if r["user"].startswith("picker") and r["user"] != "pickeroff") and "picker" not in [r for r in la if r["user"] == "pickeroff"][0] and not pc["pickeroff"]["asked"]'
expect "picker: top-row digit 2"                     'chose("pickerdigit") == "gnome"'
expect "picker: Down Down Enter"                      'chose("pickerkeys") == "plasma"'
expect "picker: Esc answers null (the broker's default)" 'pc["pickeresc"].get("line") == {"op": "choice", "desktop": None}'
expect "picker: countdown over, nothing pressed: null after the timeout" \
    'pc["pickertimeout"].get("line") == {"op": "choice", "desktop": None} and 5.5 <= pc["pickertimeout"].get("waited", 0) < 8'
expect "picker: countdown over after a move: the selected row" 'chose("pickermoved") == "gnome" and pc["pickermoved"].get("waited", 0) >= 5.5'
expect "picker: click on the row below the default"   'chose("pickerclick") == "gnome"'
expect "picker: keys from before the prompt ignored, Unicode 2 counts" 'chose("pickerearly") == "gnome"'
expect "picker: keypad 3 with NumLock"                'chose("pickerkeypad") == "plasma"'
expect "picker: client gone during the picker: broker connection closed" \
    'pc["pickergone"]["closed"] and pc["pickergone"].get("line") is None and pc["pickergone"].get("waited", 9) < 4'
expect "picker: channel data below the cap passed on, the choice counts" 'chose("pickerchan") == "gnome"'
expect "picker: channel data above the cap: login abandoned, broker connection closed" \
    'pc["pickerflood"]["closed"] and pc["pickerflood"].get("line") is None'
expect "picker: chosen logins reached the back-end, the abandoned one not" \
    'sorted(r["user"] for r in lb if r["user"].startswith("picker")) == sorted(["pickerdigit", "pickerkeys", "pickeresc", "pickertimeout", "pickermoved", "pickerclick", "pickerearly", "pickerkeypad", "pickerchan", "pickeroff"])'
expect "Shutdown Request during the session: session end reported, back-end connection closed" \
    'hold(a)[0]["closed"] is False and hold(b)[0]["closed"] and hold(b)[0]["waited"] < 2.9 and any(r["op"] == "end" and r["session_id"] in sid("holdsession") for r in a)'
expect "Shutdown Request during the picker: login abandoned, broker connection closed" \
    'pc["pickershutdown"]["closed"] and pc["pickershutdown"].get("line") is None'
errinfo() { # description client-output expected-code
    if grep -q "errinfo=$3" "$2"; then echo "ok   $1"; else echo "FAIL $1 ($(grep errinfo "$2"))"; fail=1; fi
}
errinfo "refused password: ERRINFO_SERVER_DENIED_CONNECTION"                     mallory.out    0x00000007
errinfo "not in an allowed group: ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES"        nogroup.out    0x00000009
errinfo "second factor failed: ERRINFO_SERVER_DENIED_CONNECTION"                 mfafail.out    0x00000007
errinfo "push not approved in time: ERRINFO_CB_CONNECTION_CANCELLED"             mfatimeout.out 0x00000409
errinfo "unknown reason: ERRINFO_SERVER_DENIED_CONNECTION"                       newreason.out  0x00000007
errinfo "back-end not started: ERRINFO_CB_DESTINATION_NOT_FOUND"                 nobackend.out  0x00000400
errinfo "back-end not started (broker without reason): 0x400"                    oldbackend.out 0x00000400
errinfo "back-end unreachable: ERRINFO_CB_DESTINATION_NOT_FOUND"                 deadport.out   0x00000400
errinfo "RemoteApp request refused: ERRINFO_SERVER_DENIED_CONNECTION"            rail.out       0x00000007
errinfo "smartcard PIN without NLA refused"                                      pin.out        0x00000007
errinfo "TLS login outside AllowTlsFrom: ERRINFO_SERVER_DENIED_CONNECTION"        outsider.out   0x00000007
errinfo "wrong back-end certificate: ERRINFO_CB_DESTINATION_NOT_FOUND"           badcert.out    0x00000400
errinfo "no back-end fingerprint from the broker: ERRINFO_CB_DESTINATION_NOT_FOUND" nocert.out  0x00000400
errinfo "CertificatePolicy=allow: ERRINFO_SERVER_DENIED_CONNECTION"              allowpolicy.out 0x00000007
errinfo "too many progress messages: ERRINFO_CB_DESTINATION_NOT_FOUND"        ws-flood.out   0x00000400
bitmaps() { # description client-output python-expression-over(n, rects, first_ms)
    if python3 - "$2" "$3" <<'PY'
import re, sys
m = re.search(r"bitmap_updates=(\d+) bitmap_rects=(\d+) first_bitmap_ms=(-?\d+)", open(sys.argv[1]).read())
n, rects, first_ms = map(int, m.groups()) if m else (-1, -1, -1)
sys.exit(0 if m and eval(sys.argv[2]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1 ($(grep bitmap_updates "$2"))"; fail=1; fi
}
# generic panel, MFA panel, countdown seconds, session start, cleared: at least 6 updates
for bpp in 32 24 16 15; do
    bitmaps "waiting screen at $bpp bpp: panel within 1 s, countdown redrawn, cleared" ws$bpp.out \
        'n >= 6 and 0 < first_ms <= 1000'
done
bitmaps "WaitingScreen=false: no Bitmap Updates before the back-end"         ws-off.out 'n == 0'
bitmaps "broker without progress messages: generic panel, then cleared"      ws-old.out 'n >= 2 and 0 < first_ms <= 1000'
if grep -q "status_info=0x0401" ws32.out && grep -q "status_info=0x0403" ws32.out && ! grep -q status_info ws-off.out; then
    echo "ok   StatusInfo: finding destination, bringing session online (only with StatusInfo=true)"
else
    echo "FAIL StatusInfo PDUs ($(grep status_info ws32.out ws-off.out | tr '\n' ' '))"; fail=1
fi
# the QR code on the decoded screen (32 bpp: planar, 16 bpp: interleaved) reads as the
# login-bound approval URL with the id the broker sent; needs python3 with zxing-cpp and
# Pillow (E2E_QR_PYTHON), else skipped
QRPY=${E2E_QR_PYTHON:-python3}
if "$QRPY" -I -c 'import zxingcpp, PIL' 2>/dev/null; then
    for bpp in 32 16; do
        if [ -s "panel$bpp.ppm" ] && "$QRPY" -I - "panel$bpp.ppm" "$E2E_LOGIN_ID" <<'PY'
import sys, zxingcpp
from PIL import Image
found = [r.text for r in zxingcpp.read_barcodes(Image.open(sys.argv[1]))]
print(found)
sys.exit(0 if found == ["https://rdp1.lab.example.com/web/approve?login=" + sys.argv[2]] else 1)
PY
        then echo "ok   QR code on the $bpp bpp screen decodes to the approval URL with the login's id"
        else echo "FAIL QR code on the $bpp bpp screen"; fail=1; fi
    done
else
    echo "skip QR code decoding: no python3 with zxing-cpp and Pillow (E2E_QR_PYTHON)"
fi
logged() { # description log-file fixed-string
    if grep -qF -- "$3" "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
logged "AllowTlsFrom refusal logged with the socket peer address" proxy-c.log \
    "non-NLA login from 127.0.0.1 refused (AllowTlsFrom="
logged "wrong back-end certificate logged with both fingerprints" proxy-a.log \
    "presented certificate sha256 "
logged "CertificatePolicy other than deny logged" proxy-d.log \
    "CertificatePolicy must be deny"
logged "proxy abandoned the broker request when the client went away" proxy-a.log \
    "front connection closed while waiting for the broker"
logged "... also with the waiting screen" proxy-e.log \
    "front connection closed while waiting for the broker"
logged "malformed QR code from the broker left out, login goes on" proxy-e.log \
    "malformed QR code from the broker left out"
logged "too many progress messages logged" proxy-e.log "more than 32 progress messages"
logged "picker: choice logged" proxy-e.log "desktop picker: gnome (click)"
logged "picker: closed client logged" proxy-e.log "front connection closed during the desktop picker"
logged "picker: channel data cap logged" proxy-e.log "more than 4194304 bytes of channel data during the desktop picker"
# the client really sent the data: without it the pickerchan choice check passes anyway
logged "picker: channel data below the cap sent on the announced channel" pickerchan.out \
    "channel_data=65536 sent=1"
logged "Shutdown Request during the session: Shutdown Request Denied" shutdown.out "shutdown_denied at"
if grep -q "disconnected itself after the denied shutdown request" shutdown.out &&
   ! grep -q "session closed by server" shutdown.out; then
    echo "ok   ... the proxy kept the connection, the client disconnected itself"
else
    echo "FAIL Shutdown Request during the session ($(grep -E 'shutdown|closed|errinfo' shutdown.out | tr '\n' ' '))"; fail=1
fi
# FreeRDP's mcs_send_disconnect_provider_ultimatum() writes reason 3 ("user requested")
# whatever it is asked for, so dpu=3 here although the proxy logs "provider initiated"
if grep -q "errinfo=0x00000400" backendend.out && grep -q "server_end: deactivate_all=1 dpu=3" backendend.out; then
    echo "ok   back-end ended the session: code forwarded, Deactivate All and Disconnect Provider Ultimatum to the client"
else
    echo "FAIL back-end ended the session ($(grep -E 'errinfo|server_end' backendend.out | tr '\n' ' '))"; fail=1
fi
if grep -q "shutdown_request sent=1" pickershutdown.out && ! grep -q shutdown_denied pickershutdown.out &&
   ! grep -q "disconnected itself" pickershutdown.out; then
    echo "ok   Shutdown Request during the picker: closed at once, not denied (no session yet)"
else
    echo "FAIL Shutdown Request during the picker ($(grep -E 'shutdown|closed|itself' pickershutdown.out | tr '\n' ' '))"; fail=1
fi
logged "Remote Credential Guard required: client got a negotiation response, not a dropped connection" \
    rcg.out "remote credential guard requested but not supported"
if grep -q -- "--> CONNECTION_STATE_CAPABILITIES_EXCHANGE_DEMAND_ACTIVE" proxy-a.log &&
   ! grep -q -- "--> CONNECTION_STATE_MULTITRANSPORT_BOOTSTRAPPING_RESPONSE" proxy-a.log; then
    echo "ok   no multitransport offered (no UDP listener): no Initiate Multitransport Request"
else
    echo "FAIL multitransport offered although the proxy has no UDP listener"; fail=1
fi
if [ $fail -ne 0 ]; then
    echo "--- proxy A log:"; grep -E "fastrdp|ERROR" proxy-a.log | tail -20
    echo "--- proxy E log:"; grep -E "fastrdp|ERROR" proxy-e.log | tail -20
fi
exit $fail
