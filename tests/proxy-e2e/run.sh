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
mkproxy() { # name port broker-socket [AllowTlsFrom [CertificatePolicy]]
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
EOT
}
mkproxy a 23389 a.sock '127.0.0.0/8, ::1'
mkproxy b 23390 b.sock
# TLS logins only from addresses the e2e client does not have (web-only TLS, R3)
mkproxy c 23392 a.sock '192.0.2.0/24, 2001:db8::/32'
# the module pins the back-end certificate itself and needs CertificatePolicy=deny
mkproxy d 23393 a.sock '127.0.0.0/8' allow
# proxy B is proxy A's back-end and presents cert.pem: its fingerprint goes into the targets
E2E_CERT_SHA256=$(openssl x509 -in cert.pem -outform DER | sha256sum | cut -d' ' -f1)
export E2E_CERT_SHA256
python3 "$HERE/fake_broker.py" a.sock a.log 23390 > a.out 2>&1 &
python3 "$HERE/fake_broker.py" b.sock b.log 23391 > b.out 2>&1 &
# connection state transitions (core.rdp DEBUG) show whether multitransport was offered
WLOG_FILTER="com.freerdp.core.rdp:DEBUG" LD_PRELOAD="$W/shim.so" "$PROXY" a.ini > proxy-a.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" b.ini > proxy-b.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" c.ini > proxy-c.log 2>&1 &
LD_PRELOAD="$W/shim.so" "$PROXY" d.ini > proxy-d.log 2>&1 &
for _ in $(seq 50); do grep -q ready a.out b.out 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23390) 2>/dev/null &&
    (exec 3<>/dev/tcp/127.0.0.1/23392) 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23393) 2>/dev/null &&
    break; sleep 0.2; done

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
sys.exit(0 if eval(sys.argv[1]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
expect "front broker saw the expected logins"         'len(la) == 16'
expect "pinned certificate accepted, wrong pin refused" '[r["user"] for r in la][:3] == ["alice", "mallory", "pinned"]'
expect "RemoteApp and TLS smartcard-PIN logins never reached the broker" 'not any(r["user"] in ("railuser", "pinuser") for r in la)'
expect "front login carries TLS credentials + hints"   'la[0]["method"] == "tls" and la[0]["user"] == "alice" and la[0]["password"] == "good" and la[0]["desktop_hint"] == "fastrdp:gnome" and (la[0]["width"], la[0]["height"]) == (2560, 1440)'
expect "client address is the socket peer, not the claimed one" 'la[0]["client_address"] == "127.0.0.1"'
expect "back-end received the token, not the password" 'len(lb) == 5 and all(r["password"] == "fastrdp1:TOKEN" for r in lb) and lb[0]["user"] == "alice"'
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
    'len(pw := [r for r in a if r["op"] == "pushwait"]) == 1 and pw[0]["closed"] and pw[0]["waited"] < 4'
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
fi
exit $fail
