#!/bin/bash
# Kerberos NLA end-to-end test: throwaway MIT KDC + freerdp-proxy + fastrdp module.
# Checks that the module reports the Kerberos-authenticated principal to the broker
# and that failed Kerberos logins never reach the broker.
#
# Needs krb5-kdc, krb5-admin-server, krb5-user (or KRB5_SYSROOT with them extracted)
# plus everything run.sh needs.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=${SYSROOT:-}
KRB5_SYSROOT=${KRB5_SYSROOT:-}
MA=$(gcc -print-multiarch)
LIBDIR=$SYSROOT/usr/lib/$MA
KB=$KRB5_SYSROOT/usr/sbin
W=$(mktemp -d /tmp/fastrdp-nla.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
export LD_LIBRARY_PATH="${KRB5_SYSROOT:+$KRB5_SYSROOT/usr/lib/$MA:}$LIBDIR:$LIBDIR/pulseaudio${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# shellcheck source=tests/proxy-e2e/freerdp-env.sh
. "$HERE/freerdp-env.sh"
gcc -std=c11 -D_GNU_SOURCE -fPIC -shared -fvisibility=hidden -Wno-deprecated-declarations \
    "${INC[@]}" "$HERE/shim.c" -o "$W/shim.so" "${LNK[@]}" -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3 -lcjson
gcc -std=c11 -D_GNU_SOURCE -Wno-deprecated-declarations "${INC[@]}" "$HERE/client.c" -o "$W/client" \
    "${LNK[@]}" -lfreerdp3 -lwinpr3
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=localhost -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
cd "$W"

# --- KDC
cat > krb5.conf <<EOT
[libdefaults]
    default_realm = TEST.FASTRDP
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    qualify_shortname = ""
    udp_preference_limit = 0
[realms]
    TEST.FASTRDP = {
        kdc = 127.0.0.1:28888
    }
[domain_realm]
    localhost = TEST.FASTRDP
EOT
cat > kdc.conf <<EOT
[kdcdefaults]
    kdc_tcp_listen = 28888
    kdc_listen = 28888
[realms]
    TEST.FASTRDP = {
        database_name = $W/principal
        key_stash_file = $W/stash
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
[logging]
    kdc = FILE:$W/kdc.log
EOT
if [ -n "$KRB5_SYSROOT" ]; then
    printf '[dbmodules]\n    db_module_dir = %s\n' "$KRB5_SYSROOT/usr/lib/$MA/krb5/plugins/kdb" >> kdc.conf
fi
export KRB5_CONFIG=$W/krb5.conf KRB5_KDC_PROFILE=$W/kdc.conf KRB5CCNAME=FILE:$W/none.cc
"$KB/kdb5_util" create -s -r TEST.FASTRDP -P masterpw >/dev/null 2>&1
for q in "addprinc -pw alicepw alice" "addprinc -randkey TERMSRV/localhost" \
         "ktadd -k $W/termsrv.keytab TERMSRV/localhost"; do
    "$KB/kadmin.local" -r TEST.FASTRDP -q "$q" >/dev/null 2>&1
done
"$KB/krb5kdc" -n > kdc.out 2>&1 &

# --- proxy (NLA only) + recording broker that refuses everything (no back-end needed)
cat > p.ini <<EOT
[Server]
Host=127.0.0.1
Port=23489
[Target]
FixedTarget=false
CertificatePolicy=allow
SmartcardAuth=false
[Security]
ServerNlaSecurity=true
ServerTlsSecurity=false
ServerRdpSecurity=false
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
EOT
python3 "$HERE/fake_broker.py" b.sock b.log 1 > b.out 2>&1 &
KRB5_KTNAME=FILE:$W/termsrv.keytab LD_PRELOAD="$W/shim.so" "$PROXY" p.ini > proxy.log 2>&1 &
for _ in $(seq 50); do grep -q ready b.out 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23489) 2>/dev/null && break; sleep 0.2; done

E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP timeout 20 ./client localhost 23489 alice alicepw "" >/dev/null 2>&1 || true
E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP timeout 20 ./client localhost 23489 alice wrongpw "" >/dev/null 2>&1 || true
sleep 1

fail=0
check() {
    if python3 - "$2" <<'PY'
import json, os, sys
logins = [json.loads(l) for l in open("b.log")] if os.path.exists("b.log") else []
logins = [r for r in logins if r["op"] == "login"]
sys.exit(0 if eval(sys.argv[1]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
check "exactly one login reached the broker (wrong password stopped at NLA)" 'len(logins) == 1'
check "method is nla with the Kerberos principal"   'logins[0]["method"] == "nla" and logins[0]["principal"] == "alice@TEST.FASTRDP"'
check "CredSSP user and delegated password passed" 'logins[0]["user"] == "alice" and logins[0]["password"] == "alicepw"'
if [ $fail -ne 0 ]; then echo "--- proxy log:"; grep -E "fastrdp|nla|NLA|krb|Kerberos|ERROR" proxy.log | tail -25; fi
exit $fail
