#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Smartcard (PKINIT) NLA logon through freerdp-proxy + fastrdp module.
#   SoftHSM2 token (stands in for a PIV card / YubiKey) -> FreeRDP smartcard logon
#   -> MIT KDC with PKINIT -> Kerberos NLA at the proxy -> broker request.
# Checks: the principal is bound, the request is flagged smartcard, the PIN is
# never forwarded as a password, a wrong PIN never reaches the broker, and the KDC's
# "pkinit" authentication indicator reaches the broker as kdc_evidence
# (patches/freerdp/0005, fastrdp-freerdp3 3.32.2-4).
#
# Needs krb5-kdc krb5-admin-server krb5-pkinit softhsm2 opensc p11-kit-modules plus
# what run.sh needs. KRB5_SYSROOT / SC_SYSROOT: same packages extracted from .debs.
#
# SC_MODULE=p11kit (default) hands the token to the client through p11-kit-proxy
# (small slot ids). SC_MODULE=softhsm uses libsofthsm2.so directly; its 32-bit slot
# ids trigger the FreeRDP slot-id truncation bug (docs/upstream.md). CLIENT_LIBDIR
# runs only the client against other libfreerdp3/libwinpr3 builds (e.g. a fix).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=${SYSROOT:-}
KRB5_SYSROOT=${KRB5_SYSROOT:-}
SC_SYSROOT=${SC_SYSROOT:-}
MA=$(gcc -print-multiarch)
LIBDIR=$SYSROOT/usr/lib/$MA
SCLIB=$SC_SYSROOT/usr/lib/$MA
KB=$KRB5_SYSROOT/usr/sbin
PKINIT_SO=$SCLIB/krb5/plugins/preauth/pkinit.so
SOFTHSM=$SCLIB/softhsm/libsofthsm2.so
P11PROXY=$SCLIB/p11-kit-proxy.so
case ${SC_MODULE:-p11kit} in
    p11kit) CLIENT_P11=$P11PROXY ;;
    softhsm) CLIENT_P11=$SOFTHSM ;;
    *) echo "SC_MODULE must be p11kit or softhsm" >&2; exit 2 ;;
esac
CLIENT_LIBDIR=${CLIENT_LIBDIR:-}
W=$(mktemp -d /tmp/fastrdp-sc.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
export LD_LIBRARY_PATH="${KRB5_SYSROOT:+$KRB5_SYSROOT/usr/lib/$MA:}$LIBDIR:$LIBDIR/pulseaudio:$SCLIB:$SCLIB/softhsm${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# shellcheck source=tests/proxy-e2e/freerdp-env.sh
. "$HERE/freerdp-env.sh"
gcc -std=c11 -D_GNU_SOURCE -fPIC -shared -fvisibility=hidden -Wno-deprecated-declarations \
    "${INC[@]}" "$HERE/shim.c" -o "$W/shim.so" "${LNK[@]}" -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3 -lcjson
gcc -std=c11 -D_GNU_SOURCE -Wno-deprecated-declarations "${INC[@]}" "$HERE/client.c" -o "$W/client" \
    "${LNK[@]}" -lfreerdp3 -lwinpr3
cd "$W"

# --- PKI: CA, KDC certificate, smartcard certificate for alice (PKINIT SAN + MS UPN)
cat > ext.cnf <<'EOT'
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:TEST.FASTRDP
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:TEST.FASTRDP
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4,clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:alice@TEST.FASTRDP
[princ_name]
realm=EXP:0,GeneralString:TEST.FASTRDP
principal_name=EXP:1,SEQUENCE:principal_seq
[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals
[principals]
princ1=GeneralString:alice
EOT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=test CA" -keyout ca.key -out ca.pem 2>/dev/null
for who in kdc alice; do
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$who" -keyout "$who.key" -out "$who.csr" 2>/dev/null
    ext=$([ $who = kdc ] && echo kdc_cert || echo client_cert)
    openssl x509 -req -in "$who.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 \
        -extfile ext.cnf -extensions "$ext" -out "$who.pem" 2>/dev/null
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=localhost -keyout tls.key -out tls.pem 2>/dev/null

# --- "smartcard": SoftHSM token, exposed through p11-kit-proxy (small slot ids)
export SOFTHSM2_CONF=$W/softhsm2.conf HOME=$W XDG_CONFIG_HOME=$W/.config
mkdir -p tokens .config/pkcs11/modules
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$W" > softhsm2.conf
printf 'module: %s\n' "$SOFTHSM" > .config/pkcs11/modules/softhsm.module
"${SOFTHSM_UTIL:-$SC_SYSROOT/usr/bin/softhsm2-util}" --module "$SOFTHSM" --init-token --free \
    --label piv --pin 123456 --so-pin 12345678 >/dev/null
openssl pkcs8 -topk8 -nocrypt -in alice.key -out alice.p8
"${SOFTHSM_UTIL:-$SC_SYSROOT/usr/bin/softhsm2-util}" --module "$SOFTHSM" --import alice.p8 \
    --token piv --label alice --id 01 --pin 123456 >/dev/null
openssl x509 -in alice.pem -outform DER -out alice.der
"${PKCS11_TOOL:-$SC_SYSROOT/usr/bin/pkcs11-tool}" --module "$SOFTHSM" --login --pin 123456 \
    --write-object alice.der --type cert --id 01 --label alice >/dev/null 2>&1

# --- KDC with PKINIT; alice has no usable password at all
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
        kdc = 127.0.0.1:28890
        pkinit_anchors = FILE:$W/ca.pem
    }
[domain_realm]
    localhost = TEST.FASTRDP
[plugins]
    clpreauth = {
        module = pkinit:$PKINIT_SO
    }
    kdcpreauth = {
        module = pkinit:$PKINIT_SO
    }
EOT
cat > kdc.conf <<EOT
[kdcdefaults]
    kdc_tcp_listen = 28890
    kdc_listen = 28890
[realms]
    TEST.FASTRDP = {
        database_name = $W/principal
        key_stash_file = $W/stash
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
        pkinit_identity = FILE:$W/kdc.pem,$W/kdc.key
        pkinit_anchors = FILE:$W/ca.pem
        pkinit_indicator = pkinit
    }
[logging]
    kdc = FILE:$W/kdc.log
EOT
[ -n "$KRB5_SYSROOT" ] && printf '[dbmodules]\n    db_module_dir = %s\n' "$KRB5_SYSROOT/usr/lib/$MA/krb5/plugins/kdb" >> kdc.conf
export KRB5_CONFIG=$W/krb5.conf KRB5_KDC_PROFILE=$W/kdc.conf KRB5CCNAME=FILE:$W/none.cc
"$KB/kdb5_util" create -s -r TEST.FASTRDP -P masterpw >/dev/null 2>&1
for q in "addprinc -randkey +requires_preauth alice" "addprinc -randkey TERMSRV/localhost" \
         "ktadd -k $W/termsrv.keytab TERMSRV/localhost"; do
    "$KB/kadmin.local" -r TEST.FASTRDP -q "$q" >/dev/null 2>&1
done
"$KB/krb5kdc" -n > kdc.out 2>&1 &

cat > p.ini <<EOT
[Server]
Host=127.0.0.1
Port=23689
[Target]
FixedTarget=false
CertificatePolicy=deny
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
CertificateFile=$W/tls.pem
PrivateKeyFile=$W/tls.key
[FastRDP]
BrokerSocket=b.sock
Timeout=10
EOT
python3 "$HERE/fake_broker.py" b.sock b.log 1 > b.out 2>&1 &
KRB5_KTNAME=FILE:$W/termsrv.keytab LD_PRELOAD="$W/shim.so" "$PROXY" p.ini > proxy.log 2>&1 &
for _ in $(seq 50); do grep -q ready b.out 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23689) 2>/dev/null && break; sleep 0.2; done

client() {
    E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP E2E_PKCS11=$CLIENT_P11 KRB5_TRACE=$W/client-trace.log \
        LD_LIBRARY_PATH="${CLIENT_LIBDIR:+$CLIENT_LIBDIR:}$LD_LIBRARY_PATH" \
        timeout 30 ./client localhost 23689 alice "$1" "" >/dev/null 2>&1 || true
}
client 999999
client 123456
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
check "wrong PIN stopped at PKINIT, right PIN reached the broker" 'len(logins) == 1'
check "Kerberos principal from the smartcard certificate"        'logins[0]["method"] == "nla" and logins[0]["principal"] == "alice@TEST.FASTRDP"'
check "flagged as smartcard logon"                               'logins[0]["smartcard"] is True'
check "PIN not forwarded as password"                            'logins[0]["password"] is None'
# patches/freerdp/0005: the KDC's authentication indicator (kdc.conf pkinit_indicator, as
# FreeIPA sets it) reaches the broker; MIT's minimal PAC has no logon info, so no SIDs
check "KDC evidence: the ticket's pkinit indicator"               'logins[0].get("kdc_evidence") == ["ind:pkinit"]'
if grep -qE "svc-verifier does not verify|server signature does not verify" proxy.log; then
    echo "FAIL KDC evidence: the CAMMAC and the PAC verified"; fail=1
else
    echo "ok   KDC evidence: the CAMMAC and the PAC verified"
fi
if [ $fail -ne 0 ]; then
    echo "--- proxy log:"; grep -E "fastrdp|ERROR" proxy.log | tail -15; tail -5 kdc.log
    echo "--- client PKINIT:"; grep -E "PKINIT loading identity|no matching tokens" client-trace.log | sort -u | head -4
fi
exit $fail
