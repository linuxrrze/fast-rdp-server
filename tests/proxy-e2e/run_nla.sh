#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Kerberos NLA end-to-end test: throwaway MIT KDC + freerdp-proxy + fastrdp module.
# Checks that the module reports the Kerberos-authenticated principal to the broker
# and that failed Kerberos logins never reach the broker.
# No NTLM (rdp-spec-conformance.md R5): the acceptor does not offer it; an NTLM-only client
#   fails at its first CredSSP message and the proxy logs the attempt with a Kerberos hint.
# Remote Credential Guard (client with E2E_REMOTE_GUARD=1, like mstsc /remoteGuard):
#   proxy p (default, AcceptRemoteGuard unset) answers the X.224 request with a
#   negotiation response without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED, so the client
#   stops on its own instead of seeing a dropped connection (patches/freerdp/0002);
#   proxy g (AcceptRemoteGuard=true) takes the login identity-only: the broker gets the
#   principal, "remote_guard": true and no password (patches/freerdp/0003).
# Kerberos user-to-user (mstsc under CredSSP starts with a KERB-TGT-REQUEST): the KDC mimics
#   Active Directory when kadmin has add_alias (MIT >= 1.22): TERMSRV/localhost is an alias
#   (SPN) of the machine account FASTRDP$, and the kdcpolicy module kdc_adlike.c refuses it
#   as an AS client. The acceptor must answer with FASTRDP$'s TGT: proxy u has its keys
#   (fastrdp-termsrv-keytab layout, patches/freerdp/0004), proxy t only the TERMSRV keys.
#   With the switch file of kdc_adlike.c the KDC lets TERMSRV/localhost get a TGT, as plain
#   MIT and FreeIPA do, and proxy t works with the TERMSRV keys alone. Without add_alias
#   (Debian 13: krb5 1.21) TERMSRV/localhost is a principal of its own and only that case runs.
#
# Needs krb5-kdc, krb5-admin-server, krb5-user (or KRB5_SYSROOT with them extracted),
# libkrb5-dev for kdc_adlike.c (KRB5_CFLAGS: extra compiler flags, e.g. -I<include dir>)
# plus everything run.sh needs. The Remote Credential Guard checks need a FreeRDP built
# with Kerberos (WITH_KRB5) and patches/freerdp/0002 + 0003 (fastrdp-freerdp3 3.32.2-2), the
# user-to-user checks patches/freerdp/0004 (3.32.2-3).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=${SYSROOT:-}
KRB5_SYSROOT=${KRB5_SYSROOT:-}
MA=$(gcc -print-multiarch)
LIBDIR=$SYSROOT/usr/lib/$MA
KB=$KRB5_SYSROOT/usr/sbin
# kinit for the forwardable TGT of the Remote Credential Guard client (Debian's krb5-user
# installs kinit.mit behind an alternatives link, which an extracted sysroot lacks)
KINIT=${KINIT:-}
for k in ${KRB5_SYSROOT:+"$KRB5_SYSROOT/usr/bin/kinit" "$KRB5_SYSROOT/usr/bin/kinit.mit"} "$(command -v kinit || true)"; do
    [ -z "$KINIT" ] && [ -x "$k" ] && KINIT=$k
done
[ -n "$KINIT" ] || { echo "run_nla.sh: kinit not found (krb5-user)" >&2; exit 2; }
W=$(mktemp -d /tmp/fastrdp-nla.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
export LD_LIBRARY_PATH="${KRB5_SYSROOT:+$KRB5_SYSROOT/usr/lib/$MA:}$LIBDIR:$LIBDIR/pulseaudio${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# shellcheck source=tests/proxy-e2e/freerdp-env.sh
. "$HERE/freerdp-env.sh"
gcc -std=c11 -D_GNU_SOURCE -fPIC -shared -fvisibility=hidden -Wno-deprecated-declarations \
    "${INC[@]}" "$HERE/shim.c" -o "$W/shim.so" "${LNK[@]}" -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3 -lcjson
gcc -std=c11 -D_GNU_SOURCE -Wno-deprecated-declarations "${INC[@]}" "$HERE/client.c" -o "$W/client" \
    "${LNK[@]}" -lfreerdp3 -lwinpr3
# AD-like KDC policy (krb5/kdcpolicy_plugin.h from libkrb5-dev)
KRB5_CFLAGS=${KRB5_CFLAGS-$(pkg-config --cflags krb5 2>/dev/null || true)}
# shellcheck disable=SC2086  # KRB5_CFLAGS: several flags
if ! gcc -std=c11 -Wall -Wextra -Werror -fPIC -shared $KRB5_CFLAGS "$HERE/kdc_adlike.c" \
        -o "$W/kdc_adlike.so" 2> "$W/kdc_adlike.err"; then
    cat "$W/kdc_adlike.err" >&2
    echo "run_nla.sh: cannot build kdc_adlike.c (libkrb5-dev; KRB5_CFLAGS=-I<dir with krb5/>)" >&2
    exit 2
fi
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
[plugins]
    kdcpolicy = {
        module = adlike:$W/kdc_adlike.so
    }
EOT
if [ -n "$KRB5_SYSROOT" ]; then
    printf '[dbmodules]\n    db_module_dir = %s\n' "$KRB5_SYSROOT/usr/lib/$MA/krb5/plugins/kdb" >> kdc.conf
fi
export KRB5_CONFIG=$W/krb5.conf KRB5_KDC_PROFILE=$W/kdc.conf KRB5CCNAME=FILE:$W/none.cc
# kdc_adlike.c: while this file exists, service principals may be AS clients (MIT, FreeIPA)
export FASTRDP_TEST_KDC_SPN_AS=$W/kdc-spn-as
"$KB/kdb5_util" create -s -r TEST.FASTRDP -P masterpw >/dev/null 2>&1
AD=0
# (grep without -q: reads all, so pipefail does not see kadmin's SIGPIPE)
"$KB/kadmin.local" -r TEST.FASTRDP -q "list_requests" 2>/dev/null | grep add_alias >/dev/null && AD=1
# HOST/localhost: Remote Credential Guard clients send a service ticket for HOST/<server>
# (upper case, as WinPR asks for it; MIT principal names are case-sensitive).
# AD layout: TERMSRV/localhost is an alias of FASTRDP$, the keytab entries for both carry
# the same key (as adcli writes them); ad.keytab is what fastrdp-termsrv-keytab extracts.
if [ $AD = 1 ]; then
    termsrv=("addprinc -randkey FASTRDP\$" "add_alias TERMSRV/localhost FASTRDP\$"
             "ktadd -norandkey -k $W/termsrv.keytab TERMSRV/localhost"
             "ktadd -norandkey -k $W/ad.keytab TERMSRV/localhost" "ktadd -norandkey -k $W/ad.keytab FASTRDP\$")
else
    termsrv=("addprinc -randkey TERMSRV/localhost" "ktadd -k $W/termsrv.keytab TERMSRV/localhost")
fi
for q in "addprinc -pw alicepw alice" "${termsrv[@]}" "addprinc -randkey HOST/localhost" \
         "ktadd -norandkey -k $W/alice.keytab alice"; do
    "$KB/kadmin.local" -r TEST.FASTRDP -q "$q" >/dev/null 2>&1
done
"$KB/krb5kdc" -n > kdc.out 2>&1 &

# --- proxies (NLA only) + recording brokers that refuse everything (no back-end needed)
# p: defaults (no Remote Credential Guard); g: AcceptRemoteGuard=true;
# u: AD keytab (TERMSRV + machine account keys); t: TERMSRV keys only (user-to-user cases)
mkproxy() { # name port broker-socket [extra [FastRDP] line]
cat > "$1.ini" <<EOT
[Server]
Host=127.0.0.1
Port=$2
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
CertificateFile=$W/cert.pem
PrivateKeyFile=$W/key.pem
[FastRDP]
BrokerSocket=$3
Timeout=10
${4:-}
EOT
}
mkproxy p 23489 b.sock
mkproxy g 23490 g.sock AcceptRemoteGuard=true
mkproxy u 23491 u.sock
mkproxy t 23492 t.sock
[ $AD = 1 ] || cp termsrv.keytab ad.keytab
for x in b g u t; do python3 "$HERE/fake_broker.py" $x.sock $x.log 1 > $x.out 2>&1 & done
KRB5_KTNAME=FILE:$W/termsrv.keytab LD_PRELOAD="$W/shim.so" "$PROXY" p.ini > proxy.log 2>&1 &
KRB5_KTNAME=FILE:$W/termsrv.keytab LD_PRELOAD="$W/shim.so" "$PROXY" g.ini > proxy-g.log 2>&1 &
KRB5_KTNAME=FILE:$W/ad.keytab LD_PRELOAD="$W/shim.so" "$PROXY" u.ini > proxy-u.log 2>&1 &
KRB5_KTNAME=FILE:$W/termsrv.keytab LD_PRELOAD="$W/shim.so" "$PROXY" t.ini > proxy-t.log 2>&1 &
for _ in $(seq 50); do grep -q ready b.out g.out u.out t.out 2>/dev/null &&
    (exec 3<>/dev/tcp/127.0.0.1/23489) 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23490) 2>/dev/null &&
    (exec 3<>/dev/tcp/127.0.0.1/23491) 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/23492) 2>/dev/null &&
    break; sleep 0.2; done

E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP timeout 20 ./client localhost 23489 alice alicepw "" >/dev/null 2>&1 || true
E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP timeout 20 ./client localhost 23489 alice wrongpw "" >/dev/null 2>&1 || true
# WinPR's default list (U2U, Kerberos, NTLM): the acceptor, which no longer offers NTLM,
# still picks Kerberos and the proxy does not mistake the offer for an NTLM attempt
E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP E2E_AUTH_PKGS="" timeout 20 ./client localhost 23489 alice alicepw "" >/dev/null 2>&1 || true
# a client that can only do NTLM (no ticket: IP address, KDC unreachable): refused at the
# first CredSSP message, with a plain proxy log line
t0=$(date +%s%N)
E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP E2E_AUTH_PKGS='none,ntlm' timeout 20 ./client localhost 23489 alice alicepw "" > ntlm.out 2>&1 || true
echo "$(( ($(date +%s%N) - t0) / 1000000 ))" > ntlm.ms
# Remote Credential Guard: forwardable TGT in a ccache, no password at the client
KRB5CCNAME=FILE:$W/alice.cc "$KINIT" -f -k -t "$W/alice.keytab" alice@TEST.FASTRDP > kinit.out 2>&1
RCG=(env E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP E2E_REMOTE_GUARD=1 "KRB5CCNAME=FILE:$W/alice.cc")
"${RCG[@]}" timeout 20 ./client localhost 23489 alice "" "" > rcg-refused.out 2>&1 || true
"${RCG[@]}" timeout 20 ./client localhost 23490 alice "" "" > rcg.out 2>&1 || true
# the option changes nothing for password logins
E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP timeout 20 ./client localhost 23490 alice alicepw "" >/dev/null 2>&1 || true
# Kerberos user-to-user only, like mstsc: the client's first token is a KERB-TGT-REQUEST
U2U=(env E2E_NLA=1 E2E_DOMAIN=TEST.FASTRDP E2E_AUTH_PKGS='none,u2u' timeout 20 ./client localhost)
if [ $AD = 1 ]; then
    "${U2U[@]}" 23491 alice alicepw "" > u2u-ad.out 2>&1 || true
    "${U2U[@]}" 23492 alice alicepw "" > u2u-ad-termsrv.out 2>&1 || true
fi
touch "$FASTRDP_TEST_KDC_SPN_AS"
"${U2U[@]}" 23492 alice alicepw "" > u2u-mit.out 2>&1 || true
rm -f "$FASTRDP_TEST_KDC_SPN_AS"
sleep 1

fail=0
check() { # description python-expression over logins (proxy p) and glogins (proxy g)
    if python3 - "$2" <<'PY'
import json, os, sys
load = lambda f: [r for r in (json.loads(l) for l in open(f)) if r["op"] == "login"] if os.path.exists(f) else []
logins, glogins, ulogins, tlogins = load("b.log"), load("g.log"), load("u.log"), load("t.log")
sys.exit(0 if eval(sys.argv[1]) else 1)
PY
    then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
logged() { # description file fixed-string
    if grep -qF -- "$3" "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
holds() { # description command...
    local d=$1; shift
    if "$@"; then echo "ok   $d"; else echo "FAIL $d"; fail=1; fi
}
check "two logins reached the broker (wrong password and NTLM stopped at NLA)" 'len(logins) == 2'
check "method is nla with the Kerberos principal"   'all(r["method"] == "nla" and r["principal"] == "alice@TEST.FASTRDP" for r in logins)'
check "CredSSP user and delegated password passed" 'logins[0]["user"] == "alice" and logins[0]["password"] == "alicepw" and logins[0]["remote_guard"] is False'
# R5: NTLM is not offered
logged "NTLM: proxy logged the attempt and the Kerberos hint" proxy.log \
    "attempted NTLM (offered: NTLM); only Kerberos NLA is accepted: check that the client can reach the KDC"
logged "NTLM: the client failed in NLA" ntlm.out "freerdp_connect=0"
holds "NTLM: Kerberos clients offering NTLM too are not reported" [ "$(grep -c "attempted NTLM" proxy.log)" = 1 ]
holds "NTLM: the acceptor never ran NTLM (no SAM lookup)" \
    [ "$(grep -cE "SAM database|ntlm_fetch_ntlm_v2_hash" proxy.log)" = 0 ]
holds "NTLM: refused quickly ($(cat ntlm.ms) ms)" [ "$(cat ntlm.ms)" -lt 5000 ]
# R4: Remote Credential Guard required, not offered
logged "RCG not offered: the client got a negotiation response without RCG support" rcg-refused.out \
    "remote credential guard requested but not supported"
logged "RCG not offered: proxy answered instead of dropping the connection" proxy.log \
    "REDIRECTED_AUTHENTICATION_MODE_REQUIRED but disabled, answering without"
check "RCG not offered: no login reached the broker" 'len(logins) == 2'
# AcceptRemoteGuard=true: identity only
check "RCG accepted: one login with the Kerberos principal, flagged remote_guard" \
    'len(rg := [r for r in glogins if r["remote_guard"]]) == 1 and rg[0]["method"] == "nla" and rg[0]["principal"] == "alice@TEST.FASTRDP"'
check "RCG accepted: no password and no smartcard flag reach the broker" \
    'all(r["password"] is None and r["smartcard"] is False for r in glogins if r["remote_guard"])'
logged "RCG accepted: proxy logged identity only, credentials discarded" proxy-g.log \
    "Remote Credential Guard: identity only, forwarded Kerberos credentials discarded"
logged "RCG accepted: the client reached the broker's refusal (Set Error Info 0x7)" rcg.out "errinfo=0x00000007"
check "AcceptRemoteGuard=true: password NLA login unchanged" \
    'len(pw := [r for r in glogins if not r["remote_guard"]]) == 1 and pw[0]["password"] == "alicepw"'
# Kerberos user-to-user (patches/freerdp/0004)
if [ $AD = 1 ]; then
    logged "U2U, AD: the KDC refuses TERMSRV/localhost as an AS client" kdc.log "SPN_AS_CLIENT"
    check "U2U, AD: a user-to-user-only client logs in (machine account keys in the keytab)" \
        'len(ulogins) == 1 and ulogins[0]["method"] == "nla" and ulogins[0]["principal"] == "alice@TEST.FASTRDP" and ulogins[0]["password"] == "alicepw"'
    logged "U2U, AD: the proxy answered with the TGT of FASTRDP\$" kdc.log \
        'FASTRDP$@TEST.FASTRDP for krbtgt/TEST.FASTRDP@TEST.FASTRDP'
    logged "U2U, AD: the module logged the client's user-to-user request" proxy-u.log \
        "requested Kerberos user-to-user (KERB-TGT-REQUEST)"
    logged "U2U, AD, TERMSRV keys only: refused, WinPR names the missing keys" proxy-t.log \
        "Kerberos user-to-user: no TGT for TERMSRV/localhost@TEST.FASTRDP: the keytab needs the keys of the account"
else
    echo "skip U2U, AD layout: kadmin has no add_alias (MIT krb5 < 1.22)"
fi
check "U2U, MIT/FreeIPA (TERMSRV/localhost may get a TGT): login with the TERMSRV keys alone" \
    'len(tlogins) == 1 and tlogins[0]["principal"] == "alice@TEST.FASTRDP"'
if [ $fail -ne 0 ]; then
    for f in proxy.log proxy-g.log proxy-u.log proxy-t.log; do
        echo "--- $f:"; grep -E "fastrdp|nla|NLA|krb|Kerberos|ERROR|REDIRECTED" "$f" | tail -25
    done
    echo "--- client (RCG, proxy p):"; tail -5 rcg-refused.out
    echo "--- client (RCG, proxy g):"; tail -5 rcg.out
    echo "--- kinit:"; cat kinit.out
    echo "--- client (U2U):"; tail -3 u2u-*.out
    echo "--- kdc:"; grep -E "AS_REQ|TGS_REQ" kdc.log | grep -vE "alice@TEST.FASTRDP for krbtgt" | tail -12
fi
exit $fail
