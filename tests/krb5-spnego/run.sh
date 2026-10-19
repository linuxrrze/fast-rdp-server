#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Is this host's MIT krb5 affected by the SPNEGO mechListMIC regression (krb5 #9183)?
#   throwaway MIT KDC -> WinPR (FreeRDP) SPNEGO initiator -> MIT gss_accept_sec_context
# Runs the exchange twice: FreeRDP defaults (Kerberos U2U offered first, MIC exchange
# needed) and /auth-pkg-list:'kerberos,!u2u,!ntlm' (no MIC exchange).
#
# Exit 0: MIT acceptor fine. Exit 1: affected (defaults fail, !u2u works). Other: setup
# or unexpected failure.
# WinPR before "u2u" became a package name (Debian 13: 3.15) offers U2U first in both
# runs; then "affected" means: Kerberos completed, only the MIC token was rejected.
#
# Needs libwinpr3-dev (FreeRDP 3), libkrb5-dev, krb5-kdc, krb5-admin-server, or
# SYSROOT / KRB5_SYSROOT with them extracted. WINPR_LIBDIR / MIT_LIBDIR test other
# builds of libwinpr3 / libgssapi_krb5 (e.g. MIT 1.22.2) for the initiator+acceptor.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SYSROOT=${SYSROOT:-}
KRB5_SYSROOT=${KRB5_SYSROOT:-}
MA=$(gcc -print-multiarch)
LIBDIR=$SYSROOT/usr/lib/$MA
KB=$KRB5_SYSROOT/usr/sbin
W=$(mktemp -d /tmp/fastrdp-spnego.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT

gcc -std=c11 -D_GNU_SOURCE -Wno-deprecated-declarations -I"$SYSROOT/usr/include/winpr3" \
    -I"$SYSROOT/usr/include" "$HERE/spnego_mic.c" -o "$W/spnego_mic" \
    -L"$LIBDIR" "-Wl,-rpath-link,$LIBDIR" -lwinpr3 -lgssapi_krb5
export LD_LIBRARY_PATH="${KRB5_SYSROOT:+$KRB5_SYSROOT/usr/lib/$MA:}$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$W"

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
        kdc = 127.0.0.1:28891
    }
[domain_realm]
    localhost = TEST.FASTRDP
EOT
cat > kdc.conf <<EOT
[kdcdefaults]
    kdc_tcp_listen = 28891
    kdc_listen = 28891
[realms]
    TEST.FASTRDP = {
        database_name = $W/principal
        key_stash_file = $W/stash
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
[logging]
    kdc = FILE:$W/kdc.log
EOT
[ -n "$KRB5_SYSROOT" ] && printf '[dbmodules]\n    db_module_dir = %s\n' "$KRB5_SYSROOT/usr/lib/$MA/krb5/plugins/kdb" >> kdc.conf
export KRB5_CONFIG=$W/krb5.conf KRB5_KDC_PROFILE=$W/kdc.conf KRB5CCNAME=MEMORY:spnego
"$KB/kdb5_util" create -s -r TEST.FASTRDP -P masterpw >/dev/null 2>&1
for q in "addprinc -pw alicepw alice" "addprinc -randkey TERMSRV/localhost" \
         "ktadd -k $W/termsrv.keytab TERMSRV/localhost"; do
    "$KB/kadmin.local" -r TEST.FASTRDP -q "$q" >/dev/null 2>&1
done
"$KB/krb5kdc" -n > kdc.out 2>&1 &
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/28891) 2>/dev/null && break; sleep 0.1; done

run() {
    LD_LIBRARY_PATH="${MIT_LIBDIR:+$MIT_LIBDIR:}${WINPR_LIBDIR:+$WINPR_LIBDIR:}$LD_LIBRARY_PATH" \
        KRB5_KTNAME=FILE:$W/termsrv.keytab \
        ./spnego_mic alice alicepw TEST.FASTRDP TERMSRV/localhost "$1" > "out.$2" 2>&1
}
rc_default=0; run "" default || rc_default=$?
rc_nou2u=0; run 'kerberos,!u2u,!ntlm' nou2u || rc_nou2u=$?
echo "FreeRDP defaults (U2U first, mechListMIC exchange): $(tail -1 out.default)"
echo "auth-pkg-list kerberos,!u2u,!ntlm (no MIC exchange): $(tail -1 out.nou2u)"
if [ $rc_default -eq 0 ] && [ $rc_nou2u -eq 0 ]; then
    echo "ok   MIT acceptor handles the initiator mechListMIC"
    exit 0
fi
# The acceptor rejected the round 3 token (only the mechListMIC, after the AP exchange)
# as GSS_S_DEFECTIVE_TOKEN
mic_rejected() {
    awk '/^round /{r=$2} /MIT acceptor: major/{m=$4; mr=r}
         END{exit !(mr == "3:" && m == "0x90000")}' "$1"
}
affected() {
    echo "AFFECTED: MIT krb5 ignores the initiator's mechListMIC (krb5 #9183, fixed in 1.22.2)"
    grep -A3 "^round 3" out.default | sed 's/^/    /'
    exit 1
}
if [ $rc_default -eq 6 ] && [ $rc_nou2u -eq 0 ]; then
    affected
fi
if [ $rc_default -eq 6 ] && [ $rc_nou2u -eq 6 ] &&
   grep -q 'Unknown authentication package name: u2u' out.nou2u &&
   mic_rejected out.default && mic_rejected out.nou2u; then
    echo "note: this WinPR cannot exclude U2U, so there is no run without the MIC exchange"
    affected
fi
echo "unexpected result"; cat out.default out.nou2u
exit 2
