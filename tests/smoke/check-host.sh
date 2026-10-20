#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Smoke checks on a deployed fastrdp host (run as root). Prints ok/FAIL per check.
#   sudo tests/smoke/check-host.sh [test-user]
#   tests/smoke/check-host.sh --ports      print the ports read from the configuration
# With a test user, also checks NSS/group resolution and asks the broker for status.
# Ports come from the deployed configuration (fastrdp_listen_port, fastrdp_xrdp_port).
set -uo pipefail
PROXY_INI=${FASTRDP_PROXY_INI:-/etc/fastrdp/proxy.ini}
BROKER_TOML=${FASTRDP_BROKER_TOML:-/etc/fastrdp/broker.toml}

# ini_value FILE SECTION KEY / toml_value FILE TABLE KEY (flat files written by the roles)
ini_value() {
    awk -F= -v s="[$2]" -v k="$3" '
        /^\[/ { in_s = ($0 == s); next }
        in_s && $1 ~ "^[ \t]*" k "[ \t]*$" { v = $2; gsub(/[ \t]/, "", v); print v; exit }' "$1" 2>/dev/null
}
toml_value() {
    awk -F= -v s="[$2]" -v k="$3" '
        /^\[/ { in_s = ($0 == s); next }
        in_s && $1 ~ "^[ \t]*" k "[ \t]*$" { v = $2; sub(/#.*/, "", v); gsub(/[ \t"]/, "", v); print v; exit }' "$1" 2>/dev/null
}
PROXY_PORT=$(ini_value "$PROXY_INI" Server Port)
XRDP_PORT=$(toml_value "$BROKER_TOML" backends.xrdp port)
PROXY_PORT=${PROXY_PORT:-3389}
XRDP_PORT=${XRDP_PORT:-3390}
if [ "${1:-}" = --ports ]; then
    echo "proxy=$PROXY_PORT xrdp=$XRDP_PORT"
    exit 0
fi
USER_TO_TEST=${1:-}
fail=0
ok()   { echo "ok   $*"; }
bad()  { echo "FAIL $*"; fail=1; }
chk()  { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

for u in fastrdp-brokerd fastrdp-proxy xrdp-sesman xrdp sssd; do
    chk "service $u active" systemctl is-active --quiet "$u"
done
chk "proxy listens on :$PROXY_PORT"    bash -c "ss -Hltn 'sport = :$PROXY_PORT' | grep -q ."
chk "xrdp listens on loopback only (:$XRDP_PORT)" \
    bash -c "ss -Hltn 'sport = :$XRDP_PORT' | grep -q '127.0.0.1:$XRDP_PORT' && ! ss -Hltn 'sport = :$XRDP_PORT' | grep -qv '127.0.0.1'"
chk "broker socket present"           test -S /run/fastrdp/broker.sock
chk "token socket root-only"          bash -c "[ \"\$(stat -c %a /run/fastrdp/token.sock)\" = 600 ]"
chk "nftables fastrdp table loaded"   nft list table inet fastrdp
chk "TERMSRV keys in proxy keytab"    bash -c "klist -k /etc/fastrdp/termsrv.keytab | grep -q TERMSRV/"
# NLA needs AES keys (RC4 tickets fail) at the newest kvno for the FQDN and the short
# name (identity role). FreeIPA's short-name alias shares the FQDN principal's keys.
TERMSRV_SPNS="TERMSRV/$(hostname -f)"
[ -e /etc/ipa/default.conf ] || TERMSRV_SPNS="$TERMSRV_SPNS TERMSRV/$(hostname -s | tr '[:lower:]' '[:upper:]')"
# apt (fastrdp-broker package): /usr/sbin; build install method: /usr/local/sbin
TERMSRV_CHECK=$(command -v /usr/sbin/fastrdp-termsrv-check /usr/local/sbin/fastrdp-termsrv-check | head -1)
# shellcheck disable=SC2086 # word splitting intended
chk "AES keys for $TERMSRV_SPNS (fastrdp-termsrv-check)" ${TERMSRV_CHECK:-fastrdp-termsrv-check} $TERMSRV_SPNS
chk "proxy can read its keytab"       runuser -u _fastrdp-proxy -- test -r /etc/fastrdp/termsrv.keytab
# fastrdp's Kerberos settings are a snippet; FreeIPA keeps the enrolment's krb5.conf.
chk "krb5.conf includes /etc/krb5.conf.d (fastrdp snippet)" \
    grep -Eq '^[[:space:]]*includedir[[:space:]]+/etc/krb5\.conf\.d/?[[:space:]]*$' /etc/krb5.conf
chk "fastrdp Kerberos snippet: KCM ccache" grep -Eq '^[[:space:]]*default_ccache_name[[:space:]]*=[[:space:]]*KCM:' /etc/krb5.conf.d/fastrdp
if [ -e /etc/ipa/default.conf ]; then
    chk "FreeIPA krb5.conf (PKINIT anchors of the IPA CA)" grep -q /var/lib/ipa-client/pki/ /etc/krb5.conf
fi
chk "fastrdp proxy module installed"  test -f /opt/fastrdp/lib/freerdp3/proxy/libproxy-fastrdp-plugin.so
chk "proxy uses fastrdp's FreeRDP"     bash -c "ldd /opt/fastrdp/bin/freerdp-proxy | grep -q '/opt/fastrdp/.*libfreerdp3.so' && ! ldd /opt/fastrdp/bin/freerdp-proxy | grep -q 'not found'"
chk "pam_fastrdp_token installed"     bash -c "ls /usr/lib/*/security/pam_fastrdp_token.so"
# build install method: /usr/local; apt (fastrdp-xrdp package): /usr
XRDP_BIN=$(command -v /usr/local/sbin/xrdp /usr/sbin/xrdp | head -1)
chk "xrdp built with x264"            bash -c "${XRDP_BIN:-xrdp} -v | grep -q -- --enable-x264"
chk "broker config valid"             env PYTHONPATH=/usr/lib/fastrdp/python python3 -m fastrdp_broker --check
chk "time in sync (Kerberos)"         bash -c "chronyc tracking | grep -q 'Leap status *: Normal'"

# Local users must not reach back-end ports (nftables skuid rule).
if id nobody >/dev/null 2>&1; then
    if runuser -u nobody -- bash -c "exec 3<>/dev/tcp/127.0.0.1/$XRDP_PORT" 2>/dev/null; then
        bad "back-end port reachable by other local users"
    else
        ok "back-end port blocked for other local users"
    fi
fi

if [ -n "$USER_TO_TEST" ]; then
    chk "user $USER_TO_TEST resolvable (NSS/SSSD)" id "$USER_TO_TEST"
    chk "PAM account check for $USER_TO_TEST"      bash -c "python3 - <<PY
import sys; sys.path.insert(0, '/usr/lib/fastrdp/python')
from fastrdp_broker import pamauth
pamauth.account_ok('fastrdp', '$USER_TO_TEST')
PY"
fi
echo "--- broker status"; "$(command -v /usr/local/sbin/fastrdpctl /usr/sbin/fastrdpctl | head -1)" status 2>/dev/null | head -40 || true
exit $fail
