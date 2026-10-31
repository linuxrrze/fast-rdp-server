#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Smoke checks on a deployed fastrdp host (run as root). Prints ok/FAIL per check.
# Packaged as fastrdp-check-host (fastrdp-broker).
#   sudo tests/smoke/check-host.sh [test-user]
#   sudo tests/smoke/check-host.sh --preflight   before the setup: name, DNS, time, ports
#   tests/smoke/check-host.sh --ports      print the ports read from the configuration
# With a test user, also checks NSS/group resolution and the TGT in the user's default
# cache (fastrdpctl tickets: renewable), and asks the broker for status.
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
CTL=$(command -v /usr/local/sbin/fastrdpctl /usr/sbin/fastrdpctl | head -1)
fail=0
ok()   { echo "ok   $*"; }
bad()  { echo "FAIL $*"; fail=1; }
warn() { echo "warn $*"; }
chk()  { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

# --preflight: what docs/manual-setup.md section 1 (and make preflight) checks before
# the setup. Read-only; FAIL = fix before going on, warn = check by hand.
if [ "${1:-}" = --preflight ]; then
    OS_RELEASE=${FASTRDP_OS_RELEASE:-/etc/os-release}
    os_value() { sed -n "s/^$1=//p" "$OS_RELEASE" 2>/dev/null | tr -d '"' | head -1; }
    os_id=$(os_value ID) os_ver=$(os_value VERSION_ID)
    case $os_id:$(printf '%s\n' "$os_ver" 26.04 | sort -V | head -1):${os_ver%%.*} in
        ubuntu:26.04:*) ok "Ubuntu $os_ver (26.04 or later)" ;;
        debian:*:1[3-9]|debian:*:[2-9][0-9]) ok "Debian $os_ver (13 or later)" ;;
        *) bad "supported OS (Ubuntu 26.04 or Debian 13 and later), not '${os_id:-unknown} $os_ver'" ;;
    esac
    fqdn=$(hostname -f 2>/dev/null || true)
    short=${fqdn%%.*}
    domain=${fqdn#*.}
    if [ "$fqdn" = "$short" ]; then
        bad "host name is a FQDN (hostname -f: '$fqdn'; hostnamectl set-hostname rdp1.example.com)"
    else
        ok "host name is a FQDN ($fqdn)"
        if [ "${#short}" -le 15 ]; then
            ok "short name $short has at most 15 characters (AD computer account)"
        else
            warn "short name $short has more than 15 characters: AD truncates the computer account"
        fi
        addrs=$(getent ahosts "$fqdn" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
        if [ -z "$addrs" ]; then
            bad "$fqdn resolves (getent ahosts)"
        elif grep -Eq '(^| )(127\.|::1)' <<<" $addrs"; then
            bad "$fqdn resolves to the real address, not loopback ($addrs; remove '127.0.1.1 $fqdn' from /etc/hosts)"
        else
            ok "$fqdn resolves to $addrs"
        fi
        if command -v dig >/dev/null 2>&1; then
            for srv in _kerberos._tcp _ldap._tcp; do
                if [ -n "$(dig +short SRV "$srv.$domain" 2>/dev/null)" ]; then
                    ok "DNS SRV $srv.$domain"
                else
                    warn "no DNS SRV $srv.$domain: krb5.conf finds the KDCs through DNS only (FreeIPA/AD DNS as resolver)"
                fi
            done
        else
            warn "dig missing (apt install bind9-dnsutils): DNS SRV records of $domain not checked"
        fi
    fi
    if command -v chronyc >/dev/null 2>&1; then
        chk "time in sync (chronyc tracking: Leap status Normal)" bash -c "chronyc tracking | grep -q 'Leap status *: Normal'"
    else
        bad "chrony installed (Kerberos needs the time within 5 minutes)"
    fi
    for port in "$PROXY_PORT" "$XRDP_PORT"; do
        who=$(ss -Hltnp "sport = :$port" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -1 | sed 's/.*"//')
        case $who in
            "") ok "port $port free" ;;
            freerdp-proxy|xrdp) ok "port $port used by fastrdp ($who)" ;;
            *) bad "port $port free (used by $who: a distribution xrdp or gnome-remote-desktop?)" ;;
        esac
    done
    if dpkg-query -W -f='${Status}' fastrdp-server 2>/dev/null | grep -q 'ok installed'; then
        ok "fastrdp-server installed"
        chk "nftables fastrdp table loaded (fastrdp-firewall.service)" nft list table inet fastrdp
    else
        warn "fastrdp-server not installed (apt install fastrdp-server, docs/manual-setup.md 2)"
    fi
    if command -v fastrdp-defaults >/dev/null 2>&1; then
        echo "--- fastrdp default configuration (fastrdp-defaults status)"
        fastrdp-defaults status 2>/dev/null || true
    fi
    exit $fail
fi

USER_TO_TEST=${1:-}

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
# Ticket renewal for long sessions (docs/nfs-kerberos-homes.md, Q4): sssd-kcm renews
# renewable TGTs in KCM ([kcm] tgt_renewal, krb5_renew_interval; roles/identity
# fastrdp_kcm_tgt_renewal), and kinit asks for renewable tickets (renew_lifetime).
# sssd_value SECTION KEY: effective value, sssd.conf then conf.d/*.conf (later files win)
sssd_value() {
    awk -v s="[$1]" -v k="$2" '
        FNR == 1 { in_s = 0 }
        /^[ \t]*\[/ { t = $0; gsub(/[ \t]/, "", t); in_s = (t == s); next }
        in_s && /^[ \t]*[^#; \t]/ {
            key = $0; sub(/=.*/, "", key); gsub(/[ \t]/, "", key)
            if (key == k && index($0, "=")) { v = substr($0, index($0, "=") + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); val = v }
        }
        END { print val }' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 2>/dev/null
}
chk "sssd-kcm socket/service active"   bash -c "systemctl is-active --quiet sssd-kcm.socket || systemctl is-active --quiet sssd-kcm.service"
KCM_RENEWAL=$(sssd_value kcm tgt_renewal)
KCM_INTERVAL=$(sssd_value kcm krb5_renew_interval)
if [ "${KCM_RENEWAL,,}" = true ] && [ -n "$KCM_INTERVAL" ] && [ "$KCM_INTERVAL" != 0 ]; then
    ok "sssd-kcm renews TGTs ([kcm] tgt_renewal = true, krb5_renew_interval = $KCM_INTERVAL)"
else
    bad "sssd-kcm TGT renewal off ([kcm] tgt_renewal = ${KCM_RENEWAL:-unset}, krb5_renew_interval = ${KCM_INTERVAL:-unset}): fastrdp_kcm_tgt_renewal, /etc/sssd/conf.d/50-fastrdp.conf"
fi
RENEW_LIFETIME=$(grep -Ehs '^[[:space:]]*renew_lifetime[[:space:]]*=' /etc/krb5.conf.d/fastrdp /etc/krb5.conf | head -1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//')
if [ -n "$RENEW_LIFETIME" ] && [ "$RENEW_LIFETIME" != 0 ]; then
    ok "krb5.conf asks for renewable tickets (renew_lifetime = $RENEW_LIFETIME)"
else
    bad "krb5.conf has no renew_lifetime: kinit gets non-renewable TGTs (/etc/krb5.conf.d/fastrdp)"
fi
if [ -e /etc/ipa/default.conf ]; then
    chk "FreeIPA krb5.conf (PKINIT anchors of the IPA CA)" grep -q /var/lib/ipa-client/pki/ /etc/krb5.conf
fi
chk "fastrdp proxy module installed"  test -f /opt/fastrdp/lib/freerdp3/proxy/libproxy-fastrdp-plugin.so
chk "proxy uses fastrdp's FreeRDP"     bash -c "ldd /opt/fastrdp/bin/freerdp-proxy | grep -q '/opt/fastrdp/.*libfreerdp3.so' && ! ldd /opt/fastrdp/bin/freerdp-proxy | grep -q 'not found'"
chk "pam_fastrdp_token installed"     bash -c "ls /usr/lib/*/security/pam_fastrdp_token.so"
# build install method: /usr/local; apt (fastrdp-xrdp package): /usr
XRDP_BIN=$(command -v /usr/local/sbin/xrdp /usr/sbin/xrdp | head -1)
chk "xrdp built with x264"            bash -c "${XRDP_BIN:-xrdp} -v | grep -q -- --enable-x264"
# xrdp drops to runtime_group and reaches Xorg in /run/xrdp/<uid> only through the group
# sesman gives that directory (SessionSockdirGroup; unset = root): field report 2026-10-24
RUNTIME_GROUP=$(ini_value /etc/xrdp/xrdp.ini Globals runtime_group)
SOCKDIR_GROUP=$(ini_value /etc/xrdp/sesman.ini Security SessionSockdirGroup)
chk "xrdp can reach its sessions (sesman.ini SessionSockdirGroup = xrdp.ini runtime_group '${RUNTIME_GROUP:-unset}')" \
    test "${RUNTIME_GROUP:-}" = "${SOCKDIR_GROUP:-}"
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
    # The broker runs klist as the user, without KRB5CCNAME: the cache the session uses.
    tgt=$("${CTL:-fastrdpctl}" tickets --json "$USER_TO_TEST" 2>/dev/null | python3 -c '
import json, sys
try:
    t = next(iter(json.load(sys.stdin)["tickets"].values()))
except Exception:
    t = {"state": "unknown", "error": "fastrdpctl tickets failed"}
print(t.get("state"), str(t.get("renewable", False)).lower(), t.get("renew_until", "-"), t.get("error", ""))')
    read -r tgt_state tgt_renewable tgt_until tgt_error <<<"$tgt"
    case $tgt_state in
        ok) ok "TGT of $USER_TO_TEST renewable until $tgt_until (sssd-kcm renews it)" ;;
        none) echo "skip TGT of $USER_TO_TEST: none in the default cache (log in over RDP with a password first)" ;;
        *) bad "TGT of $USER_TO_TEST: $tgt_state (renewable=$tgt_renewable, renew until $tgt_until) $tgt_error" ;;
    esac
fi
if command -v fastrdp-defaults >/dev/null 2>&1; then
    echo "--- fastrdp default configuration (fastrdp-defaults status)"
    fastrdp-defaults status 2>/dev/null || true
fi
echo "--- broker status"; "${CTL:-fastrdpctl}" status 2>/dev/null | head -40 || true
exit $fail
