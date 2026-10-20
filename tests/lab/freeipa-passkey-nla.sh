#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# shellcheck disable=SC2015  # ok() and bad() always succeed: A && ok || bad is if-then-else here
#
# LAB ONLY (needs a FreeIPA realm, an enrolled Linux client, a FIDO2 security key and a
# deployed fastrdp host; cannot run in CI). Runbook: docs/passkeys.md, "Stage 2 lab".
#
# FreeIPA passkey -> Kerberos TGT -> fastrdp NLA, with the KDC enforcing passkey/PKINIT
# for TERMSRV/<host> and the broker skipping privacyIDEA ([mfa] nla_kdc_enforced):
#   1. (--setup, as an IPA admin) passkey for the test user, auth indicators on TERMSRV;
#   2. a PASSWORD TGT must NOT get a TERMSRV ticket (KDC policy);
#   3. a PASSKEY TGT (kinit -n armor + kinit -T, PIN + touch) must get one;
#   4. xfreerdp3 /sec:nla with that TGT reaches a desktop, no password typed;
#   5. the broker log shows the login with "second factor skipped" (via ssh, optional).
#
# Usage (on the enrolled client, as a normal user):
#   tests/lab/freeipa-passkey-nla.sh [--setup] USER FASTRDP_FQDN
# Environment:
#   REALM        Kerberos realm (default: default_realm from krb5.conf)
#   XFREERDP     client binary (default: xfreerdp3, else /opt/fastrdp/bin/xfreerdp)
#   SSH_TARGET   e.g. admin@rdp1.ipa.test: read the broker log there with sudo journalctl
#   RDP_SECONDS  how long the RDP session stays up before it is closed (default 20)
#   PASSWORD_TGT=0  skip step 2 (user has passkey-only auth type)
#
# Client requirements (Fedora/RHEL 9.4+ or Debian/Ubuntu with sssd >= 2.9): sssd with
# passkey support (sssd-passkey / sssd-krb5 passkey pre-auth plugin), libfido2, krb5
# workstation tools, FreeRDP 3. The client must be an IPA client (FAST armor via kinit -n
# needs anonymous PKINIT enabled on the IPA server: ipa-pkinit-manage enable).
set -uo pipefail

setup=0
if [ "${1:-}" = --setup ]; then setup=1; shift; fi
user=${1:?usage: freeipa-passkey-nla.sh [--setup] USER FASTRDP_FQDN}
host=${2:?usage: freeipa-passkey-nla.sh [--setup] USER FASTRDP_FQDN}
realm=${REALM:-$(awk -F= '/^[[:space:]]*default_realm/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/krb5.conf)}
[ -n "$realm" ] || { echo "set REALM"; exit 2; }
xfreerdp=${XFREERDP:-$(command -v xfreerdp3 || echo /opt/fastrdp/bin/xfreerdp)}
service="TERMSRV/$host@$realm"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
armor="FILE:$work/armor"
pass=0 failed=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; failed=$((failed + 1)); }
step() { echo; echo "== $1"; }
for tool in kinit klist kvno; do
    command -v "$tool" >/dev/null || { echo "missing $tool (krb5 workstation tools)"; exit 2; }
done

if [ "$setup" = 1 ]; then
    step "1. setup (IPA admin ticket required: kinit admin)"
    command -v ipa >/dev/null || { echo "missing ipa CLI"; exit 2; }
    # password stays allowed for the user so step 2 can show the KDC refusing it
    ipa user-mod "$user" --user-auth-type=passkey --user-auth-type=password || true
    echo "Touch the security key (and enter its PIN) to register a passkey for $user:"
    ipa user-add-passkey "$user" --register || { bad "passkey registration"; exit 1; }
    ipa service-mod "TERMSRV/$host" --auth-ind=passkey --auth-ind=pkinit || true
    ipa service-show "TERMSRV/$host" --all | grep -i 'authentication indicators' \
        && ok "TERMSRV/$host has authentication indicators" || bad "TERMSRV/$host auth indicators"
fi

step "2. a password TGT must not get a TERMSRV ticket"
if [ "${PASSWORD_TGT:-1}" = 1 ]; then
    export KRB5CCNAME="FILE:$work/pw"
    kinit -n -c "$armor" "@$realm" || { bad "anonymous armor ticket (ipa-pkinit-manage enable?)"; exit 1; }
    echo "Password of $user (password only, no key):"
    if kinit -T "$armor" "$user@$realm"; then
        if kvno "$service" >"$work/kvno.pw" 2>&1; then
            bad "KDC issued $service to a password TGT (auth indicators missing?)"
        else
            grep -qiE 'policy|KDC_ERR_POLICY' "$work/kvno.pw" \
                && ok "KDC refuses $service to a password TGT ($(head -n 1 "$work/kvno.pw"))" \
                || bad "kvno failed for another reason: $(head -n 1 "$work/kvno.pw")"
        fi
    else
        bad "password kinit failed (user auth type without password? set PASSWORD_TGT=0)"
    fi
    kdestroy -q
else
    echo "skipped (PASSWORD_TGT=0)"
fi

step "3. passkey TGT (kinit -n armor, then PIN + touch)"
export KRB5CCNAME="FILE:$work/pk"
kinit -n -c "$armor" "@$realm" || { bad "anonymous armor ticket"; exit 1; }
echo "Insert the security key; enter its PIN and touch it when asked:"
if kinit -T "$armor" "$user@$realm"; then
    ok "passkey TGT for $user@$realm"
    klist
else
    bad "passkey kinit failed"; exit 1
fi
if kvno "$service" >"$work/kvno.pk" 2>&1; then
    ok "KDC issues $service to the passkey TGT"
else
    bad "no $service ticket for the passkey TGT: $(head -n 1 "$work/kvno.pk")"
fi

step "4. xfreerdp3 /sec:nla with the passkey TGT (no password)"
since=$(date '+%Y-%m-%d %H:%M:%S')
# Empty /p: use the ticket in KRB5CCNAME instead of asking for a password; Kerberos only
# (docs/freerdp-client.md, sections 2 and 4). KRB5CCNAME is a single FILE cache here, so
# no kswitch is needed (with a KCM collection: kswitch -p "$user@$realm" first).
timeout "${RDP_SECONDS:-20}" "$xfreerdp" "/v:$host" "/u:$user" "/d:$realm" /p /sec:nla \
    "/auth-pkg-list:kerberos,!ntlm" /cert:tofu >"$work/rdp.log" 2>&1
rc=$?
if [ "$rc" = 124 ]; then
    ok "RDP session stayed up ${RDP_SECONDS:-20}s (closed by the script)"
else
    bad "xfreerdp exited with $rc: $(grep -m 3 -E 'ERROR|error' "$work/rdp.log" | tr '\n' ' ')"
fi
klist | grep -qi "TERMSRV/$host" && ok "client holds the TERMSRV ticket it presented" || bad "no TERMSRV ticket in the cache"

step "5. broker log"
pattern="$user: Kerberos NLA login (principal $user@$realm); second factor skipped"
if [ -n "${SSH_TARGET:-}" ]; then
    if ssh "$SSH_TARGET" sudo journalctl -u fastrdp-brokerd --since "\"$since\"" --no-pager >"$work/broker.log"; then
        grep -qF "$pattern" "$work/broker.log" && ok "broker: NLA login, privacyIDEA skipped (nla_kdc_enforced)" \
            || bad "broker log lacks: $pattern"
        grep -qE "login $user session=.* desktop=" "$work/broker.log" && ok "broker: session started for $user" \
            || bad "broker log has no session for $user"
        grep -q "push challenge sent to $user" "$work/broker.log" && bad "broker sent a push anyway" || true
    else
        bad "could not read the broker log via ssh $SSH_TARGET"
    fi
else
    echo "On $host run: sudo journalctl -u fastrdp-brokerd --since \"$since\" | grep -F \"$pattern\""
fi

echo
echo "freeipa-passkey-nla.sh: $pass passed, $failed failed"
[ "$failed" -eq 0 ]
