#!/bin/bash
# Smoke checks on a deployed fastrdp host (run as root). Prints ok/FAIL per check.
#   sudo tests/smoke/check-host.sh [test-user]
# With a test user, also checks NSS/group resolution and asks the broker for status.
set -uo pipefail
USER_TO_TEST=${1:-}
fail=0
ok()   { echo "ok   $*"; }
bad()  { echo "FAIL $*"; fail=1; }
chk()  { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

for u in fastrdp-brokerd fastrdp-proxy xrdp-sesman xrdp sssd; do
    chk "service $u active" systemctl is-active --quiet "$u"
done
chk "proxy listens on :3389"          bash -c "ss -Hltn 'sport = :3389' | grep -q ."
chk "xrdp listens on loopback only"   bash -c "ss -Hltn 'sport = :3390' | grep -q '127.0.0.1:3390' && ! ss -Hltn 'sport = :3390' | grep -qv '127.0.0.1'"
chk "broker socket present"           test -S /run/fastrdp/broker.sock
chk "token socket root-only"          bash -c "[ \"\$(stat -c %a /run/fastrdp/token.sock)\" = 600 ]"
chk "nftables fastrdp table loaded"   nft list table inet fastrdp
chk "TERMSRV keys in proxy keytab"    bash -c "klist -k /etc/fastrdp/termsrv.keytab | grep -q TERMSRV/"
chk "proxy can read its keytab"       runuser -u _fastrdp-proxy -- test -r /etc/fastrdp/termsrv.keytab
chk "fastrdp proxy module installed"  bash -c "ls /usr/lib/*/freerdp3/proxy/libproxy-fastrdp-plugin.so"
chk "pam_fastrdp_token installed"     bash -c "ls /usr/lib/*/security/pam_fastrdp_token.so"
chk "xrdp built with x264"            bash -c "/usr/local/sbin/xrdp -v | grep -q -- --enable-x264"
chk "broker config valid"             env PYTHONPATH=/usr/lib/fastrdp/python python3 -m fastrdp_broker --check
chk "time in sync (Kerberos)"         bash -c "chronyc tracking | grep -q 'Leap status *: Normal'"

# Local users must not reach back-end ports (nftables skuid rule).
if id nobody >/dev/null 2>&1; then
    if runuser -u nobody -- bash -c 'exec 3<>/dev/tcp/127.0.0.1/3390' 2>/dev/null; then
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
echo "--- broker status"; /usr/local/sbin/fastrdpctl status 2>/dev/null | head -40 || true
exit $fail
