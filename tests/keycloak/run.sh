#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# Passkeys on the web path, end to end and without root (docs/passkeys.md, recipe A):
#   1. Keycloak 26.x in dev mode (in-memory database) on 127.0.0.1:$KC_PORT;
#   2. the sample client docs/examples/keycloak-fastrdp-web-client.json imported as is and
#      read back (Keycloak keeps every field); a fixture realm (kc_fixture.py): client
#      fastrdp-web made from that sample, alice (password + TOTP), carol (password only),
#      an unrelated client profile/policy and ACR map entry;
#   3. the web_gateway role's Keycloak tasks (fastrdp_web_passkeys: true) through
#      ansible-playbook: check mode, apply, apply again (must not change anything),
#      merge checks, and a Cookie step injected into the flow is removed again;
#   4. e2e.py: headless Chromium with a CDP virtual authenticator against the real
#      fastrdp-webgate code (passkey, password + TOTP, password only, SSO pitfall,
#      hardware-only mode and the AAGUID list it leaves behind); the approval page
#      /web/approve with pending logins in the broker's WebApprovals (fresh sign-in despite
#      an SSO session, passkey, password + TOTP, password only, old auth_time, login-bound
#      link, Deny, a sign-in too old for the login); the account console before and with
#      fastrdp_keycloak_account_console_mfa;
#   5. the broker's code check ([mfa] mode code_or_web): the role sets up the direct grant
#      flow of the sample client fastrdp-otp-check, otp_check.py checks codes with
#      keycloak_otp.py (right, wrong, no OTP credential, other client, replay);
#   6. docs/examples/keycloak-mfa/fastrdp-mfa-kcadm.sh --otp-client (Method 2, kcadm.sh of
#      that Keycloak): finds the role's result unchanged, builds the code check again after
#      it was removed (the role's check mode then reports nothing), codes work, a hand-made
#      change stops it until --rebuild, an unsafe client is refused; an AAGUID list set by
#      hand survives it and the role; without --account-console it warns about the
#      enrolment gap, with it it sets the same override as the role.
#
# Manual (heavy: JDK + Keycloak + Chromium, ~2 min). Needs python3 >= 3.11,
# python3-cryptography, ansible-playbook, curl, and:
#   CHROME        Chromium/Chrome (or chrome-headless-shell) binary; default: the newest
#                 Playwright chromium_headless_shell under ~/.cache/ms-playwright
#   CHROME_LIBS   optional extra LD_LIBRARY_PATH for that binary (no system libraries)
#   FONTCONFIG_FILE  optional; Chromium aborts without any fontconfig configuration
#   KEYCLOAK_HOME, JAVA_HOME  existing installations; otherwise Keycloak $KC_VERSION and
#                 Temurin 21 are downloaded (sha256-checked) into $FASTRDP_KC_CACHE
#   KC_PORT (18080), GATE_PORT (18090), PROBE_PORT (18091)
#
#   make test-keycloak
set -uo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"

KC_VERSION=26.8.1
KC_SHA256=4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8
JDK_URL=https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz
JDK_SHA256=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
KC_PORT=${KC_PORT:-18080}
GATE_PORT=${GATE_PORT:-18090}
PROBE_PORT=${PROBE_PORT:-18091}
CACHE=${FASTRDP_KC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/fastrdp-keycloak-test}
ADMIN_PW=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
KC="http://localhost:$KC_PORT"
HERE=$REPO/tests/keycloak

skip_or_fail() {
    if [ "${FASTRDP_TESTS_STRICT:-0}" = 1 ]; then echo "FAIL tests/keycloak/run.sh: $1"; exit 1; fi
    echo "SKIP tests/keycloak/run.sh: $1"; exit 0
}
need curl python3 ansible-playbook setsid
python3 -c 'import cryptography' 2>/dev/null || skip_or_fail "missing python3-cryptography"

if [ -z "${CHROME:-}" ]; then
    CHROME=$(find "$HOME/.cache/ms-playwright" -path '*/chrome-headless-shell-linux64/chrome-headless-shell' 2>/dev/null \
        | sort -V | tail -n 1)
fi
[ -n "${CHROME:-}" ] && [ -x "$CHROME" ] || skip_or_fail "no Chromium (set CHROME)"

fetch() {   # fetch URL SHA256 DEST-DIR: download once, verify, unpack into DEST-DIR
    local url=$1 sum=$2 dest=$3 tgz
    tgz=$CACHE/$(basename "$dest").tar.gz
    [ -d "$dest" ] && return 0
    mkdir -p "$CACHE"
    [ -f "$tgz" ] || curl -fsSL -m 900 -o "$tgz" "$url" || return 1
    echo "$sum  $tgz" | sha256sum -c --quiet || { rm -f "$tgz"; return 1; }
    mkdir -p "$dest" && tar -xzf "$tgz" -C "$dest" --strip-components=1
}
if [ -z "${KEYCLOAK_HOME:-}" ]; then
    KEYCLOAK_HOME=$CACHE/keycloak-$KC_VERSION
    fetch "https://github.com/keycloak/keycloak/releases/download/$KC_VERSION/keycloak-$KC_VERSION.tar.gz" \
        "$KC_SHA256" "$KEYCLOAK_HOME" || skip_or_fail "Keycloak download failed"
fi
if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME=$CACHE/temurin-21
    fetch "$JDK_URL" "$JDK_SHA256" "$JAVA_HOME" || skip_or_fail "JDK download failed"
fi
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"

# ------------------------------------------------------------------ Keycloak
KC_LOG=$T/keycloak.log
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PW \
    setsid "$KEYCLOAK_HOME/bin/kc.sh" start-dev --db=dev-mem --http-host=127.0.0.1 \
    --http-port="$KC_PORT" --http-management-port=$((KC_PORT + 920)) >"$KC_LOG" 2>&1 &
KC_PID=$!
stop_keycloak() {
    kill -TERM -- "-$KC_PID" 2>/dev/null
    for _ in $(seq 1 30); do kill -0 "$KC_PID" 2>/dev/null || break; sleep 1; done
    kill -KILL -- "-$KC_PID" 2>/dev/null
    rm -rf "$T"
}
trap stop_keycloak EXIT
for _ in $(seq 1 120); do
    curl -fs -o /dev/null "$KC/realms/master/.well-known/openid-configuration" && break
    kill -0 "$KC_PID" 2>/dev/null || break
    sleep 1
done
if curl -fs -o /dev/null "$KC/realms/master/.well-known/openid-configuration"; then
    ok "Keycloak $KC_VERSION started (dev mode, in-memory database)"
else
    T_OUT=$KC_LOG fail "Keycloak did not start"
    finish
fi

check "sample client docs/examples/keycloak-fastrdp-web-client.json stored as given" \
    python3 "$HERE/kc_fixture.py" check-sample "$KC" admin "$ADMIN_PW"
check "fixture realm created" python3 "$HERE/kc_fixture.py" setup "$KC" "http://localhost:$GATE_PORT" \
    "http://localhost:$PROBE_PORT/cb" admin "$ADMIN_PW"

# ------------------------------------------------------------------ the role
vars() {   # vars HARDWARE_ONLY -> extra-vars file for apply.yml
    cat >"$T/vars.json" <<EOF
{"fastrdp_web_passkeys": true,
 "fastrdp_web_oidc_issuer": "$KC/realms/fastrdp-test",
 "fastrdp_web_oidc_client_id": "fastrdp-web",
 "fastrdp_keycloak_admin_user": "admin",
 "fastrdp_keycloak_admin_password": "$ADMIN_PW",
 "fastrdp_web_passkeys_hardware_only": $1,
 "fastrdp_web_passkeys_aaguids": ["cb69481e-8ff7-4039-93ec-0a2729a154a8", "ee882879-721c-4913-9775-3dfcce97072a"]}
EOF
}
apply() {   # apply [--check]: run the role's Keycloak tasks, print the changed= count
    (cd "$REPO/ansible" && ANSIBLE_CONFIG=$REPO/ansible/ansible.cfg ansible-playbook -i localhost, -c local \
        "$HERE/apply.yml" -e "@$T/vars.json" "$@")
}
changed() { grep -oE 'changed=[0-9]+' "$T_OUT" | tail -n 1; }
state() { python3 "$HERE/kc_fixture.py" state "$KC" admin "$ADMIN_PW"; }

vars false
state >"$T/before.json"
check "role in check mode" apply --check
if grep -q 'would change: .*create flow fastrdp-mfa' "$T_OUT" && [ "$(changed)" = changed=1 ] \
    && state | cmp -s - "$T/before.json"; then
    ok "check mode reports the changes and writes nothing"
else
    fail "check mode reports the changes and writes nothing"
fi
check "role applied" apply
if [ "$(changed)" = changed=1 ]; then ok "first run changes Keycloak"; else fail "first run changes Keycloak ($(changed))"; fi
check "role applied again" apply
if [ "$(changed)" = changed=0 ]; then ok "second run is idempotent (changed=0)"; else fail "second run is idempotent ($(changed))"; fi
state >"$T/after.json"
check "client profiles/policies merged, other ACR map entries and RP name kept" python3 - "$T/after.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["profiles"] == ["unrelated-profile", "fastrdp-mfa-flow"], s["profiles"]
assert s["policies"] == ["unrelated-policy", "fastrdp-mfa"], s["policies"]
assert s["acr_loa_map"] == {"other": 5, "mfa": 2}, s["acr_loa_map"]
assert s["rp_entity_name"] == "fastrdp test", s["rp_entity_name"]
p = s["passwordless"]
assert p["webAuthnPolicyPasswordlessUserVerificationRequirement"] == "required"
assert p["webAuthnPolicyPasswordlessResidentKey"] == "required"
assert p["webAuthnPolicyPasswordlessPasskeysEnabled"] is True
assert p["webAuthnPolicyPasswordlessMediation"] == "conditional"
EOF
python3 "$HERE/kc_fixture.py" add-cookie "$KC" admin "$ADMIN_PW" fastrdp-mfa
check "role run after a Cookie step was added to fastrdp-mfa" apply
if grep -q 'rebuild flow fastrdp-mfa (removes auth-cookie)' "$T_OUT" && [ "$(changed)" = changed=1 ]; then
    ok "Cookie step in the forced flow detected and removed"
else
    fail "Cookie step in the forced flow removed"
fi

# ------------------------------------------------------------------ browser + webgate
cat >"$T/apply-mode.sh" <<EOF
#!/bin/sh
# e2e.py: re-apply the role with hardware-only on (hardware-only), the account console's
# flow override on (account-console), or neither (default)
cd "$REPO/ansible" || exit 1
python3 - "\$1" "$T/vars.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[2]))
v["fastrdp_web_passkeys_hardware_only"] = sys.argv[1] == "hardware-only"
v["fastrdp_keycloak_account_console_mfa"] = sys.argv[1] == "account-console"
json.dump(v, open(sys.argv[2], "w"))
PY
exec ansible-playbook -i localhost, -c local "$HERE/apply.yml" -e "@$T/vars.json"
EOF
chmod +x "$T/apply-mode.sh"
REPORT=${FASTRDP_KC_REPORT:-$T/report.json}
if python3 "$HERE/e2e.py" --keycloak "$KC" --chrome "$CHROME" --gate-port "$GATE_PORT" \
    --probe-port "$PROBE_PORT" --admin-password "$ADMIN_PW" --apply "$T/apply-mode.sh" \
    --report "$REPORT" --chrome-log "$T/chrome.log" >"$T/e2e.out" 2>&1; then
    rc=0
else
    rc=1
fi
grep -E '^(ok  |FAIL|     \|)' "$T/e2e.out"
T_PASS=$((T_PASS + $(grep -c '^ok  ' "$T/e2e.out")))
T_FAIL=$((T_FAIL + $(grep -c '^FAIL' "$T/e2e.out")))
[ "$rc" = 0 ] || [ "$(grep -c '^FAIL' "$T/e2e.out")" != 0 ] || { tail -20 "$T/e2e.out"; T_FAIL=$((T_FAIL + 1)); }
echo "webgate decisions (acr/amr): $(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["webgate_decisions"]))' "$REPORT" 2>/dev/null)"

# ------------------------------------------------------------------ code check (code_or_web)
# The broker's code check: the sample client imported by hand, the role adds the direct
# grant flow (Username Validation, OTP or Deny access for users without one), the amr
# mapper and the binding; otp_check.py drives keycloak_otp.py, also with flows changed by hand.
check "code check client imported from its sample" python3 "$HERE/kc_fixture.py" otp-client "$KC" admin "$ADMIN_PW"
python3 - "$T/vars.json" "$T/otp-vars.json" "$KC" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
v.update(fastrdp_web_passkeys_hardware_only=False, fastrdp_mfa_mode="code_or_web",
         fastrdp_web_enabled=True, fastrdp_mfa_keycloak_client_id="fastrdp-otp-check",
         fastrdp_mfa_keycloak_client_secret="otp-check-test-secret",   # roles/common wants one
         fastrdp_mfa_keycloak_issuer=sys.argv[3] + "/realms/fastrdp-test")
json.dump(v, open(sys.argv[2], "w"))
PY
apply_otp() { (cd "$REPO/ansible" && ANSIBLE_CONFIG=$REPO/ansible/ansible.cfg ansible-playbook -i localhost, -c local \
    "$HERE/apply.yml" -e "@$T/otp-vars.json" "$@"); }
check "role with code_or_web applied" apply_otp
if grep -q 'create direct grant flow fastrdp-otp-check' "$T_OUT" && grep -q 'direct grant flow fastrdp-otp-check' "$T_OUT" \
    && grep -q 'used more than once' "$T_OUT"; then
    ok "direct grant flow created and bound; the fixture's reusable OTP codes reported"
else
    fail "direct grant flow created and bound; reusable OTP codes reported"
fi
check "role with code_or_web applied again" apply_otp
if [ "$(changed)" = changed=0 ]; then ok "code check setup is idempotent (changed=0)"; else fail "code check setup is idempotent ($(changed))"; fi
if python3 "$HERE/otp_check.py" "$KC" "$ADMIN_PW" >"$T/otp.out" 2>&1; then rc=0; else rc=1; fi
grep -E '^(ok  |FAIL)' "$T/otp.out"
T_PASS=$((T_PASS + $(grep -c '^ok  ' "$T/otp.out")))
T_FAIL=$((T_FAIL + $(grep -c '^FAIL' "$T/otp.out")))
[ "$rc" = 0 ] || [ "$(grep -c '^FAIL' "$T/otp.out")" != 0 ] || { tail -20 "$T/otp.out"; T_FAIL=$((T_FAIL + 1)); }

# ------------------------------------------------------------------ kcadm script (Method 2)
KCADM_SCRIPT=$REPO/docs/examples/keycloak-mfa/fastrdp-mfa-kcadm.sh
export KCADM=$KEYCLOAK_HOME/bin/kcadm.sh KCADM_CONFIG=$T/kcadm.config
fixture() { python3 "$HERE/kc_fixture.py" "$1" "$KC" admin "$ADMIN_PW" "${@:2}"; }
kcadm_run() { "$KCADM_SCRIPT" -r fastrdp-test -c fastrdp-web --otp-client fastrdp-otp-check "$@"; }
codes_work() {   # alice's right code passes, carol (no OTP) gets Deny access
    python3 - "$KC" "$REPO" <<'PY'
import sys
sys.path[:0] = [sys.argv[2] + "/tests/keycloak", sys.argv[2] + "/broker/brokerd"]
from fastrdp_broker import keycloak_otp
from fastrdp_broker.config import KeycloakOtpSection
from kc_fixture import OTP_CLIENT_SECRET, REALM, totp
kc = keycloak_otp.KeycloakOtp(KeycloakOtpSection(issuer=f"{sys.argv[1]}/realms/{REALM}", client_id="fastrdp-otp-check",
                                                 client_secret_file="/nonexistent", timeout=10), secret=OTP_CLIENT_SECRET)
got = (kc.check("alice", totp()), kc.check("carol", "123456"))
assert got == (keycloak_otp.OK, keycloak_otp.NO_OTP), got
PY
}
check "kcadm.sh logged in" "$KCADM" config credentials --config "$KCADM_CONFIG" --server "$KC" --realm master \
    --user admin --password "$ADMIN_PW"
check "kcadm script --check on the role's result" kcadm_run --check
if grep -q '^no changes: .*code check fastrdp-otp-check' "$T_OUT"; then
    ok "kcadm script finds the role's setup (code check included) unchanged"
else
    fail "kcadm script finds the role's setup unchanged"
fi
fixture drop-otp-check
check "kcadm script --check after the code check was removed" kcadm_run --check
if grep -q 'would change: create direct grant flow fastrdp-otp-check' "$T_OUT" \
    && grep -q 'would change: client fastrdp-otp-check: amr mapper' "$T_OUT" \
    && grep -q 'would change: client fastrdp-otp-check: direct grant flow' "$T_OUT" \
    && ! grep -q '^ok: direct grant flow' "$T_OUT"; then
    ok "kcadm script check mode lists flow, mapper and binding"
else
    fail "kcadm script check mode lists flow, mapper and binding"
fi
check "kcadm script builds the code check" kcadm_run
check "role's check mode after the kcadm script" apply_otp --check
if [ "$(changed)" = changed=0 ]; then
    ok "kcadm script's code check equals the role's (role check mode: changed=0)"
else
    fail "kcadm script's code check equals the role's ($(changed))"
fi
check "codes work through the kcadm script's flow (alice OK, carol Deny access)" codes_work
check "kcadm script run again" kcadm_run
if grep -q '^no changes:' "$T_OUT"; then ok "kcadm script is idempotent"; else fail "kcadm script is idempotent"; fi
fixture set-otp-deny DISABLED
if kcadm_run --check >"$T/kcadm-drift.out" 2>&1; then rc=0; else rc=1; fi
if [ "$rc" = 1 ] && grep -q 'of the code check exists with another structure' "$T/kcadm-drift.out" \
    && grep -q 'have: .*deny-access-authenticator","DISABLED"' "$T/kcadm-drift.out"; then
    ok "kcadm script stops at a hand-made change of the code check's flow"
else
    T_OUT=$T/kcadm-drift.out fail "kcadm script stops at a hand-made change of the code check's flow"
fi
check "kcadm script --rebuild" kcadm_run --rebuild
if grep -q '^change: rebuild direct grant flow fastrdp-otp-check' "$T_OUT"; then
    ok "kcadm script --rebuild restores the code check's flow"
else
    fail "kcadm script --rebuild restores the code check's flow"
fi
check "codes work after the rebuild" codes_work
fixture set-otp-client fullScopeAllowed true
if kcadm_run --check >"$T/kcadm-unsafe.out" 2>&1; then rc=0; else rc=1; fi
fixture set-otp-client fullScopeAllowed false
if [ "$rc" = 1 ] && grep -q 'must be confidential, direct grants only.*fullScopeAllowed=true' "$T/kcadm-unsafe.out"; then
    ok "kcadm script refuses an unsafe code check client"
else
    T_OUT=$T/kcadm-unsafe.out fail "kcadm script refuses an unsafe code check client"
fi
# W3: an AAGUID allow-list set by hand survives the kcadm script and the role
AAGUID=ee882879-721c-4913-9775-3dfcce97072a
fixture set-aaguids "$AAGUID" optional     # another mediation: the script must update the realm
check "kcadm script with an AAGUID list set by hand" kcadm_run
if grep -q '^change: realm WebAuthn passwordless policy: webAuthnPolicyPasswordlessMediation$' "$T_OUT"; then
    ok "kcadm script updates the realm without touching attestation or AAGUIDs"
else
    fail "kcadm script updates the realm without touching attestation or AAGUIDs"
fi
has_aaguid() { state | grep -q "\"webAuthnPolicyPasswordlessAcceptableAaguids\": \[\"$AAGUID\"\]"; }
if has_aaguid; then ok "AAGUID allow-list set by hand kept by the kcadm script (W3)"
else fail "AAGUID allow-list set by hand kept by the kcadm script"; fi
fixture set-aaguids "$AAGUID" optional
check "role run with an AAGUID list set by hand" apply_otp
if grep -q 'changed: realm WebAuthn passwordless policy: webAuthnPolicyPasswordlessMediation' "$T_OUT" && has_aaguid; then
    ok "AAGUID allow-list set by hand kept by the role's realm update (W3)"
else
    fail "AAGUID allow-list set by hand kept by the role's realm update"
fi
fixture set-aaguids ""
# W4: the account console's flow override (e2e.py set it through the role)
fixture drop-account-console
if kcadm_run --check >"$T/kcadm-ac.out" 2>&1 && grep -q '^warning: enrolment gap: client account-console' "$T/kcadm-ac.out" \
    && grep -q '^no changes:' "$T/kcadm-ac.out"; then
    ok "kcadm script without --account-console: warns about the enrolment gap, changes nothing"
else
    T_OUT=$T/kcadm-ac.out fail "kcadm script without --account-console warns about the enrolment gap"
fi
check "kcadm script --account-console --check" kcadm_run --account-console --check
if grep -q "would change: client account-console: browser flow fastrdp-mfa (was the realm's browser flow)" "$T_OUT"; then
    ok "kcadm script --account-console --check lists the override"
else
    fail "kcadm script --account-console --check lists the override"
fi
check "kcadm script --account-console" kcadm_run --account-console
python3 - "$T/otp-vars.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
v["fastrdp_keycloak_account_console_mfa"] = True
json.dump(v, open(sys.argv[1], "w"))
PY
check "role's check mode after kcadm --account-console" apply_otp --check
if [ "$(changed)" = changed=0 ] && ! grep -q 'enrolment gap: client account-console' "$T_OUT"; then
    ok "kcadm script's account console override equals the role's (changed=0, no gap warning)"
else
    fail "kcadm script's account console override equals the role's ($(changed))"
fi
finish
