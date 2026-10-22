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
#      hardware-only mode).
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
# e2e.py: re-apply the role with hardware-only on (hardware-only) or off (default)
cd "$REPO/ansible" || exit 1
python3 - "\$1" "$T/vars.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[2]))
v["fastrdp_web_passkeys_hardware_only"] = sys.argv[1] == "hardware-only"
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
finish
