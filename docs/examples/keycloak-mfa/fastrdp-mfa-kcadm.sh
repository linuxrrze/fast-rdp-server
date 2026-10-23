#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# fastrdp-mfa-kcadm.sh - configure Keycloak for fastrdp's web gateway (acr=mfa) with the
# Keycloak admin CLI (kcadm.sh) instead of Ansible. Creates the same configuration as
# ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py (fastrdp_web_passkeys: true):
#
#   1. realm: WebAuthn *passwordless* policy (user verification required, discoverable
#      credential required, passkeys enabled, mediation, attestation none, no AAGUID list)
#      and the required action webauthn-register-passwordless (enabled);
#   2. top-level flow fastrdp-mfa (no Cookie step):
#        Username Form                                   REQUIRED
#        Password Form                                   REQUIRED
#        fastrdp-mfa - 2FA unless passkey (sub-flow)     CONDITIONAL
#          Condition - credential                        REQUIRED  config fastrdp-mfa-conditional-credential:
#                                                                  credentials=webauthn-passwordless, included=false
#          fastrdp-mfa - second factor (sub-flow)        REQUIRED
#            OTP Form                                    ALTERNATIVE
#            WebAuthn Authenticator                      ALTERNATIVE
#   3. client profile fastrdp-mfa-flow (auth-flow-enforcer: flow fastrdp-mfa, LoA 2) and
#      client policy fastrdp-mfa (acr-condition: mfa). Keycloak's PUT replaces ALL realm
#      profiles/policies: the script reads them, merges its own entry and writes back;
#   4. the OIDC client's ACR-to-LoA map entry mfa -> 2 (other entries kept);
#   5. only with --otp-client (broker [mfa] mode code_or_web): the broker's code check.
#      Direct grant flow fastrdp-otp-check (username + code, no password):
#        Username Validation                             REQUIRED
#        fastrdp-otp-check - otp (sub-flow)              CONDITIONAL
#          Condition - user configured                   REQUIRED
#          OTP (direct-grant-validate-otp)               REQUIRED  config fastrdp-otp-check-otp-reference:
#                                                                  default.reference.value=otp, maxAge=60
#        fastrdp-otp-check - no otp (sub-flow)           CONDITIONAL
#          Condition - sub-flow executed                 REQUIRED  config fastrdp-otp-check-no-otp-condition:
#                                                                  flow_to_check=fastrdp-otp-check - otp,
#                                                                  check_result=not-executed
#          Deny access                                   REQUIRED  config fastrdp-otp-check-no-otp-deny:
#                                                                  denyErrorMessage=fastrdp_no_otp
#      bound as the client's direct grant flow, plus the client's amr mapper "fastrdp amr"
#      (the broker accepts no token without otp in amr). The client itself is created by
#      hand (docs/examples/keycloak-fastrdp-otp-check-client.json); the script refuses it
#      unless it is confidential, allows direct grants only (no browser flow, implicit
#      flow, service account, device or CIBA grant), has full scope off, no standard token
#      exchange and no audience mapper. It warns when the realm lets an OTP code be used
#      twice or has brute-force detection off.
#
# Idempotent: pieces that already match are skipped. A flow (fastrdp-mfa, or the code
# check's flow) that exists with a different structure is NOT touched unless --rebuild is
# given (then its steps are deleted and rebuilt). The Ansible script differs for the code
# check's flow: it rebuilds a changed one at once, with a warning.
#
# Requirements: bash, jq, kcadm.sh (Keycloak 26.x, from the server's bin/ directory or the
# keycloak distribution; needs a Java 17+ runtime), an admin login with manage-realm +
# manage-clients on the target realm.
#
# Log in first (the session is stored in ~/.keycloak/kcadm.config, or in $KCADM_CONFIG):
#   service account (preferred):
#     kcadm.sh config credentials --server https://KEYCLOAK_HOST --realm ADMIN_REALM \
#         --client ADMIN_CLIENT_ID --secret 'ADMIN_CLIENT_SECRET'
#   admin user (password prompted when --password is omitted):
#     kcadm.sh config credentials --server https://KEYCLOAK_HOST --realm master --user ADMIN_USER
# then:
#   ./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID --check     # show what would change
#   ./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID             # apply
#
# Options:
#   -r, --realm REALM        target realm (required)
#   -c, --client CLIENT_ID   clientId of the webgate's OIDC client (required)
#   --flow ALIAS             flow alias (default fastrdp-mfa)
#   --acr VALUE              ACR value (default mfa; must be in fastrdp_web_required_acr)
#   --loa N                  level of authentication (default 2)
#   --profile NAME           client profile name (default fastrdp-mfa-flow)
#   --policy NAME            client policy name (default fastrdp-mfa)
#   --second-factors LIST    comma-separated authenticator ids
#                            (default auth-otp-form,webauthn-authenticator)
#   --mediation MODE         passkey mediation: conditional|optional|required|silent|none
#                            (default conditional = passkey autofill on the username form)
#   --otp-client CLIENT_ID   also set up the code check (code_or_web) for this client
#                            (default: none, i.e. no code check)
#   --otp-flow ALIAS         the code check's direct grant flow (default fastrdp-otp-check)
#   --otp-amr VALUE          amr value of the OTP step (default otp; = the broker's
#                            [mfa.keycloak] required_amr)
#   --check                  list the changes, write nothing (exit 0; "no changes" when done)
#   --rebuild                rebuild flow ALIAS (or the code check's flow) when it exists
#                            with another structure
# Environment:
#   KCADM          path of kcadm.sh (default: kcadm.sh in PATH)
#   KCADM_CONFIG   kcadm config file (default ~/.keycloak/kcadm.config)
#   KCADM_OPTS     extra kcadm options, e.g. "--truststore /path/ts.p12"
set -euo pipefail

KCADM=${KCADM:-kcadm.sh}
REALM="" CLIENT_ID="" FLOW=fastrdp-mfa ACR=mfa LOA=2 PROFILE=fastrdp-mfa-flow POLICY=fastrdp-mfa
FACTORS=auth-otp-form,webauthn-authenticator MEDIATION=conditional CHECK=0 REBUILD=0
OTP_CLIENT="" OTP_FLOW=fastrdp-otp-check OTP_AMR=otp

die() { echo "ERROR: $*" >&2; exit 1; }
usage() { sed -n '/^# Options:/,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
    case $1 in
        -r|--realm) REALM=$2; shift 2 ;;
        -c|--client) CLIENT_ID=$2; shift 2 ;;
        --flow) FLOW=$2; shift 2 ;;
        --acr) ACR=$2; shift 2 ;;
        --loa) LOA=$2; shift 2 ;;
        --profile) PROFILE=$2; shift 2 ;;
        --policy) POLICY=$2; shift 2 ;;
        --second-factors) FACTORS=$2; shift 2 ;;
        --mediation) MEDIATION=$2; shift 2 ;;
        --otp-client) OTP_CLIENT=$2; shift 2 ;;
        --otp-flow) OTP_FLOW=$2; shift 2 ;;
        --otp-amr) OTP_AMR=$2; shift 2 ;;
        --check) CHECK=1; shift ;;
        --rebuild) REBUILD=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done
[ -n "$REALM" ] && [ -n "$CLIENT_ID" ] || usage
command -v jq >/dev/null || die "jq is required"
command -v "$KCADM" >/dev/null || die "kcadm.sh not found (set KCADM=/path/to/keycloak/bin/kcadm.sh)"
[[ $LOA =~ ^[1-9][0-9]?$ ]] || die "--loa must be an integer 1..99"
[[ $ACR != 0 && $ACR != 1 ]] || die "--acr must name the MFA level (e.g. mfa), not 0/1"
case $MEDIATION in conditional|optional|required|silent|none) ;; *) die "bad --mediation";; esac
case ",$FACTORS," in
    *,auth-cookie,*|*,auth-password-form,*|*,auth-username-form,*|*,conditional-user-configured,*|\
    *,allow-access-authenticator,*|*,identity-provider-redirector,*|*,auth-spnego,*|*,,*)
        die "--second-factors: bad or forbidden authenticator in '$FACTORS'" ;;
esac
if [ -n "$OTP_CLIENT" ]; then
    [ "$OTP_CLIENT" != "$CLIENT_ID" ] || die "--otp-client must be a client of its own, not the webgate's"
    [ -n "$OTP_FLOW" ] && [ "$OTP_FLOW" != "$FLOW" ] || die "--otp-flow must name a flow of its own"
    [[ $OTP_AMR =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--otp-amr must be an amr value such as otp"
fi

COND_FLOW="$FLOW - 2FA unless passkey"
SECOND_FLOW="$FLOW - second factor"
CHANGES=0

kc() {   # kc VERB PATH [args...]: kcadm.sh against the target realm
    local verb=$1 path=$2; shift 2
    # shellcheck disable=SC2086
    "$KCADM" "$verb" "$path" -r "$REALM" ${KCADM_CONFIG:+--config "$KCADM_CONFIG"} ${KCADM_OPTS:-} "$@"
}
kget() {   # kget PATH [args...]: compact JSON on stdout (kcadm -c also prints an empty line on stderr: dropped)
    local rc=0 err
    err=$(mktemp)
    kc get "$1" "${@:2}" -c 2>"$err" || rc=$?
    grep -v '^$' "$err" >&2 || true
    rm -f "$err"
    return "$rc"
}
uri() { jq -rn --arg v "$1" '$v|@uri'; }
change() {   # change MESSAGE: record a change; returns 1 (skip the write) in --check mode
    CHANGES=$((CHANGES + 1))
    if [ "$CHECK" = 1 ]; then echo "would change: $1"; return 1; fi
    echo "change: $1"
}
ok() { echo "ok: $1"; }

# ------------------------------------------------------------------ preflight
kget "realms/$(uri "$REALM")" >/dev/null \
    || die "cannot read realm '$REALM' (logged in? 'kcadm.sh config credentials ...'; manage-realm role?)"
CLIENT_JSON=$(kget clients -q clientId="$CLIENT_ID" | jq -c '.[0] // empty')
[ -n "$CLIENT_JSON" ] || die "client '$CLIENT_ID' not found in realm '$REALM' (import docs/examples/keycloak-fastrdp-web-client.json first)"

# ------------------------------------------------------------------ 1. realm
REALM_JSON=$(kget "realms/$(uri "$REALM")")
WANTED_REALM=$(jq -nc --arg m "$MEDIATION" '{
    webAuthnPolicyPasswordlessUserVerificationRequirement: "required",
    webAuthnPolicyPasswordlessResidentKey: "required",
    webAuthnPolicyPasswordlessPasskeysEnabled: true,
    webAuthnPolicyPasswordlessMediation: $m,
    webAuthnPolicyPasswordlessAttestationConveyancePreference: "none",
    webAuthnPolicyPasswordlessAcceptableAaguids: []}')
REALM_DIFF=$(jq -c --argjson w "$WANTED_REALM" '. as $c | $w | with_entries(select($c[.key] != .value))' <<<"$REALM_JSON")
if [ "$REALM_DIFF" = "{}" ]; then
    ok "realm WebAuthn passwordless policy"
elif change "realm WebAuthn passwordless policy: $(jq -r 'keys|join(", ")' <<<"$REALM_DIFF")"; then
    # Keycloak rebuilds the whole passwordless policy from the request (missing fields fall
    # back to defaults): send all current passwordless fields with ours changed.
    jq -c --argjson d "$REALM_DIFF" 'with_entries(select(.key|startswith("webAuthnPolicyPasswordless"))) + $d' \
        <<<"$REALM_JSON" | kc update "realms/$(uri "$REALM")" -n -f -
fi

RA=$(kget authentication/required-actions | jq -c '.[] | select(.alias == "webauthn-register-passwordless")')
if [ -z "$RA" ]; then
    if change "register required action webauthn-register-passwordless"; then
        kc create authentication/register-required-action \
            -b '{"providerId":"webauthn-register-passwordless","name":"Webauthn Register Passwordless"}'
        kc update authentication/required-actions/webauthn-register-passwordless -n -b \
            '{"alias":"webauthn-register-passwordless","providerId":"webauthn-register-passwordless","name":"Webauthn Register Passwordless","enabled":true}'
    fi
elif [ "$(jq -r '.enabled' <<<"$RA")" != true ]; then
    if change "enable required action webauthn-register-passwordless"; then
        jq -c '.enabled = true' <<<"$RA" | kc update authentication/required-actions/webauthn-register-passwordless -n -f -
    fi
else
    ok "required action webauthn-register-passwordless enabled"
fi

# ------------------------------------------------------------------ 2. flow
wanted_rows() {   # the flow as rows: level kind name requirement config (one JSON array per line)
    jq -ncS --arg cond "$COND_FLOW" --arg second "$SECOND_FLOW" --arg f "$FACTORS" '
        [0,"exec","auth-username-form","REQUIRED",null],
        [0,"exec","auth-password-form","REQUIRED",null],
        [0,"flow",$cond,"CONDITIONAL",null],
        [1,"exec","conditional-credential","REQUIRED",{credentials:"webauthn-passwordless",included:"false"}],
        [1,"flow",$second,"REQUIRED",null],
        ($f | split(",")[] | [2,"exec",.,"ALTERNATIVE",null])'
}
actual_rows() {   # actual_rows ALIAS
    local e cfg
    kget "authentication/flows/$(uri "$1")/executions" | jq -c '.[]' | while read -r e; do
        cfg=null
        if [ "$(jq -r '.authenticationConfig // empty' <<<"$e")" != "" ]; then
            cfg=$(kget "authentication/config/$(jq -r '.authenticationConfig' <<<"$e")" </dev/null | jq -c '.config // {}')
        fi
        jq -cS --argjson cfg "$cfg" 'if .authenticationFlow then [.level,"flow",.displayName,.requirement,$cfg]
                                    else [.level,"exec",(.providerId // ""),.requirement,$cfg] end' <<<"$e"
    done
}
set_requirement() {   # set_requirement PARENT JQ-MATCH REQUIREMENT [CONFIG-JSON [CONFIG-ALIAS]]
    local parent=$1 match=$2 req=$3 config=${4:-} config_alias=${5:-} e
    e=$(kget "authentication/flows/$(uri "$parent")/executions" \
        | jq -c "[.[] | select(.level == 0) | select($match)] | last // empty")
    [ -n "$e" ] || die "execution just added to '$parent' not found"
    if [ "$(jq -r .requirement <<<"$e")" != "$req" ]; then
        jq -e --arg r "$req" '(.requirementChoices // [$r]) | index($r)' <<<"$e" >/dev/null \
            || die "$(jq -r .displayName <<<"$e"): requirement $req not allowed ($(jq -c .requirementChoices <<<"$e"))"
        jq -c --arg r "$req" '.requirement = $r' <<<"$e" \
            | kc update "authentication/flows/$(uri "$parent")/executions" -n -f -
    fi
    if [ -n "$config" ]; then
        jq -nc --arg a "${config_alias:-$FLOW-$(jq -r .providerId <<<"$e")}" --argjson c "$config" '{alias: $a, config: $c}' \
            | kc create "authentication/executions/$(jq -r .id <<<"$e")/config" -f - >/dev/null
    fi
}
add_exec() {   # add_exec PARENT PROVIDER REQUIREMENT [CONFIG-JSON [CONFIG-ALIAS]]
    kc create "authentication/flows/$(uri "$1")/executions/execution" -b "$(jq -nc --arg p "$2" '{provider:$p}')" >/dev/null
    set_requirement "$1" ".providerId == \"$2\"" "$3" "${4:-}" "${5:-}"
}
add_flow() {   # add_flow PARENT ALIAS REQUIREMENT
    jq -nc --arg a "$2" '{alias:$a, type:"basic-flow", provider:"registration-page-form",
                          description:"fastrdp (keycloak_passkeys)"}' \
        | kc create "authentication/flows/$(uri "$1")/executions/flow" -f - >/dev/null
    set_requirement "$1" "(.authenticationFlow == true) and (.displayName == $(jq -n --arg a "$2" '$a'))" "$3"
}
build_flow() {
    local f
    add_exec "$FLOW" auth-username-form REQUIRED
    add_exec "$FLOW" auth-password-form REQUIRED
    add_flow "$FLOW" "$COND_FLOW" CONDITIONAL
    add_exec "$COND_FLOW" conditional-credential REQUIRED '{"credentials":"webauthn-passwordless","included":"false"}'
    add_flow "$COND_FLOW" "$SECOND_FLOW" REQUIRED
    IFS=, read -ra f <<<"$FACTORS"
    for x in "${f[@]}"; do add_exec "$SECOND_FLOW" "$x" ALTERNATIVE; done
    [ "$(actual_rows "$FLOW")" = "$(wanted_rows)" ] \
        || die "flow '$FLOW' differs after building it:"$'\n'"$(actual_rows "$FLOW")"
}

FLOW_JSON=$(kget authentication/flows | jq -c --arg a "$FLOW" '.[] | select(.alias == $a)')
if [ -z "$FLOW_JSON" ]; then
    # sub-flow aliases are realm-wide: refuse leftovers of a deleted flow
    for sub in "$COND_FLOW" "$SECOND_FLOW"; do
        if kget authentication/flows | jq -e --arg a "$sub" 'any(.[]; .alias == $a)' >/dev/null; then
            die "a flow '$sub' exists without top-level flow '$FLOW'; delete it or choose --flow"
        fi
    done
    if change "create flow $FLOW"; then
        jq -nc --arg a "$FLOW" '{alias:$a, providerId:"basic-flow", topLevel:true, builtIn:false,
            description:"fastrdp: MFA for acr=mfa (passkey, or password + second factor); no Cookie step. Managed by Ansible (keycloak_passkeys)."}' \
            | kc create authentication/flows -f - >/dev/null
        build_flow
    fi
elif [ "$(jq -r .builtIn <<<"$FLOW_JSON")" = true ]; then
    die "flow '$FLOW' is a built-in flow; choose another --flow"
elif [ "$(actual_rows "$FLOW")" = "$(wanted_rows)" ]; then
    ok "flow $FLOW"
elif [ "$REBUILD" != 1 ]; then
    echo "flow '$FLOW' exists with another structure:" >&2
    actual_rows "$FLOW" | sed 's/^/  have: /' >&2
    wanted_rows | sed 's/^/  want: /' >&2
    die "not touching it; rerun with --rebuild to delete its steps and rebuild it"
elif change "rebuild flow $FLOW"; then
    kget "authentication/flows/$(uri "$FLOW")/executions" | jq -r '.[] | select(.level == 0) | .id' \
        | while read -r id; do kc delete "authentication/executions/$id" </dev/null; done
    build_flow
fi

# ------------------------------------------------------------------ 3. client profile + policy
canon='def canon: if type == "object" then with_entries(select(.value != null and .value != [] and .value != {} and .value != "") | .value |= canon)
                   elif type == "array" then map(canon) elif type == "boolean" or type == "number" then tostring else . end;'
PROFILE_ITEM=$(jq -nc --arg n "$PROFILE" --arg f "$FLOW" --argjson l "$LOA" '{name:$n,
    description:"fastrdp: force the MFA flow (managed by Ansible, keycloak_passkeys)",
    executors:[{executor:"auth-flow-enforcer", configuration:{"auth-flow-alias":$f, "auth-flow-loa":$l}}]}')
POLICY_ITEM=$(jq -nc --arg n "$POLICY" --arg p "$PROFILE" --arg f "$FLOW" --arg a "$ACR" '{name:$n,
    description:("fastrdp: acr_values=" + $a + " -> flow " + $f + " (managed by Ansible, keycloak_passkeys)"),
    enabled:true, conditions:[{condition:"acr-condition", configuration:{"acr-property":$a}}], profiles:[$p]}')
for spec in "profiles profile $PROFILE_ITEM" "policies policy $POLICY_ITEM"; do
    read -r kind noun item <<<"$spec"
    cur=$(kget "client-policies/$kind")
    name=$(jq -r .name <<<"$item")
    state=$(jq -r --argjson it "$item" --arg k "$kind" "$canon"'
        ([.[$k] // [] | .[] | select(.name == $it.name)] | first) as $have
        | if $have == null then "add" elif ($have | canon) == ($it | canon) then "same" else "update" end' <<<"$cur")
    if [ "$state" = same ]; then
        ok "client $noun $name"
        continue
    fi
    others=$(jq -r --arg k "$kind" --arg n "$name" '[.[$k] // [] | .[] | select(.name != $n)] | length' <<<"$cur")
    if change "$state client $noun $name (keeping $others other)"; then
        # PUT replaces the realm's whole list: write back all others plus ours (same position on update)
        jq -c --argjson it "$item" --arg k "$kind" '
            .[$k] = (if any(.[$k] // [] | .[]; .name == $it.name)
                     then [.[$k][] | if .name == $it.name then $it else . end]
                     else (.[$k] // []) + [$it] end)' <<<"$cur" \
            | kc update "client-policies/$kind" -n -f -
    fi
done

# ------------------------------------------------------------------ 4. client ACR-to-LoA map
LOA_MAP=$(jq -r '.attributes["acr.loa.map"] // "{}"' <<<"$CLIENT_JSON")
jq -e 'type == "object"' <<<"$LOA_MAP" >/dev/null 2>&1 || die "client $CLIENT_ID: acr.loa.map is not a JSON object: $LOA_MAP"
if [ "$(jq -r --arg a "$ACR" '.[$a] // "" | tostring' <<<"$LOA_MAP")" = "$LOA" ]; then
    ok "client $CLIENT_ID: ACR-to-LoA $ACR -> $LOA"
elif change "client $CLIENT_ID: ACR-to-LoA $ACR -> $LOA (map was $LOA_MAP)"; then
    NEW_MAP=$(jq -c --arg a "$ACR" --argjson l "$LOA" '.[$a] = $l' <<<"$LOA_MAP")
    jq -c --arg m "$NEW_MAP" '.attributes["acr.loa.map"] = $m' <<<"$CLIENT_JSON" \
        | kc update "clients/$(jq -r .id <<<"$CLIENT_JSON")" -n -f -
fi

# ------------------------------------------------------------------ 5. code check (code_or_web)
OTP_WITH="$OTP_FLOW - otp"
OTP_WITHOUT="$OTP_FLOW - no otp"
OTP_REF_CONFIG=$(jq -nc --arg v "$OTP_AMR" '{"default.reference.value": $v, "default.reference.maxAge": "60"}')
OTP_COND_CONFIG=$(jq -nc --arg f "$OTP_WITH" '{flow_to_check: $f, check_result: "not-executed"}')
OTP_DENY_CONFIG='{"denyErrorMessage":"fastrdp_no_otp"}'   # = broker keycloak_otp.py NO_OTP_ERROR
OTP_MAPPER='{"name":"fastrdp amr","protocol":"openid-connect","protocolMapper":"oidc-amr-mapper",
    "config":{"id.token.claim":"true","access.token.claim":"true","lightweight.claim":"true","introspection.token.claim":"true"}}'
otp_wanted_rows() {
    jq -ncS --arg with "$OTP_WITH" --arg without "$OTP_WITHOUT" --argjson ref "$OTP_REF_CONFIG" \
        --argjson cond "$OTP_COND_CONFIG" --argjson deny "$OTP_DENY_CONFIG" '
        [0,"exec","direct-grant-validate-username","REQUIRED",null],
        [0,"flow",$with,"CONDITIONAL",null],
        [1,"exec","conditional-user-configured","REQUIRED",null],
        [1,"exec","direct-grant-validate-otp","REQUIRED",$ref],
        [0,"flow",$without,"CONDITIONAL",null],
        [1,"exec","conditional-sub-flow-executed","REQUIRED",$cond],
        [1,"exec","deny-access-authenticator","REQUIRED",$deny]'
}
build_otp_flow() {
    add_exec "$OTP_FLOW" direct-grant-validate-username REQUIRED
    add_flow "$OTP_FLOW" "$OTP_WITH" CONDITIONAL
    add_exec "$OTP_WITH" conditional-user-configured REQUIRED
    add_exec "$OTP_WITH" direct-grant-validate-otp REQUIRED "$OTP_REF_CONFIG" "$OTP_FLOW-otp-reference"
    add_flow "$OTP_FLOW" "$OTP_WITHOUT" CONDITIONAL
    add_exec "$OTP_WITHOUT" conditional-sub-flow-executed REQUIRED "$OTP_COND_CONFIG" "$OTP_FLOW-no-otp-condition"
    add_exec "$OTP_WITHOUT" deny-access-authenticator REQUIRED "$OTP_DENY_CONFIG" "$OTP_FLOW-no-otp-deny"
    [ "$(actual_rows "$OTP_FLOW")" = "$(otp_wanted_rows)" ] \
        || die "flow '$OTP_FLOW' differs after building it:"$'\n'"$(actual_rows "$OTP_FLOW")"
}

if [ -n "$OTP_CLIENT" ]; then
    OTP_JSON=$(kget clients -q clientId="$OTP_CLIENT" | jq -c '.[0] // empty')
    [ -n "$OTP_JSON" ] || die "client '$OTP_CLIENT' (code check) not found in realm '$REALM': create it first (docs/examples/keycloak-fastrdp-otp-check-client.json)"
    OTP_ID=$(jq -r .id <<<"$OTP_JSON")
    # never change such a client: an admin has to look at it
    BAD=$(kget "clients/$OTP_ID/protocol-mappers/models" | jq -r --argjson c "$OTP_JSON" '
        ($c | [{publicClient: false, directAccessGrantsEnabled: true, standardFlowEnabled: false,
                implicitFlowEnabled: false, serviceAccountsEnabled: false, fullScopeAllowed: false,
                bearerOnly: false} | to_entries[] | select(($c[.key] // false | . == true) != .value)
               | "\(.key)=\($c[.key])"]
            + [("oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
                "standard.token.exchange.enabled") as $k
               | select((.attributes[$k] // "" | tostring | ascii_downcase) == "true") | "\($k)=true"])
        + [.[] | select(.protocolMapper == "oidc-audience-mapper") | "audience mapper \(.name)"]
        | join(", ")')
    [ -z "$BAD" ] || die "client $OTP_CLIENT (code check) must be confidential, direct grants only, full scope off, no token exchange or audience mapper; found: $BAD"

    OTP_FLOW_JSON=$(kget authentication/flows | jq -c --arg a "$OTP_FLOW" '.[] | select(.alias == $a)')
    if [ -z "$OTP_FLOW_JSON" ]; then
        for sub in "$OTP_WITH" "$OTP_WITHOUT"; do
            if kget authentication/flows | jq -e --arg a "$sub" 'any(.[]; .alias == $a)' >/dev/null; then
                die "a flow '$sub' exists without top-level flow '$OTP_FLOW'; delete it or choose --otp-flow"
            fi
        done
        if change "create direct grant flow $OTP_FLOW"; then
            jq -nc --arg a "$OTP_FLOW" '{alias:$a, providerId:"basic-flow", topLevel:true, builtIn:false,
                description:"fastrdp: code check of the broker (username + OTP, no password; users without OTP are denied), direct grants of one client only. Managed by Ansible (keycloak_passkeys); do not edit."}' \
                | kc create authentication/flows -f - >/dev/null
            build_otp_flow
        fi
    elif [ "$(jq -r .builtIn <<<"$OTP_FLOW_JSON")" = true ]; then
        die "flow '$OTP_FLOW' is a built-in flow; choose another --otp-flow"
    elif [ "$(actual_rows "$OTP_FLOW")" = "$(otp_wanted_rows)" ]; then
        ok "direct grant flow $OTP_FLOW"
    elif [ "$REBUILD" != 1 ]; then
        echo "direct grant flow '$OTP_FLOW' of the code check exists with another structure:" >&2
        actual_rows "$OTP_FLOW" | sed 's/^/  have: /' >&2
        otp_wanted_rows | sed 's/^/  want: /' >&2
        die "not touching it; rerun with --rebuild to delete its steps and rebuild it"
    elif change "rebuild direct grant flow $OTP_FLOW"; then
        kget "authentication/flows/$(uri "$OTP_FLOW")/executions" | jq -r '.[] | select(.level == 0) | .id' \
            | while read -r id; do kc delete "authentication/executions/$id" </dev/null; done
        build_otp_flow
    fi

    MAPPER=$(kget "clients/$OTP_ID/protocol-mappers/models" | jq -c '.[] | select(.name == "fastrdp amr")')
    if [ -z "$MAPPER" ]; then
        if change "client $OTP_CLIENT: amr mapper"; then
            kc create "clients/$OTP_ID/protocol-mappers/models" -f - >/dev/null <<<"$OTP_MAPPER"
        fi
    elif jq -e --argjson w "$OTP_MAPPER" '. as $m | .protocolMapper == $w.protocolMapper
            and all($w.config | to_entries[]; (($m.config // {})[.key] // "" | tostring | ascii_downcase) == .value)' \
            <<<"$MAPPER" >/dev/null; then
        ok "client $OTP_CLIENT: amr mapper"
    else
        echo "warning: client $OTP_CLIENT: amr mapper 'fastrdp amr' was changed by hand" >&2
        if change "client $OTP_CLIENT: reset amr mapper"; then
            # our keys win; Keycloak adds others (userinfo.token.claim) by itself
            jq -c --argjson w "$OTP_MAPPER" '$w + {id: .id, config: ((.config // {}) + $w.config)}' <<<"$MAPPER" \
                | kc update "clients/$OTP_ID/protocol-mappers/models/$(jq -r .id <<<"$MAPPER")" -n -f -
        fi
    fi

    FLOW_ID=$(kget authentication/flows | jq -r --arg a "$OTP_FLOW" '.[] | select(.alias == $a) | .id')
    OTP_JSON=$(kget "clients/$OTP_ID")
    if [ -n "$FLOW_ID" ] && [ "$(jq -r '.authenticationFlowBindingOverrides.direct_grant // ""' <<<"$OTP_JSON")" = "$FLOW_ID" ]; then
        ok "client $OTP_CLIENT: direct grant flow $OTP_FLOW"
    elif change "client $OTP_CLIENT: direct grant flow $OTP_FLOW"; then
        jq -c --arg f "$FLOW_ID" '.authenticationFlowBindingOverrides = ((.authenticationFlowBindingOverrides // {}) + {direct_grant: $f})' \
            <<<"$OTP_JSON" | kc update "clients/$OTP_ID" -n -f -
    fi

    REALM_JSON=$(kget "realms/$(uri "$REALM")")
    if [ "$(jq -r '.otpPolicyCodeReusable // false' <<<"$REALM_JSON")" = true ]; then
        echo "warning: realm: OTP codes may be used more than once (otpPolicyCodeReusable): a code typed on the RDP waiting screen can be replayed; turn it off" >&2
    fi
    if [ "$(jq -r '.bruteForceProtected // false' <<<"$REALM_JSON")" != true ]; then
        echo "warning: realm: brute-force detection is off; wrong codes of the code check are then limited only by the broker ([mfa] code_attempts, code_user_failures)" >&2
    fi
fi

if [ "$CHANGES" = 0 ]; then
    echo "no changes: realm '$REALM' is already configured for fastrdp (flow $FLOW, acr $ACR -> LoA $LOA${OTP_CLIENT:+; code check $OTP_CLIENT, flow $OTP_FLOW})"
elif [ "$CHECK" = 1 ]; then
    echo "$CHANGES change(s) pending (--check: nothing written)"
else
    echo "done: $CHANGES change(s) applied"
fi
