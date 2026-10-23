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
#   4. the OIDC client's ACR-to-LoA map entry mfa -> 2 (other entries kept).
#
# Idempotent: pieces that already match are skipped. A flow fastrdp-mfa that exists with a
# different structure is NOT touched unless --rebuild is given (then its steps are deleted
# and rebuilt, as the Ansible script does).
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
#   --check                  list the changes, write nothing (exit 0; "no changes" when done)
#   --rebuild                rebuild flow ALIAS when it exists with another structure
# Environment:
#   KCADM          path of kcadm.sh (default: kcadm.sh in PATH)
#   KCADM_CONFIG   kcadm config file (default ~/.keycloak/kcadm.config)
#   KCADM_OPTS     extra kcadm options, e.g. "--truststore /path/ts.p12"
set -euo pipefail

KCADM=${KCADM:-kcadm.sh}
REALM="" CLIENT_ID="" FLOW=fastrdp-mfa ACR=mfa LOA=2 PROFILE=fastrdp-mfa-flow POLICY=fastrdp-mfa
FACTORS=auth-otp-form,webauthn-authenticator MEDIATION=conditional CHECK=0 REBUILD=0

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
set_requirement() {   # set_requirement PARENT JQ-MATCH REQUIREMENT [CONFIG-JSON]
    local parent=$1 match=$2 req=$3 config=${4:-} e
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
        jq -nc --arg a "$FLOW-$(jq -r .providerId <<<"$e")" --argjson c "$config" '{alias: $a, config: $c}' \
            | kc create "authentication/executions/$(jq -r .id <<<"$e")/config" -f - >/dev/null
    fi
}
add_exec() {   # add_exec PARENT PROVIDER REQUIREMENT [CONFIG-JSON]
    kc create "authentication/flows/$(uri "$1")/executions/execution" -b "$(jq -nc --arg p "$2" '{provider:$p}')" >/dev/null
    set_requirement "$1" ".providerId == \"$2\"" "$3" "${4:-}"
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

if [ "$CHANGES" = 0 ]; then
    echo "no changes: realm '$REALM' is already configured for fastrdp (flow $FLOW, acr $ACR -> LoA $LOA)"
elif [ "$CHECK" = 1 ]; then
    echo "$CHANGES change(s) pending (--check: nothing written)"
else
    echo "done: $CHANGES change(s) applied"
fi
