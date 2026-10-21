#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Can users in RDP sessions power off, reboot, suspend, hibernate or halt the host?
# (backlog H1, base role: /etc/polkit-1/rules.d/40-fastrdp-power.rules)
#   sudo tests/smoke/check-power-actions.sh [USER]...  as root: each USER (default: every
#        logged-in user with uid >= 1000); asks polkit and logind inside the user's
#        systemd manager, which polkit maps to the user's display session (the RDP one)
#   tests/smoke/check-power-actions.sh                 as the user, in a session terminal
# Read-only: only polkit checks (pkcheck) and logind's Can* queries, never the actions.
# Expected with the rule: "no" for users, "challenge" (admin password) for members of the
# rule's admin groups; with fastrdp_power_allow_local_console, sessions on a seat keep
# the upstream answers. Prints ok/WARN/FAIL lines; exit status 1 if any check failed.
set -uo pipefail
RULE=${FASTRDP_POWER_RULE:-/etc/polkit-1/rules.d/40-fastrdp-power.rules}
# keep in sync with fastrdp_power_polkit_actions (roles/base/defaults/main.yml)
ACTIONS="power-off power-off-multiple-sessions power-off-ignore-inhibit
reboot reboot-multiple-sessions reboot-ignore-inhibit
halt halt-multiple-sessions halt-ignore-inhibit
suspend suspend-multiple-sessions suspend-ignore-inhibit
hibernate hibernate-multiple-sessions hibernate-ignore-inhibit
set-reboot-parameter set-reboot-to-firmware-setup set-reboot-to-boot-loader-menu set-reboot-to-boot-loader-entry"
METHODS="CanPowerOff CanReboot CanHalt CanSuspend CanHibernate CanHybridSleep CanSuspendThenHibernate"

case ${1:-} in -h|--help) sed -n '4,13p' "$0"; exit 0 ;; esac

fail=0
ok()   { echo "ok   $*"; }
warn() { echo "WARN $*"; }
bad()  { echo "FAIL $*"; fail=1; }
hint() { echo "     -> $*"; }

# Runs as the user: one line per logind method ("CanPowerOff no") and per polkit action
# ("power-off 1": pkcheck exit status 0 = yes, 1 = no, 2 = challenge, other = error).
# shellcheck disable=SC2016 # expanded by the inner shell
PROBE='for m in $1; do
    r=$(busctl --system call org.freedesktop.login1 /org/freedesktop/login1 \
        org.freedesktop.login1.Manager "$m" 2>/dev/null) || r=error
    r=${r#s }; echo "$m ${r//\"/}"
done
for a in $2; do
    sh -c "exec pkcheck --action-id org.freedesktop.login1.$a --process \$\$" >/dev/null 2>&1
    echo "$a $?"
done'

# ---------------------------------------------------------------- rule and polkitd
rule_present=0
if [ -r "$RULE" ]; then
    rule_present=1
    ok "power rule present: $RULE"
    missing=""
    for a in $ACTIONS; do grep -q "\"org.freedesktop.login1.$a\"" "$RULE" || missing="$missing $a"; done
    [ -z "$missing" ] || { bad "rule lacks actions:$missing"; hint "re-run the deployment (base role)"; }
elif [ "$(id -u)" != 0 ] && ! [ -r "$(dirname "$RULE")" ]; then
    rule_present=unknown   # /etc/polkit-1/rules.d is 0750 root:polkitd
    echo "skip $(dirname "$RULE") not readable: answers shown without judgement (run as root to check them)"
else
    bad "no power rule $RULE: users get the upstream polkit answers (shown below)"
    hint "fastrdp_block_power_actions: true (default) and re-run the deployment (base role)"
fi
# parsed with python3 (JSON lists in the rule); admin groups and the console setting
rule_setting() {
    [ "$rule_present" = 1 ] || return 0
    python3 -I - "$RULE" "$1" <<'PY'
import json, re, sys
m = re.search(r"var %s = (.*);" % sys.argv[2], open(sys.argv[1]).read())
print(json.dumps(json.loads(m.group(1))) if m else "")
PY
}
ADMIN_GROUPS=$(rule_setting adminGroups)
CONSOLE=$(rule_setting allowLocalConsole)
[ "$rule_present" != 1 ] || echo "     admin groups: ${ADMIN_GROUPS:-?}, local console keeps upstream defaults: ${CONSOLE:-?}"
if [ "$(id -u)" = 0 ]; then
    if systemctl is-active --quiet polkit.service 2>/dev/null; then
        ok "polkitd active"
    else
        bad "polkitd (polkit.service) not active: logind refuses every action that needs polkit"
    fi
    errs=$(journalctl -b -u polkit.service --no-pager -q 2>/dev/null | grep -F "$(basename "$RULE")" | grep -i error | tail -3)
    if [ -n "$errs" ]; then
        bad "polkitd reports errors for $(basename "$RULE"):"
        while IFS= read -r line; do echo "     $line"; done <<<"$errs"
    fi
    # The first rule with an answer wins; files are ordered by name across both directories.
    early=""
    for f in /etc/polkit-1/rules.d/*.rules /usr/share/polkit-1/rules.d/*.rules; do
        [ -f "$f" ] && [ "$f" != "$RULE" ] || continue
        [[ $(basename "$f") < $(basename "$RULE") ]] || continue
        grep -Eq 'org\.freedesktop\.login1\.(power-off|reboot|halt|suspend|hibernate|set-reboot)' "$f" && early="$early $f"
    done
    if [ -n "$early" ]; then
        warn "rules evaluated before ours also name logind power actions:$early"
        hint "check that they do not return polkit.Result.YES for RDP users"
    else
        ok "no earlier polkit rule names logind power actions"
    fi
fi

# ---------------------------------------------------------------- per user
is_admin() {   # USER: member of one of the rule's admin groups?
    [ -n "$ADMIN_GROUPS" ] || return 1
    python3 -I - "$1" "$ADMIN_GROUPS" <<'PY'
import grp, json, os, pwd, sys
pw = pwd.getpwnam(sys.argv[1])
names = set()
for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
    try:
        names.add(grp.getgrgid(gid).gr_name)
    except KeyError:
        pass
sys.exit(0 if names & set(json.loads(sys.argv[2])) else 1)
PY
}

check_user() {
    local u=$1 uid display seat sclass stype remote active role expect out
    uid=$(id -u "$u" 2>/dev/null) || { bad "no such user: $u"; return; }
    echo "--- user $u (uid $uid)"
    display=$(loginctl show-user "$uid" -p Display --value 2>/dev/null)
    if [ -n "$display" ]; then
        seat=$(loginctl show-session "$display" -p Seat --value 2>/dev/null)
        sclass=$(loginctl show-session "$display" -p Class --value 2>/dev/null)
        stype=$(loginctl show-session "$display" -p Type --value 2>/dev/null)
        remote=$(loginctl show-session "$display" -p Remote --value 2>/dev/null)
        active=$(loginctl show-session "$display" -p Active --value 2>/dev/null)
        echo "     display session $display: type=$stype class=$sclass seat=${seat:-none} remote=$remote active=$active" \
             "-> polkit local=$([ -n "$seat" ] && echo yes || echo no)"
    else
        warn "$u has no display (graphical) session: polkit sees no session, the answers below are for allow_any"
    fi
    role=user
    is_admin "$u" && role="admin"
    expect=no
    [ "$role" = admin ] && expect=challenge
    if [ "$rule_present" = 0 ]; then
        expect=no
    elif [ "$rule_present" = unknown ]; then
        expect=unknown
    elif [ "$CONSOLE" = true ] && [ -n "${seat:-}" ] && [ "${active:-}" = yes ]; then
        expect=upstream   # active console session: the rule leaves it to the defaults
    fi
    echo "     role: $role, expected: $expect"

    if [ "$(id -u)" = 0 ]; then
        # like tests/smoke/check-session-tgt.sh: inside the user's systemd manager
        if ! out=$(systemd-run --machine="$uid@.host" --user --wait --pipe --quiet --collect -- \
                   bash -c "$PROBE" probe "$METHODS" "$ACTIONS" 2>/dev/null); then
            bad "no systemd user manager for $u: log in over RDP first"
            return
        fi
    else
        out=$(bash -c "$PROBE" probe "$METHODS" "$ACTIONS")
    fi

    local name val word bad_list="" ok_list="" na_list="" other_list="" err_list=""
    while read -r name val; do
        case $val in
            0) word=yes ;; 1) word=no ;; 2) word=challenge ;;
            [0-9]*) word="error($val)" ;;
            *) word=$val ;;
        esac
        if [ "$word" = na ]; then
            na_list="$na_list $name"
        elif [[ $word == error* ]]; then
            err_list="$err_list $name"
        elif [ "$expect" = upstream ] || [ "$expect" = unknown ]; then
            other_list="$other_list $name=$word"
        elif [ "$word" = "$expect" ]; then
            ok_list="$ok_list $name"
        elif [ "$word" = yes ] || { [ "$word" = challenge ] && [ "$role" = user ]; }; then
            bad_list="$bad_list $name=$word"
        else
            other_list="$other_list $name=$word"
        fi
    done <<<"$out"
    [ -z "$ok_list" ] || ok "$u: $expect for$ok_list"
    [ -z "$na_list" ] || ok "$u: not supported on this host (na):$na_list"
    if [ -n "$err_list" ]; then
        bad "$u: could not query:$err_list"
        hint "busctl (systemd) and pkcheck (polkitd) installed? logind and polkitd running?"
    fi
    if [ "$expect" = upstream ] || [ "$expect" = unknown ]; then
        echo "     answers (not judged):$other_list"
    elif [ -n "$other_list" ]; then
        warn "$u: unexpected answers:$other_list"
        [ "$role" = admin ] && hint "admins get \"no\" when the rule's admin groups do not include theirs"
    fi
    if [ -n "$bad_list" ]; then
        bad "$u can use:$bad_list"
        if [ "$role" = user ]; then
            hint "challenge = possible with an admin's password; yes = without any password"
        else
            hint "yes = no password asked: a rule before ours (see above) or local console settings"
        fi
    fi
}

if [ "$(id -u)" = 0 ]; then
    users=("$@")
    if [ ${#users[@]} -eq 0 ]; then
        mapfile -t users < <(loginctl list-users --no-legend 2>/dev/null |
                             awk '$1 >= 1000 && $1 != 65534 { print $2 }')
    fi
    [ ${#users[@]} -gt 0 ] || { warn "nobody logged in: log in over RDP and run again (or name a user)"; exit $fail; }
    for u in "${users[@]}"; do check_user "$u"; done
else
    [ $# -eq 0 ] || { echo "as a user, run without arguments in a terminal of the RDP session" >&2; exit 2; }
    check_user "$(id -un)"
fi
exit $fail
