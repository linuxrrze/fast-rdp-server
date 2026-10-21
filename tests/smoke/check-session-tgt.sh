#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Does the Kerberos TGT of an RDP login reach the desktop's processes? (backlog K1)
# Run after logging in over RDP with a password (NLA with delegated/typed password, or
# TLS), with each desktop (xfce/wlroots via xrdp, gnome, plasma):
#   sudo tests/smoke/check-session-tgt.sh [-s SPN]... USER   as root, session running:
#        host settings, the user manager's environment (systemd user services, D-Bus
#        activated apps of GNOME/Plasma), the environment of the desktop's processes,
#        and klist/kvno run inside the user's systemd manager
#   tests/smoke/check-session-tgt.sh [-s SPN]...             as the user, in a terminal
#        of the session: the same, with this terminal's environment
# -s SPN: also get a service ticket for SPN (e.g. HTTP/intranet.example.com for
# Firefox SPNEGO, cifs/files.example.com for smbclient -k / gio smb); default
# host/<this host's FQDN>.
# Prints ok/WARN/FAIL lines with a hint; exit status 1 if any check failed.
set -uo pipefail

SPNS=()
while getopts "s:h" opt; do
    case $opt in
        s) SPNS+=("$OPTARG") ;;
        *) sed -n '4,16p' "$0"; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ ${#SPNS[@]} -gt 0 ] || SPNS=("host/$(hostname -f)")

fail=0
ok()   { echo "ok   $*"; }
warn() { echo "WARN $*"; }
bad()  { echo "FAIL $*"; fail=1; }
hint() { echo "     -> $*"; }

if [ "$(id -u)" = 0 ]; then
    U=${1:?usage: $0 [-s SPN]... USER (as root) or no USER as the user in the session}
    UID_=$(id -u "$U") || { bad "no such user: $U"; exit 1; }
    MODE="the user's systemd manager"
    # Like the broker's sysutil.run_as_user: the manager's environment, not root's.
    as_user() { systemd-run --machine="$UID_@.host" --user --wait --pipe --quiet --collect -- "$@"; }
    if ! as_user true 2>/dev/null; then
        bad "no systemd user manager for $U (uid $UID_): log in over RDP first"
        exit 1
    fi
else
    U=$(id -un)
    UID_=$(id -u)
    MODE="this terminal (KRB5CCNAME=${KRB5CCNAME:-unset})"
    as_user() { "$@"; }
fi
SHORT=${U%%@*}
echo "--- user $U (uid $UID_), commands run in $MODE"

# ---------------------------------------------------------------- host settings
if grep -Eqs '^[[:space:]]*default_ccache_name[[:space:]]*=[[:space:]]*KCM:[[:space:]]*$' /etc/krb5.conf.d/fastrdp; then
    ok "default_ccache_name = KCM: (/etc/krb5.conf.d/fastrdp)"
else
    bad "/etc/krb5.conf.d/fastrdp has no default_ccache_name = KCM:"
    hint "re-run the deployment (identity role writes it)"
fi
if systemctl is-active --quiet sssd-kcm.socket 2>/dev/null || systemctl is-active --quiet sssd-kcm.service 2>/dev/null; then
    ok "sssd-kcm socket/service active"
else
    bad "sssd-kcm is not active: KCM: caches cannot be used"
    hint "systemctl enable --now sssd-kcm.socket"
fi
# sssd follows default_ccache_name unless sssd.conf sets krb5_ccname_template.
sssd_files=(/etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)
if [ -r /etc/sssd/sssd.conf ]; then
    tmpl=$(grep -Ehs '^[[:space:]]*krb5_ccname_template[[:space:]]*=' "${sssd_files[@]}" | sed 's/^[^=]*=[[:space:]]*//' | sort -u)
    if [ -z "$tmpl" ] || [ "$tmpl" = "KCM:" ]; then
        ok "sssd krb5_ccname_template: ${tmpl:-unset (follows krb5.conf: KCM:)}"
    else
        bad "sssd krb5_ccname_template = $tmpl: pam_sss stores TGTs where the session does not look"
        hint "remove krb5_ccname_template from /etc/sssd/sssd.conf and conf.d, then systemctl restart sssd"
    fi
else
    echo "skip sssd.conf not readable (run as root to check krb5_ccname_template)"
fi
# KRB5CCNAME set for every login would override KCM: for some processes only.
envset=$(grep -Els '^[[:space:]]*(export[[:space:]]+)?KRB5CCNAME' /etc/environment /etc/security/pam_env.conf \
         /etc/environment.d/*.conf /etc/profile /etc/profile.d/*.sh 2>/dev/null | tr '\n' ' ')
if [ -z "$envset" ]; then
    ok "KRB5CCNAME not set in /etc/environment, pam_env.conf, environment.d, profile"
else
    bad "KRB5CCNAME set in $envset"
    hint "remove it: fastrdp relies on default_ccache_name = KCM: for every process"
fi
leftover=$(find /tmp -maxdepth 1 -name "krb5cc_${UID_}_*" -user "$UID_" 2>/dev/null | head -3 | tr '\n' ' ')
[ -z "$leftover" ] || warn "FILE caches from an sssd FILE template: $leftover(unused by KCM sessions)"

# ---------------------------------------------------------------- environments
if [ "$(id -u)" = 0 ]; then
    mgr=$(systemctl --user --machine="$UID_@.host" show-environment 2>/dev/null | sed -n 's/^KRB5CCNAME=//p')
    case $mgr in
        ""|KCM:*) ok "user manager (systemd user services, D-Bus activation): KRB5CCNAME=${mgr:-unset}" ;;
        *) bad "user manager has KRB5CCNAME=$mgr: user services use another cache than KCM:"
           hint "systemctl --user -M $UID_@ unset-environment KRB5CCNAME; find who imports it (pam_sss FILE template?)" ;;
    esac
fi
# The desktop's processes (whichever are running): their KRB5CCNAME from /proc.
procs="gnome-shell gnome-session-binary gnome-terminal-server plasmashell kwin_wayland startplasma-wayland
       konsole krdpserver xfce4-session xfce4-panel xfce4-terminal xfdesktop sway labwc wayfire
       xrdp-chansrv nautilus dolphin thunar firefox firefox-esr"
seen=0
for name in $procs; do
    for pid in $(pgrep -u "$UID_" -x "$name" 2>/dev/null | head -1); do
        seen=1
        val=$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sed -n 's/^KRB5CCNAME=//p')
        case $val in
            ""|KCM:*) ok "$name ($pid): KRB5CCNAME=${val:-unset} -> KCM" ;;
            *) bad "$name ($pid): KRB5CCNAME=$val (not the KCM collection the rest of the session uses)"
               hint "sssd FILE template or a profile script sets it; see the host checks above" ;;
        esac
    done
done
[ "$seen" = 1 ] || warn "no desktop process of $U found: is the RDP session running?"
if [ "$(id -u)" != 0 ]; then
    case ${KRB5CCNAME:-} in
        ""|KCM:*) ok "this terminal: KRB5CCNAME=${KRB5CCNAME:-unset}" ;;
        *) bad "this terminal: KRB5CCNAME=$KRB5CCNAME" ;;
    esac
fi

# ---------------------------------------------------------------- tickets
list=$(as_user klist -l 2>&1)
echo "--- klist -l ($MODE)"
while IFS= read -r line; do echo "     $line"; done <<<"$list"
primary=$(as_user klist 2>&1)
pcache=$(sed -n 's/^Ticket cache: //p' <<<"$primary" | head -1)
pprinc=$(sed -n 's/^Default principal: //p' <<<"$primary" | head -1)
case $pcache in
    KCM:*) ok "default cache is in KCM: $pcache" ;;
    "") bad "no default credential cache: $(head -1 <<<"$primary")"
        hint "no TGT: log in over RDP with a password (GNOME/Plasma: broker log 'Kerberos TGT stored'), or kinit" ;;
    *) bad "default cache $pcache is not KCM" ;;
esac
if [ -n "$pprinc" ]; then
    if as_user klist -s; then
        ok "primary cache has a valid TGT ($pprinc)"
    else
        bad "primary cache's TGT ($pprinc) expired or missing"
        hint "journalctl -u fastrdp-brokerd | grep -i tgt; sssd offline? kinit to get a new one"
    fi
    pname=${pprinc%@*}
    pname=${pname//\\/}
    if [ "${pname,,}" = "${SHORT,,}" ] || [ "${pname,,}" = "${U,,}" ]; then
        ok "primary principal is the login's ($pprinc)"
    else
        warn "primary principal $pprinc is not $SHORT@REALM (another kinit? UPN?): apps use it by default"
        hint "kswitch -p <your principal>; the broker switches back at the next GNOME/Plasma login"
    fi
    for spn in "${SPNS[@]}"; do
        if out=$(as_user kvno "$spn" 2>&1); then
            ok "service ticket for $spn (GSSAPI apps: Firefox negotiate, smbclient -k, ssh -K)"
        else
            bad "kvno $spn: $out"
        fi
    done
fi

# ---------------------------------------------------------------- reminder (K4)
# tgt-notify warns before the TGT can no longer be renewed (renew-until, default 7 days
# after the last password login). docs/nfs-kerberos-homes.md#long-running-sessions
NOTIFY=/usr/libexec/fastrdp/tgt-notify
if [ ! -x "$NOTIFY" ]; then
    warn "$NOTIFY missing: no reminder before the TGT can no longer be renewed (fastrdp-session, desktops role)"
elif grep -Eqs '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*false' /etc/fastrdp/tgt-notify.conf; then
    warn "reminder off (/etc/fastrdp/tgt-notify.conf: enabled = false; fastrdp_tgt_notify)"
else
    [ -f /etc/xdg/autostart/fastrdp-tgt-notify.desktop ] \
        || bad "/etc/xdg/autostart/fastrdp-tgt-notify.desktop missing: sessions do not start the reminder"
    if pgrep -u "$UID_" -f "$NOTIFY" >/dev/null 2>&1; then
        ok "reminder running in $U's session ($(pgrep -u "$UID_" -f "$NOTIFY" | wc -l) process(es), one per session bus)"
    else
        warn "no reminder process of $U (started by XDG autostart or wlroots-in-x when the desktop starts)"
    fi
    command -v notify-send >/dev/null 2>&1 || command -v gdbus >/dev/null 2>&1 \
        || bad "neither notify-send (libnotify-bin) nor gdbus: the reminder cannot show anything"
    if st=$(as_user "$NOTIFY" --status 2>&1); then
        ok "reminder status: $st"
    else
        bad "$NOTIFY --status: $st"
    fi
fi

# ---------------------------------------------------------------- applications
# Browsers for Kerberos SSO (backlog K9, docs/desktop-matrix.md#browsers-and-kerberos-sso)
for s in firefox chromium; do
    if [ -x "/snap/bin/$s" ] && snap list "$s" >/dev/null 2>&1; then
        warn "$s is a snap: snapd lets snaps reach only FILE/DIR caches in /tmp (kerberos-tickets interface), not the KCM socket; SPNEGO will not find the TGT"
        hint "a .deb browser (Ansible: fastrdp_firefox_deb: true) or Flathub's Firefox; snap remove $s when unused"
    fi
done
if command -v firefox-esr >/dev/null 2>&1 || dpkg-query -W -f='${Version}' firefox 2>/dev/null | grep -qv snap; then
    ok "Firefox from a .deb installed (uses the system's GSSAPI library and KCM)"
fi
if command -v flatpak >/dev/null 2>&1 && flatpak info org.mozilla.firefox >/dev/null 2>&1; then
    if flatpak info --show-permissions org.mozilla.firefox 2>/dev/null | grep -q 'heim_org.h5l.kcm-socket'; then
        ok "Flatpak Firefox can reach the KCM socket"
    else
        warn "Flatpak Firefox without access to /run/.heim_org.h5l.kcm-socket (overridden?)"
        hint "flatpak override --reset org.mozilla.firefox, or --filesystem=/run/.heim_org.h5l.kcm-socket"
    fi
fi
if [ -r /etc/firefox/policies/policies.json ] && grep -q '"SPNEGO"' /etc/firefox/policies/policies.json; then
    ok "Firefox SPNEGO domains set (/etc/firefox/policies/policies.json)"
elif command -v firefox >/dev/null 2>&1 || command -v firefox-esr >/dev/null 2>&1; then
    warn "no Firefox SPNEGO policy: Firefox sends Kerberos tickets to no site"
    hint "Ansible: fastrdp_browser_spnego_domains: [example.com]"
fi
home=$(getent passwd "$U" | cut -d: -f6)
if [ -n "$home" ] && findmnt -n -T "$home" -o FSTYPE,OPTIONS 2>/dev/null | grep -Eq '^nfs4? .*sec=krb5'; then
    if as_user test -r "$home"; then
        ok "Kerberized NFS home $home readable by the session (rpc.gssd/gssproxy found credentials)"
    else
        bad "Kerberized NFS home $home not readable from the session"
        hint "docs/nfs-kerberos-homes.md (Q3/Q5)"
    fi
fi
exit $fail
