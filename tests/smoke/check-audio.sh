#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Is audio (and the microphone) wired up for an RDP session? (backlog A1, docs/audio.md)
# Run while the user's session is connected, with "play on this computer" (and "record
# from this computer") chosen in the client:
#   sudo tests/smoke/check-audio.sh USER   as root: host settings, then PipeWire queries
#        inside the user's systemd manager (the PipeWire the session uses)
#   tests/smoke/check-audio.sh             as the user, in a terminal of the session
# Read-only: package and file checks, systemctl is-active, pw-cli ls, pactl info/list.
# Expected: xrdp sessions (X11 and wlroots desktops) have the nodes xrdp-sink and, unless
# fastrdp_audio_input is false, xrdp-source, with xrdp-sink the default sink; GNOME
# sessions have a sink (a real one or pipewire-pulse's auto_null) and, while the client
# offers its microphone, grd_remote_audio_source. Plasma (KRdp) has no audio.
# Prints ok/WARN/FAIL lines with a hint; exit status 1 if any check failed.
set -uo pipefail

case ${1:-} in -h|--help) sed -n '4,15p' "$0"; exit 0 ;; esac

LOADER=/usr/libexec/pipewire-module-xrdp/load_pw_modules.sh
UPSTREAM_AUTOSTART=/etc/xdg/autostart/pipewire-xrdp.desktop

fail=0
ok()   { echo "ok   $*"; }
warn() { echo "WARN $*"; }
bad()  { echo "FAIL $*"; fail=1; }
hint() { echo "     -> $*"; }

if [ "$(id -u)" = 0 ]; then
    U=${1:?usage: $0 USER (as root) or no USER as the user in the session}
    UID_=$(id -u "$U") || { bad "no such user: $U"; exit 1; }
    MODE="the user's systemd manager"
    as_user() { systemd-run --machine="$UID_@.host" --user --wait --pipe --quiet --collect -- "$@"; }
    user_ctl() { systemctl --user --machine="$UID_@.host" "$@"; }
    if ! as_user true 2>/dev/null; then
        bad "no systemd user manager for $U (uid $UID_): log in over RDP first"
        exit 1
    fi
else
    U=$(id -un)
    UID_=$(id -u)
    MODE="this terminal"
    as_user() { "$@"; }
    user_ctl() { systemctl --user "$@"; }
fi
echo "--- user $U (uid $UID_), commands run in $MODE"

installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed'; }

# ---------------------------------------------------------------- host settings
rdpsnd=$(sed -n 's/^rdpsnd=//p' /etc/xrdp/xrdp.ini 2>/dev/null | head -1)
input=$(sed -n 's/^FASTRDP_AUDIO_INPUT=//p' /etc/xrdp/sesman.ini 2>/dev/null | head -1)
case $rdpsnd in
    true) ok "xrdp.ini rdpsnd=true (audio out offered to xrdp sessions)" ;;
    false) warn "xrdp.ini rdpsnd=false: no audio in xrdp sessions (fastrdp_audio: false)" ;;
    *) warn "xrdp.ini has no rdpsnd= line (xrdp not deployed here?)" ;;
esac
echo "     microphone in xrdp sessions: ${input:-not set} (sesman.ini FASTRDP_AUDIO_INPUT, fastrdp_audio_input)"
if [ "$rdpsnd" = true ]; then
    missing=""
    for p in pipewire pipewire-bin wireplumber pipewire-pulse pipewire-module-xrdp pulseaudio-utils; do
        installed "$p" || missing="$missing $p"
    done
    if [ -z "$missing" ]; then
        ok "PipeWire and pipewire-module-xrdp installed"
    else
        bad "missing packages:$missing"
        hint "re-run the deployment (xrdp role, fastrdp_audio: true); Ubuntu: universe enabled?"
    fi
    if [ -x "$LOADER" ]; then ok "module loader $LOADER present"; else bad "$LOADER missing"; fi
    if [ -x /usr/libexec/fastrdp/xrdp-audio ] && [ -f /etc/xdg/autostart/fastrdp-xrdp-audio.desktop ]; then
        ok "fastrdp's loader and its autostart entry present (xrdp-audio)"
    else
        bad "/usr/libexec/fastrdp/xrdp-audio or /etc/xdg/autostart/fastrdp-xrdp-audio.desktop missing"
        hint "fastrdp-session package (APT install method) or the xrdp role (build)"
    fi
    hidden=false
    grep -qs '^Hidden=true' "$UPSTREAM_AUTOSTART" && hidden=true
    if [ "$input" = false ] && [ "$hidden" != true ]; then
        bad "$UPSTREAM_AUTOSTART is active although FASTRDP_AUDIO_INPUT=false: it loads the microphone too"
        hint "re-run the deployment (xrdp role hides it with Hidden=true)"
    elif [ "$input" != false ] && [ "$hidden" = true ]; then
        warn "$UPSTREAM_AUTOSTART hidden: fastrdp's entry loads the module instead (fine, but fastrdp_audio_input was false once)"
    else
        ok "module loaded by $([ "$hidden" = true ] && echo "fastrdp's autostart entry (sink-only)" || echo "the package's autostart entry")"
    fi
fi

# ---------------------------------------------------------------- the user's session
kind=""
if pgrep -u "$UID_" -x xrdp-chansrv >/dev/null 2>&1; then
    kind=xrdp
elif pgrep -u "$UID_" -f gnome-remote-desktop-daemon >/dev/null 2>&1; then
    kind=gnome
elif pgrep -u "$UID_" -x krdpserver >/dev/null 2>&1; then
    kind=plasma
fi
case $kind in
    xrdp) ok "xrdp session of $U (xrdp-chansrv running)" ;;
    gnome) ok "GNOME session of $U (gnome-remote-desktop running)" ;;
    plasma) warn "Plasma (KRdp) session of $U: KRdp has no audio; use plasma-x11 (xrdp) for audio"
            exit $fail ;;
    *) warn "no RDP session of $U found (xrdp-chansrv, gnome-remote-desktop, krdpserver): checking PipeWire anyway" ;;
esac

for unit in pipewire.service wireplumber.service pipewire-pulse.service; do
    state=$(user_ctl is-active "$unit" 2>/dev/null)
    case $state in
        active) ok "$unit active in the user manager" ;;
        *) if [ "$unit" = pipewire-pulse.service ]; then
               warn "$unit ${state:-unknown}: PulseAudio applications (and pactl) find no server"
           else
               bad "$unit ${state:-unknown}"
           fi
           hint "systemctl --user status $unit (socket activated: pipewire.socket, pipewire-pulse.socket)" ;;
    esac
done

if ! command -v pw-cli >/dev/null 2>&1; then
    bad "pw-cli not installed (pipewire-bin): cannot list the nodes"
    exit 1
fi
nodes=$(as_user pw-cli ls Node 2>&1 | sed -n 's/.*node\.name = "\([^"]*\)".*/\1/p' | sort -u)
echo "--- PipeWire nodes ($MODE)"
while IFS= read -r n; do [ -n "$n" ] && echo "     $n"; done <<<"$nodes"
has_node() { grep -qx "$1" <<<"$nodes"; }

if [ "$kind" = xrdp ] || { [ -z "$kind" ] && has_node xrdp-sink; }; then
    if has_node xrdp-sink; then
        ok "xrdp-sink present (audio out to the client)"
    else
        bad "no xrdp-sink: the PipeWire xrdp module is not loaded"
        hint "pgrep -af libpipewire-module-xrdp; run $LOADER -l in a session terminal (log in /tmp/xrdp_pipewire_*.log)"
        hint "wlroots desktops: wlroots-in-x starts it; other desktops: XDG autostart entries above"
    fi
    if has_node xrdp-source; then
        if [ "$input" = false ]; then
            bad "xrdp-source present although FASTRDP_AUDIO_INPUT=false"
            hint "someone loaded the module with a source (the user can; a default, not a policy)"
        else
            ok "xrdp-source present (microphone, used when the client offers it)"
        fi
    elif [ "$input" = false ]; then
        ok "no xrdp-source (fastrdp_audio_input: false, sink-only)"
    else
        warn "no xrdp-source: applications cannot record from the client's microphone"
    fi
    if pgrep -u "$UID_" -f libpipewire-module-xrdp >/dev/null 2>&1; then
        ok "module process running (pw-cli load-module libpipewire-module-xrdp)"
    else
        warn "no pw-cli process holding libpipewire-module-xrdp"
    fi
fi
if [ "$kind" = gnome ]; then
    if as_user pactl list short sinks 2>/dev/null | grep -q .; then
        ok "a sink exists for gnome-remote-desktop to capture"
    else
        bad "no sink: gnome-remote-desktop has nothing to send (audio out silent)"
        hint "install pipewire-pulse (gnome_rd role, fastrdp_audio: true): module-always-sink adds auto_null"
    fi
    if has_node grd_remote_audio_source; then
        ok "grd_remote_audio_source present (client microphone)"
    else
        warn "no grd_remote_audio_source: the client does not offer its microphone (or g-r-d < 46)"
    fi
fi

if command -v pactl >/dev/null 2>&1; then
    info=$(as_user pactl info 2>/dev/null)
    sink=$(sed -n 's/^Default Sink: //p' <<<"$info")
    source=$(sed -n 's/^Default Source: //p' <<<"$info")
    if [ -z "$info" ]; then
        warn "pactl info failed: no PulseAudio server (pipewire-pulse)"
    else
        echo "     default sink: ${sink:-none}, default source: ${source:-none}"
        if [ "$kind" = xrdp ] && [ "$sink" != xrdp-sink ]; then
            warn "default sink is ${sink:-none}, not xrdp-sink: applications play elsewhere"
            hint "pactl set-default-sink xrdp-sink (the loader does this when pactl is installed)"
        fi
    fi
else
    warn "pactl not installed (pulseaudio-utils): the loader cannot make xrdp-sink the default"
fi
echo "     more: journalctl -t xrdp-chansrv (negotiated format), pw-top while something plays"
exit $fail
