#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# wlroots desktops in xrdp sessions: runs broker/session/libexec/wlroots-in-x for each
# compositor on an Xvfb display (stand-in for the xorgxrdp display) and checks:
#   - the compositor starts on the X11 backend and its socket is found,
#   - its output and X window follow the X root size,
#   - the clipboard bridge works both ways,
#   - a stale wayland-N socket from a crashed session does not confuse the launcher.
#
# Needs: xvfb xwayland x11-utils x11-xkb-utils xclip wl-clipboard wlr-randr and the
# compositors to test (default: labwc sway wayfire; missing ones are skipped).
# TEST_ENV=file is sourced first (used to point at extracted packages in CI sandboxes).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LAUNCHER=$HERE/../../broker/session/libexec/wlroots-in-x
export FASTRDP_LIBEXEC=$HERE/../../broker/session/libexec
[ -n "${TEST_ENV:-}" ] && . "$TEST_ENV"
COMPOSITORS=${COMPOSITORS:-labwc sway wayfire}
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

run_one() { # compositor display width height [compositor args...]
    local comp=$1 disp=$2 w=$3 h=$4; shift 4
    local rt; rt=$(mktemp -d /tmp/fastrdp-wl.XXXXXX); chmod 700 "$rt"
    # shellcheck disable=SC2086 # XVFB_WRAP/XVFB_ARGS are intentionally word-split
    ${XVFB_WRAP:-} Xvfb ":$disp" -screen 0 "${w}x${h}x24" -nolisten tcp ${XVFB_ARGS:-} >"$rt/xvfb.log" 2>&1 &
    local xpid=$!
    sleep 2
    (
        export DISPLAY=":$disp" XDG_RUNTIME_DIR=$rt
        "$LAUNCHER" "$comp" "$@" >"$rt/comp.log" 2>&1 &
        local lpid=$!
        sleep "${START_WAIT:-7}"
        local sock size
        sock=""
        for f in "$rt"/wayland-[0-9]*; do [ -S "$f" ] && { sock=$(basename "$f"); break; }; done
        size=$(WAYLAND_DISPLAY=$sock wlr-randr 2>/dev/null | awk '/current/{print $1; exit}')
        if [ -n "$sock" ] && kill -0 $lpid 2>/dev/null; then ok "$comp: running ($sock)"; else bad "$comp: not running"; tail -5 "$rt/comp.log"; fi
        [ "$size" = "${w}x${h}" ] && ok "$comp: output follows X root ($size)" || bad "$comp: output $size != ${w}x${h}"
        printf 'rdp-%s' "$RANDOM" >"$rt/x"
        xclip -selection clipboard -i <"$rt/x" & sleep 2
        [ "$(WAYLAND_DISPLAY=$sock wl-paste --no-newline 2>/dev/null)" = "$(cat "$rt/x")" ] \
            && ok "$comp: clipboard X -> Wayland" || bad "$comp: clipboard X -> Wayland"
        printf 'wl-%s' "$RANDOM" >"$rt/w"
        WAYLAND_DISPLAY=$sock wl-copy <"$rt/w"; sleep 2
        [ "$(xclip -selection clipboard -o 2>/dev/null)" = "$(cat "$rt/w")" ] \
            && ok "$comp: clipboard Wayland -> X" || bad "$comp: clipboard Wayland -> X"
        # Crash the compositor (stale socket stays) and start again in the same runtime dir.
        pkill -9 -x "$comp"; kill $lpid 2>/dev/null; wait $lpid 2>/dev/null
        "$LAUNCHER" "$comp" "$@" >"$rt/comp2.log" 2>&1 &
        lpid=$!
        sleep "${START_WAIT:-7}"
        if kill -0 $lpid 2>/dev/null && ! grep -q "did not create" "$rt/comp2.log"; then
            ok "$comp: restarts over a stale socket"
        else
            bad "$comp: restart over stale socket"; tail -3 "$rt/comp2.log"
        fi
        kill $lpid 2>/dev/null; pkill -x "$comp"; pkill -f clipboard-bridge; pkill -f libexec/tgt-notify
    )
    kill $xpid 2>/dev/null
    wait $xpid 2>/dev/null
    rm -rf "$rt"
}

d=70
for comp in $COMPOSITORS; do
    if ! command -v "$comp" >/dev/null; then echo "skip $comp (not installed)"; continue; fi
    d=$((d + 1))
    # shellcheck disable=SC2086 # per-compositor extra args from TEST_ENV
    case $comp in
        sway)    run_one sway $d 1600 900 ${SWAY_ARGS:-} ;;
        labwc)   run_one labwc $d 1920 1080 ${LABWC_ARGS:-} ;;
        wayfire) run_one wayfire $d 1366 768 ${WAYFIRE_ARGS:-} ;;
    esac
done
exit $fail
