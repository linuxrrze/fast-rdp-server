#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# test_freerdp_switches.sh [DOC...]
#   Checks every FreeRDP command-line switch in the docs (default: docs/freerdp-client.md
#   and docs/client-guide.md) against FreeRDP itself; see check_freerdp_switches.py.
#   Switch table from, in this order:
#     FREERDP_SRC=<tree>          an unpacked FreeRDP source tree;
#     FREERDP_HELP_CMD=xfreerdp3  the /help output of an installed client (checks what
#                                 that build has; sub-options from the help text);
#     otherwise                   third_party/fetch.sh freerdp (the vendored version, with
#                                 patches/freerdp/; needs network or FASTRDP_SOURCES_CACHE).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/tests/docs
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"
need python3

if [ $# -eq 0 ]; then
    set -- "$ROOT/docs/freerdp-client.md" "$ROOT/docs/client-guide.md"
fi

W=$T    # scratch directory from tests/lib.sh, removed on exit
if [ -n "${FREERDP_SRC:-}" ]; then
    mode=(--src "$FREERDP_SRC")
elif [ -n "${FREERDP_HELP_CMD:-}" ]; then
    "$FREERDP_HELP_CMD" /help > "$W/help.txt" 2>/dev/null || true
    grep -q -- '/kerberos' "$W/help.txt" || { echo "FAIL $FREERDP_HELP_CMD /help printed no switch list"; exit 1; }
    mode=(--help-text "$W/help.txt")
else
    need curl patch tar sha256sum
    src=$("$ROOT/third_party/fetch.sh" freerdp "$W" 2>/dev/null) \
        || { echo "FAIL third_party/fetch.sh freerdp (network, or set FASTRDP_SOURCES_CACHE)"; exit 1; }
    mode=(--src "$src")
fi

python3 -I "$HERE/check_freerdp_switches.py" "${mode[@]}" --self-test "$@"
