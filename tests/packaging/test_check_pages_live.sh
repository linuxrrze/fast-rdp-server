#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# packaging/ci/check-pages-live.sh against a file:// "site": the served tree equal to the
# deployed one passes; a stale suite (the v0.5.0 case: the stable Release of the previous
# deployment) and a missing suite fail after the timeout and are named; a site that turns
# live while waiting passes; a tree without suites is refused.
#
# Needs curl. No network, no root.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need curl cmp
C=$REPO/packaging/ci/check-pages-live.sh
export PAGES_LIVE_INTERVAL=1

suite() {  # suite TREE SUITE DATE
    mkdir -p "$1/dists/$2"
    printf 'Codename: %s\nDate: %s\nSHA256:\n abc 1 main/binary-amd64/Packages\n' "$2" "$3" > "$1/dists/$2/InRelease"
}
D=$T/deployed L=$T/live
suite "$D" resolute-stable "Wed, 21 Oct 2026 21:15:11 UTC"
suite "$D" resolute-testing "Wed, 21 Oct 2026 21:07:18 UTC"
cp -a "$D" "$L"

PAGES_LIVE_TIMEOUT=0 check "served tree equals the deployed one" "$C" "file://$L/" "$D"
output_has "names the suites" 'live at file://.*: dists/resolute-stable dists/resolute-testing'

suite "$L" resolute-stable "Wed, 21 Oct 2026 21:07:18 UTC"
PAGES_LIVE_TIMEOUT=0 expect_exit 1 "stale suite fails" "$C" "file://$L" "$D"
output_has "names the stale suite and both dates" \
    'dists/resolute-stable\(served: Wed, 21 Oct 2026 21:07:18 UTC, deployed: Wed, 21 Oct 2026 21:15:11 UTC\)'
output_lacks "current suite not named" 'dists/resolute-testing\('

cp "$D/dists/resolute-stable/InRelease" "$L/dists/resolute-stable/InRelease"
suite "$D" trixie-stable "Wed, 21 Oct 2026 21:15:11 UTC"
PAGES_LIVE_TIMEOUT=0 expect_exit 1 "suite missing on the site fails" "$C" "file://$L" "$D"
output_has "names the missing suite" 'dists/trixie-stable\(curl'

# turns live while waiting (the CDN expires the old copy)
( sleep 2; cp -a "$D/dists/trixie-stable" "$L/dists/" ) &
PAGES_LIVE_TIMEOUT=30 check "live after waiting" "$C" "file://$L" "$D"
output_has "reported while waiting" 'not live yet after [0-9]+s: dists/trixie-stable'
wait

mkdir -p "$T/empty"
expect_exit 2 "tree without suites refused" "$C" "file://$L" "$T/empty"
expect_exit 2 "usage" "$C" "file://$L"

finish
