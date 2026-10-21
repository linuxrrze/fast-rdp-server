#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# After a Pages deployment: wait until the site serves the deployed APT repository, i.e.
# every dists/<suite>/InRelease of the deployed tree is byte-identical at the public URL
# (InRelease carries the date and the hashes of all indexes, so one stale or missing
# suite shows). A deployment that reports success but never goes live, or a stale CDN,
# fails the job instead of the next ansible run on a host.
#
#   packaging/ci/check-pages-live.sh <url> <site-dir>
#
# Environment:
#   PAGES_LIVE_TIMEOUT   seconds to wait in total (default 900: the CDN caches 10 minutes)
#   PAGES_LIVE_INTERVAL  seconds between attempts (default 30)
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <url> <site-dir>" >&2; exit 2; }
url=${1%/} site=$2
timeout=${PAGES_LIVE_TIMEOUT:-900}
interval=${PAGES_LIVE_INTERVAL:-30}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

suites=$(cd "$site" && find dists -mindepth 2 -maxdepth 2 -name InRelease -printf '%h\n' | sort)
[ -n "$suites" ] || { echo "no dists/*/InRelease in $site" >&2; exit 2; }

start=$(date +%s)
while :; do
    stale=
    for s in $suites; do
        if ! curl -fsS --retry 2 -o "$work/InRelease" "$url/$s/InRelease" 2>"$work/err"; then
            stale="$stale $s($(tr '\n' ' ' < "$work/err" | sed 's/ *$//'))"
        elif ! cmp -s "$work/InRelease" "$site/$s/InRelease"; then
            stale="$stale $s(served: $(sed -n 's/^Date: //p' "$work/InRelease"), deployed: $(sed -n 's/^Date: //p' "$site/$s/InRelease"))"
        fi
    done
    if [ -z "$stale" ]; then
        echo "live at $url: $(printf '%s' "$suites" | tr '\n' ' ')"
        exit 0
    fi
    waited=$(($(date +%s) - start))
    if [ "$waited" -ge "$timeout" ]; then
        echo "::error::$url does not serve the deployed tree after ${waited}s:$stale" >&2
        exit 1
    fi
    echo "not live yet after ${waited}s:$stale"
    sleep "$interval"
done
