#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Print the upstream version for a CI build.
#   tag v1.2.3            -> 1.2.3                                       (stable)
#   anything else (main)  -> <changelog version>+git<UTC commit time>.<sha7>  (testing)
# Uses GITHUB_REF_TYPE / GITHUB_REF_NAME / GITHUB_SHA when set (GitHub Actions).
set -eu
if [ "${GITHUB_REF_TYPE:-}" = tag ]; then
    v=${GITHUB_REF_NAME#v}
    # Release tags only (v1.2 / v1.2.3): pre-release tags such as v1.2.3-rc1 would
    # sort above the final release once the distro suffix is appended.
    if printf '%s\n' "$v" | grep -Eqx '[0-9]+(\.[0-9]+)+'; then
        echo "$v"
        exit 0
    fi
    echo "tag $GITHUB_REF_NAME is not a release tag v<major>.<minor>[.<patch>]" >&2
    exit 2
fi
base=$(dpkg-parsechangelog -S Version)
base=${base%%[+~]*}
sha=${GITHUB_SHA:-$(git rev-parse HEAD)}
sha=$(printf '%s' "$sha" | cut -c1-7)
ts=$(TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S "$sha" 2>/dev/null || date -u +%Y%m%d%H%M%S)
echo "$base+git$ts.$sha"
