#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Prepend a debian/changelog entry for a CI build.
#
#   packaging/ci/set-version.sh <upstream-version> <distribution> <suffix>
#
#   upstream-version  fast-rdp-server: 1.2.3 (stable, tag v1.2.3) or
#                     1.2.3+git20261019120000.abc1234 (testing, main);
#                     vendored packages: their changelog version, e.g. 3.32.2-1
#   distribution      changelog distribution: resolute, trixie, ...
#   suffix            per-distro suffix: ubuntu26.04, deb13, ... appended with "~",
#                     which sorts below everything else (stable < testing < next release)
#
# The resulting version <upstream-version>~<suffix> differs per distro, so both
# builds can share one pool in the APT repository.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <upstream-version> <distribution> <suffix>" >&2; exit 2; }
upstream=$1 dist=$2 suffix=$3

case $upstream in
    [0-9]*) ;;
    *) echo "invalid upstream version: $upstream" >&2; exit 2 ;;
esac
version="$upstream~$suffix"
maint=$(sed -n 's/^Maintainer: //p' debian/control)
srcpkg=$(sed -n 's/^Source: //p' debian/control)
date=$(date -R)

tmp=$(mktemp)
{
    printf '%s (%s) %s; urgency=medium\n\n' "$srcpkg" "$version" "$dist"
    printf '  * Automated build %s for %s.\n\n' "$upstream" "$dist"
    printf ' -- %s  %s\n\n' "$maint" "$date"
    cat debian/changelog
} > "$tmp"
mv "$tmp" debian/changelog
chmod 0644 debian/changelog
echo "debian/changelog: $version ($dist)"
