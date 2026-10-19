#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Corresponding source for a vendored binary package (GPL-3.0 §6, see docs/licensing.md).
#
#   packaging/ci/make-source-archive.sh <prepared-tree> <outdir>
#
# <prepared-tree> is the directory printed by prepare-vendored.sh, after
# set-version.sh and BEFORE dpkg-buildpackage (so it holds no build products):
# patched upstream source, debian/ and the build scripts, i.e. everything needed
# to rebuild the .deb. Writes <outdir>/<package>_<version>/ with
#   <package>_<version>.source.tar.xz   that tree (rebuild: dpkg-buildpackage -b)
#   upstream/<tarball>                  the pristine upstream release(s)
#   patches/<name>/                     the patch series applied to them
#   SHA256SUMS
# Upstream tarballs are taken from $FASTRDP_SOURCES_CACHE if set, else downloaded.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <prepared-tree> <outdir>" >&2; exit 2; }
tree=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
fetch=$root/third_party/fetch.sh

pkg=$(cd "$tree" && dpkg-parsechangelog -S Source)
ver=$(cd "$tree" && dpkg-parsechangelog -S Version)
# (no -maxdepth: compiled objects are deep in src/<name>/)
if [ -n "$(find "$tree" \( -name '*.o' -o -path '*/debian/tmp' -o -path '*/obj-*' \) -print -quit)" ]; then
    echo "$tree contains build products; run this before dpkg-buildpackage" >&2
    exit 1
fi

name=${pkg}_${ver}
out=$out/$name
rm -rf "$out"
mkdir -p "$out"
tar -C "$(dirname "$tree")" --sort=name --owner=0 --group=0 --numeric-owner \
    --transform "s|^$(basename "$tree")|$name|" -cJf "$out/$name.source.tar.xz" "$(basename "$tree")"

mkdir -p "$out/upstream" "$out/patches"
for d in "$tree"/src/*/; do
    c=$(basename "$d")
    url=$("$fetch" "$c" --print url)
    sha=$("$fetch" "$c" --print sha256)
    file=${url##*/}
    if [ -n "${FASTRDP_SOURCES_CACHE:-}" ] && [ -f "$FASTRDP_SOURCES_CACHE/$file" ]; then
        cp "$FASTRDP_SOURCES_CACHE/$file" "$out/upstream/$file"
    else
        curl -fsSL --retry 3 -o "$out/upstream/$file" "$url"
    fi
    echo "$sha  $out/upstream/$file" | sha256sum -c --quiet -
    series=$("$fetch" "$c" --print patches)
    if [ -n "$series" ]; then
        pdir=$(dirname "$series")
        mkdir -p "$out/patches/$c"
        cp "$root/$series" "$out/patches/$c/series"
        grep -v '^[[:space:]]*\(#\|$\)' "$root/$series" | while read -r p; do
            cp "$root/$pdir/$p" "$out/patches/$c/"
        done
    fi
done
(cd "$out" && find . -type f | sort | xargs sha256sum > "$out.sums" && mv "$out.sums" SHA256SUMS)
echo "$out/$name.source.tar.xz"
