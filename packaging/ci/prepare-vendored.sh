#!/bin/sh
# Assemble the build tree for a vendored dependency package.
#
#   packaging/ci/prepare-vendored.sh freerdp|xrdp <workdir>
#
# Creates <workdir>/<package>/ with
#   debian/            from packaging/<name>/debian, plus debian/vendored.mk
#   src/<upstream>/    patched upstream source(s) from third_party/fetch.sh
#   third_party/       the shared build scripts (build-<name>.sh)
# and prints that directory. Fails if packaging/<name>/debian/changelog does not
# match the upstream version(s) in third_party/sources.yml.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 freerdp|xrdp <workdir>" >&2; exit 2; }
what=$1 work=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
fetch=$root/third_party/fetch.sh

case $what in
    freerdp)
        pkg=fastrdp-freerdp3
        components=freerdp
        upstream=$("$fetch" freerdp --print version)
        ;;
    xrdp)
        pkg=fastrdp-xrdp
        components="xrdp xorgxrdp"
        upstream="$("$fetch" xrdp --print version)+xorgxrdp$("$fetch" xorgxrdp --print version)"
        ;;
    *) echo "unknown vendored package $what" >&2; exit 2 ;;
esac

mkdir -p "$work"
work=$(cd "$work" && pwd)
dir=$work/$pkg
rm -rf "$dir"
mkdir -p "$dir/src" "$dir/third_party"
cp -a "$root/packaging/$what/debian" "$dir/debian"
cp -a "$root/third_party/." "$dir/third_party/"

cv=$(cd "$dir" && dpkg-parsechangelog -S Version)
if [ "${cv%-*}" != "$upstream" ]; then
    echo "packaging/$what/debian/changelog is at ${cv%-*}, third_party/sources.yml at $upstream:" >&2
    echo "add a changelog entry for the new upstream version" >&2
    exit 1
fi

: > "$dir/debian/vendored.mk"
for c in $components; do
    src=$("$fetch" "$c" "$work/fetch")
    mv "$src" "$dir/src/$c"
    v=$("$fetch" "$c" --print version)
    printf '%s_VERSION := %s\n' "$(echo "$c" | tr '[:lower:]' '[:upper:]')" "$v" >> "$dir/debian/vendored.mk"
done
echo "$dir"
