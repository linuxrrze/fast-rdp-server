#!/bin/bash
# fetch.sh NAME DESTDIR
#   Download NAME from third_party/sources.yml (or take it from $FASTRDP_SOURCES_CACHE),
#   verify its sha256, unpack it to DESTDIR/NAME-VERSION and apply patches/NAME/series.
#   Prints the source directory on stdout.
# fetch.sh NAME --print KEY
#   Print one field (version, url, sha256, patches).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SOURCES=$ROOT/third_party/sources.yml
name=${1:?usage: fetch.sh NAME DESTDIR | fetch.sh NAME --print KEY}

field() {  # field KEY -> value of NAME.KEY in sources.yml
    awk -v n="$name:" -v k="  $1:" '
        /^[^ #]/ { inblk = ($0 == n) ; next }
        inblk && index($0, k) == 1 { v = substr($0, length(k) + 1); sub(/^ +/, "", v); gsub(/"/, "", v); print v; exit }
    ' "$SOURCES"
}

version=$(field version)
[ -n "$version" ] || { echo "fetch.sh: unknown source '$name'" >&2; exit 2; }
if [ "${2:-}" = --print ]; then
    field "${3:?--print needs a key}"
    exit 0
fi
dest=${2:?usage: fetch.sh NAME DESTDIR}
url=$(field url)
sha=$(field sha256)
series=$(field patches)
file=${url##*/}

mkdir -p "$dest"
cache=${FASTRDP_SOURCES_CACHE:-$dest}
mkdir -p "$cache"
if [ ! -f "$cache/$file" ] || ! echo "$sha  $cache/$file" | sha256sum -c --quiet - 2>/dev/null; then
    curl -fsSL --retry 3 -o "$cache/$file.part" "$url"
    mv "$cache/$file.part" "$cache/$file"
fi
echo "$sha  $cache/$file" | sha256sum -c --quiet - || { echo "fetch.sh: sha256 mismatch for $file" >&2; exit 3; }

src=$dest/$name-$version
rm -rf "$src"
mkdir -p "$src"
tar xzf "$cache/$file" -C "$src" --strip-components=1

if [ -n "$series" ]; then
    pdir=$ROOT/$(dirname "$series")
    while read -r p; do
        case $p in ''|'#'*) continue ;; esac
        patch -d "$src" -p1 --forward --batch --quiet -i "$pdir/$p" >&2 \
            || { echo "fetch.sh: $p does not apply to $name $version" >&2; exit 4; }
        echo "fetch.sh: applied $p" >&2
    done < "$ROOT/$series"
fi
echo "$src"
