#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# third_party/fetch.sh against a throwaway sources.yml (file:// URLs, no network):
# --print, unknown name (2), sha256 mismatch (3), non-applying patch (4), the
# download cache, plus consistency checks of the real sources.yml and patch series.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need curl patch sha256sum tar

# --- fixture: a copy of fetch.sh with its own sources.yml, upstream tarball, patches
R=$T/root
mkdir -p "$R/third_party" "$R/patches/good" "$R/patches/bad" "$T/up/good-1.0" "$T/dest"
cp "$REPO/third_party/fetch.sh" "$R/third_party/"
F=$R/third_party/fetch.sh
printf 'line1\nline2\n' > "$T/up/good-1.0/file.txt"
tar czf "$T/up/good-1.0.tar.gz" -C "$T/up" good-1.0
sha=$(sha256sum "$T/up/good-1.0.tar.gz" | cut -d' ' -f1)
cat > "$R/patches/good/0001-change.patch" <<'EOF'
--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2 patched
EOF
printf '# comment\n\n0001-change.patch\n' > "$R/patches/good/series"
cat > "$R/patches/bad/0001-stale.patch" <<'EOF'
--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
 line1
-not in this release
+whatever
EOF
echo 0001-stale.patch > "$R/patches/bad/series"
cat > "$R/third_party/sources.yml" <<EOF
# test sources
good:
  version: 1.0
  url: file://$T/up/good-1.0.tar.gz
  sha256: $sha
  patches: patches/good/series
goodx:
  version: 9.9
  url: file://$T/up/other.tar.gz
  sha256: "$sha"
  patches: ""
badsha:
  version: 1.0
  url: file://$T/up/good-1.0.tar.gz
  sha256: 0000000000000000000000000000000000000000000000000000000000000000
  patches: ""
badpatch:
  version: 1.0
  url: file://$T/up/good-1.0.tar.gz
  sha256: $sha
  patches: patches/bad/series
cached:
  version: 1.0
  url: file://$T/nowhere/good-1.0.tar.gz
  sha256: $sha
  patches: ""
EOF

# --- --print
check "--print version" test "$("$F" good --print version)" = 1.0
check "--print sha256 strips quotes" test "$("$F" goodx --print sha256)" = "$sha"
check "--print url" test "$("$F" good --print url)" = "file://$T/up/good-1.0.tar.gz"
check "--print patches" test "$("$F" good --print patches)" = patches/good/series
check "--print of an empty field is empty" test -z "$("$F" goodx --print patches)"
check "keys do not leak between entries (good vs goodx)" test "$("$F" goodx --print version)" = 9.9
expect_exit 2 "unknown name exits 2" "$F" nosuch "$T/dest"
output_has "unknown name is named in the error" "unknown source 'nosuch'"
expect_exit 2 "prefix of a name is unknown (goo)" "$F" goo --print version
expect_exit 2 "--print with unknown name exits 2" "$F" nosuch --print version

# --- fetch + patch
expect_exit 0 "good source fetched and patched" "$F" good "$T/dest"
check "prints the source directory on stdout" test "$(tail -1 "$T_OUT")" = "$T/dest/good-1.0"
check "patch applied" grep -qx 'line2 patched' "$T/dest/good-1.0/file.txt"
expect_exit 0 "re-fetch into the same directory starts from a clean tree" "$F" good "$T/dest"
check "patch applied exactly once" test "$(grep -c patched "$T/dest/good-1.0/file.txt")" = 1
expect_exit 3 "sha256 mismatch exits 3" "$F" badsha "$T/dest3"
output_has "sha256 mismatch is reported" "sha256 mismatch"
expect_exit 4 "non-applying patch exits 4" "$F" badpatch "$T/dest4"
output_has "failing patch is named" "0001-stale.patch does not apply"

# --- cache ($FASTRDP_SOURCES_CACHE): no download when it holds the verified file
mkdir -p "$T/cache"
cp "$T/up/good-1.0.tar.gz" "$T/cache/"
expect_exit 0 "verified cache file is used (url unreachable)" \
    env FASTRDP_SOURCES_CACHE="$T/cache" "$F" cached "$T/dest5"
echo garbage > "$T/cache/good-1.0.tar.gz"
expect_exit 0 "corrupt cache file is downloaded again" env FASTRDP_SOURCES_CACHE="$T/cache" "$F" good "$T/dest6"
check "cache now holds the verified file" cmp "$T/cache/good-1.0.tar.gz" "$T/up/good-1.0.tar.gz"
echo garbage > "$T/cache/good-1.0.tar.gz"
expect_exit nonzero "corrupt cache + unreachable url fails" \
    env FASTRDP_SOURCES_CACHE="$T/cache" "$F" cached "$T/dest7"

# --- the real sources.yml and patch series
RF=$REPO/third_party/fetch.sh
for n in freerdp xrdp xorgxrdp; do
    check "sources.yml: $n has a version" test -n "$("$RF" "$n" --print version)"
    check "sources.yml: $n sha256 is 64 hex digits" grep -Eqx '[0-9a-f]{64}' <<<"$("$RF" "$n" --print sha256)"
    url=$("$RF" "$n" --print url)
    check "sources.yml: $n url is https and names the version" \
        bash -c '[[ $1 == https://* && $1 == *"$2"* ]]' _ "$url" "$("$RF" "$n" --print version)"
    series=$("$RF" "$n" --print patches)
    [ -n "$series" ] || continue
    check "sources.yml: $n series file exists" test -f "$REPO/$series"
    while read -r p; do
        case $p in '' | '#'*) continue ;; esac
        check "$series: $p exists" test -f "$REPO/$(dirname "$series")/$p"
    done < "$REPO/$series"
done
# Every *.patch in patches/<name>/ is in its series (a forgotten patch is never applied).
for s in "$REPO"/patches/*/series; do
    d=$(dirname "$s")
    for p in "$d"/*.patch; do
        [ -e "$p" ] || continue
        check "$(basename "$d")/$(basename "$p") is listed in its series" grep -qx "$(basename "$p")" "$s"
    done
done
finish
