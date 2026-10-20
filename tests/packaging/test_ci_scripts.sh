#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# packaging/ci helpers, hermetic (small fake upstream tarballs, file:// URLs):
#   check-build-deps.sh   negative case and version constraints
#   prepare-vendored.sh   tree layout, changelog/sources.yml mismatch refused
#   set-version.sh        changelog entry, version ordering stable < testing < next
#   upstream-version.sh   tag and main versions, pre-release tags refused
#   make-source-archive.sh  contents, SHA256SUMS, reproducible, refuses build products
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need dpkg-parsechangelog dpkg curl tar xz sha256sum patch

# --- a copy of the repository parts the scripts use, with a fake sources.yml
C=$T/repo
mkdir -p "$C/third_party" "$C/packaging/ci" "$C/packaging/freerdp" "$C/packaging/xrdp" "$C/patches/freerdp" "$T/up"
cp "$REPO"/packaging/ci/*.sh "$C/packaging/ci/"
cp "$REPO"/third_party/*.sh "$C/third_party/"
cp -a "$REPO/packaging/freerdp/debian" "$C/packaging/freerdp/"
cp -a "$REPO/packaging/xrdp/debian" "$C/packaging/xrdp/"
RF=$REPO/third_party/fetch.sh
fv=$("$RF" freerdp --print version)
xv=$("$RF" xrdp --print version)
gv=$("$RF" xorgxrdp --print version)
mkfake() {  # mkfake NAME VERSION -> fake upstream tarball NAME-VERSION.tar.gz
    mkdir -p "$T/up/$1-$2"
    printf 'line1\nline2\n' > "$T/up/$1-$2/file.txt"
    tar czf "$T/up/$1-$2.tar.gz" -C "$T/up" "$1-$2"
    rm -rf "${T:?}/up/$1-$2"
    sha256sum "$T/up/$1-$2.tar.gz" | cut -d' ' -f1
}
cat > "$C/patches/freerdp/0001-change.patch" <<'EOF'
--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2 patched
EOF
printf '# fake\n0001-change.patch\n' > "$C/patches/freerdp/series"
writesources() {  # writesources FREERDP_VERSION
    cat > "$C/third_party/sources.yml" <<EOF
freerdp:
  version: $1
  url: file://$T/up/freerdp-$fv.tar.gz
  sha256: $(mkfake freerdp "$fv")
  patches: patches/freerdp/series
xrdp:
  version: $xv
  url: file://$T/up/xrdp-$xv.tar.gz
  sha256: $(mkfake xrdp "$xv")
  patches: ""
xorgxrdp:
  version: $gv
  url: file://$T/up/xorgxrdp-$gv.tar.gz
  sha256: $(mkfake xorgxrdp "$gv")
  patches: ""
EOF
}
writesources "$fv"

# --- check-build-deps.sh
CB=$C/packaging/ci/check-build-deps.sh
expect_exit 0 "check-build-deps: the real control files pass" "$CB"
sed -i 's/^ libssl-dev,$/ libssl-dev (>= 3.0),/' "$C/packaging/freerdp/debian/control"
expect_exit 0 "check-build-deps: version constraints are ignored" "$CB"
sed -i '/^ cmake,$/d' "$C/packaging/freerdp/debian/control"
sed -i '/^ nasm,$/d' "$C/packaging/xrdp/debian/control"
expect_exit 1 "check-build-deps: a missing Build-Depends fails" "$CB"
output_has "check-build-deps: names the FreeRDP dependency" "freerdp/debian/control: Build-Depends lacks cmake"
output_has "check-build-deps: names the xrdp dependency" "xrdp/debian/control: Build-Depends lacks nasm"
cp "$REPO/packaging/freerdp/debian/control" "$C/packaging/freerdp/debian/control"
cp "$REPO/packaging/xrdp/debian/control" "$C/packaging/xrdp/debian/control"
sed -i 's/^DEPS="build-essential /DEPS="libnewthing-dev build-essential /' "$C/third_party/build-freerdp.sh"
expect_exit 1 "check-build-deps: a new --deps entry must reach the control file" "$CB"
cp "$REPO/third_party/build-freerdp.sh" "$C/third_party/build-freerdp.sh"
# FASTRDP_FREERDP_WEBAUTHN=1 (opt-in rdpewa client channel): extra deps only when asked
check "build-freerdp --deps: no libfido2 by default" bash -c '! "$0" --deps | grep -qw libfido2-dev' \
    "$REPO/third_party/build-freerdp.sh"
check "build-freerdp --deps: libfido2/libcbor with FASTRDP_FREERDP_WEBAUTHN=1" bash -c \
    'FASTRDP_FREERDP_WEBAUTHN=1 "$0" --deps | grep -w libfido2-dev | grep -qw libcbor-dev' \
    "$REPO/third_party/build-freerdp.sh"

# --- prepare-vendored.sh
PV=$C/packaging/ci/prepare-vendored.sh
expect_exit 2 "prepare-vendored: usage" "$PV" freerdp
expect_exit 2 "prepare-vendored: unknown package" "$PV" krb5 "$T/pv"
expect_exit 0 "prepare-vendored: freerdp" "$PV" freerdp "$T/pv"
fdir=$(tail -1 "$T_OUT")
check "prepare-vendored: prints the package directory" test "$fdir" = "$T/pv/fastrdp-freerdp3"
check "prepare-vendored: patched source in src/freerdp" grep -qx 'line2 patched' "$fdir/src/freerdp/file.txt"
check "prepare-vendored: debian/ from packaging/freerdp" test -x "$fdir/debian/rules"
check "prepare-vendored: build scripts in third_party/" test -x "$fdir/third_party/build-freerdp.sh"
check "prepare-vendored: vendored.mk" grep -qx "FREERDP_VERSION := $fv" "$fdir/debian/vendored.mk"
expect_exit 0 "prepare-vendored: xrdp (two components)" "$PV" xrdp "$T/pv"
xdir=$(tail -1 "$T_OUT")
check "prepare-vendored: xrdp vendored.mk" \
    test "$(cat "$xdir/debian/vendored.mk")" = "$(printf 'XRDP_VERSION := %s\nXORGXRDP_VERSION := %s' "$xv" "$gv")"
check "prepare-vendored: src/xrdp and src/xorgxrdp" test -f "$xdir/src/xrdp/file.txt" -a -f "$xdir/src/xorgxrdp/file.txt"
writesources 9.9.9
expect_exit 1 "prepare-vendored: changelog behind sources.yml is refused" "$PV" freerdp "$T/pv2"
output_has "prepare-vendored: says what to do" "add a changelog entry"
writesources "$fv"

# --- set-version.sh (on the prepared tree, as CI does)
SV=$C/packaging/ci/set-version.sh
expect_exit 2 "set-version: invalid upstream version" in_dir "$fdir" "$SV" v1.0 trixie deb13
expect_exit 2 "set-version: usage" in_dir "$fdir" "$SV" 1.0 trixie
expect_exit 0 "set-version: vendored package" in_dir "$fdir" "$SV" "$fv-1" trixie deb13
check "set-version: version gets the distro suffix" \
    test "$(cd "$fdir" && dpkg-parsechangelog -S Version)" = "$fv-1~deb13"
check "set-version: distribution" test "$(cd "$fdir" && dpkg-parsechangelog -S Distribution)" = trixie
check "set-version: source name from debian/control" \
    test "$(cd "$fdir" && dpkg-parsechangelog -S Source)" = fastrdp-freerdp3
check "set-version: previous entries kept" \
    test "$(cd "$fdir" && dpkg-parsechangelog -o 1 -c 1 -S Version)" = "$fv-1"
for pair in "0.2.0~deb13 0.2.0+git20261019120000.abc1234~deb13" \
            "0.2.0+git20261019120000.abc1234~deb13 0.2.0+git20261019130000.abc1234~deb13" \
            "0.2.0+git20261019120000.abc1234~deb13 0.2.1~deb13" \
            "$fv-1~deb13 $fv-1" "$fv-1~deb13 $fv-2~deb13"; do
    # shellcheck disable=SC2086  # two words
    set -- $pair
    check "version order: $1 < $2" dpkg --compare-versions "$1" lt "$2"
done

# --- upstream-version.sh
UV=$C/packaging/ci/upstream-version.sh
check "upstream-version: tag v1.2.3" test "$(GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.3 "$UV")" = 1.2.3
check "upstream-version: tag v1.2" test "$(GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2 "$UV")" = 1.2
expect_exit 2 "upstream-version: pre-release tag refused" env GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.3-rc1 "$UV"
expect_exit 2 "upstream-version: non-version tag refused" env GITHUB_REF_TYPE=tag GITHUB_REF_NAME=vnext "$UV"
mkdir -p "$T/uv/debian"
cp "$REPO/debian/changelog" "$T/uv/debian/"
base=$(cd "$T/uv" && dpkg-parsechangelog -S Version)
base=${base%%[+~]*}
check "upstream-version: main = <changelog>+git<time>.<sha7>" \
    bash -c 'cd "$1" && GITHUB_REF_TYPE=branch GITHUB_SHA=0123456789abcdef "$2" | grep -Eqx "$3\+git[0-9]{14}\.0123456"' \
    _ "$T/uv" "$UV" "${base//./\\.}"
if command -v git >/dev/null; then
    (cd "$T/uv" && git init -q && git add -A &&
        GIT_COMMITTER_DATE=2026-10-19T12:34:56Z git -c user.name=t -c user.email=t@t commit -qm t) >/dev/null 2>&1
    sha=$(cd "$T/uv" && git rev-parse HEAD)
    check "upstream-version: commit time in UTC" \
        test "$(cd "$T/uv" && GITHUB_SHA=$sha "$UV")" = "$base+git20261019123456.${sha:0:7}"
fi

# --- make-source-archive.sh (prepared + set-version tree, before the build)
MS=$C/packaging/ci/make-source-archive.sh
name=fastrdp-freerdp3_$fv-1~deb13
expect_exit 0 "make-source-archive: archive (upstream from cache)" \
    env FASTRDP_SOURCES_CACHE="$T/up" "$MS" "$fdir" "$T/src1"
check "make-source-archive: prints the archive" test "$(tail -1 "$T_OUT")" = "$T/src1/$name/$name.source.tar.xz"
A=$T/src1/$name
for f in "$name.source.tar.xz" "upstream/freerdp-$fv.tar.gz" patches/freerdp/series patches/freerdp/0001-change.patch SHA256SUMS; do
    check "make-source-archive: $f" test -s "$A/$f"
done
check "make-source-archive: SHA256SUMS verifies" bash -c 'cd "$1" && sha256sum --quiet -c SHA256SUMS' _ "$A"
check "make-source-archive: SHA256SUMS covers every file" \
    test "$(cd "$A" && find . -type f ! -name SHA256SUMS | wc -l)" = "$(wc -l < "$A/SHA256SUMS")"
tar -tvJf "$A/$name.source.tar.xz" > "$T/list"
check "make-source-archive: one top directory named <pkg>_<version>" \
    bash -c '! awk "{print \$6}" "$1" | grep -v "^$2\(/\|$\)"' _ "$T/list" "$name"
check "make-source-archive: patched source, debian/, build scripts inside" \
    bash -c 'for f in src/freerdp/file.txt debian/rules debian/changelog third_party/build-freerdp.sh; do
        grep -q " $2/$f$" "$1" || exit 1; done' _ "$T/list" "$name"
check "make-source-archive: entries sorted by name in every directory (reproducible)" python3 -c '
import sys, os
seen = {}
for line in open(sys.argv[1]):
    p = line.split()[5].rstrip("/")
    seen.setdefault(os.path.dirname(p), []).append(os.path.basename(p))
sys.exit(any(v != sorted(v) for v in seen.values()))' "$T/list"
check "make-source-archive: owner root/root" bash -c '! awk "{print \$2}" "$1" | grep -vx "0/0"' _ "$T/list"
expect_exit 0 "make-source-archive: archive again (upstream downloaded)" "$MS" "$fdir" "$T/src2"
check "make-source-archive: reproducible source tarball" cmp "$A/$name.source.tar.xz" "$T/src2/$name/$name.source.tar.xz"
check "make-source-archive: identical SHA256SUMS" cmp "$A/SHA256SUMS" "$T/src2/$name/SHA256SUMS"
mkdir -p "$T/badcache"
echo garbage > "$T/badcache/freerdp-$fv.tar.gz"
expect_exit nonzero "make-source-archive: upstream tarball with a wrong sha256 fails" \
    env FASTRDP_SOURCES_CACHE="$T/badcache" "$MS" "$fdir" "$T/src3"
# product:what-to-remove-afterwards (find used to look only two levels deep)
for p in debian/tmp/opt:debian/tmp obj-x86_64-linux-gnu/x:obj-x86_64-linux-gnu \
         src/freerdp/build/libfreerdp/CMakeFiles/x.c.o:src/freerdp/build src/freerdp/x.o:src/freerdp/x.o; do
    product=${p%%:*}
    mkdir -p "$fdir/$(dirname "$product")"
    : > "$fdir/$product"
    expect_exit 1 "make-source-archive: refuses a tree with $product" "$MS" "$fdir" "$T/src4"
    output_has "make-source-archive: says why ($product)" "contains build products"
    rm -rf "${fdir:?}/${p#*:}"
done
finish
