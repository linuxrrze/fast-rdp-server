#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# third_party/build-key.sh (Ansible rebuild key): deterministic, independent of the
# checkout location, and changes exactly when a build input of that build changes.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need sha256sum

K=$REPO/third_party/build-key.sh
for b in freerdp xrdp; do
    check "$b: key is 16 hex digits" grep -Eqx '[0-9a-f]{16}' <<<"$("$K" "$b")"
    check "$b: deterministic" test "$("$K" "$b")" = "$("$K" "$b")"
done
check "freerdp and xrdp keys differ" test "$("$K" freerdp)" != "$("$K" xrdp)"
expect_exit 2 "unknown build exits 2" "$K" xorgxrdp
expect_exit nonzero "missing argument fails" "$K"

# A copy of the inputs: same key from another directory, then mutate one input at a time.
C=$T/copy
mkdir -p "$C/third_party" "$C/patches"
cp "$REPO"/third_party/{build-key.sh,fetch.sh,sources.yml,build-freerdp.sh,build-xrdp.sh} "$C/third_party/"
cp -a "$REPO"/patches/freerdp "$REPO"/patches/xrdp "$C/patches/"
CK=$C/third_party/build-key.sh
f0=$("$K" freerdp)
x0=$("$K" xrdp)
check "freerdp: same key from a copy elsewhere" test "$("$CK" freerdp)" = "$f0"
check "xrdp: same key from a copy elsewhere" test "$("$CK" xrdp)" = "$x0"

fp=$(grep -v '^#' "$C/patches/freerdp/series" | grep . | head -1)
xp=$(grep -v '^#' "$C/patches/xrdp/series" | grep . | head -1)
echo " " >> "$C/patches/freerdp/$fp"
check "freerdp: changes when a FreeRDP patch changes" test "$("$CK" freerdp)" != "$f0"
check "xrdp: unaffected by a FreeRDP patch" test "$("$CK" xrdp)" = "$x0"
cp "$REPO/patches/freerdp/$fp" "$C/patches/freerdp/$fp"
check "freerdp: restored patch gives the old key" test "$("$CK" freerdp)" = "$f0"

echo " " >> "$C/patches/xrdp/$xp"
check "xrdp: changes when an xrdp patch changes" test "$("$CK" xrdp)" != "$x0"
check "freerdp: unaffected by an xrdp patch" test "$("$CK" freerdp)" = "$f0"
cp "$REPO/patches/xrdp/$xp" "$C/patches/xrdp/$xp"

echo "# reordered" >> "$C/patches/freerdp/series"
check "freerdp: changes when the series file changes" test "$("$CK" freerdp)" != "$f0"
cp "$REPO/patches/freerdp/series" "$C/patches/freerdp/series"

echo "# bump" >> "$C/third_party/sources.yml"
check "freerdp: changes with sources.yml" test "$("$CK" freerdp)" != "$f0"
check "xrdp: changes with sources.yml" test "$("$CK" xrdp)" != "$x0"
cp "$REPO/third_party/sources.yml" "$C/third_party/sources.yml"

echo "# flag" >> "$C/third_party/build-xrdp.sh"
check "xrdp: changes with build-xrdp.sh" test "$("$CK" xrdp)" != "$x0"
check "freerdp: unaffected by build-xrdp.sh" test "$("$CK" freerdp)" = "$f0"
cp "$REPO/third_party/build-xrdp.sh" "$C/third_party/build-xrdp.sh"

echo "# flag" >> "$C/third_party/fetch.sh"
check "freerdp: changes with fetch.sh" test "$("$CK" freerdp)" != "$f0"
cp "$REPO/third_party/fetch.sh" "$C/third_party/fetch.sh"

echo "0002-new.patch" >> "$C/patches/freerdp/series"
expect_exit nonzero "freerdp: a series entry without its patch file fails" "$CK" freerdp
finish
