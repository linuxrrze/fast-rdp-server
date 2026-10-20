#!/bin/bash
# shellcheck disable=SC2016  # bash -c snippets take their values as arguments
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# packaging/apt/publish.sh with a throwaway signing key and dummy packages, as CI
# runs it: stable publish, testing publish (stable carried over, shared pool files),
# next stable (stale sources/ pruned), refusals, then `apt-get update` against the
# tree through a file: source with Signed-By (and a wrong key is rejected).
#
# Needs reprepro, gpg, gpgv, dpkg-deb, apt-get. No root.
set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/../lib.sh"
need reprepro gpg gpgv gpgconf dpkg-deb apt-get apt-cache
PUB=$REPO/packaging/apt/publish.sh

export GNUPGHOME=$T/gnupg
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$T"' EXIT
install -d -m 0700 "$GNUPGHOME"
# no passphrase cache: every publish below has to unlock the key itself
printf 'default-cache-ttl 0\nmax-cache-ttl 0\n' > "$GNUPGHOME/gpg-agent.conf"
genkey() {  # genkey UID PASSPHRASE -> fingerprint
    gpg --batch --pinentry-mode loopback --passphrase "$2" --quick-gen-key "$1" ed25519 sign 1d 2>/dev/null
    gpg --with-colons --list-secret-keys "$1" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}'
}
KEY=$(genkey 'fastrdp test repository <test@example.invalid>' test-pass)
OTHER=$(genkey 'someone else <other@example.invalid>' other-pass)
export APT_SIGNING_KEY_ID=$KEY APT_SIGNING_KEY_PASSPHRASE=test-pass APT_REPO_URL=https://example.invalid/repo

mkdeb() {  # mkdeb OUTDIR NAME VERSION ARCH
    local d=$T/build/$2_$3_$4
    mkdir -p "$d/DEBIAN" "$d/usr/share/doc/$2" "$1"
    echo "$2 $3" > "$d/usr/share/doc/$2/marker"
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSection: net\nPriority: optional\nMaintainer: Test <test@example.invalid>\nDescription: test package\n' \
        "$2" "$3" "$4" > "$d/DEBIAN/control"
    dpkg-deb --root-owner-group -Zxz --build "$d" "$1/$2_$3_$4.deb" >/dev/null
}
mkset() {  # mkset DIR FASTRDP_VERSION FREERDP_VERSION [nosource-for-xrdp]
    local cn sfx
    for cn in resolute:ubuntu26.04 trixie:deb13; do
        sfx=${cn#*:} cn=${cn%:*}
        mkdeb "$1/$cn" fastrdp-broker "$2~$sfx" all
        mkdeb "$1/$cn" fastrdp-freerdp3 "$3~$sfx" amd64
        mkdeb "$1/$cn" fastrdp-freerdp3-dbgsym "$3~$sfx" amd64
        # an unchanged vendored build: the identical file in every set (CI cache hit)
        mkdir -p "$T/xrdp/$cn"
        [ -f "$T/xrdp/$cn/fastrdp-xrdp_0.10.6.1+xorgxrdp0.10.5-1~${sfx}_amd64.deb" ] ||
            mkdeb "$T/xrdp/$cn" fastrdp-xrdp "0.10.6.1+xorgxrdp0.10.5-1~$sfx" amd64
        cp "$T/xrdp/$cn"/*.deb "$1/$cn/"
        mkdir -p "$1/$cn/source/fastrdp-freerdp3_$3~$sfx" "$1/$cn/source/fastrdp-xrdp_0.10.6.1+xorgxrdp0.10.5-1~$sfx"
        echo src > "$1/$cn/source/fastrdp-freerdp3_$3~$sfx/SHA256SUMS"
        echo src > "$1/$cn/source/fastrdp-xrdp_0.10.6.1+xorgxrdp0.10.5-1~$sfx/SHA256SUMS"
        [ "${4:-}" = nosource-for-xrdp ] && rm -rf "$1/$cn/source/fastrdp-xrdp_"*
    done
    return 0
}
pkgs() {  # pkgs SITE SUITE -> "name version" lines of that suite
    local f=$1/dists/$2/main/binary-amd64/Packages
    [ -f "$f" ] || return 0
    awk '/^Package:/ {p=$2} /^Version:/ {print p, $2}' "$f" | sort
}
verify_pool() {  # every Packages entry points to a pool file with that SHA256
    local site=$1 pk f sum n=0
    for pk in "$site"/dists/*/main/binary-amd64/Packages; do
        while read -r f sum; do
            [ -f "$site/$f" ] || { echo "missing $f"; return 1; }
            [ "$(sha256sum "$site/$f" | cut -d' ' -f1)" = "$sum" ] || { echo "checksum $f"; return 1; }
            n=$((n + 1))
        done < <(awk '/^Filename:/ {f=$2} /^SHA256:/ {print f, $2}' "$pk")
    done
    [ $n -gt 0 ]
}
verify_sigs() {  # InRelease + Release.gpg of every suite, against the published key
    local site=$1 d
    for d in "$site"/dists/*/; do
        gpgv --keyring "$site/fast-rdp-server-archive-keyring.gpg" "$d/InRelease" || return 1
        gpgv --keyring "$site/fast-rdp-server-archive-keyring.gpg" "$d/Release.gpg" "$d/Release" || return 1
        grep -qx 'Hash: SHA512' "$d/InRelease" || return 1
        gpg --list-packets "$d/Release.gpg" | grep -q 'digest algo 10' || return 1   # SHA512
    done
}

# --- 1. first stable publish (no previous site)
mkset "$T/debs1" 0.2.0 3.32.2-1
expect_exit 0 "stable: publish into an empty site" "$PUB" stable "$T/debs1" "$T/none" "$T/site1"
S1=$T/site1
for cn in resolute trixie; do
    sfx=$([ $cn = trixie ] && echo deb13 || echo ubuntu26.04)
    check "stable: $cn-stable has broker, freerdp3, xrdp" test "$(pkgs "$S1" $cn-stable)" = "$(printf '%s\n' \
        "fastrdp-broker 0.2.0~$sfx" "fastrdp-freerdp3 3.32.2-1~$sfx" "fastrdp-xrdp 0.10.6.1+xorgxrdp0.10.5-1~$sfx")"
    check "stable: $cn-testing is empty" test -z "$(pkgs "$S1" $cn-testing)"
done
check "stable: no dbgsym packages in the pool" test -z "$(find "$S1/pool" -name '*dbgsym*')"
check "stable: pool files match Packages" verify_pool "$S1"
check "stable: InRelease and Release.gpg verify, SHA512" verify_sigs "$S1"
check "stable: public key exported (armored and binary)" \
    test -s "$S1/fast-rdp-server-archive-keyring.asc" -a -s "$S1/fast-rdp-server-archive-keyring.gpg"
check "stable: no secret key material published" bash -c '! grep -rlq "PRIVATE KEY" "$1"' _ "$S1"
check "stable: sources for both vendored packages per distro" test "$(find "$S1/sources" -mindepth 1 -maxdepth 1 -type d | wc -l)" = 4
check "stable: index.html names the URL and fingerprint" \
    bash -c 'grep -q "https://example.invalid/repo/fast-rdp-server-archive-keyring.asc" "$1" && grep -q "$2" "$1"' _ "$S1/index.html" "$KEY"
check "stable: .nojekyll" test -f "$S1/.nojekyll"

# --- 2. testing publish from main: stable carried over unchanged
mkset "$T/debs2" 0.2.0+git20261020120000.abcdef1 3.32.3-1
cp -a "$S1" "$T/old2"
mkdir -p "$T/site2/.git" && echo keep > "$T/site2/.git/marker" && echo stale > "$T/site2/stale"
expect_exit 0 "testing: publish with stable carried over" "$PUB" testing "$T/debs2" "$T/old2" "$T/site2"
S2=$T/site2
output_has "testing: reports the carry-over" "trixie-stable: carried over"
for cn in resolute trixie; do
    check "testing: $cn-stable identical to before" test "$(pkgs "$S2" $cn-stable)" = "$(pkgs "$S1" $cn-stable)"
    check "testing: $cn-testing has the new build" \
        bash -c 'grep -q "^fastrdp-broker 0.2.0+git20261020120000.abcdef1~" <<<"$1" && grep -q "^fastrdp-freerdp3 3.32.3-1~" <<<"$1"' \
        _ "$(pkgs "$S2" $cn-testing)"
done
check "testing: the unchanged xrdp build is one pool file for both channels" \
    test "$(find "$S2/pool" -name 'fastrdp-xrdp_*deb13*' | wc -l)" = 1
check "testing: pool files match Packages" verify_pool "$S2"
check "testing: signatures verify" verify_sigs "$S2"
check "testing: sources of both FreeRDP versions kept" \
    test -d "$S2/sources/fastrdp-freerdp3_3.32.2-1~deb13" -a -d "$S2/sources/fastrdp-freerdp3_3.32.3-1~deb13"
check "testing: output dir cleaned, .git kept" test ! -e "$S2/stale" -a -f "$S2/.git/marker"

# --- 3. next stable release: 3.32.2 leaves the pool, its sources are pruned
mkset "$T/debs3" 0.3.0 3.32.3-1
cp -a "$S2" "$T/old3"
mkdir -p "$T/old3/sources/fastrdp-freerdp3_1.0-1~deb13" && echo x > "$T/old3/sources/fastrdp-freerdp3_1.0-1~deb13/SHA256SUMS"
expect_exit 0 "stable: next release" "$PUB" stable "$T/debs3" "$T/old3" "$T/site3"
S3=$T/site3
output_has "stable: pruning reported" "sources: dropped fastrdp-freerdp3_3.32.2-1~deb13"
check "stable: old FreeRDP gone from the pool" test -z "$(find "$S3/pool" -name 'fastrdp-freerdp3_3.32.2*')"
check "stable: its sources pruned" test ! -e "$S3/sources/fastrdp-freerdp3_3.32.2-1~deb13"
check "stable: stale sources from the old site pruned" test ! -e "$S3/sources/fastrdp-freerdp3_1.0-1~deb13"
check "stable: current sources kept" \
    test -d "$S3/sources/fastrdp-freerdp3_3.32.3-1~deb13" -a -d "$S3/sources/fastrdp-xrdp_0.10.6.1+xorgxrdp0.10.5-1~ubuntu26.04"
check "stable: testing still carried over" \
    test "$(pkgs "$S3" trixie-testing)" = "$(pkgs "$S2" trixie-testing)"
check "stable: pool files match Packages" verify_pool "$S3"

# --- 4. refusals
mkset "$T/debs4" 0.4.0 3.32.4-1 nosource-for-xrdp
rm -rf "$T/old4" && mkdir -p "$T/old4"
expect_exit 1 "refused: vendored package without corresponding source" "$PUB" stable "$T/debs4" "$T/old4" "$T/site4"
output_has "refusal names the package" "no corresponding source for fastrdp-xrdp_0.10.6.1"
mkdir -p "$T/debs5/resolute"
cp "$T/debs1/resolute/"*.deb "$T/debs5/resolute/"
cp -a "$T/debs1/resolute/source" "$T/debs5/resolute/"
expect_exit 1 "refused: no packages for one distro" "$PUB" stable "$T/debs5" "$T/old4" "$T/site5"
output_has "refusal names the suite" "no packages for trixie-stable"
expect_exit 2 "refused: unknown channel" "$PUB" nightly "$T/debs1" "$T/old4" "$T/site5"
expect_exit nonzero "refused: no signing key id" env -u APT_SIGNING_KEY_ID "$PUB" stable "$T/debs1" "$T/old4" "$T/site5"
expect_exit nonzero "refused: wrong passphrase" env APT_SIGNING_KEY_PASSPHRASE=wrong "$PUB" stable "$T/debs1" "$T/old4" "$T/site5"

# --- 5. apt-get update against the published tree (file: source, Signed-By)
aptconf() {  # aptconf NAME KEYFILE -> private apt configuration using only KEYFILE
    local a=$T/apt-$1
    mkdir -p "$a/state/lists/partial" "$a/cache/archives/partial" "$a/sources" "$a/parts" "$a/trusted" "$a/prefs"
    : > "$a/status"
    cat > "$a/apt.conf" <<EOF
Dir::State "$a/state";
Dir::State::status "$a/status";
Dir::Cache "$a/cache";
Dir::Etc::SourceList "/dev/null";
Dir::Etc::SourceParts "$a/sources";
Dir::Etc::Parts "$a/parts";
Dir::Etc::Trusted "/dev/null";
Dir::Etc::TrustedParts "$a/trusted";
Dir::Etc::PreferencesParts "$a/prefs";
Debug::NoLocking "true";
APT::Sandbox::User "root";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
EOF
    printf 'Types: deb\nURIs: file:%s\nSuites: trixie-stable trixie-testing\nComponents: main\nArchitectures: amd64\nSigned-By: %s\n' \
        "$S3" "$2" > "$a/sources/fast-rdp-server.sources"
    echo "$a/apt.conf"
}
GOOD=$(aptconf good "$S3/fast-rdp-server-archive-keyring.asc")
expect_exit 0 "apt: update with Signed-By the published key" env APT_CONFIG="$GOOD" apt-get update
output_lacks "apt: no warnings or errors" "^(W|E|Err):"
check "apt: stable version visible" \
    bash -c 'APT_CONFIG=$1 apt-cache policy fastrdp-broker | grep -q "0.3.0~deb13"' _ "$GOOD"
check "apt: testing version visible" \
    bash -c 'APT_CONFIG=$1 apt-cache policy fastrdp-broker | grep -q "0.2.0+git20261020120000.abcdef1~deb13"' _ "$GOOD"
mkdir -p "$T/dl"
check "apt: download verifies the pool file" in_dir "$T/dl" env APT_CONFIG="$GOOD" apt-get download fastrdp-freerdp3=3.32.3-1~deb13
gpg --armor --export "$OTHER" > "$T/other.asc"
BAD=$(aptconf bad "$T/other.asc")
expect_exit nonzero "apt: update with another key in Signed-By fails" env APT_CONFIG="$BAD" apt-get update
finish
