#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Build the signed APT repository tree (reprepro) for GitHub Pages.
#
#   packaging/apt/publish.sh <channel> <debs-dir> <old-site> <new-site>
#
#   channel   stable | testing: the channel being updated
#   debs-dir  fresh packages, one directory per distro codename:
#             <debs-dir>/resolute/*.deb, <debs-dir>/trixie/*.deb, and the corresponding
#             source of the vendored packages in <debs-dir>/<distro>/source/<pkg>_<ver>/
#             (packaging/ci/make-source-archive.sh)
#   old-site  previously published tree (gh-pages checkout; may be empty or missing).
#             The other channel is carried over from it unchanged.
#   new-site  output directory (recreated)
#
# The repository is rebuilt from scratch on every run, so no reprepro database has
# to be kept anywhere: each suite holds the latest build of its channel.
#
# Environment:
#   APT_SIGNING_KEY_ID          key (fingerprint) to sign Release files with (required)
#   APT_SIGNING_KEY_PASSPHRASE  passphrase of that key (optional)
#   GNUPGHOME                   keyring holding the secret key (gpg default otherwise)
#   APT_REPO_URL                public URL, only used in the generated index.html
set -eu

[ $# -eq 4 ] || { echo "usage: $0 stable|testing <debs-dir> <old-site> <new-site>" >&2; exit 2; }
channel=$1 debs=$2 old=$3 out=$4
case $channel in stable|testing) ;; *) echo "unknown channel $channel" >&2; exit 2 ;; esac
: "${APT_SIGNING_KEY_ID:?set APT_SIGNING_KEY_ID}"

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
old=$(cd "$old" 2>/dev/null && pwd || echo /nonexistent)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/conf"
cp "$here/distributions" "$work/conf/distributions"
find "$out" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +

rr() { reprepro --basedir "$work" --outdir "$out" --silent "$@"; }

codenames=$(sed -n 's/^Codename: //p' "$work/conf/distributions")
# Pass 1: the channel being updated, from the fresh builds.
for cn in $codenames; do
    [ "${cn##*-}" = "$channel" ] || continue
    distro=${cn%-*}
    found=0
    for deb in "$debs/$distro"/*.deb; do
        [ -e "$deb" ] || continue
        case $deb in *-dbgsym_*) continue ;; esac
        rr includedeb "$cn" "$deb"
        found=1
    done
    [ $found = 1 ] || { echo "no packages for $cn in $debs/$distro" >&2; exit 1; }
    echo "$cn: new build"
done
# Pass 2: the other channel, carried over from the old tree. Both channels share one
# pool; a file that pass 1 already put there (same name and version, e.g. an unchanged
# fastrdp-freerdp3 build) is taken from the new pool so its checksum stays consistent.
for cn in $codenames; do
    [ "${cn##*-}" != "$channel" ] || continue
    pk="$old/dists/$cn/main/binary-amd64/Packages"
    if [ -f "$pk" ]; then
        sed -n 's/^Filename: //p' "$pk" | while read -r f; do
            if [ -e "$out/$f" ]; then rr includedeb "$cn" "$out/$f"; else rr includedeb "$cn" "$old/$f"; fi
        done
        echo "$cn: carried over"
    else
        echo "$cn: empty (nothing published yet)"
    fi
done
rr export

# Corresponding source of the vendored packages (GPL-3.0 §6(d), docs/licensing.md):
# offered next to the binaries in sources/<pkg>_<version>/, for exactly the versions
# in the pool. New builds first, then whatever the old tree still provides.
mkdir -p "$out/sources"
for d in "$debs"/*/source/*/ "$old"/sources/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    [ -e "$out/sources/$n" ] || cp -a "$d" "$out/sources/$n"
done
for d in "$out"/sources/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    find "$out/pool" -name "${n}_*.deb" | grep -q . || { rm -rf "$d"; echo "sources: dropped $n"; }
done
# Every vendored binary in the pool must have its source here.
find "$out/pool" \( -name 'fastrdp-freerdp3_*.deb' -o -name 'fastrdp-xrdp_*.deb' \) | while read -r deb; do
    n=$(basename "$deb" .deb)
    n=${n%_*}
    [ -d "$out/sources/$n" ] || { echo "no corresponding source for $n (make-source-archive.sh)" >&2; exit 1; }
done

# Sign: InRelease (inline) and Release.gpg (detached) for every suite.
set -- --batch --yes --local-user "$APT_SIGNING_KEY_ID" --digest-algo SHA512
if [ -n "${APT_SIGNING_KEY_PASSPHRASE:-}" ]; then
    printf '%s' "$APT_SIGNING_KEY_PASSPHRASE" > "$work/pass"
    set -- "$@" --pinentry-mode loopback --passphrase-file "$work/pass"
fi
for rel in "$out"/dists/*/Release; do
    d=$(dirname "$rel")
    gpg "$@" --clearsign --output "$d/InRelease" "$rel"
    gpg "$@" --armor --detach-sign --output "$d/Release.gpg" "$rel"
done

gpg --armor --export "$APT_SIGNING_KEY_ID" > "$out/fast-rdp-server-archive-keyring.asc"
gpg --export "$APT_SIGNING_KEY_ID" > "$out/fast-rdp-server-archive-keyring.gpg"
[ -s "$out/fast-rdp-server-archive-keyring.gpg" ] || { echo "public key export failed" >&2; exit 1; }
fpr=$(gpg --with-colons --fingerprint "$APT_SIGNING_KEY_ID" | awk -F: '/^fpr:/ {print $10; exit}')

# fastrdp-archive-keyring: the key in every version in the pool must be the signing key
# (clients that install it trust only that key). The newest one also goes to a fixed
# name, the download that bootstraps a client (docs/packaging.md).
keyring=
for deb in $(find "$out/pool" -name 'fastrdp-archive-keyring_*.deb' | sort -V); do
    dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/share/keyrings/fast-rdp-server-archive-keyring.asc > "$work/keyring.asc"
    k=$(gpg --show-keys --with-colons "$work/keyring.asc" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
    if [ "$k" != "$fpr" ]; then
        echo "$(basename "$deb") has key ${k:-none}, the repository is signed with $fpr:" \
            "update packaging/apt/fast-rdp-server-archive-keyring.asc" >&2
        exit 1
    fi
    keyring=$deb
done
[ -z "$keyring" ] || cp "$keyring" "$out/fastrdp-archive-keyring.deb"

url=${APT_REPO_URL:-https://linuxrrze.github.io/fast-rdp-server}
touch "$out/.nojekyll"
{
    cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>fast-rdp-server APT repository</title></head>
<body>
<h1>fast-rdp-server APT repository</h1>
<p>Setup: see docs/packaging.md in the
<a href="https://github.com/linuxrrze/fast-rdp-server/blob/main/docs/packaging.md">source repository</a>.</p>
<pre>
# key + APT source (stable channel of this release) in one package:
curl -fsSLO $url/fastrdp-archive-keyring.deb
sudo apt install ./fastrdp-archive-keyring.deb &amp;&amp; sudo apt update
</pre>
<p>Or by hand:</p>
<pre>
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/fast-rdp-server.asc $url/fast-rdp-server-archive-keyring.asc
# /etc/apt/sources.list.d/fast-rdp-server.sources
Types: deb
URIs: $url
Suites: &lt;codename&gt;-stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/fast-rdp-server.asc
</pre>
<h2>Suites</h2>
<ul>
EOF
    for d in "$out"/dists/*/; do
        cn=$(basename "$d")
        printf '<li><code>%s</code>: %s</li>\n' "$cn" \
            "$(sed -n 's/^Description: //p' "$d/Release" | sed 's/&/\&amp;/g; s/</\&lt;/g')"
    done
    cat <<EOF
</ul>
<p>Corresponding source of the vendored FreeRDP and xrdp packages (patched upstream
source, packaging, build scripts, pristine upstream releases, patches):
<a href="sources/">sources/</a>. Licensing: docs/licensing.md in the source repository.</p>
<p>Signing key: <a href="fast-rdp-server-archive-keyring.asc">fast-rdp-server-archive-keyring.asc</a>
(fingerprint <code>$fpr</code>)</p>
</body></html>
EOF
} > "$out/index.html"
echo "published to $out"
