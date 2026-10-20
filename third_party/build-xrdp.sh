#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# build-xrdp.sh XRDP_SRC XORGXRDP_SRC [DESTDIR]
#   Build the patched xrdp (FFmpeg hardware H.264 encoder) and xorgxrdp from
#   third_party/fetch.sh trees. One system-wide instance: packages conflict with the
#   distribution's xrdp/xorgxrdp. Installs into DESTDIR when given (packaging).
#   The site configuration (SITE_CONFIG below) is never overwritten: upstream's versions
#   go to PREFIX/share/fastrdp-xrdp/default-config/.
#
# build-xrdp.sh --deps   prints the Debian/Ubuntu build dependencies.
# Environment:
#   FASTRDP_XRDP_PREFIX   /usr (packages); the Ansible build path uses /usr/local
#   FASTRDP_XRDP_UNITDIR  /usr/lib/systemd/system
#   FASTRDP_XRDP_FFMPEG   1 = --enable-ffmpeg (VA-API/NVENC/QSV encoder), 0 = x264 only
#   FASTRDP_XORGXRDP_GLAMOR 1 = --enable-glamor (GPU rendering)
#   JOBS
set -euo pipefail

DEPS="build-essential patch autoconf automake libtool pkgconf nasm libssl-dev libpam0g-dev
libx11-dev libxfixes-dev libxrandr-dev libxkbfile-dev libjpeg-dev libfuse3-dev libopus-dev
libmp3lame-dev libpixman-1-dev libx264-dev libimlib2-dev libfreetype-dev xserver-xorg-dev
xserver-xorg-core libepoxy-dev libegl-dev libgbm-dev libdrm-dev libavcodec-dev libavutil-dev"
# (xserver-xorg-core: xorgxrdp's glamor build links libglamoregl.so from the Xorg modules.)
if [ "${1:-}" = --deps ]; then
    echo "$DEPS" | tr '\n' ' '; echo
    exit 0
fi

usage="usage: build-xrdp.sh XRDP_SRC XORGXRDP_SRC [DESTDIR] | --deps"
xrdp_src=$(cd "${1:?$usage}" && pwd)
xorgxrdp_src=$(cd "${2:?$usage}" && pwd)
destdir=${3:-}
prefix=${FASTRDP_XRDP_PREFIX:-/usr}
unitdir=${FASTRDP_XRDP_UNITDIR:-/usr/lib/systemd/system}
jobs=${JOBS:-$(nproc)}
ffmpeg=()
[ "${FASTRDP_XRDP_FFMPEG:-1}" = 1 ] && ffmpeg=(--enable-ffmpeg)
glamor=()
[ "${FASTRDP_XORGXRDP_GLAMOR:-1}" = 1 ] && glamor=(--enable-glamor)

# Site configuration: files the fastrdp roles (or the admin, docs/manual-setup.md) write.
# xrdp has no include or drop-in mechanism for them, so they must not be package
# conffiles (dpkg would ask on every upgrade that changes upstream's version) and a
# rebuild must not overwrite them. `make install` puts upstream's versions to
# $prefix/share/fastrdp-xrdp/default-config/<path> instead; existing files stay. The
# package's postinst copies a default only where the file is missing.
SITE_CONFIG="/etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/xrdp/gfx.toml /etc/xrdp/startwm.sh
/etc/X11/xrdp/xorg.conf /etc/pam.d/xrdp-sesman"
defaults=$destdir$prefix/share/fastrdp-xrdp/default-config
keep=$(mktemp -d)
pcdir=$(mktemp -d)
restore_site_config() {
    for f in $SITE_CONFIG; do
        if [ -e "$keep$f" ]; then cp -p "$keep$f" "$destdir$f"; fi
    done
}
on_exit() {
    # (a failed `make install` may have overwritten them already)
    [ "$1" -eq 0 ] || restore_site_config
    rm -rf "$pcdir" "$keep"
}
trap 'on_exit $?' EXIT
for f in $SITE_CONFIG; do
    if [ -e "$destdir$f" ]; then
        mkdir -p "$keep$(dirname "$f")"
        cp -p "$destdir$f" "$keep$f"
    fi
done

cd "$xrdp_src"
autoreconf -fi
./configure --prefix="$prefix" --sysconfdir=/etc --localstatedir=/var \
    --with-systemdsystemunitdir="$unitdir" \
    --enable-x264 --enable-fuse --enable-pixman --enable-opus --enable-mp3lame \
    --enable-jpeg --enable-ipv6 --enable-utmp "${ffmpeg[@]}"
make -j"$jobs"
make install DESTDIR="$destdir"

# xorgxrdp finds xrdp through xrdp.pc; point it at the tree just installed.
# (Sysroot builds: DESTDIR inside PKG_CONFIG_SYSROOT_DIR, pkg-config prepends the sysroot.)
staged=$destdir$prefix
[ -n "${PKG_CONFIG_SYSROOT_DIR:-}" ] && staged=${staged#"$PKG_CONFIG_SYSROOT_DIR"}
sed "s|^prefix=.*|prefix=$staged|" "$destdir$prefix/lib/pkgconfig/xrdp.pc" > "$pcdir/xrdp.pc"
cd "$xorgxrdp_src"
PKG_CONFIG_PATH=$pcdir${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH} \
    ./configure --prefix="$prefix" --sysconfdir=/etc "${glamor[@]}"
make -j"$jobs"
make install DESTDIR="$destdir"

# Upstream's site configuration -> defaults; restore the files that existed before.
for f in $SITE_CONFIG; do
    [ -e "$destdir$f" ] || { echo "build-xrdp.sh: make install did not create $f" >&2; exit 1; }
    mkdir -p "$defaults$(dirname "$f")"
    mv -f "$destdir$f" "$defaults$f"
done
restore_site_config

# Fail early if a feature went missing. xrdp -v prints these options; read them from the
# generated header instead of running the binary (works for sysroot/cross builds too).
opts=$(cat "$xrdp_src/xrdp_configure_options.h")
for want in --enable-x264 "${ffmpeg[@]}"; do
    grep -q -- "$want" <<<"$opts" || { echo "build-xrdp.sh: xrdp lacks $want" >&2; exit 1; }
done
[ -e "$destdir$prefix/sbin/xrdp" ] || { echo "build-xrdp.sh: xrdp not installed" >&2; exit 1; }
find "$destdir" -name xrdpdev_drv.so | grep -q . || { echo "build-xrdp.sh: xorgxrdp not installed" >&2; exit 1; }
echo "xrdp + xorgxrdp installed in $destdir$prefix"
