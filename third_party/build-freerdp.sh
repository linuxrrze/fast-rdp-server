#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# build-freerdp.sh SRCDIR [DESTDIR]
#   Build the patched FreeRDP (third_party/fetch.sh freerdp ...) into the private prefix
#   /opt/fastrdp, so it coexists with the distribution's freerdp3 (gnome-remote-desktop
#   and KRdp keep using that). Installs into DESTDIR when given (packaging), else into
#   the prefix. Binaries and libraries carry DT_RPATH $ORIGIN/../lib (not RUNPATH), so
#   the patched libraries win even over LD_LIBRARY_PATH or an installed distro freerdp3.
#
#   Provides: freerdp-proxy + headers/pkg-config for the fastrdp module, the server
#   libraries, and the xfreerdp client (tests, rdpbench) with H.264 via FFmpeg.
#
# build-freerdp.sh --deps   prints the Debian/Ubuntu build dependencies.
# Environment: FASTRDP_PREFIX (/opt/fastrdp), BUILD_DIR (SRCDIR/build), JOBS,
#   FASTRDP_CMAKE_ARGS (extra cmake arguments, e.g. for sysroot builds).
set -euo pipefail

DEPS="build-essential cmake ninja-build pkg-config libssl-dev libkrb5-dev zlib1g-dev
libcjson-dev libicu-dev libsystemd-dev libpcsclite-dev
libavcodec-dev libavutil-dev libswscale-dev libswresample-dev
libx11-dev libxext-dev libxinerama-dev libxcursor-dev libxdamage-dev libxv-dev
libxkbfile-dev libxrandr-dev libxi-dev libxrender-dev libxfixes-dev"
if [ "${1:-}" = --deps ]; then
    echo "$DEPS" | tr '\n' ' '; echo
    exit 0
fi

src=$(cd "${1:?usage: build-freerdp.sh SRCDIR [DESTDIR] | --deps}" && pwd)
destdir=${2:-}
prefix=${FASTRDP_PREFIX:-/opt/fastrdp}
build=${BUILD_DIR:-$src/build}
generator=()
command -v ninja >/dev/null && generator=(-G Ninja)

# shellcheck disable=SC2086,SC2016  # FASTRDP_CMAKE_ARGS is a word list; $ORIGIN is literal
cmake -S "$src" -B "$build" "${generator[@]}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_SKIP_INSTALL_RPATH=OFF \
    -DCMAKE_INSTALL_RPATH='$ORIGIN/../lib' \
    "-DCMAKE_EXE_LINKER_FLAGS_INIT=-Wl,--disable-new-dtags" \
    "-DCMAKE_SHARED_LINKER_FLAGS_INIT=-Wl,--disable-new-dtags" \
    "-DCMAKE_MODULE_LINKER_FLAGS_INIT=-Wl,--disable-new-dtags" \
    -DWITH_BINARY_VERSIONING=OFF \
    -DBUILD_TESTING=OFF \
    -DWITH_SERVER=ON -DWITH_PROXY=ON -DWITH_PROXY_MODULES=OFF \
    -DWITH_SHADOW=OFF -DWITH_SAMPLE=OFF -DWITH_PLATFORM_SERVER=OFF \
    -DWITH_CLIENT=ON -DWITH_CLIENT_X11=ON -DWITH_CLIENT_SDL=OFF -DWITH_SDL=OFF \
    -DWITH_WAYLAND=OFF -DWITH_WEBVIEW=OFF -DWITH_MANPAGES=OFF \
    -DWITH_KRB5=ON -DWITH_PKCS11=ON -DWITH_PCSC=ON -DWITH_CJSON_REQUIRED=ON \
    -DWITH_FFMPEG=ON -DWITH_SWSCALE=ON -DWITH_DSP_FFMPEG=ON -DWITH_OPENH264=OFF \
    -DWITH_VAAPI=OFF -DWITH_VIDEO_FFMPEG=ON \
    -DWITH_CUPS=OFF -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_OSS=OFF -DWITH_FUSE=OFF \
    -DWITH_JPEG=OFF -DWITH_URIPARSER=OFF -DWITH_FAAC=OFF -DWITH_FAAD2=OFF \
    -DWITH_SOXR=OFF -DWITH_LAME=OFF -DWITH_OPUS=OFF -DCHANNEL_URBDRC=OFF \
    -DWITH_INTERNAL_RC4=ON -DWITH_INTERNAL_MD4=ON -DWITH_INTERNAL_MD5=ON \
    -DWITH_LIBSYSTEMD=ON -DWITH_TIMEZONE_ICU=OFF -DWITH_UNICODE_BUILTIN=OFF \
    ${FASTRDP_CMAKE_ARGS:-}
cmake --build "$build" -j"${JOBS:-$(nproc)}"
DESTDIR=$destdir cmake --install "$build"

# The fastrdp module and the tests look for these; fail early if a feature went missing.
root=$destdir$prefix
for f in bin/freerdp-proxy bin/xfreerdp lib/pkgconfig/freerdp3.pc \
         lib/pkgconfig/freerdp-server-proxy3.pc lib/pkgconfig/winpr3.pc; do
    [ -e "$root/$f" ] || { echo "build-freerdp.sh: missing $root/$f" >&2; exit 1; }
done
for f in bin/freerdp-proxy bin/xfreerdp lib/libfreerdp-server-proxy3.so.3; do
    # shellcheck disable=SC2016  # literal $ORIGIN
    readelf -d "$root/$f" | grep -q '(RPATH).*\$ORIGIN/../lib' \
        || { echo "build-freerdp.sh: $f has no DT_RPATH \$ORIGIN/../lib" >&2; exit 1; }
done
# WITH_GFX_H264 is derived from WITH_VIDEO_FFMPEG; check what the build really did
grep -q '^#define WITH_GFX_H264' "$build/include/freerdp/config.h" \
    || { echo "build-freerdp.sh: H.264 (WITH_GFX_H264) is not enabled" >&2; exit 1; }
echo "FreeRDP $(PKG_CONFIG_PATH=$root/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR='' pkg-config --modversion freerdp3) installed in $destdir$prefix"
