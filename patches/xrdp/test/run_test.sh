#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
# Build the patched xrdp tree first (./configure --enable-ffmpeg && make), then:
#   run_test.sh /path/to/xrdp-source [encoder] [ok|null]
# FALLBACK (default libx264) is written to [ffmpeg] fallback; "" disables it.
# Compiles the encoder with a private config dir (gfx.toml written here) and runs
# test_ffmpeg_encoder against libavcodec. Default encoder libx264 (no GPU needed);
# use h264_vaapi / h264_nvenc on a GPU host.
set -eu
SRC=$1
ENC=${2:-libx264}
EXPECT=${3:-ok}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cat > "$W/gfx.toml" <<EOT
[codec]
order = [ "H.264", "RFX" ]
h264_encoder = "ffmpeg"

[ffmpeg]
encoder = "$ENC"
device = "${VAAPI_DEVICE:-/dev/dri/renderD128}"
fallback = "${FALLBACK-libx264}"

[ffmpeg.default]
qp = 20
gop = 300
fps_num = 60
fps_den = 1
EOT
CF="${FFMPEG_CFLAGS:-$(pkg-config --cflags libavcodec libavutil)}"
LF="${FFMPEG_LIBS:-$(pkg-config --libs libavcodec libavutil)}"
# shellcheck disable=SC2086 # flag lists
cc -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
    -DHAVE_CONFIG_H -DXRDP_FFMPEG -DXRDP_CFG_PATH="\"$W\"" \
    -I"$SRC" -I"$SRC/common" -I"$SRC/xrdp" -I"$SRC/libxrdp" -I"$SRC/third_party" \
    -I"$SRC/third_party/tomlc99" $CF \
    "$HERE/test_ffmpeg_encoder.c" "$SRC/xrdp/xrdp_encoder_ffmpeg.c" \
    "$SRC/xrdp/xrdp_tconfig.c" "$SRC/third_party/tomlc99/toml.c" \
    -o "$W/test" -L"$SRC/common/.libs" -lcommon $LF -lm ${EXTRA_LDFLAGS:-}
LD_LIBRARY_PATH="$SRC/common/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$W/test" "$ENC" "$EXPECT"
