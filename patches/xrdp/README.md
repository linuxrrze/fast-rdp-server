# Patches for xrdp 0.10.6.1

Applied by the Ansible `xrdp` role to the pristine release tarball before building.

## 0001 – FFmpeg H.264 encoder (VA-API, NVENC, QSV)

Upstream xrdp 0.10 encodes H.264 only in software (x264/OpenH264). This patch adds
an encoder backend on FFmpeg's libavcodec, selected in `gfx.toml`:

```toml
[codec]
h264_encoder = "ffmpeg"

[ffmpeg]
encoder = "h264_vaapi"          # h264_vaapi | h264_nvenc | h264_qsv | libx264
device = "/dev/dri/renderD128"  # VA-API render node
fallback = "libx264"            # used if `encoder` fails its start-up probe; "" = none
options = ""                    # extra AVOptions, "key=value:key=value"

[ffmpeg.default]                # per connection type like [x264.*]
qp = 23                         # constant quality when bitrate = 0
gop = 300
fps_num = 60
fps_den = 1

[ffmpeg.wan]
bitrate = 12_000                # kbit/s
max_bitrate = 15_000
```

**How it works:**
- Input: the NV12 frame xorgxrdp already produces for x264, with the damaged
  rectangles. The patch keeps a full frame per session and copies only damaged
  rectangles into it.
- VA-API: uploads with `av_hwframe_transfer_data`. NVENC and QSV take NV12
  system memory directly.
- Latency: no B-frames, async depth 1 (VA-API, QSV), NVENC
  `preset=p1 tune=ull zerolatency delay=0`. Every input produces one access unit
  immediately, and SPS/PPS are repeated with each IDR. Options can be overridden.
- Start-up probe: `create()` encodes one 256×256 frame. If the GPU, driver or
  library is unusable, xrdp logs it once and uses `fallback` instead of failing
  on every frame.
- Build: `./configure --enable-ffmpeg` (libavcodec ≥ 60, libavutil ≥ 58;
  autoreconf needed after patching). Ubuntu 26.04's `libavcodec62` contains
  h264_vaapi, h264_nvenc and libx264.
- The encoder runs in the xrdp daemon process (uid `xrdp`). It needs read/write
  access to the render node; the `gpu` role's udev rule provides that. For NVENC,
  `/dev/nvidia*` is world-accessible by default.

**Tested** (sandbox without a GPU, `test/run_test.sh`):
- libx264 through the identical code path: one decodable picture per input
  (30/30), SPS+IDR at start and after resize, luma PSNR 56 dB at QP 20, coded
  size 1376×768 for 1366×768, partial updates, buffer overflow refused;
- h264_vaapi and h264_nvenc falling back to libx264, and failing cleanly when
  `fallback = ""`.

**Not yet tested on real Intel/AMD/NVIDIA GPUs.** Use `test/run_test.sh <src>
h264_vaapi` on a GPU host, then `tests/gpu/session_report.py` in a session.

**Upstream:**
- xrdp `devel` has `xrdp_accel_assist` for zero-copy NVENC encoding of
  glamor/GL textures; it is not in any release and NVIDIA only.
- This patch targets the 0.10 release line and adds VA-API (Intel/AMD). A VA-API
  backend for `accel_assist` (EGL → dma-buf → VA surface, no CPU copy) would be
  the natural upstream contribution.

The draft pull request text, with the to-do list for upstream submission (rebase onto
devel, xrdp test-suite fixtures, real GPU results), is in
[docs/upstream.md §4](../../docs/upstream.md#4-xrdp-ffmpeg-h264-encoder-va-api-nvenc-qsv).
