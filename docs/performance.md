# Performance and GPU use (phase 4)

This page has two parts:
- What is **measured** (in this repository's sandbox, no GPU).
- What each back-end **does with a GPU**, established from the upstream sources of
  the Ubuntu 26.04 package versions.

The GPU behaviour still has to be confirmed on real Intel/AMD/NVIDIA hosts with the
tools below.

## Tools

| Tool | Where it runs | What it tells you |
|---|---|---|
| `tests/perf/rdpbench/rdpbench` | any client host | fps, codec actually negotiated (AVC444/AVC420/RFX/…), GFX payload and wire Mbit/s, client decode ms/frame, input-to-frame latency (`--latency`). `--no-decode` measures what server + network deliver. The last line of output is JSON. |
| `tests/perf/rdpbench/perfload` | inside a session | Repeatable screen load: `video` (full motion), `scroll` (browser/terminal-like), `latency` (repaints on key press). |
| `tests/gpu/session_report.py` | inside a session | Proves from `/proc` which processes render on the GPU and which H.264 encoder is loaded (VA-API, NVENC, x264). Adds `glxinfo`/`vulkaninfo`/`vainfo`/`nvidia-smi` output if those tools are installed. |
| `tests/perf/proxy-overhead.sh` | any Linux box | Direct vs. through freerdp-proxy + fastrdp module, using Xvfb + FreeRDP shadow server as the back-end |
| `tests/perf/compare-host.sh` | deployed host (root) | Same comparison against a user's real GNOME/Plasma back-end |

Build: `make -C tests/perf/rdpbench` (needs `freerdp3-dev libwinpr3-dev libx11-dev`).

## Measured: proxy overhead

Setup:
- `tests/perf/proxy-overhead.sh 12 3`, FreeRDP 3.32.1 (Ubuntu 26.04 build).
- Back-end: shadow server on Xvfb at 1920×1080.
- Host: AMD Ryzen 7 7735HS, shared and busy (load average 8–18).
- Codec: RFX, because this FreeRDP build has no H.264 encoder (see below).
- `--no-decode` on the client.

| Load | Path | fps (3 runs) | GFX Mbit/s | proxy CPU (1 core = 100%) |
|---|---|---|---|---|
| video 1280×720 | direct | 24.6 / 26.8 / 28.2 | 34–39 | – |
| video 1280×720 | proxy | 25.8 / 25.2 / 31.9 | 34–44 | 17–18 % |
| scroll full screen | direct | 30.3 / 31.2 / 31.9 | 171–185 | – |
| scroll full screen | proxy | 31.9 / 31.9 / 31.9 | 185 | 48–50 % |

Input-to-frame latency (`perfload latency`, key every 500 ms, ~48 samples per run):
- Direct: p50 between 5 and 17 ms, p95 22–24 ms.
- Through the proxy: p50 between 1 and 18 ms, p95 20–35 ms.

**Reading:**
- The proxy costs **no frame rate**.
- Its effect on latency is **below the noise** of this host (about ±10 ms).
- Its CPU cost scales with bandwidth: about **0.3–0.5 % of one core per Mbit/s**,
  since it decrypts and re-encrypts TLS. At H.264 rates (5–20 Mbit/s per session)
  that is 2–10 % of a core per active session.
- With RFX/progressive (100+ Mbit/s on high motion) it can reach half a core per
  session. freerdp-proxy runs one thread per connection, so the cost spreads
  across cores.

Size proxy CPU for the RFX case if you have clients without H.264.

## Ubuntu's FreeRDP has no H.264 (clients!)

`freerdp-shadow-cli /buildconfig` on Ubuntu 26.04 (FreeRDP 3.32.1) shows:

```
WITH_GFX_H264=OFF  WITH_FFMPEG=OFF  WITH_OPENH264=OFF  WITH_VIDEO_FFMPEG=OFF
```

So **`xfreerdp3`/`sdl-freerdp3` from Ubuntu cannot decode AVC420/AVC444**. They fall
back to RFX/progressive at 5–10× the bandwidth.

- Server side this does not matter:
  - xrdp encodes with x264;
  - g-r-d uses its own VA-API/NVENC path;
  - KRdp uses FFmpeg via KPipeWire;
  - the proxy passes GFX through without decoding.
- Linux clients should use a FreeRDP build with `WITH_GFX_H264=ON` (check
  `xfreerdp3 /buildconfig`). Windows mstsc supports AVC420/AVC444.
- Check what a session negotiated with `rdpbench` (`main_codec`) or with the
  client's log.

## What uses the GPU (by back-end)

| Back-end | Rendering | H.264 encoding | Intel/AMD | NVIDIA | Evidence |
|---|---|---|---|---|---|
| xrdp + xorgxrdp | glamor (`/dev/dri/renderD128`) | **x264 on CPU** (`fastrdp_x264_threads` per session) | GPU render, CPU encode | VirtualGL for GL apps (`vglrun`), CPU encode | xrdp 0.10.6 has only x264/OpenH264 encoders |
| GNOME / gnome-remote-desktop 50 | Mutter on GPU (GBM) | **VA-API via Vulkan** (needs a Vulkan device and a VA H.264 encoder), **NVENC via CUDA** | GPU both | GPU both | `grd-rdp-renderer.c`: Vulkan device first, then VA-API; `grd-hwaccel-nvidia.c`. Logs `[HWAccel.VAAPI] Successfully initialized` |
| Plasma / KRdp 6.6 | KWin on GPU | KPipeWire: **h264_vaapi → libx264 → libopenh264** | GPU both | **CPU (libx264)**: KPipeWire never tries NVENC | `kpipewire/src/pipewireproduce.cpp` |

Consequences:
- On **NVIDIA hosts**, GNOME sessions get hardware encoding and Plasma sessions do
  not. Size CPU for Plasma users, or steer them to GNOME
  (`fastrdp_group_desktops`).
- On **Intel/AMD hosts**, both Wayland back-ends encode on the GPU. Install the VA
  driver with H.264 *encode* support: `va-driver-all` includes Intel `iHD` and AMD
  `radeonsi`; check `vainfo | grep EncSlice`.
- xrdp sessions always encode on the CPU. GPU rendering (glamor) still helps
  compositing and GL apps.

Ubuntu's FFmpeg (`libavcodec62`) contains `h264_vaapi`, `h264_nvenc`, `h264_vulkan`
and `libx264`, so KPipeWire's VA-API and x264 paths are available.

## Tuning knobs (Ansible role `tuning`)

| Variable | Default | Effect |
|---|---|---|
| `fastrdp_tcp_tuning` | `true` | BBR + fq, no slow-start after idle, `tcp_notsent_lowat=128k`: lower queueing delay on WAN links |
| `fastrdp_user_cpu_quota` / `fastrdp_user_memory_max` | unset | Per-user caps on `user-UID.slice` (all of one user's sessions) |
| `fastrdp_krdp_encoder` | `auto` | Force `h264_vaapi` / `libx264` / `libopenh264` for Plasma (`KPIPEWIRE_FORCE_ENCODER`) |
| `fastrdp_krdp_quality` | KRdp default | `krdpserver --quality` (upper bound with adaptive quality) |
| `fastrdp_x264_threads`, `fastrdp_x264_preset`, `fastrdp_x264_fps` | 2 / ultrafast / 60 | xrdp H.264 cost vs. quality per session |

## Runbook for a GPU host

1. Deploy with `fastrdp_gpu: auto`, reboot if the NVIDIA driver was installed, then
   run `tests/smoke/check-host.sh`.
2. For each desktop (`xfce`, `gnome`, `plasma`), log in as a test user and run inside
   the session:
   - `python3 tests/gpu/session_report.py --json > report-<desktop>.json`
   - `perfload video &`
3. From a client with H.264-capable FreeRDP:
   `rdpbench --host <fqdn> --user <u> --password <p> --shell fastrdp:<desktop> --seconds 60 --json <desktop>-video.json`.
   Repeat with `perfload scroll` and `perfload latency` (`--latency`).
4. On the server: `nvidia-smi dmon -s u` (enc %) or `intel_gpu_top` (Video engine),
   plus `pidstat -u 5` for `Xorg|xrdp|gnome-shell|gnome-remote-d|kwin_wayland|krdpserver|freerdp-proxy`.
5. Scale: 1, 5, 10, 20 concurrent `rdpbench` clients on separate test accounts.
6. Record in `tests/perf/results/<date>-<host>.md`, using the template in
   `tests/perf/README.md`.

Targets: ≥ 30 fps at 1080p for video, < 50 ms added latency on the LAN, and
session_report showing GPU rendering plus hardware H.264 wherever the table above
says it should.
