# Performance measurement (phase 4)

Goal per session: **≥ 30 fps at 1920×1080** and **< 50 ms added latency on the LAN**.
Measure CPU/GPU cost per session to size hosts.

## Method

1. **Workloads** (inside the session, one at a time, 60 s each):
   - Video: `mpv --loop --fs bbb_1080p30.mp4` (Big Buck Bunny).
   - Scrolling: a long web page in Firefox with smooth scrolling, driven by
     `xdotool`/`ydotool`.
   - 3D: `glmark2 --fullscreen` (GL) and `vkcube` (Vulkan).
2. **Client side** (xfreerdp3 with `/gfx:avc444 /network:lan`):
   - Run with `WLOG_LEVEL=INFO` and count frames from the GFX
     `EndFrame`/`FrameAcknowledge` log lines per second.
   - Check that the client log shows `AVC444` (or `AVC420`), not `RemoteFX`/`Planar`.
3. **Server side** (per session):
   - `pidstat -u -h 5` for `Xorg`/`xrdp`/`gnome-shell`/`kwin_wayland`/`krdpserver`/`freerdp-proxy`.
   - GPU encode/render load: `nvidia-smi dmon -s u` (enc column) or `intel_gpu_top`
     (Video engine busy).
4. **Latency:** show a millisecond clock both locally and inside the session, side by
   side, and film both with a high-speed phone camera. Report the median difference
   of 20 samples.
5. **Proxy overhead:** repeat one workload connecting to the back-end directly
   (temporarily allowed via `nft`), then compare fps and CPU.
6. **Scale:** N concurrent sessions (1, 5, 10, 20) with the video workload. Record
   per-session fps and total host CPU/GPU.

Record results in `tests/perf/results/<date>-<host>.md` with hardware, driver
versions and the inventory variables used (`fastrdp_x264_threads`,
`fastrdp_x264_preset`, `fastrdp_gpu`).
