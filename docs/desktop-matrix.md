# Desktops, back-ends and GPU use

Per-back-end details (how sessions start, files, configuration, troubleshooting):
[backends/](backends/README.md).

Status legend:
- **verified** = tested in this repository (unit tests, build, or proxy end-to-end tests).
- **to validate** = written against upstream source/docs; needs a lab run on real hardware.

| Desktop (`fastrdp_desktops`) | Back-end | Display server | Rendering | Video encoding to client | Status |
|---|---|---|---|---|---|
| `xfce` | xrdp | Xorg + xorgxrdp | glamor on Intel/AMD; llvmpipe otherwise; VirtualGL for GL apps on NVIDIA | H.264 AVC420 via **VA-API/NVENC** (fastrdp FFmpeg patch) or **x264 (CPU)**, RFX fallback | to validate (xrdp build + configs verified to render) |
| `mate`, `cinnamon`, `lxqt` | xrdp | Xorg + xorgxrdp | as above | as above | to validate |
| `plasma-x11` | xrdp | Xorg + xorgxrdp | as above | as above | to validate; Plasma 6.6 on Ubuntu 26.04 still ships the X11 session |
| `gnome` (GNOME 50+, Wayland only) | gnome-remote-desktop headless, started via GDM `gnome-headless-session@USER` | Mutter headless | GPU via Mesa/NVIDIA GBM | H.264 via **VA-API or NVENC (GPU)**; without either: RFX progressive (g-r-d has no software H.264) | to validate |
| `plasma` (Plasma 6, Wayland) | KRdp (`krdpserver --plasma`) in a `kwin_wayland --virtual` session | KWin virtual backend | GPU via Mesa/NVIDIA GBM | H.264 via **VA-API** (Intel/AMD); **x264 on CPU on NVIDIA** (KPipeWire has no NVENC path) | to validate; **unofficial** headless mode (spike) |
| `sway`, `labwc`, `wayfire` (wlroots, Wayland) | xrdp; the compositor runs **nested** on the wlroots X11 backend inside the xorgxrdp display (`wlroots-in-x`) | Xorg + xorgxrdp, compositor fullscreen in one X window | GLES via glamor/DRI3 (Intel/AMD); pixman (software) otherwise | same as X11 desktops (VA-API/NVENC or x264) | launcher verified with Xvfb: start, resize to the X root size, clipboard both ways, restart over a stale socket (`tests/wlroots/run.sh`); full xrdp session to validate |
| Hyprland | – | – | – | – | not supported: Hyprland 0.53 (Aquamarine) has no X11 backend; would need a second nesting layer |

## wlroots desktops (Sway, labwc, Wayfire)

There is no maintained RDP server for wlroots compositors; wayvnc is the only
exporter, and a VNC hop would lose H.264 and the GPU path. Instead, the compositor
runs **inside** an ordinary xrdp session:

1. The broker routes the login to xrdp like any X11 desktop. The xsession entry
   `fastrdp-<compositor>` runs `/usr/libexec/fastrdp/wlroots-in-x <compositor>`.
2. The launcher starts the compositor with `WLR_BACKENDS=x11`, so it draws into
   one fullscreen window of the xorgxrdp display. xrdp still provides H.264/GFX,
   clipboard, drives, audio and reconnects (audio needs an xrdp sink module, which
   no role installs; see [backends/xrdp.md](backends/xrdp.md#channels)).
3. **Renderer:** GLES when the X server offers DRI3 (xorgxrdp-glamor on
   Intel/AMD); otherwise pixman. Wayfire's GL effects (cube, fisheye, …) need GLES.
4. **Size:** the launcher watches the X root size (dynamic resolution, reconnects)
   and sets the compositor's output with `wlr-randr --custom-mode`.
5. **Keyboard:** the compositor gets the X session's layout (`setxkbmap -query`)
   at start.
6. **Clipboard:** `clipboard-bridge` copies text both ways between X (the RDP
   clipboard channel) and the Wayland clipboard.
7. **Restarts:** the compositor's socket is identified from its own file
   descriptors, so stale `wayland-N` sockets from a crashed session are harmless.

Notes:
- Sway's default modifier is the Windows key, which many RDP clients keep for the
  local OS. Use the client's "send Windows key to remote" option or change `$mod` in
  `~/.config/sway/config`.
- Only text crosses the clipboard bridge.
- A keyboard layout change in the client needs a reconnect, which restarts the
  compositor.

## Choosing a desktop

Users get exactly one desktop per login. The broker picks it in this order:

1. Client hint: put `fastrdp:<desktop>` into the RDP *alternate shell* field
   - mstsc `.rdp`: `alternate shell:s:fastrdp:gnome`
   - xfreerdp3: `/shell:fastrdp:gnome`
2. `~/.config/fastrdp/desktop` containing the desktop name, e.g. `plasma`.
3. A group default from `fastrdp_group_desktops`.
4. `fastrdp_default_desktop`.

A user can have one running session per back-end. Switching from `xfce` to `gnome`
starts a second session; the X11 one keeps running until logout or timeout.

Measured numbers, encoder details per back-end, tuning knobs and the GPU-host
runbook: [performance.md](performance.md).

## GPU notes

- `fastrdp_gpu: auto` picks `nvidia` (PCI vendor 10de), `mesa` (Intel 8086 /
  AMD 1002) or `none`.
- Render nodes (`/dev/dri/renderD*`) are made world-accessible (udev rule).
  Remote sessions have no seat, so logind never grants them device ACLs.
  Render nodes expose no display or modesetting control, which is why this is the
  usual choice for terminal servers. Set `fastrdp_render_nodes_world_accessible: false`
  to opt out.
- **Intel/AMD:**
  - X11 sessions render through glamor (`DRMAllowList` includes `xe` for current
    Intel GPUs).
  - Wayland sessions render on the GPU and encode H.264 with VA-API.
- **NVIDIA:**
  - The proprietary driver needs KMS for headless Wayland (`nvidia-drm modeset=1`,
    set by the `gpu` role; reboot needed).
  - X11 sessions use VirtualGL with its EGL back-end (`vglrun app`); glamor on
    `nvidia-drm` is experimental (`fastrdp_xorgxrdp_nvidia_glamor`).
  - g-r-d encodes with NVENC.
- **Vulkan:**
  - Works natively in GNOME/Plasma Wayland sessions.
  - In X11 sessions it works with glamor (DRI3) on Mesa. On NVIDIA it goes through
    the NVIDIA ICD; check with `vulkaninfo --summary`.
- **xrdp encoder:** with the fastrdp FFmpeg patch (`patches/xrdp/`), xrdp encodes
  H.264 with VA-API (Intel/AMD) or NVENC (NVIDIA) when `fastrdp_xrdp_h264_encoder`
  is `auto`, and falls back to x264 on the CPU (`fastrdp_x264_threads`, default 2
  per session) if the GPU encoder fails its start-up probe or no GPU is found. The
  hardware path is not yet tested on real GPUs; size CPUs for x264 until it is.
  Details: [backends/xrdp.md](backends/xrdp.md#encoding).

## Validation items before production

1. **Plasma headless:** `fastrdp-plasma@USER` reaches a usable desktop, KRdp streams
   output 0, and input works.
   - Check: `journalctl -u fastrdp-plasma@USER`, `systemctl --user -M USER@ status plasma-kwin_wayland`.
   - Fallback: `plasma-x11`.
2. **GNOME headless:** GDM creates the session without a greeter and g-r-d headless
   listens on the broker's port.
   - Check whether sssd GPO mapping needs GDM's PAM service as well (look for
     `pam_sss ... gdm` denials).
3. **glamor stability** on the actual GPUs; NVIDIA with VirtualGL.
4. **GFX/H.264 passthrough** through freerdp-proxy for each back-end (client shows
   an H.264 codec: AVC420 for xrdp, which has no AVC444; compare fps with and
   without the proxy).
