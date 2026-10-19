# Desktops, back-ends and GPU use

Status legend:
- **verified** = tested in this repository (unit tests, build, or proxy end-to-end tests).
- **to validate** = written against upstream source/docs; needs a lab run on real hardware.

| Desktop (`fastrdp_desktops`) | Back-end | Display server | Rendering | Video encoding to client | Status |
|---|---|---|---|---|---|
| `xfce` | xrdp | Xorg + xorgxrdp | glamor on Intel/AMD; llvmpipe otherwise; VirtualGL for GL apps on NVIDIA | H.264 AVC420/444 via **x264 (CPU)**, RFX fallback | to validate (xrdp build + configs verified to render) |
| `mate`, `cinnamon`, `lxqt` | xrdp | Xorg + xorgxrdp | as above | as above | to validate |
| `plasma-x11` | xrdp | Xorg + xorgxrdp | as above | as above | to validate; Plasma 6.6 on Ubuntu 26.04 still ships the X11 session |
| `gnome` (GNOME 50+, Wayland only) | gnome-remote-desktop headless, started via GDM `gnome-headless-session@USER` | Mutter headless | GPU via Mesa/NVIDIA GBM | H.264 via **VA-API or NVENC (GPU)**; without either: RFX progressive (g-r-d has no software H.264) | to validate |
| `plasma` (Plasma 6, Wayland) | KRdp (`krdpserver --plasma`) in a `kwin_wayland --virtual` session | KWin virtual backend | GPU via Mesa/NVIDIA GBM | H.264 via **VA-API** (Intel/AMD); **x264 on CPU on NVIDIA** (KPipeWire has no NVENC path) | to validate; **unofficial** headless mode (spike) |
| Sway, labwc, Hyprland (wlroots) | – | – | – | – | phase 5 (wayvnc + xrdp VNC-over-UDS) |

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
- **xrdp encodes H.264 on the CPU** (x264; `fastrdp_x264_threads`, default 2 per
  session). Size CPUs for that. A VA-API/NVENC encoder for xrdp is a phase 5
  candidate.

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
   AVC444; compare fps with and without the proxy).
