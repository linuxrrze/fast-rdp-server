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

## Host safety: power actions

One user must not be able to shut down, reboot, suspend, hibernate or halt the shared host. The base role
installs the polkit rule `/etc/polkit-1/rules.d/40-fastrdp-power.rules` for this
(`fastrdp_block_power_actions: true`, the default).

**Without the rule (upstream defaults).** logind (systemd 257 on Debian 13, 259 on Ubuntu 26.04) asks
polkit for `org.freedesktop.login1.power-off`, `reboot`, `halt`, `suspend` or `hibernate`. When other
users are logged in, which is always the case on a terminal server, it asks for the `-multiple-sessions`
variant, and for `-ignore-inhibit` when an inhibitor blocks. `systemctl poweroff`/`reboot`/`suspend`
as a user goes through the same logind call. polkit treats a session as *local* only when it has a
seat. No fastrdp session has one:

| Session | How logind registers it | polkit sees |
|---|---|---|
| xrdp (X11 desktops, wlroots) | xrdp-sesman's PAM: `PAM_TTY=:N` (an X display whose server has no VT), `PAM_RHOST` = client address, no `XDG_SEAT` → type `x11`, class `user`, no seat | not local → `allow_any` |
| GNOME | GDM's RemoteDisplayFactory (`gdm-new-session --headless`): a display with `is-local=false` and no seat id, so no `XDG_SEAT` → type `wayland`, no seat | not local → `allow_any` |
| Plasma | `fastrdp-plasma@.service`, `PAMName=fastrdp-session`, no `TTYPath=` (no `PAM_TTY`), `pam_systemd type=wayland` → no seat | not local → `allow_any` |

`allow_any` is `auth_admin_keep` for all of these actions. So a user cannot do it without a password,
but every desktop shows the entries ("challenge"), and anyone who knows an admin's password (polkit
admins: group `sudo`, on Ubuntu also `admin`) can shut the host down from any session. Only active
sessions *on a seat* (the console, GDM's login screen) get `allow_active = yes`, and Ubuntu's
`policykit-desktop-privileges` refuses hibernate for everyone. Root is never asked (`sudo systemctl
poweroff` works).

**With the rule.** For the 15 power actions and `set-reboot-parameter`/`set-reboot-to-*` (these
imply `reboot` in polkit and would otherwise authorize it through `allow_active = yes`):

| Who | Answer | Desktop menus |
|---|---|---|
| user | `no` (logind `CanPowerOff` and friends: `no`) | entries hidden or greyed out (table below) |
| member of `fastrdp_power_admin_groups` (default `[sudo]`) | `auth_admin_keep`: admin password, as before | entries shown, password prompt |
| root | never reaches the rules | `sudo systemctl poweroff` works |
| active console session, with `fastrdp_power_allow_local_console: true` | upstream defaults (`yes`) | as without the rule |

Log out, lock, switching users, inhibitors (`systemd-inhibit`), lingering and the wall message keep
their defaults. polkitd reloads the rules directory by itself.

| Desktop | Reaction to `no` | Basis |
|---|---|---|
| GNOME (Shell system menu, end-session dialog) | power off, restart and suspend hidden | verified in source: gnome-session maps `no`/`na` to unavailable, gnome-shell `systemActions.js` hides unavailable actions |
| Plasma, Plasma X11 | shutdown, restart, sleep, hibernate hidden in the leave menu and logout screen | verified in source: libkworkspace counts only `yes`/`challenge`/inhibited as possible |
| MATE | buttons not added to the shutdown dialog | verified in source: mate-session `gsm-logout-dialog.c` |
| XFCE | logout dialog keeps *Restart*, *Shut Down*, *Suspend*, *Hibernate* visible but greyed out | verified in source: xfce4-session sets them insensitive |
| LXQt | lxqt-leave buttons disabled/hidden | source: liblxqt counts only `yes`/`challenge`; dialog to validate |
| Cinnamon | hidden like GNOME | to validate (cinnamon-session is a gnome-session fork) |
| Sway, labwc, Wayfire | the launchers add no power menu; `systemctl poweroff` in a terminal is refused | verified (repository) |

Settings (`roles/common/defaults/main.yml`, checked by the common role):

- `fastrdp_block_power_actions: true`. `false` removes the rule.
- `fastrdp_power_admin_groups: [sudo]`. These users still get the admin password prompt. Name only
  groups that polkit accepts as admins (Ubuntu/Debian: `sudo`, Ubuntu also `admin`). For a directory
  group (e.g. `rdp-admins@example.com`), add a polkit admin rule for it as well, or those admins can
  only answer the prompt with a `sudo` member's password. `[]` = only root.
- `fastrdp_power_allow_local_console: false`. `true` leaves active console sessions (including GDM's
  login screen) at the upstream defaults. RDP sessions never have a seat.

Check on the host: log in over RDP as a normal user and as an admin, then
`sudo tests/smoke/check-power-actions.sh USER...` (it only queries polkit and logind, it never
powers off). In a session terminal, `busctl --system call org.freedesktop.login1
/org/freedesktop/login1 org.freedesktop.login1.Manager CanPowerOff` must print `s "no"`. Only after
that, `systemctl -i poweroff` must be refused with *Access denied*. Without `-i`, systemctl stops
earlier because other users are logged in, so that message proves nothing. Not covered: other services that reboot
on their own after an update (e.g. PackageKit offline updates triggered by an admin), and the physical
power button (logind `HandlePowerKey`).

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
