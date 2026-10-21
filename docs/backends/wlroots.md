# wlroots desktops (Sway, labwc, Wayfire) nested in xrdp

Desktops: `sway`, `labwc`, `wayfire`. Hyprland is not supported (no X11 backend in
Aquamarine; see [desktop-matrix.md](../desktop-matrix.md)).

There is no RDP server for wlroots compositors. fastrdp runs the compositor as the
"desktop" of an ordinary xrdp session: the compositor uses wlroots' X11 backend and
draws into one fullscreen window of the xorgxrdp display. Everything below the X
server (login, token handoff, encoder, channels, reconnect) is the
[xrdp back-end](xrdp.md); this page covers only the extra layer.

## How it works

1. The broker treats these desktops as `backend = "xrdp"` with
   `xsession = "fastrdp-<compositor>"` (`fastrdp_desktop_xsessions`) and routes to
   xrdp exactly like `xfce` ([xrdp.md](xrdp.md#how-it-works)).
2. `startwm.sh` reads `fastrdp-sway` (etc.) from `/run/fastrdp/desktop/<user>`
   and runs the `Exec=` line of `/usr/share/xsessions/fastrdp-sway.desktop`:
   `/usr/libexec/fastrdp/wlroots-in-x sway`, inside `dbus-run-session`.
3. `wlroots-in-x <comp>` (as the user, `$DISPLAY` set by xrdp):
   - exports `WLR_BACKENDS=x11 WLR_X11_OUTPUTS=1 XDG_SESSION_TYPE=wayland`,
     `XDG_CURRENT_DESKTOP=<comp>`, and `MOZ_ENABLE_WAYLAND=1`,
     `QT_QPA_PLATFORM="wayland;xcb"`, `GDK_BACKEND="wayland,x11"` for applications;
   - **renderer:** if `xdpyinfo -queryExtensions` does not list `DRI3`, sets
     `WLR_RENDERER=pixman` (software); otherwise wlroots picks its GPU renderer
     (GLES2) and shares dma-bufs with Xorg;
   - **keyboard:** copies `setxkbmap -query` (model, layout, variant, options) into
     `XKB_DEFAULT_*`, once at start;
   - Sway on hosts with `/proc/driver/nvidia/version` gets `--unsupported-gpu`;
   - starts the compositor, then finds **its** Wayland socket: the listening Unix
     socket in `$XDG_RUNTIME_DIR` held by the compositor's own file descriptors
     (`/proc/<pid>/fd` → inode → `/proc/net/unix`). Stale `wayland-N` sockets from a
     crashed session are ignored. Gives up after 100 × 0.1 s;
   - **size follower** (background loop, 1 s): reads the X root size with `xdpyinfo`
     and applies it with `wlr-randr --output X11-1 --custom-mode <WxH>` when it
     changes (dynamic resolution, reconnect with another size);
   - **clipboard:** starts `/usr/libexec/fastrdp/clipboard-bridge`
     (`$FASTRDP_LIBEXEC` overrides the directory);
   - **notifications:** starts `mako` if installed (`mako-notifier`; the compositors
     bring no notification daemon) and `/usr/libexec/fastrdp/tgt-notify`, the
     Kerberos login reminder (these compositors run no XDG autostart;
     [long-running sessions](../nfs-kerberos-homes.md#long-running-sessions));
   - waits for the compositor; on exit kills its children.
4. `clipboard-bridge` (Python) polls both sides every 0.5 s with `xclip`
   (`UTF8_STRING`) and `wl-paste`/`wl-copy` (`text/plain;charset=utf-8`), copies
   whichever side changed last, and uses SHA-256 digests to avoid ping-pong. Max
   4 MiB. Text only.

Processes, all as the session user inside the xrdp logind session: Xorg (xorgxrdp),
`wlroots-in-x` (sh), the compositor, the size loop, `clipboard-bridge`, Xwayland for
X11 applications started inside the compositor (package `xwayland`).

## Components on a deployed host

| Path | From |
|---|---|
| `/usr/libexec/fastrdp/wlroots-in-x`, `/usr/libexec/fastrdp/clipboard-bridge` | role `desktops` (build, only if a wlroots desktop is in `fastrdp_desktops`) or package `fastrdp-session` |
| `/usr/share/xsessions/fastrdp-{sway,labwc,wayfire}.desktop` | role `desktops` (build: one per selected compositor) or `fastrdp-session` (all three) |
| packages per compositor | `fastrdp_desktop_packages`: `sway: [sway, swaybg, foot]`, `labwc: [labwc, foot]`, `wayfire: [wayfire, foot]` |
| helper packages | `fastrdp_wlroots_common_packages`: `xwayland, wlr-randr, wl-clipboard, xclip, x11-utils, x11-xkb-utils, python3` |

Everything else (xrdp, sesman, `startwm.sh`, PAM): [xrdp.md](xrdp.md#components-on-a-deployed-host).

## Configuration

Role `desktops` (`ansible/roles/desktops/defaults/main.yml`):

| Variable | Default | Effect |
|---|---|---|
| `fastrdp_desktops` | inventory | add `sway`, `labwc` and/or `wayfire` to enable them |
| `fastrdp_wlroots_desktops` | `[sway, labwc, wayfire]` | which desktop names get the launcher, helpers and xsession files |
| `fastrdp_desktop_xsessions` | `sway: fastrdp-sway`, … | `xsession` written into `broker.toml` |
| `fastrdp_desktop_packages` | see above | packages per compositor |
| `fastrdp_wlroots_common_packages` | see above | launcher and clipboard bridge dependencies |

Compositor configuration is the user's own (`~/.config/sway/config`,
`~/.config/labwc/`, `~/.config/wayfire.ini`) or the distribution default.
The launcher passes extra arguments after the compositor name to the compositor,
but the shipped `.desktop` files pass none.

## GPU and performance path

- **Rendering:** with xorgxrdp glamor (Intel/AMD, `fastrdp_xorgxrdp_glamor`), the X
  server offers DRI3 and wlroots renders with GLES2. Without DRI3 (no GPU, NVIDIA
  without experimental glamor) the launcher forces pixman. Wayfire's GL effects need
  GLES.
- **Encoding:** the xrdp encoder, identical to X11 desktops
  ([xrdp.md](xrdp.md#encoding)): FFmpeg VA-API/NVENC/QSV or x264, from `gfx.toml`.
- **Verify:**

  ```sh
  xdpyinfo -queryExtensions | grep DRI3          # present -> GLES renderer
  tr '\0' '\n' < /proc/$(pgrep -u "$USER" -x sway)/environ | grep WLR_RENDERER   # pixman if forced
  python3 tests/gpu/session_report.py           # Xorg row shows the render node (glamor)
  ```

  `session_report.py` lists `sway`, `labwc` and `wayfire` as renderers next to
  `Xorg`, so the compositor's own render node and GL driver appear in the report.
- **Cost:** one extra composition step (compositor → X window → xorgxrdp capture)
  compared with an X11 desktop. Not measured.

## Security properties

Same as [xrdp.md](xrdp.md#security-properties). The compositor, its Wayland socket
(`$XDG_RUNTIME_DIR`, user-private) and the clipboard bridge run as the user. The
bridge puts clipboard text through `xclip`/`wl-copy` processes of the same user
only.

## Limitations and known issues

- Sway's default `$mod` is the Windows key, which many clients keep locally. Use
  the client's "send Windows key to remote" option or change `$mod`.
- Clipboard: text only (no images, no files); 0.5 s polling.
- Keyboard layout is copied once at start; a layout change in the client needs a
  new session (logout/login).
- One output (`WLR_X11_OUTPUTS=1`, output name `X11-1`); RDP multi-monitor becomes
  one large X root and one compositor output.
- If `wlr-randr` fails (compositor without `wlr-output-management`), the output
  keeps its old size; the loop retries every second.
- Full xrdp session with a real xorgxrdp display and GPU: **to validate**. Tests ran
  on Xvfb only.
- Audio and drive redirection behave as in xrdp ([xrdp.md](xrdp.md#channels)).
- No desktop notifications without `mako-notifier` (not installed by fastrdp: its
  D-Bus activation file can take over notifications of MATE sessions on the same
  host); the Kerberos login reminder then only logs
  ([long-running sessions](../nfs-kerberos-homes.md#long-running-sessions)).

## Troubleshooting

| Symptom | Checks |
|---|---|
| Session closes right after login | xsession file present: `ls /usr/share/xsessions/fastrdp-*.desktop`; compositor installed (`command -v sway`); `startwm.sh` falls back to `xfce` if the `.desktop` file is missing, so an XFCE desktop instead of Sway also points here |
| `wlroots-in-x: sway did not create a Wayland socket` | the compositor exited or took > 10 s; run `DISPLAY=:10 /usr/libexec/fastrdp/wlroots-in-x sway` from a terminal in an X11 session to see its output; `journalctl _UID=$(id -u USER)` |
| Desktop does not follow window size | `WAYLAND_DISPLAY=wayland-N wlr-randr` inside the session; `xdpyinfo \| grep dimensions` |
| Clipboard not working | `pgrep -u USER -f clipboard-bridge`; `xclip -selection clipboard -o` and `wl-paste` inside the session; only text is bridged |
| Slow / software rendering | `xdpyinfo -queryExtensions \| grep DRI3`; glamor state in the xorgxrdp log ([xrdp.md](xrdp.md#troubleshooting)) |
| Wrong keyboard layout | check `setxkbmap -query` in the X session; reconnect does not update it |

## Tests

`make test-wlroots` (`tests/wlroots/run.sh`, manual, not in CI): for each installed
compositor it starts Xvfb at a fixed size (sway 1600×900, labwc 1920×1080, wayfire
1366×768), runs the launcher and checks:
- the compositor runs and its socket is found;
- the output size equals the X root size (initial size; a live resize is not
  exercised);
- clipboard X → Wayland and Wayland → X;
- a restart after `kill -9` with the stale socket left behind.

Not covered: real xorgxrdp, GPU renderer, the RDP path.
