# xrdp back-end (X11 desktops)

Desktops: `xfce`, `mate`, `cinnamon`, `lxqt`, `plasma-x11`. The wlroots desktops use
the same back-end; their extra layer is in [wlroots.md](wlroots.md).

Driver: `broker/brokerd/fastrdp_broker/backends/xrdp.py`. xrdp and xorgxrdp are
fastrdp's own build (xrdp 0.10.6.1 + `patches/xrdp/`, xorgxrdp 0.10.5; versions in
`third_party/sources.yml`).

## How it works

1. The proxy authenticates the client and sends `login` to the broker
   ([README.md](README.md#login-flow)).
2. `XrdpBackend.ensure()`:
   1. checks that the listener on `[backends.xrdp] port` (default 3390) is owned by
      exactly uid 0 (`listener_user = "root"`: xrdp binds as root, then drops to
      `runtime_user=xrdp`). Otherwise: `backend error: xrdp listener on port 3390 not
      owned by uid 0 (found [...])`;
   2. writes the desktop's `xsession` name to `/run/fastrdp/desktop/<user>`
      (directory 0755, file 0644, written atomically);
   3. issues a one-time token `fastrdp1:…` (`tokens.py`): bound to the user, valid
      `token_ttl` (60 s), single use, memory only. If the proxy learned the user's
      real password (NLA with delegated credentials, or TLS password login), it is
      stored with the token;
   4. records a `Session(backend="xrdp", port=0)` in `/var/lib/fastrdp/sessions.json`
      and returns `127.0.0.1:3390`, `username=<user>`, `password=<token>`,
      `security=tls`.
3. The proxy connects to xrdp over TLS (`/etc/xrdp/cert.pem`, self-signed,
   `CertificatePolicy=allow` in `proxy.ini`) and auto-logs in with user + token.
4. xrdp (`require_credentials=true`, `hidelogwindow=true`, `[Xorg] username=ask
   password=ask`) passes the credentials to xrdp-sesman. sesman runs PAM service
   `xrdp-sesman` (`/etc/pam.d/xrdp-sesman`):
   - `pam_fastrdp_token.so` redeems the token over `/run/fastrdp/token.sock`
     (0600, root only). Results:
     - valid + password known → `PAM_SUCCESS`, password set as `PAM_AUTHTOK`, then
       `pam_sss.so use_first_pass` gets a Kerberos TGT;
     - valid, no password (Kerberos SSO without delegation, smartcard, web) →
       `PAM_IGNORE`, the stack skips `pam_sss` (no failed-logon counts in AD);
     - anything else → `PAM_AUTH_ERR`. A plain password never works here, so xrdp
       cannot be used to bypass MFA.
   - session phase: `pam_mkhomedir` (before `pam_systemd`, which starts the user
     manager in the home; the broker has normally created the home already, or
     refused a home with a missing parent), `pam_systemd.so class=user type=x11`
     (logind session), `pam_sss`, keyrings if installed.
5. If the user has a session for the same colour depth (`[Sessions] Policy=Default`),
   sesman reconnects to it. Otherwise it starts `/usr/lib/xorg/Xorg -config
   xrdp/xorg.conf` (display offset 10) as the user, then the window manager script.
6. `startwm.sh` (`EnableUserWindowManager=false`, so `~/startwm.sh` is ignored)
   sources `/etc/profile` and `~/.profile`, reads `/run/fastrdp/desktop/$USER`
   (characters outside `A-Za-z0-9._-` removed), falls back to `xfce` if the file or
   `/usr/share/xsessions/<name>.desktop` is missing, takes `Exec=` and `DesktopNames=`
   from the `.desktop` file and runs `dbus-run-session -- <Exec>`.
7. On disconnect the module sends `end`; the X session keeps running.

### Processes and users

| Process | User | Unit / cgroup | Notes |
|---|---|---|---|
| `xrdp` (listener + one forked child per connection) | binds as root, runs as `xrdp` | `xrdp.service` | TLS to the proxy; **H.264 encoder runs here** |
| `xrdp-sesman` | root | `xrdp-sesman.service` | PAM, session start |
| `Xorg` with `xorgxrdp` | session user | user's logind session | rendering (glamor or software) |
| `xrdp-chansrv` | session user | user's logind session | clipboard, drives (FUSE), audio channel |
| desktop (`startwm.sh` → `dbus-run-session`) | session user | user's logind session | own D-Bus session bus per X session |

### Reconnect and session lifetime

- Reconnect is xrdp's own: one session per user and colour depth (`Policy=Default`).
  A client that connects with another colour depth gets a second session.
- Disconnected sessions stay (`KillDisconnected=false`). `DisconnectedTimeLimit` =
  `fastrdp_xrdp_disconnected_time_limit` × 60 s; 0 (default) = never.
  `IdleTimeLimit=0`.
- On reconnect the desktop already running is used. `/run/fastrdp/desktop/<user>`
  is read only when a new session starts, so switching from `xfce` to `mate` needs a
  logout first. The broker sees the running session (a logind session of the user
  opened by the `xrdp-sesman` PAM service, state not `closing`), keeps the recorded
  desktop and logs `reconnecting to running <desktop> session (requested <other>)`.
- `fastrdpctl logout USER` ends only those xrdp logind sessions
  (`loginctl terminate-session <id>`); SSH and other logins of the user stay.
- `fastrdpctl status` first drops records of xrdp sessions that no longer exist
  (ended from inside the session, or after a reboot).

### Resize and multi-monitor

- `xrdp.ini`: `allow_multimon=true`; `proxy.ini`: `DisplayControl=true`.
- `xorg.conf` lists fixed modes up to 1920×1080; xorgxrdp also resizes to the
  client size on connect and on DisplayControl requests (upstream behaviour).
- Multi-monitor and dynamic resize **through freerdp-proxy** are not tested in
  this repository (to validate).

### Channels

| Channel | xrdp setting | Notes |
|---|---|---|
| Clipboard | `cliprdr=true`; sesman `RestrictOutboundClipboard=none`, `RestrictInboundClipboard=none` | handled by chansrv |
| Drives | `rdpdr=true`; `[Chansrv] FuseMountName=thinclient_drives`, `FileUmask=077` | needs `fuse3` (runtime package of the role) |
| Audio out | `rdpsnd=true`; `PULSE_SCRIPT=/etc/xrdp/pulse/default.pa` | needs an xrdp sink module for PulseAudio/PipeWire (e.g. `pulseaudio-module-xrdp` or `pipewire-module-xrdp`). **No role installs one; audio is untested and probably does not work as deployed.** |
| RemoteApp | `rail=true` in xrdp | the proxy has `RemoteApp=false` |
| Video redirection | `xrdpvr=true` | not tested |

## Components on a deployed host

| Path | From | Content |
|---|---|---|
| `/usr/local/sbin/xrdp`, `/usr/local/sbin/xrdp-sesman` | build (`third_party/build-xrdp.sh`, prefix `/usr/local`) | xrdp binaries |
| `/usr/sbin/xrdp`, `/usr/sbin/xrdp-sesman`, `/usr/lib/xrdp/` | apt (`fastrdp-xrdp`, prefix `/usr`) | same, packaged; conflicts with the distro `xrdp`/`xorgxrdp` |
| `/etc/systemd/system/xrdp{,-sesman}.service` | build | units (`FASTRDP_XRDP_UNITDIR`) |
| `/usr/lib/systemd/system/xrdp{,-sesman}.service` | apt | units (installed disabled; the role enables them) |
| `/etc/xrdp/xrdp.ini` | `xrdp.ini.j2` | loopback listener, TLS, channels, frame intervals |
| `/etc/xrdp/sesman.ini` | `sesman.ini.j2` | session policy, Xorg command line, chansrv |
| `/etc/xrdp/gfx.toml` | `gfx.toml.j2` | GFX codec order and H.264 encoder settings |
| `/etc/X11/xrdp/xorg.conf` | `xorg.conf.j2` | xorgxrdp devices; glamor options |
| `/etc/xrdp/cert.pem`, `/etc/xrdp/key.pem` | role (build) or `fastrdp-xrdp.postinst` (apt) | loopback TLS cert (EC P-256, CN `fastrdp-xrdp-backend`); key `root:xrdp 0640` |
| `/etc/xrdp/startwm.sh` | `broker/session/libexec/startwm.sh` (build) or copied from `/usr/libexec/fastrdp/startwm.sh` (apt, `fastrdp-session`) | desktop launcher |
| `/etc/pam.d/xrdp-sesman` | `broker/session/pam/xrdp-sesman` (build) or copied from `/usr/share/fastrdp-session/pam.d/xrdp-sesman` (apt) | token-only PAM stack |
| `/usr/lib/<triplet>/security/pam_fastrdp_token.so` | role `broker` (build) or `libpam-fastrdp-token` | token PAM module |
| `/run/fastrdp/desktop/<user>` | broker | chosen xsession name |
| `/run/fastrdp/token.sock` | broker | token redemption, root only |
| `/usr/share/xsessions/*.desktop` | desktop packages, `fastrdp-session` | what `startwm.sh` can start |
| `/usr/local/src/fastrdp/vendor/.installed-xrdp-<key>-glamor<bool>-ffmpeg<bool>` | build | build stamp; a new key, glamor or FFmpeg choice triggers a rebuild |

Logs: `xrdp.ini` `LogFile=xrdp.log` and `sesman.ini` `LogFile=xrdp-sesman.log`
(relative names; xrdp resolves them under `/var/log`), both also to syslog
(`EnableSyslog=true`). Xorg writes `.xorgxrdp.<display>.log` (relative path from
`sesman.ini`; the exact directory depends on xrdp/Xorg defaults, typically the
user's home or `~/.local/share/xorg/`).

## Configuration

Role `xrdp` (`ansible/roles/xrdp/defaults/main.yml`) unless noted.

| Variable | Default | Effect |
|---|---|---|
| `fastrdp_install_method` | `build` (role `base`) | `build`: compile on the host into `/usr/local`; `apt`: install `fastrdp-xrdp` + `fastrdp-session` |
| `fastrdp_xrdp_port` | `3390` (role `common`) | `xrdp.ini` `port=tcp://127.0.0.1:<port>`, broker `[backends.xrdp] port`, nftables set, reserved ports |
| `fastrdp_xrdp_h264_encoder` | `auto` | `auto` → `nvenc` (GPU stack `nvidia`), `vaapi` (`mesa`), else `x264`; or `vaapi`, `nvenc`, `qsv`, `x264`. Result: `fastrdp_xrdp_h264_encoder_effective` |
| `fastrdp_ffmpeg_qp` | `23` | `[ffmpeg.default] qp` (constant quality on LAN) |
| `fastrdp_ffmpeg_gop` | `300` | `[ffmpeg.default] gop` (IDR interval) |
| `fastrdp_x264_preset` | `ultrafast` | `[x264.default] preset` |
| `fastrdp_x264_fps` | `60` | `fps_num` for x264 and FFmpeg; `xrdp.ini` `h264_frame_interval = 1000/fps` |
| `fastrdp_x264_threads` | `2` (inventory `group_vars`) | `[x264.default] threads` |
| `fastrdp_xrdp_autodetect_profile` | `wan` (role `common`) | profile for clients that send connection type "auto-detect" (mstsc's default): broker `[network] xrdp_autodetect_profile`, gfx.toml `[x264.autodetect]` / `[ffmpeg.autodetect]` |
| `fastrdp_lan_networks` | `[]` (role `common`) | client CIDRs whose auto-detect sessions get `lan` (uncapped): broker `[network] lan_networks` |
| `fastrdp_xrdp_max_sessions` | `100` | `sesman.ini` `MaxSessions` |
| `fastrdp_xrdp_disconnected_time_limit` | `0` | minutes until disconnected sessions are killed; 0 = never |
| `fastrdp_xorgxrdp_glamor` | `true` if GPU stack is `mesa` or `fastrdp_xorgxrdp_nvidia_glamor` | build with `--enable-glamor` (build method) and write `DRMDevice`/`DRI3`/`DRMAllowList` into `xorg.conf` |
| `fastrdp_xorgxrdp_nvidia_glamor` | `false` | experimental glamor on `nvidia-drm` |
| `fastrdp_xorgxrdp_drm_device` | `/dev/dri/renderD128` | glamor device and `[ffmpeg] device` |
| `fastrdp_desktops`, `fastrdp_desktop_xsessions` | inventory / role `desktops` | which `[desktops.*]` the broker gets and their `xsession` names |
| `fastrdp_default_desktop`, `fastrdp_group_desktops` | inventory | broker `[defaults]` |

Broker side (`/etc/fastrdp/broker.toml`, rendered by role `broker`):

```toml
[desktops.xfce]
backend = "xrdp"
xsession = "xfce"          # /usr/share/xsessions/xfce.desktop

[backends.xrdp]
port = 3390
listener_user = "root"
# host = "127.0.0.1", security = "tls" are the defaults (config.py)
```

## GPU and performance path

### Rendering

- **Intel/AMD** (`fastrdp_gpu_effective == 'mesa'`): xorgxrdp with glamor renders
  on `fastrdp_xorgxrdp_drm_device`. `DRMAllowList "amdgpu i915 xe msm radeon"`.
  Clients of the X server get DRI3.
- **NVIDIA:** no glamor by default. GL/Vulkan applications use VirtualGL
  (`fastrdp_virtualgl`, VirtualGL `fastrdp_virtualgl_version` 3.1.5,
  `/etc/profile.d/fastrdp-virtualgl.sh` sets `VGL_DISPLAY=egl`): run `vglrun app`.
- **No GPU:** software rendering (Xorg `fb`, llvmpipe for GL clients).
- Render nodes are mode 0666 (`/etc/udev/rules.d/70-fastrdp-render.rules`,
  `fastrdp_render_nodes_world_accessible`), because remote sessions have no seat.

### Encoding

GFX codec order (`gfx.toml`): `H.264` then `RFX`. xrdp 0.10 sends H.264 as AVC420.

| `fastrdp_xrdp_h264_encoder_effective` | `gfx.toml` | Build |
|---|---|---|
| `x264` | `h264_encoder = "x264"` | without `--enable-ffmpeg` (build method) |
| `vaapi` / `nvenc` / `qsv` | `h264_encoder = "ffmpeg"`, `[ffmpeg] encoder = "h264_<enc>"`, `device`, `fallback = "libx264"`, `[ffmpeg.<conn-type>]` bitrate caps | `--enable-ffmpeg` |

The apt package `fastrdp-xrdp` is always built with `--enable-ffmpeg` and glamor;
`gfx.toml` and `xorg.conf` decide what is used.

Behaviour of the FFmpeg encoder (`patches/xrdp/README.md`):
- input is the NV12 frame xorgxrdp already produces; damaged rectangles are copied
  into a per-session frame; VA-API uploads it, NVENC/QSV take system memory;
- low-latency settings (no B-frames; NVENC `preset=p1 tune=ull zerolatency delay=0`);
- **start-up probe**: one 256×256 frame is encoded at encoder creation. If it fails,
  xrdp logs `xrdp_encoder_ffmpeg: <enc> is not usable on this host, falling back to
  libx264` and uses `fallback`;
- the encoder runs in the `xrdp` process (uid `xrdp`), which needs the render node
  (world-accessible via the udev rule) or `/dev/nvidia*`.

Rate control per RDP connection type (client `network:` setting or autodetect):
`[ffmpeg.lan]` uses `qp`; `wan` 12/15 Mbit/s, `broadband_high` 6/8,
`satellite` 4/5, `broadband_low` 1.4/1.6, `modem` 1.0/1.2 (bitrate/max). x264 has
matching `vbv_max_bitrate` caps and slower presets on slow links. The values live in
one table in `gfx.toml.j2`.

**Auto-detect.** xrdp 0.10.6.1 keeps parameters for types 1–6 only
(`NUM_CONNECTION_TYPES` 7 in `xrdp/xrdp_tconfig.h`) and encodes type 7 (auto-detect,
mstsc's default) and 0 (none sent) like `lan`. An `[x264.autodetect]` section is parsed
but never used. fastrdp therefore changes the type on the proxy's back-end hop: the
broker returns `connection_type` with the login target, `lan` for clients in
`fastrdp_lan_networks`, otherwise `fastrdp_xrdp_autodetect_profile` (default `wan`), and
the proxy module sends that to xrdp. Types 1–6 chosen by the client are kept. gfx.toml
still gets `[x264.autodetect]` / `[ffmpeg.autodetect]` equal to the chosen profile, for
an xrdp that reads them. Details: [performance.md](../performance.md#bitrate-profile-of-x11-xrdp-sessions).

**Status:** the FFmpeg path is tested with libx264 through the same code and with
VA-API/NVENC falling back in a GPU-less sandbox. It is **not yet tested on real
Intel/AMD/NVIDIA GPUs**.

### Verifying

```sh
# Which encoder did xrdp pick? (encoder lines are logged once per encoder creation)
sudo grep -E 'xrdp_encoder_create|xrdp_encoder_ffmpeg' /var/log/xrdp.log | tail
journalctl -u xrdp -g xrdp_encoder | tail

# Inside the session, as the user
python3 tests/gpu/session_report.py
#   rendering:     gpu (mesa)   <- Xorg holds /dev/dri/renderD128 (glamor)
#   H.264 encoder: xrdp: not readable as this user, see xrdp.log 'xrdp_encoder_ffmpeg: using'
sudo python3 tests/gpu/session_report.py   # as root the xrdp process maps are readable

# GPU engine load while video plays (perfload video from tests/perf/rdpbench)
sudo intel_gpu_top            # Video engine
nvidia-smi dmon -s u          # enc %
vainfo | grep EncSlice        # VA driver can encode H.264
```

`session_report.py` lists **every** `xrdp` process on the host (one per connection,
any user's), because which one serves the current session is not visible from
`/proc`. If they disagree, the verdict says `differs between xrdp processes ...` and
lists each; `xrdp.log` (`xrdp_encoder_ffmpeg: using ...`) is the authoritative answer.

### Tuning knobs

- `fastrdp_xrdp_h264_encoder`, `fastrdp_ffmpeg_qp`, `fastrdp_ffmpeg_gop`,
  `fastrdp_x264_*` (above).
- `fastrdp_xrdp_autodetect_profile` (default `wan`) and `fastrdp_lan_networks`: the
  bitrate cap for mstsc's default "auto-detect" connections, and the client networks
  that get the uncapped `lan` profile.
- Role `tuning`: `fastrdp_tcp_tuning` (BBR + fq), `fastrdp_user_cpu_quota`,
  `fastrdp_user_memory_max`, `fastrdp_user_tasks_max` on `user-.slice`.
  The per-user slice limits cover Xorg and the desktop, **not** the H.264 encoder,
  which runs in `xrdp.service` (system slice) for all users together. Cap that daemon
  as a whole with `fastrdp_xrdp_cpu_quota` / `fastrdp_xrdp_memory_max` (e.g. `800%`),
  sized for the number of concurrent sessions.
- Size CPU for x264 if no hardware encoder works: about `fastrdp_x264_threads`
  threads per active session ([performance.md](../performance.md)).

## Security properties

- xrdp listens on `127.0.0.1:<fastrdp_xrdp_port>` only (`xrdp.ini` `port=`); the
  smoke test checks it. nftables drops new non-loopback connections to the port and
  rejects loopback connections from users other than `_fastrdp-proxy` and root.
- The only accepted credential is a broker token (60 s, single use, bound to the
  user). `token.sock` accepts only uid 0 (xrdp-sesman).
- `AllowRootLogin=false`, `MaxLoginRetry=1`, `AlwaysGroupCheck=false` (group checks are
  in the broker and SSSD). SSSD's GPO mapping includes `xrdp-sesman`
  (`ad_gpo_map_remote_interactive`).
- The broker refuses to route if the port is not held by root, so a user who binds
  3390 while xrdp is down cannot receive tokens.
- The xrdp daemon and its encoder run as `xrdp`; Xorg and the desktop run as the
  user. Users can see each other's processes unless `fastrdp_proc_hidepid: true`.
- The user's real password crosses only the proxy → broker → PAM path, never the
  RDP hop to xrdp (verified by `tests/proxy-e2e/run.sh`).

## Limitations and known issues

- Hardware H.264 is untested on real GPUs (VA-API, NVENC, QSV).
- No audio sink module is installed (see Channels).
- One X11 session per user (per colour depth); switching X11 desktops needs a logout.
- `fastrdpctl logout` terminates all of the user's logind sessions.
- H.264 is AVC420 only; xrdp 0.10 has no AVC444.
- NVIDIA: X server rendering is software unless the experimental glamor is enabled;
  applications need `vglrun`.
- Multi-monitor and dynamic resize through the proxy: to validate.
- glamor stability on the target GPUs: to validate ([desktop-matrix.md](../desktop-matrix.md#validation-items-before-production)).

## Troubleshooting

| Symptom | Checks |
|---|---|
| Client gets "session could not be started"; broker logs `xrdp listener on port 3390 not owned by uid 0 (found [])` | `systemctl status xrdp xrdp-sesman`; `ss -ltnp 'sport = :3390'`. `found [<uid>]` with a non-zero uid: another process holds the port |
| Login reaches xrdp but fails | `journalctl -t xrdp-sesman -g pam_fastrdp_token` or `journalctl _COMM=xrdp-sesman`: `invalid or expired broker token` (proxy took > 60 s, or token reused), `login for X without broker token refused`, `cannot reach broker at /run/fastrdp/token.sock`. Broker side: `token redemption failed for X` |
| Black screen / session ends at once | `/var/log/xrdp-sesman.log`; Xorg log `.xorgxrdp.<display>.log`; `journalctl _UID=$(id -u USER)`. Check `/run/fastrdp/desktop/USER` and that `/usr/share/xsessions/<name>.desktop` exists (`startwm.sh` silently falls back to `xfce`) |
| Wrong desktop | an existing session was reused (logout first), or the hint was refused: `journalctl -u fastrdp-brokerd -g "login USER"` shows the chosen desktop |
| No session TGT (`klist` empty) | expected for Kerberos SSO without delegated password, smartcard and web logins; otherwise check `pam_sss` in `journalctl -t xrdp-sesman` |
| Low fps / high CPU in `xrdp` | `grep xrdp_encoder_ffmpeg /var/log/xrdp.log` for a fallback; `vainfo`, `ls -l /dev/dri/renderD128`; client must decode H.264 ([client-guide.md](../client-guide.md)) |
| Glamor not active | `grep -i glamor ~/.xorgxrdp.*.log`; `fastrdp_gpu_effective` in the Ansible output; `/etc/X11/xrdp/xorg.conf` has `DRMDevice` only when glamor is on |
| Host-level checks | `sudo tests/smoke/check-host.sh USER`: services `xrdp`, `xrdp-sesman` active, 3390 on loopback only, `token.sock` 0600, `pam_fastrdp_token.so` present, xrdp built with x264, nftables blocks user `nobody` from 3390 |

## Tests

| Test | What |
|---|---|
| `make test-pam` | token module against a fake broker: valid token with and without password (next module sees the password / is skipped), unknown token, another user's token, plain password |
| `make test-broker` | token store, desktop choice, listener-uid parsing (the xrdp driver's `ensure()` itself is mocked) |
| `make test-e2e` | proxy sends the token, never the password, to a TLS back-end; shell hint not forwarded |
| `make test-xrdp-encoder XRDP_SRC=…` | FFmpeg encoder with libx264; `h264_vaapi` with `fallback = ""` failing cleanly |
| `make test-gpu` | `session_report.py` verdicts for xrdp (software, VA-API, unreadable) |
| `tests/smoke/check-host.sh` | deployed host (manual) |

No automated test starts a real xrdp/xorgxrdp session.
