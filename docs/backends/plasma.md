# Plasma back-end (KWin virtual backend + KRdp)

Desktop: `plasma` (Plasma 6, Wayland). Driver:
`broker/brokerd/fastrdp_broker/backends/plasma.py`. Status: **to validate**, and
headless KRdp with `kwin_wayland --virtual` is **not an officially supported Plasma
mode**. Fallback: `plasma-x11` through [xrdp](xrdp.md).

## How it works

Before `PlasmaBackend.ensure()`, under the same lock, the broker gets the user a
**Kerberos TGT** when the login carried the password (`[broker] session_tgt`), on every
login including reconnects; same mechanism as for
[GNOME](gnome.md#kerberos-ticket-tgt). The TGT is in the user's KCM cache before
`fastrdp-plasma@<user>` starts, so Plasma can use a Kerberized NFS home from its first
access. A reconnect with a password renews it (new renewal limit); before the limit the
session shows a reminder (`fastrdp_tgt_notify`, XDG autostart, plasmashell
notifications) ([long-running sessions](../nfs-kerberos-homes.md#long-running-sessions)).

`PlasmaBackend.ensure()` (under the broker's per-user lock):

1. **Reuse:** if `sessions.json` has a `plasma` session for the user,
   `fastrdp-plasma@<user>.service` is active and the recorded port is held by exactly
   the user's uid, return the stored target.
2. **Otherwise start:**
   1. allocate a port from `[broker] port_range` (as for [GNOME](gnome.md#how-it-works));
   2. random secret, per-user cert `/var/lib/fastrdp/users/<user>/tls.{crt,key}`;
   3. write `/run/fastrdp/sessions/<user>.plasma.env` (0600 root, directory 0700):
      ```
      FASTRDP_PORT, FASTRDP_RDP_USER=fastrdp, FASTRDP_RDP_PASSWORD,
      FASTRDP_WIDTH, FASTRDP_HEIGHT, FASTRDP_TLS_CERT, FASTRDP_TLS_KEY
      ```
      `WIDTH`/`HEIGHT` are the client's desktop size from this login (falls back to
      `[defaults] geometry` if the proxy sent none);
   4. record the session in `sessions.json`;
   5. `systemctl restart --no-block fastrdp-plasma@<user>.service` (a stale unit,
      e.g. after a KRdp crash, restarts with the new settings);
   6. wait up to 90 s for the port to listen as the user's uid.
3. Return `127.0.0.1:<port>`, `fastrdp` / secret, `security = "nla"`. The proxy uses
   NLA with `AuthenticationPackageList=!kerberos` (NTLM on the loopback hop).

`fastrdp-plasma@.service` (`broker/session/systemd/`):

```ini
[Unit]
After=systemd-user-sessions.service fastrdp-brokerd.service
ConditionPathExists=/run/fastrdp/sessions/%i.plasma.env
[Service]
User=%i
PAMName=fastrdp-session
EnvironmentFile=/run/fastrdp/sessions/%i.plasma.env
ExecStart=/usr/libexec/fastrdp/session-plasma
KillMode=control-group
Restart=no
TimeoutStopSec=20
```

- `PAMName=fastrdp-session` opens a logind session. `/etc/pam.d/fastrdp-session` has
  only account (`pam_sss`) and session modules (`pam_limits`, `pam_loginuid`,
  `pam_env` with `/etc/default/locale`, `pam_keyinit`, `pam_mkhomedir` (before
  `pam_systemd`; the broker has normally created the home already), `pam_systemd
  class=user type=wayland desktop=KDE`, `pam_sss`, optional `pam_kwallet5`).
  There is no auth phase; systemd does not call it. The session's TGT comes from the
  broker (PAM service `fastrdp-tgt`), not from this stack.

`/usr/libexec/fastrdp/session-plasma` (as the user):

1. requires the `FASTRDP_*` variables; sources `/etc/fastrdp/session.env` if present
   (`KPIPEWIRE_FORCE_ENCODER`, `FASTRDP_KRDP_QUALITY`);
2. sets `XDG_SESSION_TYPE=wayland`, `XDG_CURRENT_DESKTOP=KDE`,
   `DESKTOP_SESSION=plasma`, `DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus`;
3. `systemctl --user set-environment FASTRDP_HEADLESS=1 FASTRDP_WIDTH FASTRDP_HEIGHT`;
   the user drop-in `plasma-kwin_wayland.service.d/fastrdp.conf` replaces `ExecStart`
   with `/usr/libexec/fastrdp/kwin-wayland-launch`, which runs
   `kwin_wayland_wrapper --xwayland --virtual --width W --height H` when
   `FASTRDP_HEADLESS=1`, and the stock `kwin_wayland_wrapper --xwayland` otherwise;
4. starts `startplasma-wayland`, waits up to 60 s for `$XDG_RUNTIME_DIR/wayland-0`;
5. starts
   `krdpserver --plasma --address 127.0.0.1 --port $FASTRDP_PORT [--quality Q]
   --username fastrdp --password <secret> --certificate … --certificate-key …
   --monitor 0`. `--plasma` streams through KWin's screencast protocol, so no portal
   permission dialog appears;
6. polls every 2 s; when Plasma **or** KRdp exits, the script exits, unsets the
   environment variables and kills the other. With `KillMode=control-group` and
   `Restart=no` the unit then stops.

### Processes and users

| Process | User | Cgroup (expected from systemd semantics, not verified) |
|---|---|---|
| `session-plasma`, `krdpserver` | the user | `system.slice/fastrdp-plasma@<user>.service` |
| `startplasma-wayland` | the user | same unit |
| `kwin_wayland` (`plasma-kwin_wayland.service`), plasmashell and other Plasma user units | the user | `user@<uid>.service` in `user-<uid>.slice` |

Consequence: the `user-.slice` limits do not reach `krdpserver`, which does the H.264
encoding. Role `tuning` therefore applies the same per-user limits
(`fastrdp_user_cpu_quota`, `fastrdp_user_memory_max`, `fastrdp_user_tasks_max`) to
every `fastrdp-plasma@.service` instance as a drop-in. Check with
`systemd-cgls -u fastrdp-plasma@USER.service` and
`systemctl show -p CPUQuotaPerSecUSec fastrdp-plasma@USER.service`.

### Reconnect and session lifetime

- A new login reuses the running session with the same credentials while the unit is
  active and the port is owned by the user.
- The desktop size is fixed when the session starts (`--width/--height`). Whether
  KRdp honours DisplayControl resize requests is not tested.
- If KRdp or Plasma exits, the unit stops and the next login starts a **new**
  Plasma session (open applications are lost).
- `fastrdpctl logout USER` → `systemctl stop --no-block fastrdp-plasma@USER.service`.
- No idle or disconnect timeout in the broker.

### Channels

Clipboard, audio and drive redirection depend on KRdp's features; **none is tested
through fastrdp**. KRdp exports one output (`--monitor 0`).

## Components on a deployed host

| Path | From (build / apt `fastrdp-session`) |
|---|---|
| `/usr/libexec/fastrdp/session-plasma`, `/usr/libexec/fastrdp/kwin-wayland-launch` | role `plasma_krdp` / package |
| `/etc/systemd/system/fastrdp-plasma@.service` | role (build) |
| `/usr/lib/systemd/system/fastrdp-plasma@.service` | package (apt) |
| `/etc/systemd/user/plasma-kwin_wayland.service.d/fastrdp.conf` | role (build) |
| `/usr/lib/systemd/user/plasma-kwin_wayland.service.d/fastrdp.conf` | package (apt) |
| `/etc/pam.d/fastrdp-session` | role (build) / package |
| `/etc/fastrdp/session.env` | role `tuning` (always written; empty unless knobs are set) |
| `/etc/xdg/kscreenlockerrc` (`Autolock=false`, `LockOnResume=false`), `/etc/xdg/kdeglobals` (`AnimationDurationFactor=0`) | role `plasma_krdp` |
| `/run/fastrdp/sessions/<user>.plasma.env` | broker (0600 root) |
| `/var/lib/fastrdp/users/<user>/tls.{crt,key}` | broker |
| packages `fastrdp_plasma_packages`: `plasma-desktop, plasma-workspace, kwin-wayland, krdp, xwayland, konsole, dolphin` | role `plasma_krdp` |

The KWin drop-in applies to every user's `plasma-kwin_wayland.service` on the host;
without `FASTRDP_HEADLESS=1` it runs the stock command.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `fastrdp_desktops` contains `plasma` | inventory | `[desktops.plasma] backend = "plasma"`; runs role `plasma_krdp` |
| `fastrdp_plasma_packages` | see above | role `plasma_krdp` |
| `fastrdp_krdp_encoder` | `auto` (role `tuning`) | `h264_vaapi`, `libx264` or `libopenh264` → `KPIPEWIRE_FORCE_ENCODER` in `/etc/fastrdp/session.env` |
| `fastrdp_krdp_quality` | `""` (KRdp default) | 0–100 → `krdpserver --quality` |
| `fastrdp_default_geometry` | `1920x1080` (inventory) | fallback size if the client sent none |
| `fastrdp_backend_port_range` | `[33900, 34899]` | port pool |
| `[backends.plasma] unit` / `security` | `fastrdp-plasma@{user}.service` / `nla` | `config.py` defaults, not rendered by Ansible |
| `fastrdp_session_tgt` | `auto` (role `common`) | broker `[broker] session_tgt`: TGT before the session starts when the login carries the password; `required` refuses logins without one; `off` |

## GPU and performance path

From [performance.md](../performance.md) (KPipeWire source review, not measured here):

- KWin renders on the GPU via GBM (NVIDIA needs `nvidia-drm modeset=1`, role `gpu`).
- KPipeWire tries `h264_vaapi` → `libx264` → `libopenh264`. **It never uses NVENC**,
  so on NVIDIA hosts Plasma sessions encode on the CPU.
- Intel/AMD: VA-API needs a driver with H.264 encode (`vainfo | grep EncSlice`).

Verify inside the session:

```sh
python3 tests/gpu/session_report.py
#   rendering:     gpu (mesa) | gpu (nvidia)       <- kwin_wayland holds a render node
#   H.264 encoder: vaapi (gpu) | x264 (cpu) | openh264 (cpu)   <- libraries mapped by krdpserver
cat /etc/fastrdp/session.env
```

Tuning: `fastrdp_krdp_encoder`, `fastrdp_krdp_quality`; steer NVIDIA users to `gnome`
(NVENC) or `plasma-x11` (xrdp NVENC) with `fastrdp_group_desktops`.

## Security properties

- KRdp binds `127.0.0.1:<port>`; ownership check and nftables rules as for
  [GNOME](gnome.md#security-properties).
- The env file with the secret is root-only; systemd reads it as root.
- The secret is on `krdpserver`'s command line, visible to all local users in
  `/proc/<pid>/cmdline` unless `fastrdp_proc_hidepid: true`. It is useless to them:
  nftables allows only the proxy and root to connect, and it changes with every
  session start.
- The user's password never reaches the session, so `pam_kwallet5` cannot unlock
  the wallet with it. The broker uses the password, when the login carried it, only
  for the TGT (PAM conversation of `fastrdp-tgt`, never argv, environment or files).
- PAM `fastrdp-session` is in sssd's `ad_gpo_map_remote_interactive`, so GPO logon
  rights apply to the session as well as to the broker's `fastrdp` check.

## Limitations and known issues

- Unofficial headless mode; whole back-end to validate (desktop-matrix item 1: usable
  desktop, KRdp streams output 0, input works).
- NVIDIA: CPU encoding.
- Fixed desktop size per session; one exported monitor.
- `session-plasma` assumes the compositor socket is `wayland-0`. A second Wayland
  session of the same user (e.g. `gnome`) or a leftover socket breaks this. Also,
  `FASTRDP_HEADLESS=1` is set in the user's systemd manager, which is shared with any
  other session of that user (a local Plasma login during a remote session would get
  the virtual backend). Both not tested.
- A KRdp crash ends the Plasma session (by design of `session-plasma`).
- The proxy → KRdp NLA hop is not covered by automated tests.

## Troubleshooting

| Symptom | Checks |
|---|---|
| `no listener on port P after 90s` | `systemctl status fastrdp-plasma@USER`; `journalctl -u fastrdp-plasma@USER` (`session-plasma: compositor did not start`, `startplasma-wayland exited`); `systemctl --user -M USER@ status plasma-kwin_wayland`; `journalctl _UID=$(id -u USER)` |
| Unit does not start at all | `ConditionPathExists`: `ls -l /run/fastrdp/sessions/USER.plasma.env`; `systemctl cat fastrdp-plasma@USER` shows the unit file in use (build vs. apt copy) |
| KWin on DRM instead of virtual | `systemctl --user -M USER@ show-environment \| grep FASTRDP`; `systemctl --user -M USER@ cat plasma-kwin_wayland` must show the fastrdp drop-in |
| PAM / logind problems | `journalctl -u fastrdp-plasma@USER -g pam`; `loginctl list-sessions` should show a session for the user |
| CPU encoding on Intel/AMD | `vainfo`; `session_report.py`; force with `fastrdp_krdp_encoder: h264_vaapi` and check KRdp's log in `journalctl -u fastrdp-plasma@USER` |
| Benchmark direct vs. proxied | `sudo tests/perf/compare-host.sh USER 'PASSWORD'` |

## Tests

| Test | What |
|---|---|
| `make test-gpu` | `session_report.py` verdict "Plasma on NVIDIA falls back to x264" (fake `/proc`) |
| `make lint` | shellcheck of `session-plasma` and the other session scripts, ansible-lint |
| `make test-broker` | config defaults for `[backends.plasma]` (via the example config); TGT before the start, never without a password, `auto`/`required`/`off` (`test_session_tgt.py`) |

`PlasmaBackend.ensure()`, the unit and `session-plasma` have no functional test.
