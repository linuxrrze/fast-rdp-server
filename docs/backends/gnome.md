# GNOME back-end (GDM headless + gnome-remote-desktop)

Desktop: `gnome` (GNOME 50+, Wayland only). Driver:
`broker/brokerd/fastrdp_broker/backends/gnome.py`. Status: **to validate** on real
hosts; nothing in this repository starts a real GNOME session.

fastrdp does not use g-r-d's system "remote login" daemon (the role disables
`gnome-remote-desktop.service`). It runs g-r-d in **headless mode inside each
user's session**, started through GDM's `gnome-headless-session@<user>.service`.
The user never sees a GDM greeter; authentication and MFA happened at the proxy.

## How it works

Before `GnomeBackend.ensure()`, under the broker's per-user lock, the broker gets the
user a **Kerberos TGT** when the login carried the password (`[broker] session_tgt`,
see [Kerberos ticket](#kerberos-ticket-tgt)); on every login, so also on a reconnect.
Then it checks the user's **home directory** (`[broker] home_check`): `grdctl` writes
the RDP settings and credentials into it, and nothing on GNOME's path runs
`pam_mkhomedir` (`grdctl` runs in `user@<uid>.service`, PAM service `systemd-user`,
reached through `systemd-run --machine=<uid>@.host`, PAM service `login`). A missing
home is created (mode 0700, `/etc/skel`) when its parent exists and is in
`[broker] home_create_roots` (default `/home`); a missing parent,
e.g. `/autofs` without autofs, refuses the login with a log line naming it, instead of
`grdctl`'s *Error creating directory /autofs: Permission denied* and an assertion
([nfs-kerberos-homes.md](../nfs-kerberos-homes.md#where-homes-are)).

`GnomeBackend.ensure()` (under the broker's per-user lock):

1. **Reuse:** if `sessions.json` has a `gnome` session for the user,
   `gnome-headless-session@<user>.service` is active, and the recorded port is held
   by exactly the user's uid, update `last_login` and return the stored target.
2. **Otherwise start or repair:**
   1. allocate a free port from `[broker] port_range` (33900–34899): not in
      `sessions.json`, not reserved by a start in progress, no loopback/any listener,
      and bindable on 127.0.0.1;
   2. generate a random secret (`secrets.token_urlsafe(24)`);
   3. ensure a per-user self-signed cert (`sysutil.ensure_backend_cert`):
      `/var/lib/fastrdp/users/<user>/tls.crt` (0644) and `tls.key` (0600), owned by the
      user, EC P-256, CN `fastrdp-backend-<user>`, 10 years; directories root-owned
      0711 so the user cannot plant symlinks;
   4. run as the user, inside the user's systemd manager
      (`systemctl start user@<uid>.service`, then
      `systemd-run --machine=<uid>@.host --user --wait --pipe …`; the uid, since a
      fully qualified name like `alice@example.com` has an `@` of its own):
      ```
      grdctl --headless rdp set-tls-cert /var/lib/fastrdp/users/<user>/tls.crt
      grdctl --headless rdp set-tls-key  /var/lib/fastrdp/users/<user>/tls.key
      grdctl --headless rdp set-port <port>
      grdctl --headless rdp disable-port-negotiation
      grdctl --headless rdp set-credentials fastrdp      # secret on stdin
      grdctl --headless rdp enable
      systemctl --user --runtime enable gnome-remote-desktop-headless.service
      ```
      `--runtime` puts the `gnome-session.target.wants` link into
      `$XDG_RUNTIME_DIR/systemd/user` (`/run/user/<uid>`, tmpfs), which is in the user
      unit search path (systemd `src/libsystemd/sd-path/path-lookup.c`, `runtime_config`),
      instead of `~/.config/systemd/user`. A user manager that starts while the home is
      unreadable (Kerberized NFS without a TGT) ignores unit links in the home
      ([nfs-kerberos-homes.md](../nfs-kerberos-homes.md), Q1). The link lives as long as
      the user manager, and the broker writes it on every session start. Hosts upgraded
      from older fastrdp versions keep a harmless persistent link in the home.
   5. if `gnome-headless-session@<user>.service` is already active (session alive,
      g-r-d gone or on another port): `systemctl --user restart
      gnome-remote-desktop-headless.service`; else `systemctl start --no-block
      gnome-headless-session@<user>.service`;
   6. record the session (port, `rdp_user = "fastrdp"`, secret) in `sessions.json`;
   7. wait up to `session_start_timeout` (90 s) until the port listens on loopback and
      is held by exactly the user's uid. Another uid on the port → `port <p> is held
      by unexpected uid(s)`; nothing → `no listener on port <p> after 90s`.
3. Return `127.0.0.1:<port>`, `fastrdp` / secret, `security = "nla"`.

The proxy then connects with NLA. The module sets
`AuthenticationPackageList=!kerberos`, so the loopback hop uses NTLM against the
credentials g-r-d was given. The client's alternate-shell value is not forwarded.

What GDM's unit does internally (which PAM service it uses, how it registers the
logind session, how gnome-session pulls in `gnome-remote-desktop-headless.service`
through `gnome-session.target`) is GDM 50 upstream behaviour and has **not** been
checked in this repository.

### Processes and users

| Process | User | Started by |
|---|---|---|
| `gnome-headless-session@<user>.service` | the user | broker (`systemctl start`), unit shipped by GDM |
| `gnome-shell` (headless) and session services | the user | GDM / gnome-session (upstream) |
| `gnome-remote-desktop-daemon` (headless) | the user | user unit `gnome-remote-desktop-headless.service` |
| `grdctl` calls | the user | broker via `systemd-run --user` |

### Reconnect and session lifetime

- A new login reuses the running session and the same secret as long as the unit is
  active and the port is held by the user.
- If g-r-d died or the state file was lost, the broker reconfigures g-r-d on a new
  port with a new secret and restarts only g-r-d; the GNOME session survives.
- If the unit is not active, a new GNOME session is started.
- Sessions run until `fastrdpctl logout USER` (`systemctl stop --no-block
  gnome-headless-session@USER.service`) or until they end on their own. The
  broker has no idle or disconnect timeout for GNOME.
- What happens to a second, concurrent connection of the same user: g-r-d
  upstream behaviour, not tested.

### Resize, multi-monitor, channels

The broker passes no geometry to g-r-d (width/height from the client are ignored for
this back-end). Monitor layout, dynamic resize (proxy passes DisplayControl),
clipboard, audio and drive redirection are whatever g-r-d's headless RDP server
implements; **none of these is tested through fastrdp**.

## Components on a deployed host

| Path / unit | From |
|---|---|
| packages `fastrdp_gnome_packages`: `gdm3, gnome-shell, gnome-session, gnome-remote-desktop, gnome-control-center, gnome-console, nautilus, xwayland, dconf-cli` | role `gnome_rd` |
| `/usr/lib/systemd/system/gnome-headless-session@.service` | GDM 50+ (the role asserts it exists) |
| `gdm.service` | enabled and started by the role |
| `gnome-remote-desktop.service` (system) | disabled and stopped by the role |
| `gnome-remote-desktop-headless.service` (user unit) | g-r-d package; enabled per user by the broker in `/run/user/<uid>/systemd/user` (`--runtime`) |
| `/etc/dconf/profile/user` | role, if missing: `user-db:user` + `system-db:local` (an existing profile only gets the `system-db:local` line); without it the `local.d` settings below are ignored |
| `/etc/dconf/db/local.d/50-fastrdp` | role: `lock-enabled=false`, `idle-delay=uint32 0`, `enable-animations=false`; compiled by `dconf update` |
| `/var/lib/fastrdp/users/<user>/tls.{crt,key}` | broker |
| `/var/lib/fastrdp/sessions.json` (0600 root) | broker: port, `rdp_user`, `rdp_password` |
| g-r-d's headless settings (port, TLS paths, enable) | written by `grdctl` as GSettings `org.gnome.desktop.remote-desktop.rdp` into the user's dconf database, `~/.config/dconf/user` |
| g-r-d's headless RDP credentials (`fastrdp` + secret) | TPM-sealed if a TPM is usable, else `$XDG_DATA_HOME/gnome-remote-desktop/credentials.ini` = `~/.local/share/…` (g-r-d `grd-settings.c` `create_headless_credentials`, `grd-credentials-file.c`) |

The role `gnome_rd` runs only when `gnome` is in `fastrdp_desktops` (`site.yml`).

## Configuration

| Setting | Default | Where |
|---|---|---|
| `fastrdp_desktops` contains `gnome` | inventory | renders `[desktops.gnome] backend = "gnome"` |
| `fastrdp_gnome_packages` | see above | role `gnome_rd` |
| `fastrdp_backend_port_range` | `[33900, 34899]` (inventory) | broker `[broker] port_range`, nftables set, `ip_local_reserved_ports` |
| `[broker] session_start_timeout` | `90` | `config.py` default; not rendered by Ansible |
| `[backends.gnome] unit` | `gnome-headless-session@{user}.service` | `config.py` default |
| `[backends.gnome] security` | `nla` | `config.py` default |
| `fastrdp_group_desktops` | `{}` | e.g. `{rdp-gnome: gnome}` |
| `fastrdp_session_tgt` | `auto` | broker `[broker] session_tgt`: TGT before the session starts (`auto`, `required`, `off`); see below |

There are no GNOME-specific encoder or quality variables in the Ansible roles.

## GPU and performance path

From [performance.md](../performance.md) (upstream source review of g-r-d 50, not
measured here):

- Mutter renders on the GPU (GBM). NVIDIA needs `nvidia-drm modeset=1` (role `gpu`
  writes `/etc/modprobe.d/fastrdp-nvidia.conf`; reboot required).
- g-r-d encodes H.264 with **VA-API via Vulkan** (needs a Vulkan device and a VA
  driver with H.264 encode, e.g. `va-driver-all`) or **NVENC via CUDA**.
- **No software H.264.** Without VA-API/NVENC, g-r-d sends RFX progressive, at much
  higher bandwidth. Avoid `gnome` on GPU-less hosts.

Verify inside the session (as the user):

```sh
python3 tests/gpu/session_report.py
#   rendering:     gpu (mesa) | gpu (nvidia)        <- gnome-shell holds a render node
#   H.264 encoder: vaapi (gpu) | nvenc (gpu) | no h264 encoder loaded (rfx/progressive)
vainfo | grep EncSlice
vulkaninfo --summary
journalctl --user -u gnome-remote-desktop-headless -g HWAccel   # upstream logs "[HWAccel.VAAPI] Successfully initialized"
```

Tuning knobs: only the generic ones in role `tuning` (`fastrdp_tcp_tuning`,
`fastrdp_user_cpu_quota`, `fastrdp_user_memory_max`, `fastrdp_user_tasks_max`).
Whether all GNOME processes land in `user-<uid>.slice` depends on how GDM's unit
places them; not checked.

## Security properties

- g-r-d listens on a per-user port; the broker refuses to route unless the port is
  held by exactly the user's uid. A user who grabs a port the broker picked for
  someone else causes a failed login (`held by unexpected uid`), not a hijack.
- nftables: only `_fastrdp-proxy` and root may open connections to the port range on
  loopback; no remote access.
- Credentials are random per g-r-d (re)configuration and stored in the root-only
  `sessions.json`. The user can read their own g-r-d credentials (they are in the
  user's account), which gains nothing: the port is unreachable for the user's own
  processes (nftables), and it is the user's own session.
- The user's password never reaches GNOME. The broker uses it, when the login
  carried it, only to get a Kerberos TGT through PAM (next section). (Keyring
  unlocking: not handled by fastrdp; upstream behaviour unknown.)
- AD GPO logon rights: the broker checks PAM service `fastrdp` (mapped in
  `ad_gpo_map_remote_interactive`). A GNOME session runs three more PAM services,
  each with an account phase that sssd's GPO check sees: `gdm-autologin`
  (`gnome-headless-session@`; not in any of sssd's default maps, so
  `ad_gpo_default_right = deny` would refuse it: fastrdp adds it to
  `ad_gpo_map_remote_interactive`), `systemd-user` (`user@<uid>.service`, in sssd's
  default `ad_gpo_map_permit`) and `login` (the broker's `systemd-run
  --machine=…@.host` for `grdctl`, through machined; in sssd's default
  `ad_gpo_map_interactive`). With `fastrdp_ad_gpo_access_control: enforcing` GNOME
  users therefore also need the *Allow log on locally* right, or `login` moved into
  the remote-interactive map (`ad_gpo_map_interactive = -login`, `+login` in
  `ad_gpo_map_remote_interactive`), which also changes console logins of the host.
  Which PAM service GDM 50 uses for headless sessions: from the GDM sources, not yet
  validated on a host.

## Kerberos ticket (TGT)

Same mechanism for GNOME and Plasma (`Broker.session_tgt`, `fastrdp_broker/tgt.py`):

- **When:** the login carries the user's password: NLA with a delegated password
  (mstsc, xfreerdp `/p`, Windows "Allow delegating default credentials"), or a TLS
  password login. Kerberos SSO without delegation, smartcard and web logins carry
  none: no TGT (`kinit` in the session, or gssproxy impersonation for NFS homes,
  `fastrdp_nfs_krb5_homes`).
- **How:** after MFA and before the session starts, the broker (root) runs
  `pam_authenticate` + `pam_setcred` for the user with PAM service **`fastrdp-tgt`**
  (`/etc/pam.d/fastrdp-tgt`: `pam_sss` only, no `pam_faillock`, so a stale
  delegated password cannot lock the account for fastrdp). sssd's `krb5_child`
  switches to the user's uid and stores the TGT in the user's ccache (`KCM:`) and
  registers it for renewal (`krb5_renew_interval`). The password passes only
  through the PAM conversation, never argv, environment, files or logs. Then
  `klist -s` runs with the user's uid/gid (no supplementary groups, `HOME=/`, cwd
  `/`) to check that a valid TGT is really there (sssd authenticates offline from
  its cache without a TGT).
- **Reconnect:** runs on every login with a password, also when the running session
  is reused, so a reconnect renews an expiring TGT for all processes of the uid.
- **`[broker] session_tgt`** (`fastrdp_session_tgt`): `auto` (default) = failures
  are logged (`no Kerberos TGT for the gnome session: …`), the login continues;
  `required` = such failures refuse the login, and logins **without** a password are
  refused early, before MFA (`login without a password, but [broker] session_tgt =
  required`), for every back-end, also on the web path; `off` = never.

## Limitations and known issues

- Whole back-end: to validate on GNOME 50 / GDM 50 (desktop-matrix item 2).
- No software H.264.
- The proxy → g-r-d NLA hop is not covered by automated tests.
- Running a `gnome` and a `plasma` session for the same user at the same time shares
  one `XDG_RUNTIME_DIR` and one systemd user manager. `session-plasma` waits for
  `$XDG_RUNTIME_DIR/wayland-0`, which gnome-shell may already own. Not tested;
  avoid it (restrict with `groups`, or tell users).
- `sessions.json` loss (corrupt file) costs only the reuse shortcut: g-r-d is
  reconfigured on a new port.

## Troubleshooting

| Symptom | Checks |
|---|---|
| `backend error: GNOME session for USER: grdctl --headless rdp … (systemd-run as the user) failed (N): <first error lines>` | `grdctl` or `systemctl --user` failed as the user: `systemctl status user@$(id -u USER)`; `journalctl _UID=$(id -u USER)` |
| `backend error: home directory H of USER does not exist (parent P missing: automount not set up?)` | the directory names a home path this host does not have: set up autofs (`fastrdp_autofs`) or use local homes (`fastrdp_sssd_override_homedir`), [nfs-kerberos-homes.md](../nfs-kerberos-homes.md#where-homes-are) |
| `no listener on port P after 90s` | `systemctl status gnome-headless-session@USER`; `journalctl -u gnome-headless-session@USER`; `systemctl --user -M UID@ status gnome-remote-desktop-headless`; `sudo systemd-run --machine=UID@.host --user --wait --pipe grdctl --headless status` (same way the broker runs `grdctl`) |
| `port P is held by unexpected uid(s) [...]` | `ss -ltnp 'sport = :P'`: another user's process holds the port; next login picks another port |
| Session starts but login at g-r-d fails (proxy log: back-end connect error) | credentials mismatch after a manual `grdctl` change: `fastrdpctl logout USER` and log in again |
| GPO denial | `journalctl -u sssd -g gpo` / `/var/log/sssd/` for denials naming GDM's PAM service |
| No H.264 (client shows RFX/progressive) | `vainfo`, `vulkaninfo --summary`, NVIDIA `nvidia-smi`; `session_report.py` verdict; client must decode H.264 ([client-guide.md](../client-guide.md)) |
| Benchmark direct vs. proxied | `sudo tests/perf/compare-host.sh USER 'PASSWORD'` (reads port and credentials from `sessions.json`) |

## Tests

| Test | What |
|---|---|
| `make test-broker` | port allocation/reservation (`BackendHelperTests` uses `GnomeBackend`), listener parsing, config defaults; `--runtime` enable (`test_gaps.BackendTests.test_gnome_start`); TGT step before the start, on reconnect, never without a password, password only in the PAM conversation, `auto`/`required`/`off` (`test_session_tgt.py`) |
| `make test-gpu` | `session_report.py` verdicts for GNOME with VA-API and NVENC (fake `/proc`) |
| `tests/perf/compare-host.sh` | manual, on a deployed host |

`GnomeBackend.ensure()` and the GDM/g-r-d interaction have no automated test.
