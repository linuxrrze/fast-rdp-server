# Back-ends

Every RDP login enters through one front-end (`freerdp-proxy` with the fastrdp
module, user `_fastrdp-proxy`, TCP 3389). The broker (`fastrdp-brokerd`, root)
authorises the login and starts or reuses the user's session on one of the
back-ends below. Back-ends listen on loopback only and are reached only by the
proxy.

| Page | Back-end | Desktops (`fastrdp_desktops`) |
|---|---|---|
| [xrdp.md](xrdp.md) | xrdp + xorgxrdp (X11) | `xfce`, `mate`, `cinnamon`, `lxqt`, `plasma-x11` |
| [wlroots.md](wlroots.md) | xrdp + nested wlroots compositor | `sway`, `labwc`, `wayfire` |
| [gnome.md](gnome.md) | GDM headless session + gnome-remote-desktop | `gnome` |
| [plasma.md](plasma.md) | `kwin_wayland --virtual` + KRdp | `plasma` |
| [web.md](web.md) | browser access path (Keycloak → webgate → Guacamole → proxy) | any of the above |

Broker driver code: `broker/brokerd/fastrdp_broker/backends/{xrdp,gnome,plasma}.py`.
wlroots desktops use the `xrdp` driver; the web path uses whichever driver the
chosen desktop maps to. Related pages: [architecture.md](../architecture.md),
[desktop-matrix.md](../desktop-matrix.md), [performance.md](../performance.md),
[auth-matrix.md](../auth-matrix.md).

## Login flow

```mermaid
sequenceDiagram
    autonumber
    participant C as RDP client
    participant P as freerdp-proxy + fastrdp module<br/>(_fastrdp-proxy, :3389)
    participant B as fastrdp-brokerd (root)<br/>/run/fastrdp/broker.sock
    participant X as Back-end (loopback)
    C->>P: TLS + NLA (Kerberos) or TLS + password[+OTP] / web token
    Note over P: ServerPeerLogon: NLA must be Kerberos,<br/>principal read via SECPKG_ATTR_AUTH_IDENTITY
    P->>B: {"op":"login", method, user, principal, password, desktop_hint, width, height, client_address}
    Note over B: PAM account (service "fastrdp"), allow_groups,<br/>MFA (privacyIDEA) unless exempt / web token,<br/>desktop choice, TGT (GNOME/Plasma, PAM "fastrdp-tgt")<br/>→ backend.ensure()
    B->>X: xrdp: write /run/fastrdp/desktop/<user>, issue token<br/>gnome: grdctl + start gnome-headless-session@<user><br/>plasma: env file + restart fastrdp-plasma@<user>
    B-->>P: target {host 127.0.0.1, port, username, password, security tls|nla}
    Note over P: ClientPreConnect: swap credentials,<br/>drop client alternate shell
    P->>X: RDP (TLS for xrdp; NLA/NTLM for g-r-d and KRdp)
    X-->>C: desktop, relayed by the proxy (GFX/H.264 passed through)
    P->>B: {"op":"end"} on disconnect (session keeps running)
```

Same flow as text, for terminals:

```
client ──RDP :3389──▶ freerdp-proxy + fastrdp module ──JSON──▶ fastrdp-brokerd
                         │  (credentials swapped)                │ ensure(): start/reuse
                         ▼                                       ▼
        ┌──────── 127.0.0.1:3390  xrdp (TLS, user + one-time token)
        │                 └─ sesman → Xorg/xorgxrdp → startwm.sh → X11 desktop
        │                                                      └─ or wlroots-in-x → sway/labwc/wayfire
        ├──────── 127.0.0.1:339xx g-r-d headless (NLA, "fastrdp" + random secret)
        │                 └─ gnome-headless-session@USER (GDM) → gnome-shell headless
        └──────── 127.0.0.1:339xx krdpserver --plasma (NLA, "fastrdp" + random secret)
                          └─ fastrdp-plasma@USER → session-plasma → kwin_wayland --virtual
```

Facts common to all back-ends (from `server.py`, `backends/base.py`, the proxy module):

- **Identity (NLA):** the account of the Kerberos principal (`identity.resolve_principal`),
  never the typed CredSSP user name, so UPNs that differ from the account name and
  `DOMAIN\user` work ([auth-matrix.md](../auth-matrix.md), Kerberos specifics). The
  host's TERMSRV names and keys come from the `identity` role: `fastrdp_termsrv_aliases`
  (role `common`, default `[]`) and `fastrdp_termsrv_enctypes` (default AES256 +
  AES128; the role fails without AES keys).
- **Desktop choice:** client hint `fastrdp:<desktop>` in the alternate-shell field,
  then the desktop chosen on the webgate's chooser page (`<state_dir>/desktop-prefs/<user>`,
  `desktopprefs.py`), then `~/.config/fastrdp/desktop`, then `[defaults.groups]`, then
  `[defaults] desktop` (`identity.choose_desktop`). A hint for a desktop the user may not use is ignored
  silently and the next rule applies (RDP clients). The broker reads the preference
  file as root in a worker thread for at most `[broker] home_read_timeout` seconds
  (default 3, `0` = never); an unreadable or hanging home (NFS with `sec=krb5*`,
  server down) means "no preference" ([nfs-kerberos-homes.md](../nfs-kerberos-homes.md)). The web chooser offers only the
  desktops the user may use and refuses others ([web.md](web.md)).
- **Home directory** (`[broker] home_check`, default `create`): before any back-end
  starts, the broker refuses a home whose parent is missing (automount not set up) or
  that is not a usable directory, and creates a missing home like `pam_mkhomedir`
  (0700, `/etc/skel`) when only its last component is missing, in a root-owned, local
  directory that is one of `[broker] home_create_roots` (default `/home`)
  or below one. GNOME needs this: nothing in its session path runs `pam_mkhomedir`
  ([nfs-kerberos-homes.md](../nfs-kerberos-homes.md#where-homes-are)).
- **Kerberos TGT** (`[broker] session_tgt`, Ansible `fastrdp_session_tgt`, role
  `common`, default `auto`): for GNOME and Plasma the broker obtains the user's TGT
  through PAM service `fastrdp-tgt` before the session starts, on every login that
  carries the password (also reconnects); xrdp gets it through its own PAM stack.
  `auto` logs failures, `required` refuses failed TGT requests and logins without a
  password (before MFA), `off` disables it. See [gnome.md](gnome.md#kerberos-ticket-tgt)
  and [nfs-kerberos-homes.md](../nfs-kerberos-homes.md).
- **Kerberos login reminder** (`fastrdp_tgt_notify`, default on, role `desktops`): every
  desktop session warns its user 24 h and 2 h before the TGT can no longer be renewed
  and when it has expired (reconnect with the password, or `kinit`); quiet without a
  TGT ([long-running sessions](../nfs-kerberos-homes.md#long-running-sessions)).
- **Ticket renewal** (role `identity`): `fastrdp_krb5_renewable_lifetime` (`7d`),
  `fastrdp_krb5_renew_interval` (`1h`), `fastrdp_kcm_tgt_renewal` (`true`, sssd-kcm
  renews every TGT in KCM, also from `kinit`), in `/etc/sssd/conf.d/50-fastrdp.conf`,
  `sssd.conf` (AD) and `/etc/krb5.conf.d/fastrdp` (`renew_lifetime`).
- **Restricting desktops:** `fastrdp_desktop_groups` (e.g. `{plasma: [rdp-kde]}`)
  renders `groups = [...]` per desktop into `broker.toml`; desktops not listed are open
  to every allowed user. `fastrdp_desktop_labels` sets the names shown in the web
  chooser. Both default to `{}` (role `common`).
- **One session per user and back-end driver.** Logins of the same user are
  serialised by a per-user lock in the broker.
- **Listener ownership check:** before routing, the broker reads `/proc/net/tcp{,6}`
  and requires the target port to be held by exactly one expected uid (root for
  xrdp, the session user for GNOME/Plasma).
- **Proxy → back-end security:** `tls` for xrdp, `nla` for g-r-d and KRdp. For NLA the
  module sets `AuthenticationPackageList=!kerberos`, i.e. the loopback hop uses NTLM
  with broker-generated credentials. (The *front* NLA must be Kerberos; that is a
  different hop.)
- **Proxy channel settings** (`/etc/fastrdp/proxy.ini`, `[Channels]`): GFX,
  DisplayControl, Clipboard, AudioInput/Output, DeviceRedirection, VideoRedirection,
  CameraRedirection on; RemoteApp off. Whether a feature works end to end depends on
  the back-end (table below).
- **Firewall** (`/etc/nftables.d/fastrdp.nft`, table `inet fastrdp`): back-end ports
  (`fastrdp_xrdp_port` and `fastrdp_backend_port_range`) drop new connections from
  non-loopback interfaces; on loopback, new connections are rejected unless the
  socket owner (`meta skuid`) is `_fastrdp-proxy` or `root`. The same ports are in
  `net.ipv4.ip_local_reserved_ports` (`/etc/sysctl.d/60-fastrdp.conf`).

## Comparison

Status words as in [desktop-matrix.md](../desktop-matrix.md): *verified* = tested in
this repository; *to validate* = written from code and upstream sources, not yet
run on real hardware. "Proxy passes" means the channel is enabled in `proxy.ini`;
it does not mean the back-end implements it.

| | xrdp (X11) | wlroots (nested) | GNOME | Plasma (Wayland) | Web |
|---|---|---|---|---|---|
| Desktops | xfce, mate, cinnamon, lxqt, plasma-x11 | sway, labwc, wayfire | gnome (GNOME 50+) | plasma (Plasma 6) | any configured desktop |
| Display server | Xorg + xorgxrdp (`xrdpdev`) | Xorg + xorgxrdp; compositor on `WLR_BACKENDS=x11` in one X window | Mutter headless | KWin virtual backend | – (inherits) |
| Session started by | xrdp-sesman (root) after PAM token check; `startwm.sh` reads the broker's choice | same, xsession `fastrdp-<comp>` runs `wlroots-in-x` | broker: `grdctl --headless` as the user, then `systemctl start gnome-headless-session@USER` | broker: env file, `systemctl restart fastrdp-plasma@USER` (PAM `fastrdp-session`) | the driver of the chosen desktop |
| Back-end listener | `127.0.0.1:3390`, one for all users, socket owned by root | same | per-user port from 33900–34899, owned by the user | per-user port, owned by the user, `--address 127.0.0.1` | proxy at `127.0.0.1:3389` via guacd |
| Proxy → back-end auth | TLS, user + one-time token `fastrdp1:…` (60 s, single use) | same | NLA (NTLM), `fastrdp` + random secret per session start | same as GNOME | TLS, user + web token `fastrdp-web1:…` to the proxy |
| Encoder | H.264 AVC420 via FFmpeg `h264_vaapi`/`h264_nvenc`/`h264_qsv` (fastrdp patch), fallback libx264; or x264 only; RFX fallback | same as xrdp | g-r-d: VA-API (via Vulkan) or NVENC; no software H.264 (RFX progressive) | KPipeWire: h264_vaapi → libx264 → libopenh264; never NVENC | guacd re-encodes to images; no H.264 to the browser |
| GPU rendering | glamor on Intel/AMD (`/dev/dri/renderD128`); NVIDIA: VirtualGL (`vglrun`) or experimental glamor | GLES via DRI3 if the X server offers it, else pixman | Mutter on GBM | KWin on GBM | – |
| Reconnect | xrdp-sesman reconnects to the user's session (`Policy=Default`); disconnected sessions kept, `fastrdp_xrdp_disconnected_time_limit` (0 = forever) | same; compositor keeps running | broker reuses the session if the unit is active and the port is held by the user; otherwise reconfigures g-r-d on a new port | broker reuses if the unit is active and the port is held by the user; otherwise restarts the unit (new session) | as the target back-end |
| Resize / multi-monitor | `allow_multimon=true`; proxy passes DisplayControl; xorgxrdp resizes the root window (to validate through the proxy) | follows the X root size via `wlr-randr --custom-mode` (verified on Xvfb); one output `X11-1` | not configured by fastrdp; g-r-d upstream feature, to validate | size fixed at session start (`--width/--height` from the first login); KRdp exports `--monitor 0` only | guacamole `resize-method=display-update` |
| Clipboard | xrdp `cliprdr` + chansrv | text only, via `clipboard-bridge` (verified on Xvfb) | g-r-d upstream, not tested here | KRdp upstream, not tested here | Guacamole capabilities |
| Audio | proxy passes; needs `pipewire-module-xrdp`, which **no role installs**: no audio today (mic: `AUDIO_INPUT`, PCM) | as xrdp, plus starting the module in `wlroots-in-x` | out and mic implemented in g-r-d; out probably needs `pipewire-pulse`; not tested here | none (KRdp has no audio) | Guacamole: out by default, mic with `enable-audio-input` ([audio.md](../audio.md)) |
| Drive redirection | xrdp `rdpdr` + FUSE (`thinclient_drives`) | as xrdp | not tested here | not tested here | Guacamole capabilities |
| Kerberos TGT in session | yes if the proxy learned the password (token module hands it to `pam_sss`) | as xrdp | yes if the proxy learned the password: the broker gets it through PAM `fastrdp-tgt` before the start (`fastrdp_session_tgt`) | as GNOME | no |
| Maturity | to validate (build, configs, token PAM, proxy e2e verified) | launcher verified on Xvfb; full xrdp session to validate | to validate | to validate; headless KRdp is **unofficial** | unit tests + proxy e2e for the token path; real deployment to validate |
| Main limits | x264 on the CPU without a working GPU encoder; encoder runs in the shared `xrdp` daemon | Sway `$mod` key, text-only clipboard, keymap fixed at start | no H.264 without a GPU; GDM PAM/GPO mapping unknown | NVIDIA → CPU x264; fixed size; one Plasma session per user | low frame rate, no TGT |

## Which back-end for which situation

| Situation | Use | Why |
|---|---|---|
| Default for most users, many sessions per host | xrdp with `xfce` or `mate` | Lightest desktops; the most tested handoff (token PAM, proxy e2e); xrdp handles reconnects itself |
| Sessions need a Kerberos ticket (NFS `sec=krb5` homes, SSO to web apps) | any RDP back-end, with logins that carry the password (NLA with delegated password, TLS) | xrdp gets the TGT through its PAM stack, GNOME/Plasma from the broker (`fastrdp_session_tgt`). SSO without delegation, smartcard and web logins get none: gssproxy impersonation (`fastrdp_nfs_krb5_homes`) or `kinit`. `fastrdp_session_tgt: required` refuses logins without a password |
| Users want GNOME | `gnome` | Only route to GNOME 50+ (Wayland-only). Needs a GPU with VA-API (Intel/AMD) or NVENC (NVIDIA) for H.264; without one, g-r-d sends RFX progressive at much higher bandwidth |
| Users want KDE on Intel/AMD | `plasma` | VA-API encoding; but headless KRdp is unofficial, validate first |
| Users want KDE on NVIDIA, or Plasma Wayland fails validation | `plasma-x11` (xrdp) | KPipeWire never uses NVENC, so `plasma` encodes with libx264 on the CPU there |
| Host without a GPU | xrdp/wlroots desktops | x264 on the CPU; avoid `gnome` (no software H.264) |
| Tiling / Wayland-native users | `sway`, `labwc`, `wayfire` | No RDP server exists for wlroots; nesting in xrdp keeps H.264 and xrdp's channels |
| Smartcard / YubiKey PIV users | any (front NLA via PKINIT) | The PIN is never forwarded, so no back-end gets a TGT ([smartcard-nla.md](../smartcard-nla.md)) |
| No RDP client, occasional access | web path | Browser only; MFA at Keycloak; lowest frame rate |

Steer groups with `fastrdp_group_desktops` (group → default desktop). Per-desktop
`groups` restrictions exist in the broker (`[desktops.<name>] groups`) but the
Ansible template `broker.toml.j2` does not render them; add them by hand if needed.

## Common operations

```sh
# Broker view: sessions (rdp_password removed), connected count, pending tokens
sudo fastrdpctl status            # build install: /usr/local/sbin, apt: /usr/sbin
sudo fastrdpctl logout alice      # stop all of alice's back-end sessions (see per-page notes)

# Host smoke test (services, ports, sockets, nftables, keytab, PAM module, broker config)
sudo tests/smoke/check-host.sh [test-user]

# Power off/reboot/suspend refused for users in their RDP sessions (polkit rule, base role;
# desktop-matrix.md#host-safety-power-actions); read-only, log in first
sudo tests/smoke/check-power-actions.sh [user]...

# Follow one login end to end
journalctl -f -u fastrdp-proxy -u fastrdp-brokerd

# Inside a session: which GPU paths are used
python3 tests/gpu/session_report.py
```

Broker log lines to look for (`journalctl -u fastrdp-brokerd`):

| Message | Meaning |
|---|---|
| `login USER session=… desktop=D -> 127.0.0.1:PORT (tls\|nla)` | routed |
| `denied (REASON): …` | account, group, realm, MFA or desktop refusal, or `session_tgt = required` without a TGT. The proxy gets "access denied" plus REASON and sends the RDP client an error code: `not_allowed` 0x9, `mfa_timeout` 0x409, `denied` / `mfa_failed` 0x7 (table in [client-guide.md](../client-guide.md#when-the-server-refuses-the-login), reasons in `protocol.py`) |
| `USER: no Kerberos TGT for the gnome\|plasma session …` | `session_tgt = auto`: the TGT request failed (sssd offline, wrong delegated password, local account); the session starts without one |
| `backend error: …` | the back-end driver failed; the proxy gets "session could not be started" (reason `backend`), the client error code 0x400 |
| `op 'login' not permitted for uid N` | something other than the proxy uid used `broker.sock` |

## Automated tests per area

| Test | Covers | Runs in CI |
|---|---|---|
| `make test-broker` (`broker/brokerd/tests/`) | config parsing, desktop choice, tokens, `/proc/net/tcp` parsing, port reservation, NLA/TLS/smartcard/web-token logins over the socket protocol, back-end start/stop error paths; xrdp session tracking (reconnect keeps the running desktop, logout ends only xrdp logind sessions, stale records reaped) against a fake `loginctl` | yes |
| `make test-pam` (`broker/pam_fastrdp_token/test/`) | token redemption in the xrdp PAM stack | yes |
| `make test-webgate` | OIDC checks, Guacamole JSON format, CSRF, cert pinning, chooser lists only allowed desktops | yes |
| `make test-gpu` (`tests/gpu/test_session_report.py`) | `session_report.py` verdicts on fake `/proc` trees | yes |
| `make lint` | ansible-lint of `site.yml`; shellcheck of the session scripts and all test/build scripts | yes |
| `make test-ansible` (`tests/ansible/`) | role templates rendered and parsed (gfx.toml per encoder, proxy.ini, broker.toml incl. desktop groups/labels and a minimal inventory, resource limits), site checks of role `common`, smoke-test port parsing, the polkit power rule evaluated in node | yes |
| `make test-e2e`, `test-e2e-nla`, `test-e2e-smartcard[-softhsm]` (`tests/proxy-e2e/`) | real freerdp-proxy + module: token instead of password towards a **TLS** back-end, peer address, shell hint dropped, Kerberos principal binding, smartcard PIN not forwarded, 32-bit PKCS#11 slot ids | yes (job `e2e`, against the vendored FreeRDP) |
| `make test-wlroots` (`tests/wlroots/run.sh`) | `wlroots-in-x` on Xvfb | no (manual) |
| `make test-xrdp-encoder` (`patches/xrdp/test/`) | FFmpeg encoder code path with libx264, VA-API/NVENC fallback, fallback disabled | yes (job `vendored`, xrdp) |
| `tests/perf/*`, `tests/smoke/check-host.sh`, `check-power-actions.sh` | measurements, deployed-host checks | no (manual) |

Not covered by any automated test: the NLA hop from the proxy to g-r-d or KRdp,
the GNOME and Plasma drivers against real services, and xrdp sessions with a real
xorgxrdp display.
