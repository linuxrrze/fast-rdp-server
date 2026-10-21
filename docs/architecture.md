# Architecture

fastrdp turns a Linux host into a multi-user RDP terminal server. One front-end
(`freerdp-proxy3`) authenticates every connection and hands it to a per-user
desktop session. A small broker decides who gets in and which desktop they get.

Per-back-end details (session start, files, configuration, GPU path, security,
troubleshooting): [backends/](backends/README.md).

```
 client (mstsc, xfreerdp3, Remmina)
    │  RDP over TLS; NLA/Kerberos or password(+OTP)        :3389, only exposed port
    ▼
 freerdp-proxy3 + fastrdp module  (user _fastrdp-proxy)
    │  JSON over /run/fastrdp/broker.sock
    ▼
 fastrdp-brokerd  (root)  ── PAM "fastrdp" (SSSD) ── privacyIDEA (OTP / push)
    │ starts or reuses the user's session and returns host:port + credentials
    ├── X11 desktops ─ xrdp 0.10.6.1 + xorgxrdp(-glamor) ───────── 127.0.0.1:3390
    ├── GNOME 50+    ─ GDM gnome-headless-session@USER + g-r-d ── 127.0.0.1:339xx
    └── Plasma 6     ─ fastrdp-plasma@USER: KWin --virtual + KRdp  127.0.0.1:339xx
```

## Components

| Component | Source | Runs as | Purpose |
|---|---|---|---|
| `freerdp-proxy` | fastrdp's patched FreeRDP in `/opt/fastrdp` (`fastrdp-freerdp3`; [vendoring.md](vendoring.md)) | `_fastrdp-proxy` | RDP front-end: TLS, NLA (Kerberos acceptor via `/etc/fastrdp/termsrv.keytab`), channel passthrough (GFX/H.264, clipboard, drives, audio) |
| fastrdp proxy module | `broker/proxy-module/` (C) | in the proxy | Binds NLA identity to the Kerberos principal, asks the broker, routes to the back-end, swaps credentials |
| `fastrdp-brokerd` | `broker/brokerd/` (Python, stdlib only) | root | Account and group checks, MFA, desktop choice, session start/reuse, one-time tokens |
| `pam_fastrdp_token` | `broker/pam_fastrdp_token/` (C) | in xrdp-sesman | xrdp accepts only one-time broker tokens; hands the real password on for the TGT |
| fastrdp-webgate (optional) | `broker/webgate/` (Python) | `_fastrdp-web` | Browser path: Keycloak OIDC login, one-time web token, encrypted Guacamole connection ([web-access.md](web-access.md)) |
| xrdp + xorgxrdp | release tarballs + `patches/xrdp/`, built by Ansible or packaged as `fastrdp-xrdp` | `xrdp` (daemon), root (sesman) | X11 and wlroots desktops; H.264 via FFmpeg VA-API/NVENC/QSV (fastrdp patch) or x264 |
| gnome-remote-desktop | distro package | the user | GNOME headless sessions, hardware H.264 (VA-API/NVENC) |
| KRdp | distro package | the user | Plasma sessions (FreeRDP + PipeWire, VA-API H.264) |

## Login flow

1. **Front-end authentication** (proxy)
   - *NLA*: CredSSP with Kerberos. The proxy accepts tickets for `TERMSRV/<fqdn>`.
     NTLM is not offered (the module sets `AuthenticationPackageList=!ntlm` on the
     front): the proxy has no SAM file, so domain passwords cannot be checked that way.
     A client without a ticket fails at its first CredSSP message, and the proxy logs
     `attempted NTLM` with the fix ([windows-clients.md](windows-clients.md) §3.13).
   - *TLS* (optional, `fastrdp_allow_tls_logins`): the client sends user and
     password (+OTP) in the Client Info PDU. The broker verifies them through PAM.
   - *Smartcard*: NLA as above. The client got its ticket by PKINIT, and the
     card PIN is never forwarded ([smartcard-nla.md](smartcard-nla.md)).
   - *Web*: guacd logs in over TLS with a one-time `fastrdp-web1:` token, which
     is accepted only from loopback and only once.
2. **Identity binding** (module, `ServerPeerLogon`). For NLA the module reads the
   authenticated principal with `SECPKG_ATTR_AUTH_IDENTITY`. The user name and
   password from the client's TSCredentials are only used if the user matches that
   principal; the broker re-checks this.
3. **Authorisation** (broker): PAM account phase (`/etc/pam.d/fastrdp` → SSSD,
   including AD GPO "logon through RDS" rights), `allow_groups`, then MFA.
4. **Desktop choice**, first match wins:
   1. a client hint `fastrdp:<desktop>` in the RDP *alternate shell* field;
   2. `~/.config/fastrdp/desktop`;
   3. a group default (`[defaults.groups]`);
   4. the global default.

   Per-desktop `groups` restrict who may use each desktop.
5. **Session** (broker back-end driver):
   - *xrdp*: write `/run/fastrdp/desktop/<user>`, issue a one-time token, then route to
     `127.0.0.1:3390` with `user / token`. xrdp-sesman's PAM stack redeems the token.
     If the proxy knew the real password, the token module puts it into
     `PAM_AUTHTOK`, so `pam_sss` obtains a Kerberos TGT for the session.
   - *gnome*: configure g-r-d headless mode as the user (port, cert, random
     credentials), start `gnome-headless-session@<user>.service` (GDM 50) and wait
     until the port listens as that user.
   - *plasma*: write a root-only env file and start `fastrdp-plasma@<user>.service`.
     That unit opens a logind session through PAM `fastrdp-session`, runs KWin on its
     virtual backend and starts `krdpserver --plasma` on the allocated loopback port.
6. **Back-end connection** (module, `ClientPreConnect`): the proxy connects with the
   broker's credentials and protocol (TLS for xrdp, NLA for g-r-d/KRdp; on this
   loopback hop NLA uses NTLM, `AuthenticationPackageList=!kerberos`). The
   client's alternate shell and working directory, its routing token and the
   INFO_RAIL / smartcard-PIN flags are not forwarded. A Server Redirection PDU from a
   back-end is refused.
7. On disconnect the module reports `end`. Sessions keep running, and the next
   login of the same user reconnects to them.

Refusals after the RDP connection is up (broker says no, back-end not startable or
unreachable, RemoteApp requested) end with a Set Error Info PDU, so mstsc shows a
reason instead of a bare disconnect. The proxy does not offer UDP multitransport.
Spec details: [rdp-spec-conformance.md](rdp-spec-conformance.md).

## Trust boundaries and hardening

- **Only the proxy is reachable from the network.** Back-end ports (3390 and the
  per-user range, default 33900–34899) are dropped on non-loopback interfaces. On
  loopback, nftables allows only `_fastrdp-proxy` and root to open new connections
  (`ct state new meta skuid`). Other local users therefore cannot use credentials they might
  see, such as KRdp's `--password` argument.
- **Port hijack protection:** before routing, the broker checks in `/proc/net/tcp*`
  that the target port is held by exactly the expected uid: the session user, or
  root for xrdp (xrdp binds as root, then drops privileges). Back-end ports are in
  `ip_local_reserved_ports`, so the kernel never hands them out as ephemeral ports.
- **xrdp cannot be used to skip MFA:** its PAM stack accepts only unexpired,
  unused tokens bound to the user. Plain passwords fail.
- **Back-end certificates** are per-user self-signed certificates on loopback,
  in root-owned directories (`/var/lib/fastrdp/users/<user>/`, files owned by the
  user), so users cannot redirect root's writes with symlinks. The
  proxy uses `CertificatePolicy=allow` for them; the uid check and the nftables
  owner rule replace certificate pinning.
- **Secrets:**
  - The proxy wipes the front password (module copy and front settings) after
    handing it to the broker.
  - NLA must have used Kerberos (checked via `SECPKG_ATTR_PACKAGE_INFO`); NTLM is not
    offered and would be refused.
  - Tokens live 60 s, are single-use, and are kept in memory only.
  - g-r-d/KRdp credentials are random per session and stored in the root-only
    `/var/lib/fastrdp/sessions.json`.
- **Sockets:**
  - `broker.sock` (0660, group `_fastrdp-broker`: proxy and webgate) accepts `login`/`end` only from
    the proxy uid, and `status`/`logout` only from root.
  - `token.sock` (0600) accepts only root, i.e. xrdp-sesman.

## Broker protocol

Newline-delimited JSON over Unix sockets. See the docstring in
`broker/brokerd/fastrdp_broker/protocol.py`.

A refusal is `{"ok": false, "error": TEXT, "reason": REASON}`. TEXT stays generic
("access denied", "session could not be started"); details go only to the broker log.
REASON is machine-readable, and the proxy module turns it into the Set Error Info code
the RDP client sees:

| REASON | When | Error info |
|---|---|---|
| `denied` | bad or unknown credentials (never told apart), invalid web token, realm, policy (`session_tgt = required`), anything else | 0x7 SERVER_DENIED_CONNECTION |
| `not_allowed` | identity proven, but not in `allow_groups`, PAM account check failed, or no permitted desktop | 0x9 SERVER_INSUFFICIENT_PRIVILEGES |
| `mfa_failed` | second factor rejected or missing, no push-capable token, MFA service unreachable | 0x7 |
| `mfa_timeout` | push not approved in time | 0x409 CB_CONNECTION_CANCELLED |
| `backend` | the session could not be started | 0x400 CB_DESTINATION_NOT_FOUND |

`not_allowed` confirms that the credentials are valid. The broker therefore sends it only
when the client knows that already (NLA: CredSSP succeeded; web: the IdP signed the user
in) or no second factor is due. A TLS password login that still owes its second factor
gets `denied`. Unknown reasons count as `denied`. The webgate uses the same reasons for its
error pages.

## Files on a deployed host

| Path | Content |
|---|---|
| `/etc/fastrdp/proxy.ini` | proxy configuration (`[FastRDP]` section for the module) |
| `/etc/fastrdp/broker.toml` | broker configuration (example: `broker/brokerd/config/broker.toml.example`) |
| `/etc/fastrdp/termsrv.keytab` | `TERMSRV/*` keys only; re-extracted when sssd rotates the machine password |
| `/etc/pam.d/{fastrdp,fastrdp-tgt,fastrdp-session,xrdp-sesman}` | PAM stacks (`broker/session/pam/`; `fastrdp-tgt`: session TGT for GNOME/Plasma) |
| `/run/fastrdp/` | sockets, desktop choice per user, Plasma session env files |
| `/var/lib/fastrdp/` | session state, per-user back-end certificates |
| `/usr/lib/fastrdp/python/` | broker package; admin CLI `fastrdpctl status|tickets [USER]|logout USER|clear-grace [USER]` (status: sessions and each session user's TGT expiry/renewal, `tickets.py`) |
