# Home directories on Kerberized NFS (`sec=krb5`, `krb5i`, `krb5p`)

Can users log in to fastrdp when `$HOME` is an NFS mount that requires Kerberos?

**Short answer:** only when a usable Kerberos credential exists for the user's uid
*before* the session first touches `$HOME`. Out of the box, that holds for logins
that carry the user's password (NLA with a delegated password, TLS): xrdp gets the
TGT through its PAM stack, and for GNOME and Plasma the broker now gets it before the
session starts (`fastrdp_session_tgt`, default `auto`). Everything else (Kerberos SSO
without password delegation, smartcard, web) fails, unless the host gets NFS tickets
by **gssproxy impersonation** (S4U2Self + S4U2Proxy). fastrdp ships that as an opt-in
Ansible option, `fastrdp_nfs_krb5_homes`. Sites without impersonation can refuse the
logins that cannot work, early and with a clear log message:
`fastrdp_session_tgt: required`.

This page is based on reading the code. It has **not** been tested against a real
Kerberized NFS server; see [Lab test plan](#lab-test-plan). Statements are marked
**[verified]** when they were checked in source code (file:line, versions below) and
**[inferred]** when they follow from the code but still need a lab run.

Sources read: nfs-utils 2.8.5 (Ubuntu 26.04) and 2.8.3 (Debian 13; `utils/gssd` differs
from 2.8.5 only by a 3-line locking fix in `krb5_util.c`), gssproxy 0.9.2 (both
distributions) with the Debian packaging, sssd 2.12.0 (Ubuntu 26.04) and 2.10.1
(Debian 13), systemd v257/v259 units, Linux-PAM 1.7.0, xrdp 0.10.6.1 and FreeRDP
3.32.2 (the versions fastrdp builds), GDM and gnome-remote-desktop `main`.

## Support matrix

"Works" means that the session can read and write `$HOME` when it starts.

| Login method | xrdp (X11, incl. wlroots-in-X) | GNOME | Plasma |
|---|---|---|---|
| NLA, password typed and delegated (mstsc, xfreerdp `/p`, Windows "Allow delegating default credentials") | **works** [verified order, inferred result] | **works** with `fastrdp_session_tgt: auto`/`required` [inferred, see Q3] | **works** (as GNOME) [inferred] |
| NLA, Kerberos SSO, no password delegation | **fails** | **fails** | **fails** |
| NLA, smartcard / PKINIT (PIN never forwarded) | **fails** | **fails** | **fails** |
| TLS, password (+OTP) | **works** | **works** (as above) [inferred] | **works** [inferred] |
| Web (Keycloak, Guacamole) | **fails** | **fails** | **fails** |
| **Any of the above with `fastrdp_nfs_krb5_homes: true`** (gssproxy impersonation, KDC delegation configured) | works [inferred] | works [inferred] | works [inferred] |

With `fastrdp_session_tgt: required` (no impersonation), the "fails" rows are refused
by the broker before MFA, with `login without a password, but [broker] session_tgt =
required` in the broker log, instead of failing after the client connected; GNOME and
Plasma logins whose TGT request fails are refused too.

Exceptions to "fails":

- `KCM:` caches are **per uid**, not per session. If the user still has a valid TGT on
  this host from another login (a running xrdp session started with a password,
  `ssh` with a password, `kinit`), every process of that uid can use NFS, so a
  "failing" login can work. Failures can therefore look intermittent.
- With gssproxy, accounts that the KDC refuses to impersonate (AD "Protected Users",
  "Account is sensitive and cannot be delegated"; FreeIPA without a delegation rule)
  still need a typed password (gssproxy falls back to the user's own TGT, see Q5a).

How the failures show:

- **xrdp:** the broker accepts the login, xrdp authenticates the token, then sesman
  cannot create `~/.Xauthority` and does not start the X server
  (xrdp `sesman/sesexec/session.c:516-532`). The client connects and is disconnected.
- **GNOME:** `grdctl` runs as the user before the session starts
  (`backends/gnome.py`) and needs `$HOME` (dconf, the gnome-remote-desktop
  credentials file). It fails, so the broker returns "session could not be started".
  (The unit link of `systemctl --user --runtime enable` is in `/run/user/<uid>`, not
  in `$HOME`, see Q6.)
- **Plasma:** `fastrdp-plasma@USER` starts, but Plasma cannot read or write
  `~/.config`, `~/.local/share` and `~/.cache`; the session is expected to fail or
  stay unusable, and the broker times out waiting for KRdp [inferred].

## Q1: Who accesses `$HOME`, and when

### root

| Who | When | Access | With `sec=krb5*` |
|---|---|---|---|
| broker (`identity.read_desktop_pref`, `identity.py:85`) | every login without a usable desktop hint, and the web chooser, **before** any session exists | `open`/`fstat`/`read` of `~/.config/fastrdp/desktop` as root | root uses the host's machine credential (rpc.gssd default `use-machine-creds=1`, `gssd_proc.c:763-779`, `gssd.man` "Credentials for UID 0"). The server maps it to an unprivileged id or root-squashes it, so a 0700 home gives `EACCES` [inferred]. A hung server or a slow upcall **blocks** the call. |
| `pam_mkhomedir` (`xrdp-sesman`, `fastrdp-session`, session phase, runs as root) | session open | `stat(pw_dir)`; creates the home only if `stat` fails (Linux-PAM 1.7.0 `pam_mkhomedir.c:252-260`) | `stat` needs only search permission on the parent, normally granted, so it returns success [inferred]. If not, `mkhomedir_helper` fails; the module is `optional`, so nothing breaks. Home directories must be created on the NFS server, not by `pam_mkhomedir`. |
| broker certificates, state, desktop choice, Plasma env | – | `/var/lib/fastrdp`, `/run/fastrdp` (`sysutil.py:104-131`, `xrdp.py:55-64`, `plasma.py:34-44`) | local, not affected |

Before this change the broker read the preference file **in the asyncio event
loop** (`server.py`, `choose_desktop` was synchronous) and caught only errors from
`open()`. Two problems:

1. An unreachable NFS server (hard mount), or an rpc.gssd upcall waiting for its
   timeout (`upcall-timeout`, default 30 s), would freeze **all** logins of all users.
2. An error from `fstat()`/`read()` (for example `EKEYEXPIRED`, `EIO`) escaped as an
   unexpected exception; the login failed without a reply.

`EACCES` from `open()` was already handled (fallback to the group or global default).
Both problems are fixed now (see [Changes](#changes-in-this-repository)).

### The user, before any TGT exists

- `pam_systemd` (session phase) makes logind start `user@UID.service`. That unit has
  no `WorkingDirectory=` (systemd v257/v259 `units/user@.service.in`), so the start
  itself does not need `$HOME` [verified]. The user manager reads
  `~/.config/systemd/user` and the other user unit directories; unreadable
  directories are logged and ignored (systemd v257 `src/shared/unit-file.c:440-443`)
  [verified]. Consequence: units the user (or the broker, for GNOME) enabled in
  `$HOME` are silently missing if the manager starts without credentials, and stay
  missing until the next `daemon-reload` [inferred].
- Everything started by the user manager (D-Bus activated services, dconf,
  gnome-session, pipewire, portals, indexers) touches `$HOME`.
- **GNOME:** the broker starts `user@UID.service` itself (`sysutil.py:65-66`) and
  runs `grdctl ... set-credentials/set-tls-*/enable` and `systemctl --user --runtime enable`
  (`backends/gnome.py`) before GDM opens the session; with a password, only after
  the broker stored the user's TGT (Q3). `grdctl` writes GSettings
  (dconf, `~/.config/dconf/user`) and the credentials file in the user data
  directory (gnome-remote-desktop `src/grd-credentials-file.c:143-170`:
  `$XDG_DATA_HOME/gnome-remote-desktop/credentials.ini`, when the file backend is
  used). GDM's `gnome-headless-session@.service` runs `gdm-new-session %i --headless`,
  which asks GDM over D-Bus (`CreateUserDisplay`) to start the session; no password
  is involved.
- **Plasma:** `fastrdp-plasma@USER.service` opens a PAM session with the
  `fastrdp-session` stack, which has no `auth` phase (`broker/session/pam/fastrdp-session`),
  then `session-plasma` starts Plasma, which reads and writes `$HOME` immediately.

### Session processes

- **xrdp:** sesexec sets `HOME` and `chdir`s into it (`sesman/sesexec/env.c:171-172`),
  writes `.Xauthority` relative to it (`session.c:516-532`), Xorg writes
  `~/.xorgxrdp.N.log` (`sesman.ini` `-logfile .xorgxrdp.%s.log`), `startwm.sh` sources
  `~/.profile` (`startwm.sh:11`), chansrv mounts `~/thinclient_drives` (FUSE), then
  the desktop.
- **GNOME/Plasma:** the whole desktop.

## Q2: Which credentials rpc.gssd can use

For a uid other than 0, rpc.gssd (nfs-utils 2.8.x, `utils/gssd/gssd_proc.c:568-604`)
[verified]:

1. **switches the upcall thread to the user** (`change_identity`, `setresuid` by raw
   syscall per thread, `gssd_proc.c:490-560`),
2. calls `gss_acquire_cred(GSS_C_NO_NAME, ...)` (`gssd_acquire_user_cred`,
   `krb5_util.c:1500-1540`). This uses **the default ccache from `krb5.conf`**, here
   `default_ccache_name = KCM:` (`ansible/roles/identity/templates/krb5-fastrdp.conf.j2`,
   installed as `/etc/krb5.conf.d/fastrdp`).
   sssd-kcm identifies the caller by its socket peer uid, which is the user's after
   step 1. So **KCM works** without any option [verified for gssd; KCM peer-uid
   behaviour inferred]. This path exists since 2013 (nfs-utils commit 302de786,
   "gssd: Allow GSSAPI to try to acquire credentials first").
3. only if that fails, searches **file** caches: directories from `-d` /
   `cred-cache-directory`, default `/tmp:/run/user/%U` (`gssd.h:46-48`,
   `gssd.man:242-248`), files whose name contains `krb5cc`, owned by the uid,
   `FILE:` or `DIR:` type only (`krb5_util.c:231-330`). `EKEYEXPIRED` is reported
   only from this file search (`gssd_proc.c:595-596`); an expired KCM TGT ends as
   `EACCES` [inferred].

Other relevant gssd settings ([verified] in `gssd.c` and `gssd.man`):

- `-k`/`keytab-file`: keytab for **machine** credentials (uid 0, NFSv4 state
  operations). Order of principals: `<HOST>$@REALM`, `root/`, `nfs/`, `host/`. An AD
  join with adcli or a FreeIPA enrolment provides them.
- `set-home=1` (default): gssd sets `HOME=/` so libkrb5 does not read
  `~/.k5identity` from the NFS home it is trying to authenticate to (`gssd.c:1159-1166`).
- `use-gss-proxy=1`: sets `GSS_USE_PROXY=yes` (`gssd.c:1065`, `1169-1172`), so the
  GSSAPI calls of step 2 go to gssproxy (see Q5a).
- `rpc-gssd.service` starts only if `/etc/krb5.keytab` exists
  (`systemd/rpc-gssd.service.in`).

What fastrdp configures (role `identity`):

- `krb5-fastrdp.conf.j2` → `/etc/krb5.conf.d/fastrdp` (every provider):
  `default_ccache_name = KCM:`, `renew_lifetime`; `krb5.conf.j2` (AD, none):
  `default_realm`, `dns_lookup_kdc = true`, `rdns = false`, `includedir /etc/krb5.conf.d/`
  (FreeIPA keeps the enrolment's `krb5.conf`); `sssd-kcm` is installed (`tasks/main.yml`).
- `sssd-ad.conf.j2` (AD only; FreeIPA uses the `sssd.conf` written by
  `ipa-client-install`): no `krb5_ccname_template`, so sssd uses `KCM:` from
  `krb5.conf` (sssd-krb5(5): "Default: (from libkrb5)") [verified];
  `krb5_renewable_lifetime = 7d`, `krb5_renew_interval = 1h`
  (`fastrdp_krb5_renewable_lifetime`, `fastrdp_krb5_renew_interval`).
- `/etc/sssd/conf.d/50-fastrdp.conf` (`sssd-fastrdp.conf.j2`, every provider):
  `[kcm] tgt_renewal = true` with the same interval and lifetime
  (`fastrdp_kcm_tgt_renewal`), and on FreeIPA the domain renewal options that
  `ipa-client-install` does not write. `/etc/krb5.conf.d/fastrdp` has `renew_lifetime`,
  so `kinit` asks for renewable tickets too.
- Before this change fastrdp installed neither `nfs-common` nor `gssproxy`, and did not
  touch `nfs.conf`.

## Q3: Does the session have a TGT when it first touches `$HOME`?

### xrdp with a typed password (NLA delegated password, or TLS)

The broker hands the password to xrdp in a one-time token (`backends/xrdp.py:85`);
`pam_fastrdp_token` sets it as `PAM_AUTHTOK` and `pam_sss use_first_pass` authenticates
(`broker/session/pam/xrdp-sesman:6-7`). Ordering in xrdp 0.10.6.1 [verified]:

1. `pam_authenticate` (`sesman/libsesman/verify_user_pam.c:290`): sssd's krb5_child
   gets the TGT and **stores it in the user's ccache during authentication**, after
   switching to the user (sssd 2.12.0 `src/providers/krb5/krb5_child.c:2541-2562`,
   2.10.1 `:2406`). `pam_sss`'s `setcred` does nothing for Kerberos.
2. `pam_setcred` + `pam_open_session` (`verify_user_pam.c:416, 426`) via
   `auth_start_session` (`session.c:643`): `pam_systemd` starts `user@UID.service`,
   which now finds the TGT in KCM.
3. Only then is the X server forked (`session.c:676`), with `HOME` and `chdir`.

So the TGT exists before anything reads `$HOME`. Every connection, including a
reconnect, is a new login request that runs PAM authentication again
(`sesman/scp_process.c:73-140`, reconnect at `:419-441`), so **a reconnect with a
password renews the TGT** [verified flow, inferred result].

Weak point: `pam_sss` is `optional` in the sesman stack. If the KDC is unreachable,
sssd authenticates offline from its cache and creates **no** TGT
(`krb5_store_password_if_offline = true` fetches one later, when the KDC is back). The
session then starts without NFS access and fails as described above.

### SSO without delegation, smartcard, web

No password reaches the server (`server.py:100-106` drops a smartcard PIN, the web
path returns `password=None`, `server.py:122`), so there is no TGT and the session
cannot read `$HOME`. CredSSP cannot carry a TGT (Q5b).

### GNOME and Plasma

These back-ends never receive the password (`backends/gnome.py`,
`backends/plasma.py`; only a random per-session secret). Before this change, NLA
logins got no TGT (the broker ran only the PAM account phase), and TLS logins only
as a side effect of the password check through PAM service `fastrdp`.

Now the broker obtains the TGT itself, for every login that carries the password
(NLA with delegated password, TLS), after MFA and before `backend.ensure()`
(`Broker.session_tgt`, `fastrdp_broker/tgt.py`):

1. `pam_authenticate` + `pam_setcred(PAM_ESTABLISH_CRED)` for the user with PAM
   service `fastrdp-tgt` (`broker/session/pam/fastrdp-tgt`: `auth required pam_sss.so`
   only). The password goes only through the PAM conversation.
2. `klist -s` with the user's uid/gid (no supplementary groups, clean environment,
   `HOME=/`, cwd `/`, `KRB5CCNAME` as reported by `pam_sss`) checks that a valid TGT
   is now in the cache.
3. `[broker] session_tgt`: `auto` logs a failure and starts the session anyway,
   `required` refuses the login, `off` skips both steps.

Why PAM (option a) and not `kinit` in the user's manager (option b), from sssd
2.12.0 sources [verified]:

- The ccache is written by `krb5_child`, not by the PAM caller. `krb5_auth.c:714`
  takes the uid from sssd's cache (`SYSDB_UIDNUM`), `krb5_child_handler.c:201` sends
  it to `krb5_child`, and `krb5_child.c:2541-2562` calls `switch_to_user()`
  (`krb5_ccache.c:45`) before `create_ccache()`. So the broker running as root makes
  no difference; KCM sees the user's peer uid. For collections (`KCM:`)
  `create_ccache()` reuses the cache of the same principal or creates one and makes
  it primary (`krb5_child.c:1662-1707`, `krb5_cc_switch`), so `klist -s` sees it.
- The cache template is sssd's (`krb5_auth.c:299`, `krb5_ccname_template`, default
  from libkrb5), the principal is the user's real UPN from the directory (no
  `user@REALM` guess as with `kinit`), KDC discovery and failover are sssd's, and
  the TGT is registered for sssd's own renewal (`krb5_auth.c:1199-1207`,
  `add_tgt_to_renew_table`).
- `pam_sss` reports the cache in the PAM environment (`krb5_child.c:1848-1871`
  `k5c_attach_ccname_msg`, `pam_sss.c:1121-1136` `pam_putenv`), which the check in
  step 2 uses.
- `kinit` inside the user's systemd manager (`sysutil.run_as_user`) would start
  `user@UID.service` *before* the TGT exists, which is the failure described in Q1,
  and its ticket would only be renewed by sssd-kcm.

Limits [inferred, lab check needed]: when sssd is offline (KDC unreachable) or uses
`cached_auth_timeout`, authentication succeeds from the cache without a TGT; the
`klist -s` check catches that (with `auto`: warning only). The extra authentication
is one more AS exchange per GNOME/Plasma login (for TLS logins the second one); a
wrong delegated password counts at the KDC (AD `badPwdCount`) but not in
`pam_faillock` (`fastrdp-tgt` has none on purpose).

## Q4: Ticket lifetime and renewal

- AD defaults: TGT lifetime 10 h, renewable for 7 days. fastrdp asks for renewable
  tickets (`krb5_renewable_lifetime = 7d`) and sssd renews every hour
  (`krb5_renew_interval = 1h`).
- sssd's domain-level renewal registers the ccache name of every successful PAM
  authentication, whatever its type (sssd 2.12.0 `krb5_auth.c:1199-1207`), and renews
  it with `krb5_get_renewed_creds` as the user (`krb5_child.c:3028-3075`); only
  `FILE:` caches get an extra expiry check. So renewal of the sssd-created KCM TGT
  should work [inferred]. Limits: TGTs from `kinit` inside the session are not
  registered; while sssd is offline the renewal timer is removed
  (`krb5_renew_tgt.c`, `renew_tgt_offline_callback`).
- sssd-kcm can renew every TGT in KCM itself (`[kcm] tgt_renewal = true`;
  sssd-kcm(8) "RENEWALS"; built by default when libkrb5 has
  `krb5_unmarshal_credentials`, `src/external/krb5.m4:114-130`). fastrdp now
  configures it in `/etc/sssd/conf.d/50-fastrdp.conf` with `krb5_renew_interval` and
  `krb5_renewable_lifetime` in the `[kcm]` section itself rather than
  `tgt_renewal_inherit`, so it works for every identity provider
  (`kcm_renew.c:300-370`: without `tgt_renewal_inherit` the `[kcm]` options are
  read). Renewals start at half the ticket lifetime. `krb5.conf` `renew_lifetime`
  makes `kinit` ask for renewable tickets.
- **After `renew_till` (7 days)** nothing can renew without a password. Once the
  kernel's GSS context for that user expires (at the end of the `nfs/` service
  ticket, at most the TGT's lifetime), the next upcall fails and every process of
  the user gets `EACCES` or `EKEYEXPIRED` ("Key has expired") on the home: autosave,
  mail clients, browser profiles. Writes of open files fail too. A disconnected
  xrdp session lives on (`fastrdp_xrdp_disconnected_time_limit: 0` = forever), so a
  session left alone for more than a week loses its home.
- **Reconnect:** xrdp with a password runs PAM authentication again and gets a fresh
  TGT, and all processes of the uid can use NFS again (KCM is per uid). GNOME/Plasma
  reconnects with a password do the same through the broker (`session_tgt`), also
  when the running session is reused. Reconnects without a password (SSO,
  smartcard, web) do not refresh anything; the user must run `kinit` in the session.
- **With gssproxy impersonation** none of this applies. gssproxy gets new tickets with
  the host keytab whenever rpc.gssd needs a context, so access does not expire with
  the user's TGT (gssproxy `docs/NFS.md`: access is "always on") [inferred].

## Q5: Solutions

### a) gssproxy impersonation (S4U2Self + S4U2Proxy), recommended

How it works [verified in gssproxy 0.9.2 source]:

1. rpc.gssd, started with `use-gss-proxy=1`, sets `GSS_USE_PROXY=yes`. The gssproxy
   interposer (`/etc/gss/mech.d`) forwards rpc.gssd's GSSAPI calls to
   `/var/lib/gssproxy/default.sock`. Debian builds gssproxy with
   `--with-gpp-default-behavior=REMOTE_FIRST` (`debian/rules`; upstream default
   is `LOCAL_FIRST`, `conf_macros.m4:271-280`): gssproxy is asked first, and the
   local ccache (KCM) is used only if gssproxy fails.
2. gssproxy matches the service by the peer uid (the user's, because rpc.gssd
   switched identity), `allow_any_uid`, and `program` (`src/gp_creds.c:74-95`).
3. With `impersonate`, a request from a uid other than `euid` maps the uid to a user
   name with `getpwuid` and imports it as `GSS_C_NT_USER_NAME`, which means
   `<name>@<default_realm>` (`gp_creds.c:106-117`, `361-383`).
4. gssproxy gets the host's credential from the keytab (the **first principal** in
   the keytab, since no name is given), gets a ticket to itself for the user
   (S4U2Self), turns it into a delegated credential (`gp_creds.c:660-760`), and
   rpc.gssd's `gss_init_sec_context` to `nfs/<server>` then does S4U2Proxy. The KDC
   decides whether this host may do that for this user and service.

Directory configuration (choose one):

- **Active Directory, classic constrained delegation with protocol transition:**
  on the RDP host's computer account, "Trust this computer for delegation to
  specified services only" + "Use any authentication protocol", service
  `nfs/nfs1.example.com`:
  ```powershell
  Set-ADComputer RDP1 -Add @{'msDS-AllowedToDelegateTo'=@('nfs/nfs1.example.com','nfs/NFS1')}
  Set-ADAccountControl -Identity 'RDP1$' -TrustedToAuthForDelegation $true
  ```
- **Active Directory, resource-based constrained delegation (RBCD):** set on the
  NFS server's account, no flag on the RDP host; AD accepts the non-forwardable
  S4U2Self ticket for RBCD. Needs MIT krb5 ≥ 1.18 on the client (Debian 13 has 1.21,
  Ubuntu 26.04 1.22):
  ```powershell
  Set-ADComputer NFS1 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer RDP1)
  ```
- **Samba AD:** `samba-tool delegation add-service 'RDP1$' nfs/nfs1.example.com` and
  `samba-tool delegation for-any-protocol 'RDP1$' on` (check S4U support of the Samba
  version in use).
- **FreeIPA:** a service delegation rule plus permission for protocol transition:
  ```sh
  ipa servicedelegationtarget-add nfs-homes
  ipa servicedelegationtarget-add-member nfs-homes --principals=nfs/nfs1.example.com@EXAMPLE.COM
  ipa servicedelegationrule-add rdp-to-nfs-homes
  ipa servicedelegationrule-add-member rdp-to-nfs-homes --principals=host/rdp1.example.com@EXAMPLE.COM
  ipa servicedelegationrule-add-target rdp-to-nfs-homes --servicedelegationtargets=nfs-homes
  ipa host-mod rdp1.example.com --ok-to-auth-as-delegate=true
  ```
  (Recent FreeIPA also offers RBCD: `ipa service-add-delegation`.)

Client configuration (what `fastrdp_nfs_krb5_homes: true` installs):

```ini
# /etc/gssproxy/90-fastrdp-nfs-client.conf
[service/fastrdp-nfs-client]
mechs = krb5
cred_store = keytab:/etc/krb5.keytab
cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
cred_usage = initiate
allow_any_uid = yes
impersonate = yes
trusted = yes
euid = 0
program = /usr/sbin/rpc.gssd

# /etc/nfs.conf.d/fastrdp-gssd.conf
[gssd]
use-gss-proxy = 1
```

This follows gssproxy's `docs/NFS.md` ("User Impersonation via Constrained
Delegation") and `examples/99-network-fs-clients.conf.in`, plus `program =` so that
only rpc.gssd can use the service (`docs/network_fs_clients.md`). Debian's
`gssproxy.service` creates `/var/lib/gssproxy/clients` (`StateDirectory=`) and is
ordered `Before=rpc-gssd.service`. nfs-utils reads `/etc/nfs.conf.d/*.conf` after
`/etc/nfs.conf` (`nfs.conf(5)`).

Check the keytab order first: `klist -k /etc/krb5.keytab | head`. On AD the first
entry should be `RDP1$@REALM` (adcli), on FreeIPA `host/rdp1.example.com@REALM`. The
fastrdp keytab also contains `TERMSRV/` entries; they belong to the same computer
account. If the first entry is not the machine principal, build a keytab with only
that principal (like `fastrdp-termsrv-keytab` does for TERMSRV) and set
`fastrdp_nfs_gssproxy_keytab`.

Security implications:

- root on the RDP host (or anyone who can read the host keytab) can obtain NFS access
  as **any** user, to the NFS services listed in the delegation, including users who
  never logged in. Without impersonation, root already reaches every user with a live
  TGT on the host; with it, the scope is every user. Keep the delegation limited to
  the home servers, never "any service".
- The uid to principal mapping is by **name**. A local account (in `/etc/passwd`) whose
  name exists in the directory is impersonated as that directory user and gets that
  user's files on the NFS server. Make sure local account names do not collide with
  directory accounts (`getent passwd` vs. AD/IPA).
- Accounts that must never be impersonated (admins): AD "Protected Users" or
  "Account is sensitive and cannot be delegated"; they then need a typed password
  (the fallback to their own KCM TGT still works).
- Delegation is visible in the KDC logs (S4U2Self/S4U2Proxy events, AD 4769).

### b) Forwarding the client's TGT

- CredSSP ([MS-CSSP] 2.2.1.2 TSCredentials) carries a password (`TSPasswordCreds`),
  smartcard PIN + CSP data (`TSSmartCardCreds`), or Remote Credential Guard data
  (`TSRemoteGuardCreds`). None of them is a TGT. Remote Credential Guard keeps the
  credentials on the client and sends Kerberos requests back over the MS-RDPEAR
  virtual channel; a Linux server would have to implement that channel and a krb5
  plugin around it. Not realistic.
- A forwarded TGT inside the Kerberos AP-REQ (GSS checksum delegation field) would need
  the `TERMSRV` account to be trusted for **unconstrained** delegation and a client
  that asks for it. FreeRDP 3.32.2's Kerberos SSP ignores it on the server side: the
  acceptor reads only the flags from the checksum and never calls `krb5_rd_cred`
  (`winpr/libwinpr/sspi/Kerberos/kerberos.c:1639-1653`), and FreeRDP clients do not
  send one ("delegation not implemented", `:1254`) [verified]. Implementing it means
  patching WinPR, passing the KRB-CRED from the proxy module to the broker, and storing
  it in the user's KCM. Whether mstsc requests delegation in CredSSP is not verified.
  Unconstrained delegation is a larger risk than option a).
- How a Windows RDP host gets Kerberos credentials in each mstsc mode (password
  delegation, Restricted Admin, Remote Credential Guard), compared with fastrdp:
  [windows-clients.md](windows-clients.md) §3.12.

### c) Require a typed password for users with Kerberized homes

Works for every RDP back-end (NLA with password, or TLS). Smartcard, SSO without
delegation and web users cannot use the server; `fastrdp_session_tgt: required`
refuses them early. Users must reconnect with a password at least once per renewal
period (7 days).

### d) Local or cached home directories

Give sessions a local `$HOME` (e.g. `fallback_homedir`/`override_homedir = /home/%u`
on local disk) and mount the NFS share somewhere else (`~/nfs`, `/nfs/home/%u`).
The desktop starts for every login method; access to the NFS share still needs a
TGT (or impersonation). Trade-offs: settings are per host (problem with several RDP
hosts behind a load balancer), local disk use, users must learn where their files are.

### e) `sec=sys`

Not acceptable: the NFS server trusts the uid the client claims, so root on any
client (or anyone with a laptop on the network, without export restrictions) can read
every home. It also removes integrity and privacy on the wire that `krb5i`/`krb5p`
provide.

## Q6: What fastrdp changes

Implemented (see [Changes](#changes-in-this-repository)):

1. **Broker robustness:** the preference file is read off the event loop, with a
   time limit, and any I/O error means "no preference".
2. **Ansible option `fastrdp_nfs_krb5_homes`** (default `false`, role `identity`):
   installs `nfs-common` and `gssproxy`, writes the two files from Q5a, restarts
   gssproxy and rpc-gssd. The directory side (delegation) stays manual.
3. **GNOME/Plasma TGT with a password** (`[broker] session_tgt`,
   `fastrdp_session_tgt`, default `auto`): see Q3. Runs on every login with a
   password, so reconnects refresh the TGT.
4. **Early refusal** (`fastrdp_session_tgt: required`, default off): logins without a
   password are refused before MFA, for every back-end and on the web path
   (`web_token`/`web_desktops`); failed TGT requests for GNOME/Plasma refuse the
   login. It is a site decision, not derived from `fastrdp_nfs_krb5_homes` (with
   impersonation, password-less logins work and `required` is not needed). The
   client sees "access denied" like every refusal; the reason is in the broker log.
   xrdp's own TGT (pam_sss is `optional` in `xrdp-sesman`) cannot be checked by the
   broker before the session starts.
5. **GNOME unit link outside `$HOME`:** the broker enables
   `gnome-remote-desktop-headless.service` with `systemctl --user --runtime enable`.
   The link goes to `$XDG_RUNTIME_DIR/systemd/user` (systemd `path-lookup.c`,
   `runtime_config`; in the user unit search path), a tmpfs that exists while the
   user manager runs, so a manager started without NFS credentials still sees it.
   Not changed: a global enable (`/etc/systemd/user/gnome-session.target.wants/`)
   would start the headless daemon in every GNOME session on the host, and the unit
   `Conflicts=gnome-remote-desktop.service` (desktop sharing of a local session).
   `grdctl` settings stay in `$HOME`: they are GSettings in the user's dconf
   database (`~/.config/dconf/user`, shared with gnome-shell), and the headless
   credentials are TPM-sealed or in `$XDG_DATA_HOME/gnome-remote-desktop/credentials.ini`
   (g-r-d `grd-settings.c` `create_headless_credentials`,
   `grd-credentials-file.c:144-170`). Moving them would need the same
   `XDG_DATA_HOME`/dconf profile for `grdctl` and the g-r-d unit (a drop-in), a change
   to the whole session's dconf, which is not low-risk. With a TGT (3) or
   impersonation, the home is readable when `grdctl` runs. With `sec=krb5`/`krb5i`
   the per-session RDP secret travels unencrypted to the NFS server; it changes every
   session and is accepted only on loopback, so this is a minor issue.
6. **Ticket renewal:** `[kcm] tgt_renewal` in `/etc/sssd/conf.d/50-fastrdp.conf`
   (`fastrdp_kcm_tgt_renewal`, `fastrdp_krb5_renew_interval`,
   `fastrdp_krb5_renewable_lifetime`), `renew_lifetime` in `/etc/krb5.conf.d/fastrdp`.
7. **FreeIPA:** the same snippet adds `krb5_renewable_lifetime`/`krb5_renew_interval`
   to `[domain/<fastrdp_domain>]`, which `ipa-client-install` does not write.

## Where homes are

The home directory is whatever NSS (sssd) reports: AD `unixHomeDirectory`, FreeIPA
`homeDirectory`, or for AD accounts without one `fallback_homedir = /home/%u`
(`sssd-ad.conf.j2`). That path must exist on the RDP host, or be creatable there.
A directory that names `/autofs/srv/home/<user>` on a host without autofs breaks
every session: GNOME's `grdctl` aborts with *Init file credentials failed: Error
creating directory /autofs: Permission denied*; xrdp's `pam_mkhomedir` would even
create `/autofs/srv/home/<user>` on local disk, as root.

**What the broker does** (`broker/brokerd/fastrdp_broker/home.py`, `[broker]
home_check`, default `create`), before any back-end starts, for every desktop:

| Home | Result |
|---|---|
| exists, a directory (a symlink to one is fine), owned by the user | login goes on |
| exists, owned by another uid | the user must be able to write to it (tested as the user, `test -w`); else refused, uid 65534 with a hint at NFSv4 id mapping |
| only the last component is missing | created like `pam_mkhomedir umask=0077`: `mkhomedir_helper <user> 0077 /etc/skel 0700`, as in the `xrdp-sesman` and `fastrdp-session` stacks, always mode 0700 (their `pam_mkhomedir` would use `HOME_MODE` from `/etc/login.defs`, 0750 on Ubuntu). Only in a parent that is one of `[broker] home_create_roots` (Ansible `fastrdp_home_create_roots`, default `[/home]`, `[]` = never) or below one, as named and with symlinks resolved (a root that is itself a symlink, `/home -> /var/home`, is fine; a symlink below a root leading out of it is not), that exists (the roots and other missing parents are never created; the helper itself would create missing parents), that is root-owned and writable by root alone along the whole path, as named and resolved (no symlink swaps), on a local file system (NFS, CIFS, FUSE, ...: provision homes on the server), and never inside an automount point (its entries come from the map). GNOME has no `pam_mkhomedir` in its path, so this is what creates its homes |
| a parent is missing | refused: `backend error: home directory /autofs/srv/home/marcel of marcel does not exist (parent /autofs missing: automount not set up?)` (below an automount point: *no map entry, or server down?*) |
| not a directory, dangling symlink, relative path | refused |
| root may not look (`sec=krb5*`, `root_squash`: EACCES), or no answer within `home_read_timeout` (3 s; hung NFS) | not checked, the login goes on |

A refusal is reason `backend`: the client gets *ERRINFO_CB_DESTINATION_NOT_FOUND*
(0x400), like any session start failure; the cause is in the broker log
(`journalctl -u fastrdp-brokerd`). `home_check = "check"` never creates homes (sites
that provision them elsewhere), `"off"` skips all of it. The setting is in
`/etc/fastrdp/broker.toml` (not rendered by Ansible: the default fits).

**The fixes**, in Ansible terms:

1. **Mount what the directory names** (the directory's paths are right, the host is
   missing the automounter): `fastrdp_autofs`, see
   [Automounted homes](#automounted-homes).
2. **Local homes** (the directory's paths are for other machines):
   `fastrdp_sssd_override_homedir: /home/%u` renders `override_homedir` in sssd
   (AD: `sssd.conf`, FreeIPA: `/etc/sssd/conf.d/50-fastrdp.conf`), which wins over
   the directory's attribute. Expansions as in `sssd.conf(5)`: `%u` (login name),
   `%U` (uid), `%d` (domain), `%f` (fully qualified name), `%l` (first letter), `%P`,
   `%o` (the directory's home), `%h` (lower-case name), `%H` (`homedir_substring`),
   `%%`. The broker creates only the last component: for `/home/%d/%u` create
   `/home/<domain>` first. A path outside `fastrdp_home_create_roots` (default `[/home]`) is
   never created by the broker: add its root, or provision the homes. Provider `none`: put `override_homedir = /home/%u` into
   your `[domain/...]` section. Option d) in [Q5](#q5-solutions) for Kerberized
   NFS is this plus a mount elsewhere.

`make preflight` samples `fastrdp_preflight_user` (inventory or `-e`, a directory
user) and the join account: `getent passwd`, then `stat` of every path component as
the SSH user (5 s limit each). Check *home directories*: FAIL when a parent of the
test user's home is missing and neither `fastrdp_autofs` nor
`fastrdp_sssd_override_homedir` is set, or when the override's fixed prefix does not
exist; WARN for the join account, hung mounts, and override paths with several
dynamic components.

## Automounted homes

`fastrdp_autofs` (role `identity`, `tasks/autofs.yml`; default `none`: the host's
business, nothing changed):

- `sssd`: automount maps from the directory (AD and FreeIPA store them in LDAP).
  Installs `autofs`; adds sssd's autofs responder (AD: `services = nss, pam, autofs`
  and `autofs_provider = ad` in `sssd.conf`; FreeIPA: `autofs` appended to the
  `services` line of the enrolment's `sssd.conf`, as `ipa-client-automount` does, and
  `autofs_provider = ipa`, `ipa_automount_location = <fastrdp_autofs_ipa_location>`
  (default `default`) in the conf.d snippet); sets `automount: files sss` in
  `/etc/nsswitch.conf`; restarts sssd, then enables and starts `autofs`; drop-ins
  `fastrdp-autofs.conf` order the boot `sssd` → `autofs` (else autofs reads empty
  directory maps) → `fastrdp-brokerd` (both modes). `files`
  first: Debian's `/etc/auto.master` includes `/etc/auto.master.d` and then
  `+auto.master`, the master map from the next source (sss), so local and directory
  maps work side by side. The LDAP schema sssd expects for the maps, and the
  `ldap_autofs_*` options for another one, are in `sssd-ad(5)` / `sssd-ldap(5)`.
  Provider `none`: the role installs autofs and sets nsswitch, the sssd part is
  yours (`services = ..., autofs`, `autofs_provider`).
- `files`: installs and enables `autofs`; the maps are yours, e.g.

  ```
  # /etc/auto.master.d/home.autofs
  /autofs/srv/home  /etc/auto.home  --timeout=600
  # /etc/auto.home
  *  -fstype=nfs4,sec=krb5p  nfs1.example.com:/srv/home/&
  ```

  then `systemctl reload autofs`.

Upgrades: on AD the role writes the whole `sssd.conf`, so an automount set up by hand
there (`autofs` in `services`) is lost at every deployment unless
`fastrdp_autofs: sssd` is set.

Check: `automount -m` lists the maps, `ls /autofs/srv/home/<user>` mounts a home,
`sss_cache -A` drops cached maps after a change in the directory.

**Snaps** (Firefox and others on Ubuntu) refuse homes outside `/home`. Tell snapd
the other prefix once per host: `snap set system homedirs=/autofs/srv/home` (snapd
2.59+; several prefixes comma-separated; some snapd versions accept only prefixes
below `/home`, then local homes via `fastrdp_sssd_override_homedir` are the way out).
Not done by the roles. autofs `browse_mode` stays as configured (Debian: `no`); the
broker stats homes with a trailing slash, so placeholders of browse mode are mounted
before they are judged.

## NFS server and client checklist

NFS server (Linux):

- `nfs/nfs1.example.com@REALM` in the server keytab (AD: `adcli update
  --add-service-principal=nfs/nfs1.example.com`; FreeIPA: `ipa service-add nfs/...` +
  `ipa-getkeytab`), gssproxy (`24-nfs-server.conf`) or rpc.svcgssd running.
- Export, e.g. `/home *.example.com(rw,sec=krb5p:krb5i:krb5,root_squash)`; homes owned
  by the user, mode 0700, created on the server.
- NFSv4 id mapping: the same `Domain` in `/etc/idmapd.conf` on client and server; the
  same uids on both sides (fastrdp uses sssd `ldap_id_mapping = true` on AD: the NFS
  server must use the same algorithm and ranges, or POSIX attributes from AD on both).

RDP host (client):

- Joined to the domain (keytab with the machine principal), `rpc-gssd` running.
- Mount by the **FQDN** that matches the `nfs/` SPN (rpc.gssd `avoid-dns=1` uses the
  name as given): `nfs1.example.com:/home /home nfs4 sec=krb5p,_netdev 0 0`, or autofs.
- `fastrdp_nfs_krb5_homes: true` plus the directory delegation (Q5a), or restrict
  logins to typed passwords (Q5c).
- Optional: `[broker] home_read_timeout = 0` if the broker should never read files in
  homes, plus `home_check = "off"` to skip the [home check](#where-homes-are) too.

## Lab test plan

Setup: AD (or FreeIPA) with users `pw1` (password), `sc1` (smartcard), `prot1`
(Protected Users); Linux NFS server exporting `/home` with `sec=krb5p`; the RDP host
mounting it; Windows client (domain-joined, with and without "Allow delegating default
credentials"), xfreerdp, Keycloak web path.

1. **Baseline, without gssproxy.** For each user × back-end: log in, record whether the
   session starts, `klist -l` (KCM collection), `ls ~`, broker/xrdp/sesman logs,
   `journalctl -u rpc-gssd` with `verbosity=3` in `[gssd]`. Expect the matrix above.
   Clear KCM between runs (`kdestroy -A` as the user) because of the per-uid effect.
2. **Broker:** stop the NFS server (hard mount) and log in: the login must answer
   within `home_read_timeout` with the default desktop, other users' logins must not
   stall. With the server up, check that root gets `EACCES` on
   `~/.config/fastrdp/desktop` and that a desktop preference is ignored.
3. **GNOME/Plasma TGT:** for NLA with delegated password and for TLS, confirm the
   broker log `Kerberos TGT stored for the gnome session` and a TGT in the user's
   KCM (`sudo -u pw1 klist -l`), present before the session's first home access
   (`journalctl -u rpc-gssd`). Repeat with sssd offline (`auto`: warning, `required`:
   refused), with a wrong delegated password (no `pam_faillock` entry:
   `faillock --user pw1`), and on a reconnect after `kdestroy -A` (new TGT). With
   `required`: SSO, smartcard and web logins refused before the push. GNOME: the
   g-r-d link in `/run/user/<uid>/systemd/user/gnome-session.target.wants/`.
4. **Renewal:** shorten the TGT lifetime (KDC policy, e.g. 15 min, renewable 1 h);
   disconnect; check renewals (`klist` times, sssd_be log; for a `kinit` TGT the
   sssd_kcm log, `debug_level` in `[kcm]`), then the failure after
   `renew_till` (errno seen by `cat ~/x`), then recovery on reconnect with and without
   password.
5. **gssproxy:** enable `fastrdp_nfs_krb5_homes`, configure delegation; repeat 1 and 4
   for all logins (expect "works"); `prot1` must fail without a password and work with
   one (fallback); KDC logs show S4U2Self/S4U2Proxy; `klist -c
   /var/lib/gssproxy/clients/krb5cc_<uid>`.
6. **Negative security checks:** a local account whose name exists in AD must not get
   that user's files (it will, if names collide: document the result); a non-rpc.gssd
   program with `GSS_USE_PROXY=yes` must not get impersonated credentials (`program =`).
7. **Keytab order:** with the fastrdp TERMSRV entries present, check which principal
   gssproxy uses (`GSSPROXY` debug, `debug_level = 3` in `[gssproxy]`).
8. **Home paths:** a user whose directory home is below a missing automount root:
   GNOME and xrdp logins refused with the *parent ... missing* line, nothing created
   on local disk; with `fastrdp_autofs: sssd` and a directory map the home mounts; with
   `fastrdp_sssd_override_homedir: /home/%u` a new user gets `/home/<user>` (0700, skel)
   at the first GNOME login.

## Changes in this repository

- `broker/brokerd/fastrdp_broker/identity.py`: `read_desktop_pref` treats every
  `OSError` (also from `fstat`/`read`) as "no preference" and closes the descriptor;
  `hinted_desktop` split out; `choose_desktop(..., pref=)` takes a preference read by
  the caller.
- `broker/brokerd/fastrdp_broker/server.py`: `Broker.read_desktop_pref` /
  `Broker.choose_desktop` read the file in a dedicated 4-thread pool with
  `asyncio.wait_for` (a hung NFS read blocks at most that pool, never the event loop or
  the PAM threads); used by `login` and `web_desktops`. A client hint naming an
  allowed desktop skips the read.
- `broker/brokerd/fastrdp_broker/config.py`: `[broker] home_read_timeout` (seconds,
  default 3, `0` = never read homes, 0..60).
- `broker/brokerd/tests/test_home_access.py`: unreadable home (mode 000), `open`
  errors (`EACCES`, `EPERM`, `EKEYEXPIRED`, `EIO`, `ESTALE`), `read`/`fstat` errors,
  a hanging read (login answers within the limit, the event loop keeps running, the
  web chooser too), timeout `0`, config validation.
- `ansible/roles/identity`: `fastrdp_nfs_krb5_homes`, `fastrdp_nfs_gssproxy_keytab`,
  `tasks/nfs_krb5.yml`, templates `gssproxy-nfs-client.conf.j2`, `nfs-gssd.conf.j2`,
  handlers; rendered and checked in `tests/ansible/` (`NfsKrb5Homes`).
- `broker/brokerd/fastrdp_broker/tgt.py`, `server.py` (`Broker.require_credential`,
  `Broker.session_tgt`), `pamauth.py` (`establish_credentials`), `sysutil.py`
  (`run_dropped`), `backends/base.py`/`xrdp.py` (`obtains_tgt`), `config.py`
  (`[broker] session_tgt`), `broker/session/pam/fastrdp-tgt` (installed by role
  `broker` and package `fastrdp-broker`); Ansible `fastrdp_session_tgt` (role
  `common`). Tests: `broker/brokerd/tests/test_session_tgt.py`.
- `backends/gnome.py`: `systemctl --user --runtime enable` (test in
  `test_gaps.BackendTests.test_gnome_start`).
- `ansible/roles/identity`: `sssd-fastrdp.conf.j2` → `/etc/sssd/conf.d/50-fastrdp.conf`,
  `renew_lifetime` in `krb5-fastrdp.conf.j2`, variables in `sssd-ad.conf.j2`, handler
  `Restart sssd-kcm`; rendered and checked in `tests/ansible/` (`TicketRenewal`).
- `broker/brokerd/fastrdp_broker/home.py`, `server.py` (`Broker.login`), `config.py`
  (`[broker] home_check`), `sysutil.py` (`describe`, `summarize`: back-end errors name
  the command and its meaningful stderr lines): [Where homes are](#where-homes-are).
  Tests: `broker/brokerd/tests/test_home_dir.py`. Ansible
  `fastrdp_sssd_override_homedir`, `fastrdp_autofs` and `fastrdp_home_create_roots` (role `common`, checked there; the
  last one rendered as `[broker] home_create_roots`), `fastrdp_autofs_ipa_location`,
  `roles/identity/tasks/autofs.yml`, handler `Restart autofs`; rendered and checked in
  `tests/ansible/` (`HomeDirectories`); preflight check *home directories*.
