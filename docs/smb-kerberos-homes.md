# Home directories and shares on SMB/CIFS with Kerberos (`sec=krb5`)

Can sessions use an SMB home or share (Windows file server, Samba) with the user's
own identity when the login carried no password?

**Short answer:** yes, with the same design as for Kerberized NFS
([nfs-kerberos-homes.md](nfs-kerberos-homes.md), Q5a): a `multiuser,sec=krb5` CIFS
mount, `cifs.upcall` asking **gssproxy** when the user has no TGT, and gssproxy
obtaining `cifs/<server>` tickets by **impersonation** (S4U2Self + S4U2Proxy) with
the host keytab. The KDC must allow constrained delegation from the RDP host to
`cifs/<server>`. fastrdp ships the client side as an opt-in Ansible option,
`fastrdp_smb_krb5_homes`; the delegation is a directory admin task (below).
Users whose login carried a password (NLA with a delegated password, TLS) have a TGT
and keep using it, as without gssproxy.

This page is based on reading the code; it has **not** been tested against real file
servers yet, see [Lab test plan](#lab-test-plan). **[verified]** = checked in the
source (versions below), **[inferred]** = follows from the code, needs a lab run.

Sources read: cifs-utils 7.4 (Debian 13 `2:7.4-1` and `2:7.4-1+deb13u1`, Ubuntu
26.04 `2:7.4-1ubuntu0.26.04.4` with its patches), 7.0, 6.15 and 6.14 release
tarballs; gssproxy 0.9.2 (Debian 13); keyutils 1.6.3 (`request-key.c`); Linux 6.12
`fs/smb/client/cifs_spnego.c` and `connect.c`.

## Support matrix

"Works" means that the session can read and write the SMB home or share.

| Login method | without `fastrdp_smb_krb5_homes` | with it (delegation configured) |
|---|---|---|
| NLA with a delegated password, TLS (xrdp; GNOME/Plasma with `fastrdp_session_tgt: auto`) | **works** (the user's TGT) [inferred] | **works** (the user's TGT; gssproxy not asked) [inferred] |
| NLA Kerberos SSO without delegation, smartcard, web | **fails** (no credentials) | **works** [inferred] |
| Remote Credential Guard, identity only (`fastrdp_accept_remote_guard: true`) | **fails** | **works** [inferred] |
| Accounts the KDC refuses to impersonate (AD "Protected Users", "sensitive and cannot be delegated"; FreeIPA outside the rule) | as above | only with a typed password |

## Versions

| Distribution | cifs-utils | `cifs.upcall` GSSAPI fallback + `GSS_USE_PROXY` | gssproxy |
|---|---|---|---|
| Debian 13 (trixie) | `2:7.4-1`, security update `2:7.4-1+deb13u1` (2026-10-14) | yes [verified] | 0.9.2-3 |
| Ubuntu 26.04 (resolute) | `2:7.4-1build1`, updates `2:7.4-1ubuntu0.26.04.4` | yes [verified] | 0.9.2 |
| Debian 12, Ubuntu 24.04 | 7.0 | yes [verified] (not supported by fastrdp) | 0.9.1 |
| Ubuntu 22.04 | 6.14 | **no** (needed a patched `cifs.upcall`) [verified] | |

- The fallback was added in **cifs-utils 7.0**: `cifs_gss_get_req()` and the
  `GSS_USE_PROXY="yes"` entry in `cifs.upcall(8)` ("keytab based client initiation as
  well as (Resource Based) Constrained Delegation") are in the 7.0 tarball and in
  neither 6.15 nor 6.14 [verified]. Debian's and Ubuntu's own patches (`fPIE`,
  spelling) do not touch it.
- **CVE-2026-12505 (cifs.upcall uid lookup):** upstream fixed it in two commits,
  `972c5b5` "remove getpwuid() dependency" and `70bb0f8` "fix regression with krb5 +
  creduid". Ubuntu 26.04 has both since `0.26.04.3` (`0.26.04.1` had only the first and
  broke Kerberos mounts, LP: #2159053; `0.26.04.2` disabled it). Debian 13's
  `+deb13u1` has **only the first** [verified in its `cifs.upcall.c`]: it replaces
  the uid from the key (`creduid`) with the real uid of the process that triggered the
  upcall. For the sessions here that is the same user, but an upcall from a kernel
  thread (reconnect) or a setuid process would get root's credentials (the host's)
  [inferred]. Preflight warns about this version; use the follow-up update as soon as
  Debian ships it, and test reconnects in the lab.

## How it works

1. **The mount** (static in `/etc/fstab`, or autofs) is done by root with
   `sec=krb5,multiuser`. Root's upcall (`cruid` defaults to the mounting uid, 0) finds
   no TGT in root's cache, so `cifs.upcall` calls GSSAPI; gssproxy sees uid 0 =
   `euid`, the service is `trusted`, no name is asked for, so it uses the keytab's
   first principal: the **mount authenticates as the host** (AD `RDP1$`, FreeIPA
   `host/rdp1...`) [verified gssproxy `gp_creds.c:350-357`, inferred result]. Root's
   accesses to the mount (the broker's home check) use this session.
2. **multiuser:** every other uid that touches the mount gets its own SMB session.
   The kernel does not pass a user name for these Kerberos sessions (`connect.c:4030`
   "krb5 is special"), only `creduid=<fsuid>` in the key description
   (`cifs_spnego.c:119-157`) [verified]. Files show the accessing user as owner and the
   server enforces permissions (`multiuser` implies `noperm`, `mount.cifs(8)`).
3. **The upcall:** request-key runs
   `/usr/bin/env GSS_USE_PROXY=yes /usr/sbin/cifs.upcall %k`
   (`/etc/request-key.d/fastrdp-cifs.spnego.conf`). `cifs.upcall` switches to the
   user (`setuid`, capabilities dropped, `cifs.upcall.c:1585-1592`), looks for the
   user's ccache (`KRB5CCNAME` of the triggering process, else `default_ccache_name`,
   `KCM:`) and uses a valid TGT natively (`:1604-1617`). Without a TGT it calls
   `gss_init_sec_context` for `cifs@<server>` with no credential (`:951-963`,
   `cifs_gss_get_req` `:829`) [verified].
4. **gssproxy:** the interposer (`/etc/gss/mech.d/proxymech.conf`, Debian builds with
   `REMOTE_FIRST`) sends the call to `/var/lib/gssproxy/default.sock`. gssproxy
   matches the service by `allow_any_uid` and `program = /usr/sbin/cifs.upcall`
   (`gp_creds.c:74-95`), and because the peer uid differs from `euid` and
   `impersonate = yes`, it maps the uid to its name (`getpwuid`) and impersonates
   `<name>@<default_realm>` (`:336-385`): S4U2Self with the host keytab, then
   S4U2Proxy to `cifs/<server>` [verified code path, inferred result]. The KDC
   decides.
5. The kernel gets the AP-REQ and session key and sets up the user's SMB session.

Why a second gssproxy service and not the NFS one: rpc.gssd's service has
`program = /usr/sbin/rpc.gssd`; gssproxy refuses two `allow_any_uid` services with
the same socket, program and SELinux context (`gp_config.c:274-292`), so different
programs on the default socket are fine, which is also gssproxy's own recipe
(`docs/network_fs_clients.md`) [verified]. Separate impersonated caches
(`krb5cc_smb_%U`) keep rpc.gssd's and cifs.upcall's tickets apart.

Why the request-key line wins over cifs-utils' own: Debian installs
`/etc/request-key.d/cifs.spnego.conf` (`create cifs.spnego * * /usr/sbin/cifs.upcall %k`).
request-key reads every `*.conf` there in directory order and keeps the line whose
wildcards skip the fewest characters (`request-key.c:298-327`, `:430-460`, `match()`
`:479-542`); ties go to the first one read. fastrdp's line matches the description
with `ver=0x*` (the kernel's descriptions start with `ver=0x2;`), so it is always
less wild than `*` and wins without editing the package's conffile [verified].
request-key starts the program with `execv` and cannot set variables, hence `env`;
`GSSPROXY_SOCKET` is not needed (default socket).

## What `fastrdp_smb_krb5_homes: true` installs

Role `identity`, `tasks/smb_krb5.yml`:

- packages `cifs-utils`, `keyutils`, `gssproxy`; refuses cifs-utils older than 7.0
  and a missing `fastrdp_smb_gssproxy_keytab` (default `/etc/krb5.keytab`);
- `/etc/gssproxy/91-fastrdp-smb-client.conf`:

  ```ini
  [service/fastrdp-smb-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_smb_%U
  cred_usage = initiate
  allow_any_uid = yes
  impersonate = yes
  trusted = yes
  euid = 0
  program = /usr/sbin/cifs.upcall
  ```

- `/etc/request-key.d/fastrdp-cifs.spnego.conf`:

  ```
  create  cifs.spnego  ver=0x*  *  /usr/bin/env GSS_USE_PROXY=yes /usr/sbin/cifs.upcall %k
  ```

- gssproxy enabled and (re)started;
- optional static mounts, `fastrdp_smb_mounts`, in a marked block of `/etc/fstab`,
  then `systemctl daemon-reload` and the `.automount` units started:

  ```yaml
  fastrdp_smb_krb5_homes: true
  fastrdp_smb_mounts:
    - {what: //fs1.example.com/users$, where: /smb/users}
    - {what: //fs1.example.com/projects, where: /smb/projects, options: "vers=3.1.1,seal"}
  ```

  ```
  //fs1.example.com/users$ /smb/users cifs sec=krb5,multiuser,nosuid,nodev,_netdev,nofail,x-systemd.automount,x-systemd.after=gssproxy.service 0 0
  ```

  `options` are appended (no spaces; `sec=krb5i` replaces `sec=krb5`, other `sec=`
  values are refused). Changed options apply after the share is unmounted (reboot or
  `systemctl stop <unit>.mount`). The server name must be the FQDN of the `cifs/`
  principal (cifs.upcall asks for `cifs/<name as given, lower case>`). An empty list
  removes the block; turning the option off leaves the files in place (like NFS).

The keytab: as for NFS, gssproxy uses the **first** principal in the keytab; check
`klist -k /etc/krb5.keytab | head` (AD: `RDP1$@REALM`, FreeIPA: `host/rdp1...`), or
build a keytab with only that principal and set `fastrdp_smb_gssproxy_keytab`.

## Directory configuration (delegation to `cifs/<server>`)

Add `cifs/<server>` for every SMB server users need without a password (homes and
group shares), next to `nfs/` entries if any. Choose one model:

- **Active Directory, classic constrained delegation with protocol transition**
  ("Trust this computer for delegation to specified services only" + "Use any
  authentication protocol", service type `cifs`):
  ```powershell
  Set-ADComputer RDP1 -Add @{'msDS-AllowedToDelegateTo'=@('cifs/fs1.example.com','cifs/FS1')}
  Set-ADAccountControl -Identity 'RDP1$' -TrustedToAuthForDelegation $true
  ```
  `cifs/` is an alias of `HOST/` on Windows servers (`sPNMappings`); the delegation
  entry still names `cifs/...` [inferred: the GUI writes it this way].
- **Active Directory, resource-based (RBCD)**, on the file server's account; no flag
  on the RDP host; works across domains and for Samba file servers joined to AD
  [inferred]:
  ```powershell
  Set-ADComputer FS1 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer RDP1)
  ```
  For a cluster or DFS namespace, set it on every account whose `cifs/` name clients
  use.
- **Samba AD DC:** `samba-tool delegation add-service 'RDP1$' cifs/fs1.example.com`,
  `samba-tool delegation for-any-protocol 'RDP1$' on`.
- **FreeIPA** (Samba file server enrolled with `ipa-client-samba`, principal
  `cifs/fs1.ipa.example.com`):
  ```sh
  ipa servicedelegationtarget-add smb-homes
  ipa servicedelegationtarget-add-member smb-homes --principals=cifs/fs1.ipa.example.com@IPA.EXAMPLE.COM
  ipa servicedelegationrule-add rdp-to-smb-homes
  ipa servicedelegationrule-add-member rdp-to-smb-homes --principals=host/rdp1.ipa.example.com@IPA.EXAMPLE.COM
  ipa servicedelegationrule-add-target rdp-to-smb-homes --servicedelegationtargets=smb-homes
  ipa host-mod rdp1.ipa.example.com --ok-to-auth-as-delegate=true
  ```
  An existing NFS rule can take the `cifs/` principal as another target member. RBCD
  instead: `ipa service-add-delegation cifs/fs1.ipa.example.com host/rdp1.ipa.example.com`.

File servers need nothing special: a Kerberos ticket obtained by S4U2Proxy looks like
any other user ticket. Windows file servers authorize by the user's SID; Samba by
its usual id mapping (winbind or sssd on the file server).

## Where SMB homes come from

Linux sessions use the home path that NSS reports, never a UNC path:

- **AD:** `homeDirectory` + `homeDrive` (`\\fs1\users$\alice`, `H:`) are for Windows
  logons; sssd uses `unixHomeDirectory` (else `fallback_homedir = /home/%u`). To give
  Linux sessions the same directory, mount the share and point the home at it,
  either per user in AD (`unixHomeDirectory: /smb/users/alice`) or for everyone with
  `fastrdp_sssd_override_homedir: /smb/users/%u`, which matches the usual
  `\\fs1\users$\%username%` layout:
  ```yaml
  fastrdp_smb_krb5_homes: true
  fastrdp_smb_mounts: [{what: //fs1.example.com/users$, where: /smb/users}]
  fastrdp_sssd_override_homedir: /smb/users/%u
  ```
- **One share per user** (or homes on several servers): autofs, `fastrdp_autofs:
  files` with your map, e.g.
  ```
  # /etc/auto.master.d/smb.autofs
  /smb/home  /etc/auto.smbhome  --timeout=600
  # /etc/auto.smbhome
  *  -fstype=cifs,sec=krb5,multiuser,nosuid,nodev  ://fs1.example.com/users$/&
  ```
  or directory maps with `fastrdp_autofs: sssd` and the same entry in the directory.
  autofs mounts as root (`cruid` 0, the host's credentials as in step 1); the user's
  own session follows on first access.
- **FreeIPA:** `homeDirectory` is a POSIX path already; point it at the mount (or use
  `fastrdp_sssd_override_homedir`).

**The broker's home check** ([nfs-kerberos-homes.md](nfs-kerberos-homes.md#where-homes-are))
treats `cifs`/`smb3` as a network file system: it never creates a home there
(provision homes on the file server, as Windows does with the "Home folder" field or
a script). Root's look at the home goes through the host's SMB session: if the host
may not see it (`EACCES`) the check is skipped; if it sees it, the home appears owned
by root and the broker runs `test -w` as the user, which already sets up the user's
own SMB session (`multiuser` reports it writable without asking the server, so this
does not prove the delegation) [inferred]. A missing home is refused with the usual
*does not exist ... the broker does not create it* line.

## Security implications

As for NFS (Q5a there): root on the RDP host, or anyone who can read the keytab, can
reach the listed SMB servers as **any** user; keep the delegation to the file servers
users need, never "any service" (unconstrained). The uid → principal mapping is by
**name** (`getpwuid`): a local account named like a directory user is that user on
the file server. `program =` filters which binary may use the service, it is not a
boundary: any local user can run `cifs.upcall` (it is not setuid) and so obtain, as
themselves only, tickets to the delegation targets, which the mount gives them anyway.
Admin accounts belong in AD "Protected Users" or "Account is sensitive and cannot be
delegated". With `fastrdp_sssd_fully_qualified_names: true` the user name is
`alice@example.com`, which gssproxy imports as a principal in the realm
`example.com`; untested, use short names or test it (preflight warns).

Without `fastrdp_smb_krb5_homes` nothing changes: cifs.upcall then uses only the
user's own TGT, and the gssproxy interposer falls back to local credentials when no
service matches.

## Preflight

`make preflight` with `fastrdp_smb_krb5_homes: true`: check *SMB homes*, FAIL when
cifs-utils (installed, else the APT candidate) is older than 7.0 or missing, gssproxy
is not available, or a server in `fastrdp_smb_mounts` does not resolve; WARN for
`2:7.4-1+deb13u1` (see Versions) and for fully qualified names. The delegation itself
can only be tested with a user (lab test plan, step 2).

## Lab test plan

Setup: AD with a Windows Server file server (`users$` share, homes with the usual
owner-only ACL) and a Samba member server; a FreeIPA domain with a Samba server
(`ipa-client-samba`); users `pw1` (password), `sc1` (smartcard), `prot1` (Protected
Users); RDP host on Debian 13 and on Ubuntu 26.04 with `fastrdp_smb_krb5_homes: true`,
`fastrdp_smb_mounts` and `fastrdp_sssd_override_homedir` as above.

1. **Client side:** `make preflight`; after deployment `systemctl status gssproxy`,
   `journalctl -u gssproxy` (no "allow_any_uid ... same socket" error);
   `readlink -f /usr/sbin/cifs.upcall` is `/usr/sbin/cifs.upcall` (gssproxy compares
   the executable's real path). Which path cifs.upcall takes is in its debug log:
   `journalctl -t cifs.upcall -p debug` shows `handle_krb5_mech: using GSS-API`
   or `using native krb5` (the user's TGT); with `debug_level = 2` in `[gssproxy]`
   (`/etc/gssproxy/gssproxy.conf`) its log says `Connection matched service
   fastrdp-smb-client` (no such line: request-key ran cifs-utils' own line, without
   `GSS_USE_PROXY`).
2. **Directory:** configure the delegation (AD CD, then AD RBCD; FreeIPA rule). As
   root: `ls /smb/users` mounts the share (host credentials; KDC event 4768/4769 for
   `RDP1$`). `sudo -u pw1 kdestroy -A; sudo -u pw1 ls /smb/users/pw1` must list the
   home (S4U2Self + S4U2Proxy, AD events 4769 with "Transited Services"); `klist -c
   /var/lib/gssproxy/clients/krb5cc_smb_<uid>`; `cat /proc/fs/cifs/DebugData` shows one
   session per uid.
3. **Logins:** for each user × back-end (xrdp, GNOME, Plasma) × method (NLA with
   password, SSO without delegation, smartcard, web, Remote Credential Guard identity
   only): the session starts, writes `~/.config`, files on the server are owned by the
   user (Windows: file owner SID; Samba: `ls -l` on the server). `prot1` fails without
   a password, works with one.
4. **Own TGT preferred:** log in `pw1` with a password; the upcall uses the user's
   KCM TGT (no new entry in `krb5cc_smb_<uid>`, AD event for `pw1` without
   S4U). `kdestroy` in the session: next new SMB session goes through gssproxy.
5. **Expiry and reconnect:** shorten ticket lifetimes; after expiry, file access
   triggers a new upcall; check **which identity** the server sees after a
   reconnect (file server restart, `ss -K` on port 445) on Debian `+deb13u1` and on
   Ubuntu `0.26.04.4` (see Versions: the reconnect may run as root on Debian).
6. **Broker home check:** home missing on the server: refused with "does not exist";
   host may not list the share (`EACCES`): login goes on; file server down: login
   answers within `home_read_timeout`; record the errno root sees when the automount
   fails (it must not be an unexpected error in the broker log).
7. **Negative:** a local account named like a directory user (expect access as that
   user: document); a program other than cifs.upcall with `GSS_USE_PROXY=yes` gets
   no impersonated credentials; NFS (`fastrdp_nfs_krb5_homes`) and SMB together on
   one host, both work; `fastrdp_sssd_fully_qualified_names: true` result.
8. **autofs variant:** `fastrdp_autofs: files` with the per-user map; repeat 2 and 3.

## Changes in this repository

- `ansible/roles/identity`: `fastrdp_smb_krb5_homes`, `fastrdp_smb_gssproxy_keytab`,
  `fastrdp_smb_mounts` (defaults), `tasks/smb_krb5.yml`, templates
  `gssproxy-smb-client.conf.j2`, `request-key-cifs-spnego.conf.j2`, `fstab-smb.j2`.
- `ansible/roles/common/tasks/main.yml`: checks of the three variables.
- `ansible/preflight.yml`: check *SMB homes*.
- Tests: `tests/ansible/render.yml`, `test_templates.py` (`SmbKrb5Homes`).
