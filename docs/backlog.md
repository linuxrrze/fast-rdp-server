# Backlog

Open improvements that are not scheduled yet. Each item says what it would change, why,
and roughly what it costs. Done items move to the docs they changed.

## Kerberos tickets in sessions

Background: how sessions get a TGT today ([auth-matrix.md](auth-matrix.md#kerberos-tgt-per-back-end)),
Kerberized NFS homes ([nfs-kerberos-homes.md](nfs-kerberos-homes.md)), Windows for
comparison ([windows-clients.md](windows-clients.md) §3.12).

| # | Item | Benefit | Effort / risk |
|---|---|---|---|
| K1 | **TGT in the GNOME/Plasma session environment.** **Status: analysed and fixed, host validation pending.** Analysis (sssd, MIT krb5, xrdp sources): our sssd configs set no `krb5_ccname_template`, so sssd follows `default_ccache_name = KCM:`; KCM is per uid; xrdp exports pam_sss's `KRB5CCNAME=KCM:`, GDM autologin and `fastrdp-plasma@` set none, so every back-end and the user manager use the same KCM collection. Fixed: the broker checks the default cache (the session's view), refuses a FILE cache from an sssd template, and makes the login's cache primary (`kswitch`) when another principal is primary (sssd switches only for new caches); the identity role restarts sssd when the Kerberos config changes; diagnostic `tests/smoke/check-session-tgt.sh`. Open: run it as root (`sudo tests/smoke/check-session-tgt.sh -s HTTP/… -s cifs/… USER`) and in a session terminal for xfce, a wlroots desktop, gnome and plasma | No "the TGT exists but applications don't see it" | host validation only |
| K9 | **Snap and Flatpak applications cannot use KCM.** Ubuntu's Firefox snap: snapd's `kerberos-tickets` interface only allows `/tmp/krb5cc*` FILE caches and is not auto-connected, so SPNEGO in snap Firefox does not find the session TGT [inferred]; Flatpak likely the same. Options: document a .deb Firefox (Mozilla APT repository) for Kerberos SSO, or check the interface on 26.04 | Intranet SSO from the browser in sessions | small (docs), verify on a host |
| K2 | **Ticket visibility.** **Status: done, host check pending.** `fastrdpctl status` lists each session user's TGT from the default credential cache (broker `tickets.py`: `klist -f`/`-l` as the user without `KRB5CCNAME`, `LC_ALL=C TZ=UTC`, 5 s timeout): principal, cache, expiry and renew-until (UTC, time left) and a state `ok` / `expiring` (< 1 h) / `not_renewable_soon` (not renewable or renewal ends within 24 h) / `expired` / `none` / `unknown`, metadata only; `--json` gives the raw reply; `fastrdpctl tickets [USER]` also for accounts without a session (root only). `tests/smoke/check-host.sh` checks sssd-kcm, the effective `[kcm] tgt_renewal = true` and `krb5_renew_interval`, `renew_lifetime`, and with a test user that the TGT is renewable. Open: real `klist` output on Debian 13 / Ubuntu 26.04, renewal moving the expiry forward | Operators see who is about to lose Kerberos access | host check only |
| K3 | **SMB/CIFS homes with gssproxy.** A `multiuser,sec=krb5` CIFS mount (static or autofs) with `cifs.upcall` using `GSS_USE_PROXY=yes`, a second gssproxy service for `cifs.upcall`, `cifs/<fileserver>` in the constrained-delegation targets (`msDS-AllowedToDelegateTo` or RBCD). Same S4U design as for NFS (`fastrdp_nfs_krb5_homes`) | SMB homes and shares work with the user's identity without a password: SSO, smartcard, web, Remote Credential Guard identity-only | medium; lab with Samba and Windows file servers; check the cifs-utils versions of Debian 13 / Ubuntu 26.04 (older ones needed a patched `cifs.upcall`) |
| K4 | **Sessions longer than the renewable lifetime** (`krb5_renewable_lifetime`, default 7 days). A desktop notification before the TGT can no longer be renewed ("lock and unlock" / "reconnect"); verify that a reconnect with a password renews the TGT on GNOME/Plasma as on xrdp; or S4U (gssproxy) as the default for long-running sessions | Long terminal-server sessions do not silently lose NFS/SMB access (Windows re-acquires from a cached password key; fastrdp cannot) | small to medium |
| K5 | **`session_tgt` per group.** E.g. `required` for members of a group with Kerberized homes, `auto` for everyone else (broker `[broker] session_tgt` today applies to all users) | Clear refusal for users who need a TGT, no impact on others | small (broker, config, role) |
| K6 | **KDC proxy (MS-KKDCP) on the web gateway.** `python-kdcproxy` behind the existing nginx; client docs for FreeRDP (`/kerberos:kdc-url:`) and Windows (KDC proxy GPO) | Kerberos NLA from outside the network without VPN (today: TLS logins as fallback) | medium |
| K7 | **Remote Credential Guard phase 1 (opt-in).** Store the full TGT that FreeRDP clients forward with `/remoteGuard` (unencrypted KRB-CRED, verified) in the user's KCM after checks (client principal = NLA principal, krbtgt server, FORWARDED flag, lifetime); mstsc-style credentials stay identity-only | Linux FreeRDP users with `kinit -f` get a session TGT without delegating a password | 6–10 days; this is unconstrained delegation (root on the host can use the TGT for any service until it expires); a future FreeRDP may encrypt the KRB-CRED or make the key opaque. Phases 0a/0b are done ([rdp-spec-conformance.md](rdp-spec-conformance.md) R4) |
| K8 | **Windows lab tests S2 / L6.** mstsc `/remoteGuard`: the error dialog without `AcceptRemoteGuard`, an identity-only login with it, whether mstsc sends `supplementalCreds`, the GPO "Remote Credential Guard or Restricted Admin" case; Credential Guard and `/restrictedAdmin` behaviour ([windows-clients.md](windows-clients.md) §7) | Confirms the RCG phases and the Windows documentation | Windows lab only |

## Host safety in RDP sessions

| # | Item | Benefit | Effort / risk |
|---|---|---|---|
| H1 | **Prevent shutdown, reboot, suspend and hibernate from RDP sessions.** Investigate what a user in each session type can do today: logind's polkit actions `org.freedesktop.login1.{power-off,reboot,suspend,hibernate,halt}` and their `-multiple-sessions` / `-ignore-inhibit` variants (defaults: `allow_active` = yes for an *active local* session, otherwise `auth_admin_keep`); whether xrdp, GNOME headless and Plasma headless sessions count as active/local for polkit (GNOME headless sessions are created by GDM, possibly on a seat). Then: a polkit rule from the roles that refuses these actions for users who are not admins (or for every non-local session: `subject.local`, `subject.active`, `subject.session`), hide the menu entries (GNOME `org.gnome.desktop.lockdown` / `disable-log-out` semantics vs. power off, XFCE and MATE kiosk/action settings, KDE kiosk `[KDE Action Restrictions]`, wlroots launchers), and keep log out working. Also check `systemctl poweroff` from a terminal and the `-ignore-inhibit` paths | One user cannot shut down or reboot the shared host for everyone | small to medium; must not lock out the console admin (rule by group, e.g. allow `sudo`/admin group); test per desktop on a lab host |

Not planned (evaluated):
- **Kerberos delegation inside NLA** (`GSS_C_DELEG_FLAG`, forwarded TGT in the
  AP-REQ): unconstrained delegation, needs WinPR patches on both sides, and mstsc
  does not request it ([nfs-kerberos-homes.md](nfs-kerberos-homes.md) Q5b).
- **Full Remote Credential Guard for mstsc** (server-side MS-RDPEAR, a Kerberos client
  whose TGT key stays on the client): about 80–150 person-days, no open-source
  implementation to build on, and MIT krb5/KCM cannot use remote-held keys. Revisit
  only if a Windows lab shows cleartext service-ticket keys from mstsc or FreeRDP gains
  a server-side RDPEAR.
