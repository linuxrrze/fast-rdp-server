# Windows hosts as back-end (research, not implemented)

**Status: deferred, not implemented** (backlog [B1](../backlog.md#back-ends)). This page
keeps the research from 2026-10-22 so the feature can be picked up later. Code
references are to fastrdp 0.7.0 and the vendored FreeRDP 3.32.2 (paths inside the
FreeRDP source tree are marked `FreeRDP:`); re-check them before implementing.
Items marked *[unverified]* were not confirmed in code or a lab.

## Idea

Put fastrdp's front-end (proxy + module + broker, with all MFA modes, the waiting
screen and the QR approval) in front of **real Windows RDP hosts** (Windows 10/11,
Windows Server, AD-joined or standalone). The client connects to fastrdp, passes the
second factor, and the proxy then connects to the Windows host with the user's own
credentials ("password relay"). Value: MFA for unmodified mstsc and the Windows App
without an agent on the hosts, without RD Gateway and without an Entra licence.

## Feasibility

**Short answer:** yes for every login in which the proxy learns the user's password;
no for logins without one (see the table below).

### Credentials towards the Windows host

- The module already replaces username, password, domain and NLA/TLS with what the
  broker returns, in `ClientPreConnect` (`broker/proxy-module/fastrdp_plugin.c`
  around line 2076–2131). The broker already receives the user's password when the
  client delegated one (`backends/base.py`, `req.password`).
- A Windows driver would return `Target(username=user, password=req.password,
  domain=<AD domain>, security="nla")`.
- Required change: the back-end authentication package list is hard-coded to
  `"!kerberos"` (NTLM only, `fastrdp_plugin.c` around line 2127). AD hosts need
  Kerberos (SPN `TERMSRV/<fqdn>`, so the proxy must reach a KDC) with NTLM as
  fallback, chosen per target. WinPR can get a TGT from a password
  (`FreeRDP: winpr/libwinpr/sspi/Kerberos/krb5glue_mit.c`).

### Which front-end logins carry a password

From [auth-matrix.md](../auth-matrix.md):

| Front-end login | Password available for the Windows host? |
|---|---|
| NLA/Kerberos with a typed password (mstsc, xfreerdp, Remmina) | yes |
| mstsc SSO with "Allow delegating default credentials", no Credential Guard | yes |
| mstsc SSO with Credential Guard (Win11 22H2+ Enterprise default) | mstsc prompts and delegates the typed password → yes |
| TLS with password (+ OTP) in one field | yes |
| Linux SSO (`/p` empty) | no |
| Smartcard | no |
| `/restrictedAdmin`, `/remoteGuard` | no |
| Web/OIDC path (Guacamole) | no |

Options when there is no password:

- **Restricted Admin + S4U2Self/S4U2Proxy to `TERMSRV/<host>`:** CredSSP with empty
  `TSPasswordCreds` is a network logon on the host; the broker would obtain the ticket
  through constrained delegation, as gssproxy does for NFS
  ([nfs-kerberos-homes.md](../nfs-kerberos-homes.md)). Limits: the user must be a
  local administrator, `DisableRestrictedAdmin=0` on the host, the session has no
  network identity (acts as `HOST$`), Protected Users are excluded, and the proxy's
  account needs delegation rights to `TERMSRV/*`. Whether WinPR's client sends
  Restricted Admin with an S4U ccache: *[unverified]*. Admin-only; later at best.
- **Remote Credential Guard:** impossible. Tickets are bound to the proxy's own
  `TERMSRV`; Microsoft supports RCG only for direct connections
  ([MS: supported configurations](https://learn.microsoft.com/en-au/windows-server/remote/remote-desktop-services/rds-vdi-supported-config)).
- **Smartcard:** impossible without giving up NLA termination at the proxy (end-to-end
  PKINIT with the redirected card); the proxy's own smartcard emulation uses one
  proxy-held certificate and is built off (`FreeRDP: server/proxy/CMakeLists.txt`).
- **Back-end without NLA + autologon via Client Info:** still needs the password and
  weakens the host. Not useful.
- **Entra ID (AAD) RDP authentication:** impossible through a terminating proxy
  ([windows-clients.md](../windows-clients.md)). Entra-only accounts are out of scope.

### Host certificate

- Per-target SHA-256 pinning exists (`fastrdp_plugin.c` around line 2112–2122,
  `proxy.ini.j2` `CertificatePolicy=deny`).
- Windows' self-signed RDP certificate is renewed about every six months
  *[inferred]*, which breaks pins. Use certificates from an AD CS template and add CA
  + hostname validation per target.

### Licensing

- The proxy is the RDP client; FreeRDP derives the licence hardware id from
  `ClientHostname`, which is copied from the front client
  (`FreeRDP: libfreerdp/core/license.c`).
- RDS session hosts need CALs; Per-User mode is the safe choice. Per-Device CAL
  behaviour through the proxy: *[unverified]*. Windows 10/11 desktops need no CALs.

### Channels

- Generic static and dynamic channel passthrough is on (`PassthroughIsBlacklist=true`
  with an empty list, `proxy.ini.j2`): GFX/H.264/AVC444 (bytes passed through, no
  re-encode), clipboard, audio, drives (rdpdr is parsed by the proxy), display control,
  multi-monitor (`FreeRDP: server/proxy/pf_client.c`, `pf_server.c`).
- Smartcard redirection into the session, WebAuthn (`WebAuthN_Channel` DVC, see
  [webauthn-redirection.md](../webauthn-redirection.md)) and USB (URBDRC) should pass
  *[unverified]*.
- RemoteApp is off in fastrdp ([backlog A2](../backlog.md#sessions)).

### Reconnect, load balancing, redirection

- The proxy forwards Save Session Info including auto-reconnect cookies from the
  back-end (`FreeRDP: server/proxy/pf_update.c`) and enables auto-reconnect on its
  client side (`pf_client.c`). Whether a client's ARC cookie works on a new proxied
  connection: *[unverified]*. fastrdp's `reconnect_grace` covers the MFA side.
- fastrdp clears `LoadBalanceInfo` (`fastrdp_plugin.c` around line 2111) and refuses
  Server Redirection PDUs from back-ends (around line 2177–2184). Stock
  freerdp-proxy follows them (`pf_client.c`, `FreeRDP: libfreerdp/core/connection.c`
  `rdp_client_redirect`). RD Connection Broker farms need either an allow-listed
  "follow redirect" mode or the broker targeting session hosts directly.

### Transport

TCP only: no UDP transport (MS-RDPEMT, [performance.md](../performance.md)) and no
RD Gateway front-end (MS-TSGU, [windows-clients.md](../windows-clients.md)).
Off-network users need a VPN, the KDC proxy plus TLS, or rdpgw in front
([backlog K12](../backlog.md#kerberos-tickets-in-sessions)).

## What would have to be built

Broker:

- New driver `backends/windows.py`: static map user/group → targets (FQDN, port,
  certificate pin or CA, domain, `security`, auth packages, optionally
  `allow_restricted_admin`); TCP/TLS health check; optional least-sessions placement
  (`qwinsta`/WMI).
- Refuse logins without a password with a clear reason (or the Restricted Admin +
  S4U path, later).
- Skip the xrdp/Linux-specific parts for these targets: `ensure()` session start,
  desktop picker and desktop hints, one-time tokens and per-session secrets,
  `session_tgt`/keytab/`fastrdp-tgt` (Windows gets its own TGT from the password),
  connection-type/encoder profiles (`apply_connection_type`), the loopback listener
  ownership check, home-directory checks.

Proxy module (vendored, fastrdp-only patches if FreeRDP needs changes):

- Per-target auth package list (Kerberos + NTLM), CA chain + hostname validation,
  optional redirect following for allow-listed hosts.
- Everything else is reusable as it is: MFA, waiting screen/QR, Set Error Info, secret
  wiping.

Ansible/docs: target map variables, firewall checklist for the Windows hosts, GPO
hints (NLA required, RDP only from the proxy), certificate template.

## Security

- **The Windows hosts must accept 3389 only from the proxy** (host firewall via GPO
  plus network ACL). Otherwise anyone with the password connects directly and MFA is
  bypassed. Same for RD Gateway, WinRM and SMB access with the same password.
- MFA protects only RDP; other services that accept the password (mail, VPN, file
  shares) are not covered.
- Keep NLA required on the hosts, so a host never shows its logon UI before
  authentication.
- The proxy sees every user's domain password in clear text: treat it as a
  tier-0-adjacent system (hardening, monitoring, no other workloads).
- Restricted Admin, Remote Credential Guard and Credential Guard SSO protections end
  at the proxy, not at the Windows host.
- An S4U path would give the proxy's account constrained delegation to `TERMSRV/*`,
  a powerful right.

## Alternatives (state 2026-10)

| Option | Where MFA happens | Unmodified mstsc? | Cost / licence |
|---|---|---|---|
| privacyIDEA Credential Provider ([docs](https://privacyidea-credential-provider.readthedocs.io/)) | agent on each host | yes (NLA supported) | open source (Apache 2.0) |
| multiOTP Credential Provider ([GitHub](https://github.com/multiOTP/multiOTPCredentialProvider)) | agent on each host | yes | open source (Apache 2.0) |
| Duo for Windows Logon & RDP ([Duo](https://duo.com/docs/rdp-faq)) | agent on each host | yes | paid |
| RD Gateway + NPS extension ([MS](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-nps-extension-rdg)) | gateway, Entra push via RADIUS | yes | Entra ID P1 |
| rdpgw ([GitHub](https://github.com/bolkedebruin/rdpgw)) | OIDC in the browser, then a short-lived `.rdp` | yes | open source |
| Guacamole + TOTP/OIDC | web front-end | no (browser) | open source |
| Cloudflare Access browser RDP | Access SSO | no (browser) | SaaS |
| Teleport desktop access | Teleport SSO, virtual smartcard to AD | no (browser/tsh) | open core |
| Pomerium, HashiCorp Boundary | OIDC before the tunnel / credential injection | no (helper client) | open source + enterprise / enterprise |
| Devolutions Gateway | Devolutions Server/Hub, credential injection | RDM/web | mostly commercial |
| Entra-joined hosts with FIDO2 / Windows Hello | Entra auth on the host | yes (`enablerdsaadauth`) | not proxyable |

Host agents are the cheapest real competitors; their weak points are that MFA runs
after the host already has the password, smartcard/SSO paths vary, and every host
needs the agent. Inuvika and OpenRDP were not looked at.

## Proposed scope if picked up

MVP, about 8–12 person-days plus 3–5 days of lab work:

1. Static per-group target map with health check.
2. Kerberos and NTLM NLA towards the host with the delegated or typed password.
3. Per-target certificate pin or CA validation.
4. Logins without a password refused with a clear error.
5. Back-end redirects stay refused.
6. Firewall checklist and docs.

Out of scope: smartcard, Remote Credential Guard, Entra ID, Connection Broker farms,
UDP.

Later: Restricted Admin + S4U for administrators without a password (about 5–8 days,
high risk); allow-listed redirect following for RDS farms (about 3–5 days).

Main risks: clear-text domain passwords on the proxy; bypass through incomplete host
firewalling; Credential Guard SSO users get prompted; certificate pin rotation; CAL
accounting; auto-reconnect behaviour; the Windows App on macOS/iOS/Android needs
Kerberos or TLS + OTP to reach the front.

## Lab checks before implementing

1. mstsc and the Windows App through the proxy: Kerberos, then NTLM, to Windows 11
   and Server 2022/2025 (AD-joined and standalone).
2. GFX/AVC444, multi-monitor, drives, clipboard, audio, smartcard in the session,
   WebAuthn, USB.
3. Network drop: auto-reconnect cookie vs. a fresh login, with `reconnect_grace`.
4. RDS session host with Per-User and Per-Device CALs.
5. Certificate pin behaviour across the Windows self-signed certificate renewal.
6. Restricted Admin with an S4U ccache.
7. Domain with NTLM disabled.
