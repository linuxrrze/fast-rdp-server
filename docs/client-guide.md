# Client guide

Always connect to the server's **FQDN** (Kerberos needs it), e.g. `rdp1.lab.example.com`.
With NLA, you are logged in as the owner of your Kerberos ticket, whatever user name
the client sends.

## FreeRDP 3 (Linux, macOS) – reference client

Check that your build can decode H.264: `xfreerdp3 /buildconfig | tr ' ' '\n' | grep GFX_H264`
must say `ON`. **Ubuntu 26.04's packages say `OFF`**: they still work, but fall
back to RFX/progressive at several times the bandwidth. See
[performance.md](performance.md).

```sh
# Kerberos NLA, desktop from server defaults, GFX/H.264 AVC444, adaptive network
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM \
    /sec:nla /auth-pkg-list:'kerberos,!ntlm' \
    /gfx:avc444 /network:auto /dynamic-resolution +clipboard

# single sign-on with the ticket from kinit or your desktop login: empty /p, no prompt
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /p \
    /sec:nla /auth-pkg-list:'kerberos,!ntlm'

# smartcard / YubiKey PIV (asks for the PIN; no /u, /d: taken from the certificate)
xfreerdp3 /v:rdp1.lab.example.com /sec:nla /auth-pkg-list:'kerberos,!ntlm' \
    /smartcard-logon /kerberos:pkcs11-module:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

# pick a desktop for this session
xfreerdp3 ... /shell:fastrdp:gnome

# outside the VPN: KDC proxy (MS-KKDCP). Give the host; FreeRDP adds https://.../KdcProxy.
# It only covers the first ticket: also put the proxy into krb5.conf (freerdp-client.md §7)
xfreerdp3 ... /kerberos:kdc-url:kdcproxy.lab.example.com

# password + OTP in one field (server must allow TLS logins); type "Secret123456" at the prompt
xfreerdp3 /v:rdp1.lab.example.com /u:alice /sec:tls /gfx:avc444
```

`sdl-freerdp3` and `wlfreerdp3` take the same options. Ubuntu 26.04 names the client
`xfreerdp`. Every login method with the exact switches, what the session gets, MFA and
error messages: [freerdp-client.md](freerdp-client.md).

## Windows Remote Desktop Connection (mstsc)

Domain-joined Windows uses Kerberos automatically. Useful `.rdp` lines:

```
full address:s:rdp1.lab.example.com
enablecredsspsupport:i:1
authentication level:i:2
use redirection server name:i:0
alternate shell:s:fastrdp:plasma
networkautodetect:i:1
bandwidthautodetect:i:1
connection type:i:7
```

- **Computer name:** the FQDN (`rdp1.lab.example.com`). The short name works on AD
  (`TERMSRV/RDP1`) and on FreeIPA (principal alias); DNS aliases only if they are in
  `fastrdp_termsrv_aliases`. An IP address never works: Windows falls back to NTLM,
  which the server refuses.
- **User name:** use the **UPN**, `alice@lab.example.com` (or your UPN suffix,
  e.g. `marcel.ritter@corp.example.com`). Windows finds the KDC from it, also on
  machines that are not domain members.
  - The server logs in the account of the **Kerberos principal** that the domain
    controller puts in the ticket (the sAMAccountName), not the typed name.
    `marcel.ritter@corp.example.com` therefore logs in as `mritter`.
  - `LAB\alice` and `LAB.EXAMPLE.COM\alice` are accepted as well. On a non-member
    machine, Windows usually cannot find a KDC from the NetBIOS name `LAB` and falls
    back to NTLM (refused); use the UPN there.
  - If the typed name is clearly another account than the ticket's, the server
    ignores the typed password (the session then has no Kerberos TGT).
- Approve the push on the phone while mstsc shows "Configuring remote session…".
- Outside the network the KDC must be reachable (VPN), or set a KDC proxy in group
  policy ([windows-clients.md](windows-clients.md) §3.10).

## When the server refuses the login

A refusal after the connection is up comes with an RDP error code ([MS-RDPBCGR]
2.2.5.1.1). FreeRDP prints the code and the text below; mstsc shows its own dialog
(texts not yet recorded, lab test S4 in [rdp-spec-conformance.md](rdp-spec-conformance.md)).
The exact cause is only in the server log.

| Code | FreeRDP text | Cause |
|---|---|---|
| 0x7 ERRINFO_SERVER_DENIED_CONNECTION | The server denied the connection. | wrong password or unknown user (never told apart), second factor rejected or missing, policy (e.g. no password but the server needs one for a Kerberos TGT), RemoteApp requested, smartcard PIN without NLA |
| 0x9 ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES | The user cannot connect to the server due to insufficient access privileges. | signed in, but not allowed: not in an allowed group, account expired or locked, or no desktop permitted. A password login (TLS) that still needs its second factor gets 0x7 instead |
| 0x409 ERRINFO_CB_CONNECTION_CANCELLED | Processing of the connection has been cancelled. | push not approved in time, or the server did not answer in time |
| 0x400 ERRINFO_CB_DESTINATION_NOT_FOUND | The target endpoint could not be found. | the desktop session could not be started or reached; try again later or tell the administrators |

## Remmina

- Protocol: RDP.
- Server: the FQDN; User: alice; Domain: `LAB.EXAMPLE.COM`.
- Security protocol: NLA.
- Preferences → RDP → "FreeRDP auth-pkg-list": `kerberos,!ntlm`.
- Single sign-on with your ticket: leave the password empty and tick Advanced → "Allow
  sending empty password". Smartcard: Basic → "Use a smartcard for logon". More:
  [freerdp-client.md](freerdp-client.md) §13.
- Colour depth: GFX AVC444 (32 bpp).
- Advanced → "Start-up program": `fastrdp:gnome` sets the desktop.

## Choosing your default desktop

Write the desktop name to `~/.config/fastrdp/desktop`, e.g.
`echo plasma > ~/.config/fastrdp/desktop`. It applies from the next login.

Available names: see `fastrdp_desktops` in the inventory (`xfce`, `mate`,
`cinnamon`, `lxqt`, `plasma-x11`, `gnome`, `plasma`, and the wlroots desktops
`sway`, `labwc`, `wayfire`).
