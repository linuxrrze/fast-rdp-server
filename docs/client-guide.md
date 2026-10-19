# Client guide

Always connect to the server's **FQDN** (Kerberos needs it), e.g. `rdp1.lab.example.com`.

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

# pick a desktop for this session
xfreerdp3 ... /shell:fastrdp:gnome

# outside the VPN: reach the KDC through a KDC proxy (MS-KKDCP)
xfreerdp3 ... /kerberos:kdc-url:https://kdcproxy.lab.example.com/KdcProxy

# password + OTP in one field (server must allow TLS logins)
xfreerdp3 /v:rdp1.lab.example.com /u:alice /p:'Secret123456' /sec:tls /gfx:avc444
```

`sdl-freerdp3` and `wlfreerdp3` take the same options.

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

- Approve the push on the phone while mstsc shows "Configuring remote session…".
- Non-domain Windows: enter `LAB\alice`. The KDC must be reachable, or set a KDC
  proxy in group policy.

## Remmina

- Protocol: RDP.
- Server: the FQDN; User: alice; Domain: `LAB.EXAMPLE.COM`.
- Security protocol: NLA.
- Colour depth: GFX AVC444 (32 bpp).
- Advanced → "Start-up program": `fastrdp:gnome` sets the desktop.

## Choosing your default desktop

Write the desktop name to `~/.config/fastrdp/desktop`, e.g.
`echo plasma > ~/.config/fastrdp/desktop`. It applies from the next login.

Available names: see `fastrdp_desktops` in the inventory (`xfce`, `mate`,
`cinnamon`, `lxqt`, `plasma-x11`, `gnome`, `plasma`).
