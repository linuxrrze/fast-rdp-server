# RDP specification conformance

This review checks the parts of the RDP stack that fastrdp writes, configures or changes against
Microsoft's Remote Desktop Services protocol specifications. Those parts are:

- the freerdp-proxy configuration;
- the fastrdp proxy module;
- the back-end hops;
- the xrdp FFmpeg H.264 patch;
- display control;
- the web path.

For each part it records where fastrdp deviates from the specs, where Windows mstsc and
other non-FreeRDP clients are at risk, and what is missing.

**Sources:**
- Current revisions on learn.microsoft.com (open specifications, fetched 2026-10-20):
  - MS-RDPBCGR: pages updated 2026-03-06;
  - MS-RDPEGFX: revision 19.0, 2026-05-11;
  - also MS-CSSP, MS-RDPEDYC, MS-RDPEDISP, MS-RDPEMT/MS-RDPEUDP, MS-RDPELE, MS-RDPEWA and
    MS-RDPESC.
- FreeRDP 3.32.2 (`third_party/fetch.sh freerdp`).
- xrdp 0.10.6.1 with `patches/xrdp/0001-*` (`third_party/fetch.sh xrdp`).

**How it was checked:**
- **Code reading.**
- **The proxy end-to-end test, run locally:** a local build of freerdp-proxy 3.32.2 against
  the system OpenSSL 3.5, running `tests/proxy-e2e/run.sh`.
- **The encoder test, run locally:** `patches/xrdp/test/run_test.sh` against libx264 and
  FFmpeg 7.1.1 built from source.
- **Not checked here:** anything that needs mstsc, the Windows App, macOS clients or a GPU.
  These items are listed as lab tests ([§13](#13-lab-tests)).

**Paths:**
- `freerdp/` is the FreeRDP 3.32.2 source tree.
- `xrdp/` is the patched xrdp tree.
- Paths without a prefix are in this repository.
- `module` is `broker/proxy-module/fastrdp_plugin.c` (line numbers after this review's changes).

**Status values:**

| Status | Meaning |
|---|---|
| **conforms** | matches the spec, or the spec leaves it to the server |
| **deviation** | does not do what the spec says |
| **risk** | spec-conformant, but an interoperability or operational risk |
| **unknown** | needs a lab test |
| **fixed** | was a deviation or risk; fixed in this review (see [§11](#11-changes-made-in-this-review)) |

## Top findings

Sorted by severity. "Fixed" means fixed in this review.

1. **Refusals reached mstsc without a reason (fixed).**
   - **What happened:** every refusal after the RDP connection was up ended with Deactivate
     All and a Disconnect Provider Ultimatum, but no Set Error Info PDU. The refusals were:
     broker denies, MFA fails or times out, user not in an allowed group, back-end cannot be
     started or reached. The front `errorInfo` stayed 0, so FreeRDP's `rdp_send_error_info`
     sent nothing (`freerdp/libfreerdp/core/rdp.c:2297-2314`, `peer.c:1208-1243`). FreeRDP
     clients then report `ERRINFO_LOGOFF_BY_USER`. mstsc shows a generic "remote session
     ended" message.
   - **Now:** the module sets [MS-RDPBCGR] 2.2.5.1.1 codes (see [§5](#5-session-end-refusals-and-error-info)), chosen by the broker's `reason` (R1), and the e2e test checks them.
2. **The proxy offered UDP multitransport it cannot serve (fixed).**
   - **What happened:** FreeRDP's defaults (`settings.c:1054-1058`) made the front advertise
     TS_UD_SC_MULTITRANSPORT and send an Initiate Multitransport Request
     ([MS-RDPBCGR] 2.2.15.1). freerdp-proxy has no MS-RDPEUDP listener. The server then waits
     in `MULTITRANSPORT_BOOTSTRAPPING_RESPONSE` until the client gives up on UDP and answers
     E_ABORT ([MS-RDPBCGR] 2.2.15.2, 1.3.1.1 phase 8).
   - **Effect:** for mstsc and the Windows App this is a UDP connect attempt to a closed
     port on every login: extra connect time, plus the UDP timeout if the firewall drops
     instead of rejecting.
   - **Now:** the module stops offering multitransport before the connection sequence starts.
3. **A smartcard PIN on the TLS path went to the broker as a password (fixed).**
   - **What happened:** a Client Info PDU with INFO_PASSWORD_IS_SC_PIN
     ([MS-RDPBCGR] 2.2.1.11.1.1) was handled like a password login. The e2e test against the
     old module confirmed that the PIN reached the broker, and from there PAM and MFA. On the
     NLA path the module already dropped PINs.
   - **Now:** the TLS path refuses such logins.
4. **Front-only fields leaked into the back-end Client Info (fixed).**
   - **What happened:** the back-end connection's settings are a copy of the front client's
     (`pf_context_copy_settings`, `freerdp/server/proxy/pf_context.c:260-306`). The module
     reset user, password, domain and alternate shell, but not:
     - WorkingDir;
     - INFO_RAIL;
     - INFO_PASSWORD_IS_SC_PIN;
     - the routing token.
   - **Effect:** after a smartcard NLA login the back-end received the broker's one-time
     token flagged as a smartcard PIN, and a RemoteApp request reached xrdp as INFO_RAIL.
   - **Now:** all four are cleared in `ClientPreConnect` (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2722-2738`).
5. **RemoteApp requests are now refused (fixed).**
   - **What happened:** `RemoteApp=false` blocks the RAIL channel, but a client with INFO_RAIL
     (mstsc RemoteApp, `.rdp` `remoteapplicationmode:i:1`) still got a full desktop session.
     That session had no RAIL channel, and the client waited for a window that never came.
   - **Now:** refused with ERRINFO_SERVER_DENIED_CONNECTION (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2481-2500`).
6. **A back-end Server Redirection PDU was followed blindly (fixed).**
   - **What happened:** FreeRDP's client would reconnect wherever a back-end redirected it,
     using the broker's credentials (`freerdp/libfreerdp/core/connection.c:647-712`). The
     GNOME and Plasma back-ends run as the user.
   - **Now:** the module refuses redirection (`ClientRedirect`, `fastrdp_client_redirect()`, `fastrdp_plugin.c:2804-2811`).
7. **H.264: lost output was not followed by an IDR (fixed in the xrdp patch).**
   - **What happened:** MS-RDPEGFX has no picture-loss feedback. When an encoded frame was
     dropped (output larger than the 3 MiB buffer, or an encoder error), later P-frames
     referenced a frame the client never got, until the next GOP (up to 300 encoded frames).
   - **Now:** the patch forces an IDR with SPS/PPS after any lost output, and the regression
     test checks it.
8. **H.264: the VUI said limited range, but the input is full-range BT.709 (fixed in the
   xrdp patch).**
   - **What happened:** xorgxrdp delivers `XRDP_nv12_709fr`, the conversion
     [MS-RDPEGFX] 3.3.8.3.1 prescribes. The patch signalled `AVCOL_RANGE_MPEG` and pre-filled
     never-damaged areas with Y=16.
   - **Effect:** mstsc and FreeRDP ignore the VUI. Undamaged areas were dark grey instead of
     black. VUI-honouring decoders washed the colours out.
9. **H.264 level and size limits for large monitors (risk, open).**
   - **What happens:** a 3840×2160 monitor at 60 fps gets level 5.2 (32,400 MBs × 60 fps
     exceeds level 5.1's MaxMBPS of 983,040). Windows' Media Foundation H.264 decoder
     documents "up to level 5.1" and at most 4096×2304. A monitor wider than 4096 px exceeds
     both MF and typical hardware encoders (NVENC, VA-API).
   - **Recommendation:** lab test S12; if needed, cap the level or fps, or use RFX for
     monitors wider than 4096 px.
10. **Every reconnect is a full login with MFA (risk; mitigated by R2, opt-in).**
    - **What happens:**
      - neither the proxy nor xrdp issues an auto-reconnect cookie (ARC, [MS-RDPBCGR] 5.5);
      - the proxy cannot validate one.
    - **Effect:** after a network drop, mstsc must reconnect from scratch: Kerberos NLA, then
      a new push.
    - **Now (R2):** `[mfa] reconnect_grace` (default off) lets such a reconnect skip a
      second factor passed shortly before by the same account, login method, principal and
      client address ([auth-matrix.md](auth-matrix.md#reconnect-grace)).
11. **WAN clients got LAN encoder settings (fixed, R6).**
    - **What happened:** mstsc sends `connectionType` = CONNECTION_TYPE_AUTODETECT (7). The
      proxy does no connect-time auto-detection ([MS-RDPBCGR] 2.2.14) and copied the
      value to xrdp. xrdp 0.10.6.1 has no slot for type 7: `NUM_CONNECTION_TYPES` is 7
      (`xrdp/xrdp_tconfig.h:32`), the loaders read `[*.modem]` … `[*.lan]` only
      (`xrdp/xrdp_tconfig.c:682-708`), and the encoders map 0 and 7 to `lan`
      (`xrdp/xrdp_encoder_x264.c:133-136`, `xrdp_encoder_openh264.c:156`, `xrdp_encoder_ffmpeg.c:427`).
      fastrdp's `[*.lan]` is empty, so it inherits `[*.default]`: QP 23, no bitrate cap.
      An `[x264.autodetect]` section would be parsed and ignored.
    - **Now:** the broker chooses the type the proxy sends to xrdp for clients that sent
      7, 0 or an invalid value: `lan` for client addresses in `[network] lan_networks`
      (`fastrdp_lan_networks`), otherwise `xrdp_autodetect_profile`
      (`fastrdp_xrdp_autodetect_profile`, default `wan`: 12/15 Mbit/s). A type the client
      chose (1–6) is kept. gfx.toml also gets `[*.autodetect]` copies of that profile.
12. **mstsc's X ended the session as a server-side disconnect (fixed in the FreeRDP patch).**
    - **What happened:** the X in mstsc's connection bar sends a Shutdown Request PDU
      (2.2.2.2). With a logged-on user the server must answer with a Shutdown Request
      Denied PDU and leave the disconnect to the client (1.3.1.4.1). FreeRDP's server
      always disconnected with "provider initiated" (`peer.c:390-394`). Field report
      2026-10-23: the next *Connect* in the same mstsc showed a black window instead of the
      waiting screen until the login timed out.
    - **Now:** `patches/freerdp/0008` (`fastrdp-freerdp3` 3.32.2-7) denies the request
      once PostConnect accepted the client; before that (no session yet) the connection is
      still closed at once. Whether this also fixes the next *Connect* in mstsc is lab S15.

## 1. Security negotiation (X.224, [MS-RDPBCGR] 2.2.1.1–2.2.1.2, 5.4)

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| Server selects one protocol from `requestedProtocols` (2.2.1.2.1) | Order: RDSTLS > HYBRID_EX > HYBRID > SSL > RDP (`freerdp/libfreerdp/core/connection.c:1503-1522`). fastrdp enables HYBRID always, SSL only with `fastrdp_allow_tls_logins` or web, no RDP security, no HYBRID_EX (`ansible/roles/freerdp_proxy/templates/proxy.ini.j2:41-45`) | conforms | mstsc (requests SSL\|HYBRID\|HYBRID_EX) gets HYBRID. |
| HYBRID_EX / Early User Authorization Result PDU (2.2.10.2) | Not offered (`ServerExtSecurity=false`). FreeRDP would send AUTHZ_SUCCESS right after TSCredentials (`nla.c:946-952`), before the module's decision, so it could not report the module's refusal anyway | conforms | Offering HYBRID_EX would not improve error reporting. Keep it off. |
| RDP_NEG_FAILURE codes (2.2.1.2.2) | NLA-only server and client without HYBRID → HYBRID_REQUIRED_BY_SERVER (0x5); TLS also enabled and client asks for plain RDP → SSL_REQUIRED_BY_SERVER (0x1) (`connection.c:1524-1552`). SSL_NOT_ALLOWED_BY_SERVER only when RDP security is enabled, which fastrdp never does | conforms | mstsc with `enablecredsspsupport:i:0` on an NLA-only fastrdp shows its "remote computer requires Network Level Authentication" message (lab S1). |
| Restricted Admin / Remote Credential Guard flags in RDP_NEG_REQ (2.2.1.1.1) and RDP_NEG_RSP (2.2.1.2.1) | Restricted Admin: RESTRICTED_ADMIN_MODE_SUPPORTED set (default). RCG, default: not supported. FreeRDP used to **drop the connection while parsing the request** (`nego.c:1335-1360`); `patches/freerdp/0002` answers RDP_NEG_RSP without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED instead (R4). RCG *or* Restricted Admin requested: Restricted Admin, unchanged. `[FastRDP] AcceptRemoteGuard=true`: the flag is set (`fastrdp_server_session_init()`), RCG identity only ([§2](#2-credssp--nla-ms-cssp)) | fixed | mstsc `/remoteGuard` gets an answer and can refuse with its own message (dialog: lab S2). No RDP_NEG_FAILURE code fits: they all name security protocols (2.2.1.2.2), and the server does support the requested protocol (3.3.5.3.2). |
| `routingToken` / `mstshash` cookie (2.2.1.1) | Ignored for routing: the module always returns `PROXY_FETCH_TARGET_USE_CUSTOM_ADDR` (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2661`), and `FixedTarget=false` never uses the token. FreeRDP copies the client's routing token into the back-end X.224 request (`pf_client.c:131-143`); the module now clears it (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2738`) | fixed | A client-chosen `Cookie: msts=` can no longer reach a back-end. The `mstshash` cookie towards the back-end is the broker's user name. |
| Server certificate / TLS (5.4.5) | TLS 1.2+, OpenSSL defaults, front certificate from `/etc/fastrdp/front.crt` ([windows-clients.md](windows-clients.md) §3.7) | conforms | – |

## 2. CredSSP / NLA ([MS-CSSP])

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| TSRequest versions 2–6, clientNonce and SHA-256 pubKeyAuth for v5+ (2.2.1, 3.1.5) | FreeRDP answers version 6 and uses the echo form for v<5 and the hash form for v5/6 (`nla.c:2420`, [windows-clients.md](windows-clients.md) §3.4) | conforms | – |
| `errorCode` in TSRequest (v3, v4, v6) (2.2.1) | Server sets STATUS_LOGON_FAILURE, PASSWORD_EXPIRED and similar on SSPI failure, and omits it for v5 (`nla.c:872-885, 2123`) | conforms | mstsc shows a CredSSP-specific message for Kerberos failures. |
| TSCredentials types (2.2.1.2): 1 TSPasswordCreds, 2 TSSmartCardCreds, 6 TSRemoteGuardCreds | 1: domain, user and password into the front settings. 2: PIN as password plus PasswordIsSmartcardPin (`nla.c:1480-1525`). The module drops the PIN and sets `smartcard` (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2410-2422`). 6: by default never reached (RCG not offered at negotiation; credentials sent anyway are refused by `fastrdp_remote_credentials()`). With `AcceptRemoteGuard=true`: accepted after Kerberos NLA, the `KERB_TICKET_LOGON` (HOST/ service ticket, TGT as KRB-CRED) and NTLM supplemental credentials are zeroed and discarded, the broker gets `"remote_guard": true` and no password. FreeRDP rejected TSRemoteGuardCreds without the optional `supplementalCreds` (2.2.1.2.3), i.e. from every FreeRDP client; `patches/freerdp/0003` fixes the parser. Restricted Admin: empty TSPasswordCreds, user = Kerberos principal (`fastrdp_plugin.c:2423-2424`) | conforms | The delegated password is only a convenience for a TGT on X11. Identity comes from the Kerberos principal. |
| Kerberos-only acceptor | **Before:** the acceptor offered NTLM; it ran the whole NTLM exchange and failed at the missing SAM file, and the module refused any non-Kerberos package after NLA. **Now:** the front acceptor does not offer NTLM (`AuthenticationPackageList=!ntlm` plus a refusing NTLM hash callback, `fastrdp_server_session_init()`), so a client without a Kerberos ticket gets the TSRequest `errorCode` STATUS_LOGON_FAILURE at its first CredSSP message. The module logs `client <addr> attempted NTLM (offered: …)` with the fix (FQDN, KDC reachability, UPN), read from that message (`fastrdp_read_pdu()`). The package check after NLA stays (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2360-2370`) | fixed | Faster, clearer failure; no NTLMv2 response leaves the client. The mstsc dialog is probably still the generic "logon attempt failed" (same NTSTATUS); lab L9 in [windows-clients.md](windows-clients.md) §3.13. |
| Kerberos user-to-user under CredSSP ([MS-CSSP] with [MS-KILE] U2U; draft-swift-win2k-krb-user2user) | mstsc calls the Kerberos SSP with ISC_REQ_USE_SESSION_KEY, so its first token is a KERB-TGT-REQUEST (U2U OID, TOK_ID `04 00`) under the MS-KRB5 mechType. The acceptor must answer with a TGT whose client owns `TERMSRV/<host>`. **Before:** WinPR asked the KDC for a TGT of `TERMSRV/<host>` (and `<fqdn>$`); AD refuses an SPN as AS client, so Kerberos was dropped for every mstsc login on AD hosts (field report: "Client 'TERMSRV/…' not found in Kerberos database", then NTLM). **Now:** `patches/freerdp/0004` takes the machine account's TGT from its keytab entry (`<NAME>$`, copied by `fastrdp-termsrv-keytab`, same keys as TERMSRV); MIT/FreeIPA unchanged. The module logs `requested Kerberos user-to-user` | fixed (e2e with an AD-like MIT KDC; mstsc against AD confirmed, field report 2026-10-22) | WinPR ends the exchange with accept-completed + AP-REP without a mechListMIC (optional per RFC 4178 §5 when the first mechanism is chosen); Windows' own acceptor sends one; mstsc accepts the exchange without it. Lab L18 in [windows-clients.md](windows-clients.md) §3.14. |

## 3. Client Info PDU and the credential swap ([MS-RDPBCGR] 2.2.1.11)

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| INFO_AUTOLOGON: "The client requests auto logon using the included user name, password and domain" (2.2.1.11.1.1) | TLS path: the module uses user and password whether or not INFO_AUTOLOGON is set (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2521-2532`). There is no logon UI at the proxy, so a client without credentials is refused (now with ERRINFO 0x7) | deviation (benign) | Using a password without INFO_AUTOLOGON is outside the spec's wording. The alternative, a server logon screen, does not exist here. mstsc sets INFO_AUTOLOGON when it sends saved credentials. Keep, documented. |
| Back-end auto-logon (2.2.1.11.1.1) | Back-end hop sets AutoLogonEnabled, so INFO_AUTOLOGON, plus broker user and token or random secret, and Domain = broker value, usually `""` (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2713-2716`) | conforms | An empty Domain also keeps xrdp from interpreting the domain field as an `xrdp.ini` section selector. |
| Password field and INFO_PASSWORD_IS_SC_PIN: "Password … contains a smart card PIN"; UserName SHOULD be ignored (2.2.1.11.1.1) | TLS path: was treated as a password; **now refused** (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2513-2520`). NLA path: PIN dropped. Back-end: PasswordIsSmartcardPin and SmartcardLogon reset (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2730-2731`) | fixed | No PIN reaches PAM, the MFA server or a back-end. |
| AlternateShell "MUST only be initialized if the client is requesting a shell other than the default" (2.2.1.11.1.1) | Used only as a desktop hint `fastrdp:<desktop>`. The broker strips the prefix and accepts only allowed desktop names (`broker/brokerd/fastrdp_broker/identity.py:118-127`). Never forwarded: `ClientPreConnect` clears it (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2722`), and the e2e test checks this | conforms | A non-matching value (e.g. `||notepad`, `C:\x.exe`) is ignored, as a Windows host with "Start a program on connection" policy-disabled would ignore it. Nothing is executed. mstsc sets it only from `.rdp` `alternate shell:s:` (and `||app` for RemoteApp, which is now refused). |
| WorkingDir "directory that contains the executable … in AlternateShell" (2.2.1.11.1.1) | Was copied to the back-end; now cleared (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2728`) | fixed | Belongs to the dropped shell. |
| INFO_RAIL (2.2.1.11.1.1, [MS-RDPERP]) | Was forwarded to the back-end while the proxy blocked the RAIL channel. Now refused unless `RemoteApp=true` (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2481-2500`) and cleared on the back-end hop (`fastrdp_client_pre_connect()`, `fastrdp_plugin.c:2729`) | fixed | mstsc RemoteApp gets an error dialog instead of a hang. ERRINFO_REMOTEAPPSNOTENABLED (0x10F3) means the opposite (server *only* hosts RemoteApps), so 0x7 is used. |
| INFO_LOGONNOTIFY / INFO_LOGONERRORS and the Save Session Info PDU (2.2.10.1) | Flags are copied to the back-end hop. The back-end's Save Session Info is forwarded to the client (`pf_update.c:301-332`). xrdp sends logon info via `libxrdp_send_session_info` | conforms | The user name in Logon Info is the back-end's (broker user), which is correct. |
| `clientAddress` (2.2.1.11.1.1.1) | Ignored. The module reports the socket peer to the broker (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2551-2554`, e2e-tested) | conforms | – |
| `connectionType` / RNS_UD_CS_VALID_CONNECTION_TYPE (2.2.1.3.2) | mstsc sends AUTODETECT (7); the proxy does no auto-detection (2.2.14), and xrdp 0.10.6.1 encodes 7 (and 0) like `lan` (`xrdp_tconfig.h:32`, `xrdp_encoder_x264.c:133-136`). **Now** the module sends the front's type to the broker, and for xrdp desktops the broker returns `target.connection_type` for clients that sent 7, 0 or an invalid value: `lan` inside `[network] lan_networks` (socket address, IPv4-mapped IPv6 included), else `xrdp_autodetect_profile` (default `wan`). The module sets only `FreeRDP_ConnectionType` on the back-end hop (`apply_connection_type`); performance flags and RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT stay the client's. Types 1–6 chosen by the client are kept. gnome-remote-desktop 49 and KRdp 6.4 never read `ConnectionType` (they use their own RTT/bandwidth auto-detection), so the broker leaves them alone | fixed | Pick the WAN cap per site (`fastrdp_xrdp_autodetect_profile`), list LAN/VPN client networks in `fastrdp_lan_networks`. Lab S13. |

## 4. Licensing ([MS-RDPBCGR] 1.3.1.1 phase 7, 2.2.1.12; [MS-RDPELE])

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| Server without a license server sends a License Error Message with STATUS_VALID_CLIENT, ST_NO_TRANSITION and an empty BB_ERROR_BLOB (2.2.1.12.1.3; [MS-RDPELE] 1.3.3) | The front (FreeRDP peer, `ServerLicenseRequired` false) sends exactly that (`peer.c:613-634`, `license.c:2847-2857`, preamble version 3, no EXTENDED_ERROR_MSG_SUPPORTED in server mode, `license.c:883-891`) | conforms | This is what mstsc accepts from non-Windows servers. Every path (NLA, TLS, web) goes through the same front. |
| Back-end licensing | xrdp, g-r-d and KRdp each run their own licensing exchange with the proxy's FreeRDP client. It never reaches mstsc | conforms | – |

## 5. Session end, refusals and error info

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| Server-initiated disconnect: optional Set Error Info, optional Deactivate All, optional Disconnect Provider Ultimatum, reason "user requested" when the user ended the session on the server (1.3.1.4.2), "provider initiated" for an administrator (1.3.1.4.3); 2.2.5.1 | FreeRDP's `freerdp_peer_close` sends Deactivate All, Set Error Info (only if `errorInfo != 0` and the client set RNS_UD_CS_SUPPORT_ERRINFO_PDU, `gcc.c:1074-1075`) and the Ultimatum (`peer.c:1208-1244`, pristine 3.32.2). When the back-end ends a running session, the proxy first forwards the back-end's Set Error Info code unchanged (`pf_client_on_error_info()`, `pf_client.c:74-97`), then closes the front this way [tested: `run.sh`, back-end closing with 0x400]. **But** `mcs_send_disconnect_provider_ultimatum()` ignores its `reason`: it writes the choice byte 0x21 and `per_write_enumerated(s, 0x80, reason)` writes 0x80, so every Ultimatum on the wire says "user requested" (3), although FreeRDP logs "provider initiated" [verified: `mcs.c:1426-1460`, `per.c:382-388`; tested: the e2e client decodes 3]. gnome-remote-desktop sends ERRINFO_RPC_INITIATED_DISCONNECT (0x1, "an administrative tool on the server in another session") whenever it stops a session it did not queue itself, a GNOME logout included [verified: `grd_session_rdp_stop()`, gnome-remote-desktop main branch; field log 2026-10-23]; a Windows server sends ERRINFO_LOGOFF_BY_USER (0xC) for a logoff | deviation (reason field; codes as the back-end sends them) | mstsc sets the flag. Whether mstsc treats the following *Connect* in the same process differently after 0x1 + "user requested" (grd logout) than after 0xC (Windows) is open (lab S15). The proxy cannot tell a logout from an administrative stop: grd sends 0x1 for both, so mapping 0x1 to 0xC in the module would guess. Not changed. |
| User-initiated disconnect on the client: Shutdown Request PDU; with a logged-on user the server always answers with a Shutdown Request Denied PDU, the client then sends a Disconnect Provider Ultimatum "user requested"; without one the server closes at once (1.3.1.4.1, 2.2.2.2, 2.2.2.3) | FreeRDP 3.32.2 always closed with a "provider initiated" Disconnect Provider Ultimatum and had no way to send the Denied PDU (`peer.c:390-394`). `patches/freerdp/0008` (`fastrdp-freerdp3` 3.32.2-7) sends it once PostConnect has accepted the client (the broker gave a target: a session exists) and keeps the connection; during PostConnect (MFA wait, desktop picker) the connection is still closed at once | fixed (fastrdp's FreeRDP build) | mstsc sends the request for the X in its connection bar; FreeRDP clients never send it. Lab S15: mstsc's dialog and the next *Connect* in the same process. A request sent while the module only watches the front socket (MFA wait without the picker or the code field) is read after PostConnect, when the login has ended either way. |
| Meaningful `errorInfo` on refusal (2.2.5.1.1) | **Before:** the module never set one. **Now** (`errinfo_for_reply()`, `fastrdp_plugin.c:2164-2182`), from the broker's `reason` (`protocol.py`):<br>- `denied` (bad or unknown credentials, invalid web token, realm, `session_tgt = required`), `mfa_failed` (OTP rejected or missing, no push token, MFA service down) and unknown reasons → ERRINFO_SERVER_DENIED_CONNECTION 0x7;<br>- `not_allowed` (not in `allow_groups`, PAM account check failed, no permitted desktop) → ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES 0x9;<br>- `backend` ("session could not be started"), broker unreachable or malformed reply, back-end connection failed (`ClientLoginFailure`) → ERRINFO_CB_DESTINATION_NOT_FOUND 0x400;<br>- `mfa_timeout` (push not approved in time) or broker timeout → ERRINFO_CB_CONNECTION_CANCELLED 0x409;<br>- RemoteApp, TLS + PIN, no credentials, refused redirection → 0x7.<br>An error info forwarded from the back-end (`pf_client.c:74-97`, e.g. ERRINFO_LOGOFF_BY_USER on logout) is not overwritten | fixed | The `error` text stays "access denied", and the broker never tells an unknown user from a wrong password. `not_allowed` confirms the credentials, so the broker sends it only when the client already knows they are valid (NLA: CredSSP succeeded; web: IdP login) or no second factor is due; a TLS password login that still owes MFA gets `denied`. `mfa_failed` stays 0x7 for the same reason. `mfa_timeout` (0x409) comes only after a correct password, but by then the client has waited out the push timeout, so the code reveals nothing the timing does not. No logon-timeout code exists: ERRINFO_LOGON_TIMEOUT (0x4) is "The active session limit timer on the server has elapsed", so 0x409 ("Processing of the connection has been cancelled") is the closest. |
| Server Status Info PDU (2.2.5.2) only to a client that set RNS_UD_CS_SUPPORT_STATUSINFO_PDU (3.3.5.7.2) | The proxy forwards a back-end's Status Info PDU (`pf_client_server_status_info()`, `pf_update.c`). FreeRDP 3.32.2 forwarded it without looking at the front client's flag; `patches/freerdp/0006` (`fastrdp-freerdp3` 3.32.2-5) drops it, with a DEBUG message, when `FreeRDP_SupportStatusInfoPdu` is off in the front peer's settings. The back-end hop announces the front client's flag (its settings are a copy of the front's), so only a back-end that ignores the flag sent one | fixed (fastrdp's FreeRDP build) | Not reached with conforming back-ends; no e2e back-end sends the PDU. |
| Refusals before MCS (NLA identity checks in `ServerPeerLogon`) | The connection is closed right after CredSSP. No RDP-level error is possible yet | conforms | NTLM, or non-Kerberos NLA, already fails in CredSSP with an errorCode. The module check is a backstop. |
| Timing: the broker call (MFA push or web approval plus the session start, up to `Timeout=180` s) runs in `PostConnect`, i.e. **after** the client has received Font Map (`peer.c:744-757`) | The client is in the active state with no graphics until the back-end is connected, unless `[FastRDP] WaitingScreen` draws a panel meanwhile (see "Waiting screen: Bitmap Updates"). The proxy then does a Deactivation-Reactivation (1.3.1.3) to adopt the back-end's settings (`pf_client.c:559-563`) | unknown | mstsc probably shows an empty session window during a push. It would not show "Configuring remote session…" as [windows-clients.md](windows-clients.md) §3.8 assumed. Lab S3. The broker call blocks the peer thread, but `broker_call()` also polls the front socket (`abort_fds()`): a client that disconnects meanwhile ends the wait at once, and the broker cancels the login when its connection closes (R8, [§11](#11-changes-made-in-this-review)). With the desktop picker the module also reads the client's input during this wait (see "Waiting screen: Bitmap Updates", `patches/freerdp/0007`). |

### Waiting screen: Bitmap Updates

With `[FastRDP] WaitingScreen=true` (Ansible `fastrdp_proxy_waiting_screen`; the default,
also the module's own without the key)
the module fills the wait described above (`waitingScreen` in `fastrdp_plugin.c`,
panel in `fastrdp_panel.h`):

| Requirement (spec §) | What fastrdp does | Status | Notes |
|---|---|---|---|
| Graphics before the back-end exists | Bitmap Update ([MS-RDPBCGR] 2.2.9.1.1.3.1.2) over fast-path, the one graphics output every client must support. Nothing else is possible at that point: drdynvc (GFX, H.264) is set up only after PostConnect returns (`pf_server.c:688-760`), and the proxy zeroes `OrderSupport` (`pf_server.c:537-540`). The module is the only writer to the front (the proxy's client thread starts after the hook, `pf_server.c:369`) | conforms | FreeRDP clients at 15/16/24/32 bpp in `tests/proxy-e2e/run.sh`, the received screen decoded (QR code read back); mstsc, Windows App, Remmina: lab S3 |
| TS_BITMAP_DATA fields (2.2.9.1.1.3.1.2.2) | The proxy sets `autoCalculateBitmapData = FALSE` (`pf_server.c:543`), so the module fills every field: `BITMAP_COMPRESSION`, `NO_BITMAP_COMPRESSION_HDR` only if the client's `NoBitmapCompressionHeader` says so, otherwise the TS_CD_HEADER sizes; 64×64 tiles with a width rounded up to a multiple of 4, `destRight`/`destBottom` clipped to the desktop | conforms | Same layout as FreeRDP's shadow server (`shadow_client_send_bitmap_update()`, `shadow_client.c:1995-2135`) |
| Compression ([MS-RDPEGDI] 2.2.2.5 planar, 2.2.2.3 interleaved RLE) | 32 bpp: planar with RLE and no alpha plane; 15/16/24 bpp: interleaved RLE; 8 bpp: no waiting screen (would need a palette) | conforms | Antialiased text, rounded corners and the card's shadow (`fastrdp_panel.h`) cost more than flat colours: the whole 1920×1080 desktop with the web approval panel and QR code is 265 KB planar (228 KB with the earlier bitmap font), 46 KB interleaved at 16 bpp (28 KB); at 3840×2160 932 KB (857 KB). A countdown second resends only the tiles of its line: 5–15 KB planar, 2–4 KB at 16 bpp (as before) |
| Update size ([MS-RDPBCGR] 2.2.7.2.6 multifragment) | Tiles are grouped into updates of at most the client's `MultifragMaxRequestSize` (FreeRDP's 16256 bytes without the capability), at most 64 tiles and 256 KiB; a compressed tile stays below 16 KiB | conforms | |
| After the wait | Before the hook returns a granted login, the panel is painted over in the screen colour around it, so nothing stays if the back-end does not repaint the whole desktop after the Deactivation-Reactivation (`pf_client.c:559-563`) | conforms | |
| Server Status Info PDU (2.2.5.2) | Optional (`[FastRDP] StatusInfo`, default off): TS_STATUS_FINDING_DESTINATION when the broker is called, TS_STATUS_BRINGING_SESSION_ONLINE at the session start; only to clients that announced RNS_UD_CS_SUPPORT_STATUSINFO_PDU (FreeRDP's server keeps `SupportStatusInfoPdu` only then) | conforms | FreeRDP clients never announce it (the e2e client does on purpose); what mstsc shows: lab S3 |
| Input during the wait: the desktop picker (`[broker] desktop_picker`) | Input is allowed once the server has received Confirm Active (1.3); the client sends it from the active state on. While the module waits in PostConnect the proxy's peer loop does not read the connection, its input handlers drop input until the back-end is active (`pf_input.c:34-190`), and module input filters run only after that. The picker therefore reads the front connection itself: it polls the peer's event handles (the socket and the transport's reread event for TLS bytes already decrypted) and calls `CheckFileDescriptor()` with its own input callbacks (keyboard, Unicode, mouse; Synchronize for NumLock, passed on to the proxy) installed and restored afterwards (`ws_picker_start()`, `ws_picker_end()`). Channel data read meanwhile goes the proxy's way (queued for the back-end, a queue without a limit): the module counts it (`ws_picker_channel_data()`, the peer's `ReceiveChannelData` swapped like the input callbacks) and abandons the login above 4 MiB (each chunk counted with 128 bytes extra). It does not drop it: the proxy's intercepted channels (rdpdr, drdynvc) already talk to the client in PostConnect and their answers must reach the proxy; Refresh Rect and Suppress Output reach the proxy's handlers, which ignore them before the back-end exists. `client->activated` stays FALSE, so the proxy's Activate runs as before | conforms (fastrdp's FreeRDP build) | FreeRDP 3.32.2 would call PostConnect again for every PDU read inside it (`client->connected` is set only when PostConnect returns, `peer.c:744-757`); `patches/freerdp/0007` (`fastrdp-freerdp3` 3.32.2-6) handles such PDUs as input of the active connection, and the module offers the picker only when `freerdp_peer_in_post_connect()` says so. FreeRDP clients in `run.sh` (keys, keypad, Unicode, click, stale keys, timeout, client closed, channel data below and above the cap); mstsc, Windows App, Remmina, touch: lab S3 |
| Stale input | Keys and clicks sent during the MFA wait sit in the socket until the picker reads them: the picker reads and drops what is waiting before it takes input (at most 500 ms), counts a key only on its release after a press it saw, a click only with both halves on the same row | conforms | `run.sh`: digits and Enter typed before the picker do not choose |

The broker sends the panel's texts, countdown and the QR code of the approval page as
progress lines before its reply (`protocol.py`); the module bounds them (32 messages,
64 KiB each, 16 lines, QR versions 1–40) and keeps watching the front connection and the
proxy's abort event while it waits, as before. The desktop picker's prompt is bounded the
same way (9 rows, names of 64 bytes, 60 s); its one answer line goes back on the broker
connection, and a client that closes during the picker ends the wait at once.

## 6. Redirection, load balancing, reconnect

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| Server Redirection PDU (2.2.13), the spec's connection-broker model | fastrdp proxies instead of redirecting | conforms (design) | See the note below the table. |
| Server Redirection **from a back-end** | Was followed by FreeRDP's client using the broker's credentials. Now refused (`fastrdp_client_redirect()`, `fastrdp_plugin.c:2804-2811`) | fixed | – |
| Auto-reconnect (5.5; ARC_SC_PRIVATE_PACKET 2.2.4.2 in Save Session Info 2.2.10.1.1.4; ARC_CS 2.2.4.3) | xrdp ignores the client's cookie and sends none (`xrdp/libxrdp/xrdp_sec.c:998`). The proxy forwards whatever the back-end sends, but cannot validate a cookie itself. The front never sets AUTORECONNECT_SUPPORTED | risk | After a network drop mstsc does a fresh connection: NLA, which is silent with a Kerberos ticket, plus a new MFA push. Sessions themselves survive (xrdp reconnect, broker reuse). R2 (done, opt-in): `[mfa] reconnect_grace` skips the push for a reconnect within N seconds of a passed second factor, bound to account, login method, principal and client address ([auth-matrix.md](auth-matrix.md#reconnect-grace)). Lab S8. |

**Why fastrdp proxies instead of redirecting.** The spec's model is a broker that sends a
Server Redirection PDU, so that the client connects directly to the target. fastrdp does
not use it because:

- back-ends listen on loopback only, and nftables lets only the proxy uid connect to them;
- the user's password and Kerberos identity must never reach a back-end, which only gets a
  one-time token or a random secret;
- xrdp, g-r-d and KRdp cannot authenticate Kerberos users;
- per-user ports would have to be exposed.

The consequences:

- a second RDP hop on the host (CPU, a few hundred µs latency);
- no UDP transport;
- the proxy is a single point of failure;
- GFX/H.264 bytes pass through unchanged, so there is no re-encoding.

## 7. Multitransport / UDP ([MS-RDPBCGR] 2.2.1.3.8, 2.2.1.4.6, 2.2.15; [MS-RDPEMT], [MS-RDPEUDP])

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| Server offers multitransport only if it can carry it (2.2.1.4.6, 2.2.15.1, 1.3.1.1 phase 8) | **Before:** FreeRDP defaults offered reliable UDP and sent an Initiate Multitransport Request, then waited for E_ABORT (`peer.c:956-985`, `multitransport.c:119-140, 202-212`); freerdp-proxy has no RDP-UDP listener. **Now:** the module clears SupportMultitransport and MultitransportFlags in `ServerSessionInitialize` (`fastrdp_server_session_init()`, `fastrdp_plugin.c:2936-2964`). No SC_MULTITRANSPORT is sent and the bootstrapping phase is skipped (`gcc.c:923-925`). The back-end hop inherits this | fixed | TCP only, as before, but without the failed UDP attempt. Performance effect: no UDP means no FEC-based loss recovery and higher latency on lossy WAN links. Documented in [performance.md](performance.md) (proxy overhead section). A real UDP transport would need MS-RDPEUDP in freerdp-proxy, which FreeRDP does not implement server-side. |

## 8. Channels ([MS-RDPEDYC], [MS-RDPEGFX] transport, [MS-RDPEFS]/[MS-RDPESC], [MS-RDPEWA])

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| DVC transport (MS-RDPEDYC) | `PassthroughIsBlacklist=true` with an empty list makes every static channel pass through, including `drdynvc` (`pf_utils.c:30-71`). drdynvc is intercepted only if one of GFX, audio, multitouch, video or camera is disabled (`pf_context.c:60-84`); in fastrdp all are on | conforms | Capability and version negotiation, Soft-Sync and compression are end to end between client and back-end. The proxy's per-DVC filters (`pf_config.c:1490-1520`) are **not** in effect. Disabling a DVC in `proxy.ini` would flip drdynvc to intercept mode, which is less tested (lab S10). |
| GFX (MS-RDPEGFX) | DYNVC_GFX_PROTOCOL_SUPPORTED is set in RDP_NEG_RSP (`nego.c:1623-1626`). The DVC is passed through | conforms | Frame acknowledge and queueDepth go straight to the back-end ([§10](#10-h264--avc420-ms-rdpegfx-xrdp-ffmpeg-patch)). |
| Display control (MS-RDPEDISP) | Passed through ([§9](#9-resize--display-control-ms-rdpedisp)) | conforms | – |
| Clipboard, drives, printers, audio | Passed through | conforms | Policy, not protocol. Drive redirection exposes client files to the session. |
| Smartcard redirection (MS-RDPESC over MS-RDPEFS `rdpdr`) | Passed through (`DeviceRedirection=true`, rdpdr not intercepted because `SmartcardAuth=false`) | conforms | Works if the back-end supports it (xrdp chansrv; g-r-d/KRdp do not). |
| WebAuthn redirection (MS-RDPEWA) | DVC passed through. No back-end opens it | conforms | Unavailable inside sessions; harmless. |
| RemoteApp (MS-RDPERP) | `RemoteApp=false`: the rail static channel is not created (`pf_config.c:1570-1572`); INFO_RAIL is now refused ([§3](#3-client-info-pdu-and-the-credential-swap-ms-rdpbcgr-22111)) | fixed | – |

## 9. Resize / display control ([MS-RDPEDISP])

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| DISPLAYCONTROL_CAPS_PDU from server, then MONITOR_LAYOUT from client (2.2.2.1, 2.2.2.2) | End to end between client and back-end (passthrough). `DisplayControl=true` makes the back-end hop advertise it (`pf_client.c:243-247`) | conforms | – |
| Back-end support | **xrdp:** handles it with xorgxrdp resize (not yet tested through the proxy). **g-r-d:** upstream support (not tested). **KRdp:** fixed size from the first login. **wlroots:** follows the X root | unknown | With KRdp, mstsc "smart sizing" and Guacamole `resize-method=display-update` have no effect. Lab S9. |
| Server-side Deactivation-Reactivation resize (non-GFX path, 1.3.1.3) | The proxy re-syncs the front on back-end DesktopResize (`pf_update.c:149-160`, `pf_client.c:55-71`) | conforms | – |
| Monitor geometry limits (2.2.2.2.1: width 200–8192 and even, height 200–8192) | Initial size from Client Core Data. The broker clamps to 320–8192 (`server.py` `int_field`) | conforms | – |

## 10. H.264 / AVC420 ([MS-RDPEGFX], xrdp FFmpeg patch)

The patch is `patches/xrdp/0001-*`. The encoder is `xrdp/xrdp/xrdp_encoder_ffmpeg.c` (patched
tree); the egfx code is `xrdp/xrdp/xrdp_encoder.c` (`xe`) and `xrdp/xrdp/xrdp_mm.c` (`mm`).
MS-RDPEGFX itself sets **no** profile, level or B-frame rule. The practical constraint is the
Windows Media Foundation H.264 decoder: Baseline, Main and High, up to level 5.1, at most
4096×2304.

| Requirement (spec §) | What fastrdp / the component does | Status | Impact / recommendation |
|---|---|---|---|
| AVC420 bitstream: YUV420p, Annex B, one frame per `avc420EncodedBitstream` (2.2.4.4) | No AV_CODEC_FLAG_GLOBAL_HEADER, so SPS and PPS are in-band with every IDR (NVENC `repeatSPSPPS`, x264 `b_repeat_headers`). One access unit per input with async depth 1 / NVENC `delay=0` / x264 zerolatency. Test: 30/30 frames decode immediately, no IDR inside the GOP, no B-frames | conforms | If an encoder ever buffered, `ffmpeg_drain` would concatenate two access units into one stream. Only a theoretical risk with the shipped options. |
| Coded size "MUST be aligned to a multiple of 16 and MUST be cropped by the region mask in regionRects" (2.2.4.4) | Coded size aligned up to 16 with no SPS cropping (`ctx->width = (w+15)&~15`). destRect is the surface size (xe:936-941). regionRects are the damaged rects (+1 px, clamped, exclusive right/bottom per RDPGFX_RECT16 2.2.1.2; xe:709-752) | conforms | Same design as upstream's x264 module. Test: 1366×768 is coded as 1376×768. |
| RDPGFX_AVC420_METABLOCK quantQualityVals: same count as regionRects, qp in the H.264 range, qualityVal 0–100 (2.2.4.4.1, 2.2.4.4.2) | Constant qp=23, p=0, quality=100 per rect (xe:745-752) | conforms | Informational only ("SHOULD NOT be used by the client when decoding"). |
| Profile and constraint set | `profile=main` for VA-API, NVENC, QSV and libx264. x264 `ultrafast` signals Constrained Baseline (no CABAC). No B-frames, `max_b_frames=0` | conforms | Main or Baseline are the safest profiles for MF and thin clients. The test checks Baseline/Main. |
| Level | Not set; each encoder picks it (VA-API `ff_h264_guess_level` at 60 fps, NVENC autoselect, x264 auto) | risk | 3840×2160@60 → level 5.2 > the 5.1 that MF documents. Monitors wider than 4096 px exceed MF and NVENC/VA-API limits; `ffmpeg_encoder_open` then fails for every frame of that monitor. Lab S12. Options: `options="level=51"` with fps ≤ 30 for 4K, or an RFX fallback for monitors wider than 4096 px. |
| Colour conversion: full-range BT.709 (3.3.8.3.1) | xrdp requests `XRDP_nv12_709fr` when H.264 is active (xe:252), and xorgxrdp converts with full-range BT.709. **The VUI said limited range and the initial frame was Y=16; now full range, BT.709 primaries/transfer, Y=0** | fixed | mstsc and FreeRDP apply the spec's fixed conversion and ignore the VUI. The fix makes the stream self-consistent and turns undamaged areas black instead of grey (16,16,16). |
| Recovery without picture-loss feedback (no PLI in RDPEGFX; WIRE_TO_SURFACE "MUST be part of a logical frame", 3.2.5.1) | **Before:** lost output (`rv` 3/4) left the next frames referencing a frame the client never got. **Now:** `force_idr` makes the next frame an IDR with SPS/PPS, with `forced-idr` for NVENC/QSV/x264 (VA-API always makes I-frames IDR) | fixed | Test "frame after a lost output carries SPS+IDR". An empty StartFrame/EndFrame pair for a frame without output is legal (xe:1459-1496). |
| Frame acknowledge / queueDepth (2.2.2.13, 3.2.5.13: server "SHOULD use this value to … throttle") | xrdp throttles on frames in flight (2, mm:1473-1505) and honours only SUSPEND_FRAME_ACKNOWLEDGEMENT (mm:1523-1544). Acks pass through the proxy unchanged | conforms | Ignoring queueDepth beyond SUSPEND is upstream xrdp behaviour (a SHOULD). The encoder adds no latency of its own (1 in, 1 out). |
| Capability negotiation and AVC444 (2.2.3.x; AVC_DISABLED 0x20 for 10.x; AVC420_ENABLED 0x10 for 8.1; AVC_THINCLIENT 0x40 is a preference) | xrdp confirms the highest allowed capset and never sends AVC444/AVC444v2 (xorgxrdp uses codec 0x000B). No H.264 for 8.0, 8.1 without AVC420_ENABLED, or 10.x with AVC_DISABLED (mm:1348-1418) | conforms | A client that asks for 4:4:4 gets 4:2:0. That is allowed, because the server picks the codec. Text and thin lines lose chroma detail compared with Windows hosts. |
| Resize | Encoder re-created; the first frame has SPS+IDR (flags 3, test) | conforms | – |

## 11. Changes made in this review

| Change | Files | Test |
|---|---|---|
| Set Error Info codes on every refusal after MCS: broker deny, not-allowed (`reason`), back-end not startable or unreachable, broker timeout, RemoteApp, TLS + PIN, redirection | `broker/proxy-module/fastrdp_plugin.c` (`errinfo_for_reply`, `set_front_errinfo`, `ClientLoginFailure` hook) | `tests/proxy-e2e/run.sh`: 6 new `errinfo` checks. `client.c` now prints the received code and sets RNS_UD_CS_SUPPORT_ERRINFO_PDU like mstsc; `fake_broker.py` has `nogroup` / `nobackend` / `deadport` |
| R1: the broker sends a `reason` with every refusal (`denied`, `not_allowed`, `mfa_failed`, `mfa_timeout`, `backend`); the module maps `mfa_timeout` (was `timeout`, never sent) to 0x409; the webgate shows "not allowed" only for `not_allowed` and answers 503 when the broker is unreachable | `broker/brokerd/fastrdp_broker/{server,protocol,identity,mfa,pamauth}.py`, module `errinfo_for_reply`, `broker/webgate/fastrdp_webgate/app.py` | `broker/brokerd/tests/test_gaps.py` (`ServerPolicyTests`: reason per refusal path, unknown user and wrong password give the same reply, `not_allowed` withheld while MFA is owed); `run.sh`: 4 more `errinfo` checks (`mfafail`, `mfatimeout`, unknown reason, broker without `reason`); webgate `test_gaps.py` |
| Multitransport not offered on the front (no UDP listener) | module `ServerSessionInitialize` | `run.sh`: proxy A runs with core.rdp DEBUG; asserts no `--> MULTITRANSPORT_BOOTSTRAPPING_RESPONSE` |
| TLS path: refuse INFO_PASSWORD_IS_SC_PIN | module `fastrdp_fetch_target` | `run.sh`: `pinuser` never reaches the broker; errinfo 0x7 |
| Refuse INFO_RAIL when `RemoteApp=false` | module `fastrdp_fetch_target` | `run.sh`: `railuser` never reaches the broker; errinfo 0x7 |
| Back-end hop: clear WorkingDir, RemoteApplicationMode, PasswordIsSmartcardPin, SmartcardLogon, LoadBalanceInfo (routing token) | module `ClientPreConnect` | covered indirectly (back-end hop still logs in; e2e `back-end received the token`) |
| Refuse a back-end Server Redirection PDU | module `ClientRedirect` hook | not tested here (needs a redirecting fake back-end) |
| R6: connection type towards xrdp chosen by the broker (`lan_networks`, `xrdp_autodetect_profile`); `[*.autodetect]` in gfx.toml | `broker/brokerd/fastrdp_broker/conntype.py`, `config.py`, `server.py`; module `apply_connection_type`; `gfx.toml.j2`, `broker.toml.j2`, `roles/common` | `broker/brokerd/tests/test_conntype.py`; `run.sh`: front type 7/2 reported, broker's `lan` reaches the back-end as 6, missing/unknown keeps the client's; `tests/ansible/test_templates.py` |
| R2: MFA grace for reconnects, `[mfa] reconnect_grace` (seconds, default 0 = off) and `reconnect_grace_same_address` (default true): a login whose second factor privacyIDEA confirmed and whose session started records an entry (account, `nla`/`tls`, Kerberos principal, client address); reconnects matching it within the period skip OTP/push. Absolute from the real second factor, memory only, `fastrdpctl clear-grace [USER]` | `broker/brokerd/fastrdp_broker/{grace,server,config,protocol,__main__}.py`; `roles/common` (`fastrdp_mfa_reconnect_grace*`, validation), `broker.toml.j2`; `fastrdpctl.8` | `broker/brokerd/tests/test_reconnect_grace.py` (off by default, skip and log, expiry, absolute, address on/off, method and principal binding, nothing recorded on MFA failure, refusal, back-end error, exempt or `nla_kdc_enforced`; first factor, account and group checks still run; TLS OTP replay; clear); `tests/ansible/test_templates.py`. No e2e case: the proxy module is unchanged |
| Webgate: `rdp_parameters` can no longer override hostname, port, username, password or `security`; a pinned fingerprint removes `ignore-cert` | `broker/webgate/fastrdp_webgate/app.py` | `broker/webgate/tests/test_gaps.py::test_rdp_parameters_cannot_override_security_or_pin` |
| xrdp patch: IDR after lost output (`force_idr`, `forced-idr`); full-range BT.709 VUI and black | `patches/xrdp/0001-*.patch` (regenerated with `git format-patch` against pristine 0.10.6.1) | `patches/xrdp/test/test_ffmpeg_encoder.c`: no B-frames or mid-GOP IDR, Baseline/Main profile, full-range VUI, SPS+IDR after lost output, then P-frames, full-range black |
| R8: the broker call ends as soon as the front client goes away (TCP FIN/RST on the front socket, found through the peer's event handles) or the proxy's `abort_event` is set; logged as `front connection closed while waiting for the broker`, no error info (nobody to send it to). The broker cancels the login when the proxy closes the connection: a push wait stops polling privacyIDEA, a session start under way completes but is not recorded as connected, a reply that cannot be written is no longer an "unexpected error" | `broker/proxy-module/fastrdp_plugin.c` (`abort_fds()`, `broker_call()`); `broker/brokerd/fastrdp_broker/{server,mfa,privacyidea,protocol}.py` (`Broker.login_unless_abandoned`) | `run.sh`: `pushwait` (fake broker waits 8 s as for a push, client gives up after 1 s): broker connection closed early (< 4 s), proxy logs the abandoned request; `broker/brokerd/tests/test_gaps.py` (`AbandonedLoginTests`, push wait cancel in `SecondFactorTests` / `PrivacyIdeaTests`) |
| R3: `[FastRDP] AllowTlsFrom` (addresses/CIDRs, IPv4-mapped IPv6 as IPv4, empty = any) limits TLS logins to the listed TCP peers before anything reaches the broker; refused with ERRINFO_SERVER_DENIED_CONNECTION 0x7. The check sits in `ServerFetchTargetAddr`: `ServerPeerLogon` runs right after X.224/TLS negotiation, before MCS, when no error info can reach the client. Ansible `fastrdp_tls_login_sources`: `127.0.0.1,::1` with web access but no TLS logins, else empty | `broker/proxy-module/fastrdp_addr.h`, `fastrdp_plugin.c` (`tls_peer_allowed()`); `roles/common` (default, check), `roles/freerdp_proxy/templates/proxy.ini.j2` | `tests/proxy-module/test_addr.c` (`make test-proxy-module`); `run.sh`: proxy C with a non-matching list refuses `outsider` with 0x7 and logs the peer address, the broker never sees it, proxy A (`127.0.0.0/8, ::1`) serves every other check; `tests/ansible/test_templates.py` (lab, web-only, NLA-only, explicit list; refused malformed lists) |
| R4 + identity-only Remote Credential Guard: an unsupported RCG request gets an RDP_NEG_RSP without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED instead of a dropped TCP connection; TSRemoteGuardCreds without `supplementalCreds` are parsed. Opt-in `[FastRDP] AcceptRemoteGuard` (Ansible `fastrdp_accept_remote_guard`, default false): the module sets `FreeRDP_RemoteCredentialGuard` on the front before `freerdp_peer_initialize()` copies it into the negotiation, installs `peer->RemoteCredentials` (`fastrdp_remote_credentials()`: zero and discard the tickets, refuse when the option is off), clears the setting for the back-end hop, and sends `"remote_guard": true` without a password; the broker logs `remote credential guard: identity only, credentials discarded`, no session TGT (`session_tgt = required` refuses), MFA as for SSO NLA | `patches/freerdp/0002-*`, `0003-*` (`fastrdp-freerdp3` 3.32.2-2); `broker/proxy-module/fastrdp_plugin.c`; `broker/brokerd/fastrdp_broker/{server,protocol}.py`; `roles/common`, `roles/freerdp_proxy/templates/proxy.ini.j2` | `run.sh`: TLS client requiring RCG gets the negotiation response (client log), never reaches the broker; `run_nla.sh` (MIT KDC, forwardable TGT, `HOST/localhost`): refused cleanly without the option, identity-only login with it (`remote_guard`, no password), password NLA unchanged; broker `test_server.py`, `test_session_tgt.py`, `test_kdc_enforced.py`; `tests/ansible/test_templates.py` |
| R5: the front NLA acceptor offers Kerberos (and U2U) only. The module sets `FreeRDP_AuthenticationPackageList=!ntlm` on the front settings and installs a refusing `SspiNtlmHashCallback`; that callback is what makes `credssp_auth_setup_server()` hand the list to WinPR's Negotiate (it honours it only with auth data: keytab, SAM file or hash callback), and it leaves the Kerberos keytab handling (`KRB5_KTNAME`) as it was. A wrapper around the transport's `ReadPdu` reads the mechTypes of the client's first TSRequest and logs `client <addr> attempted NTLM (offered: …); only Kerberos NLA is accepted: check …` when NTLM comes without Kerberos; it removes itself after that PDU. The back-end hop's package list is set explicitly (`!kerberos` with NLA, none without) | `broker/proxy-module/fastrdp_plugin.c` (`fastrdp_server_session_init()`, `fastrdp_ntlm_refused()`, `fastrdp_read_pdu()`, `fastrdp_client_pre_connect()`), `broker/proxy-module/fastrdp_spnego.h` | `tests/proxy-module/test_spnego.c` (`make test-proxy-module`: Windows-style and FreeRDP offers, bare NTLMSSP, truncated and malformed PDUs); `run_nla.sh`: an NTLM-only FreeRDP client fails in NLA within 5 s, the proxy logs the attempt and the hint, never runs NTLM (no SAM lookup), a client offering WinPR's default `[U2U, Kerberos, NTLM]` still logs in with Kerberos and is not reported; `run.sh` unchanged (30/30) |
| Kerberos user-to-user for mstsc (field report 2026-10-21, [windows-clients.md](windows-clients.md) §3.14): the WinPR U2U acceptor answers with the TGT of the machine account found in its keytab (`<NAME>$@REALM`), then tries the service principal itself (MIT, FreeIPA), else logs which keys are missing. `fastrdp-termsrv-keytab` copies the machine account's entries whose kvno, enctype and key equal a TERMSRV entry's (AD: one key set per account, no new key for the proxy; `-n` / `FASTRDP_TERMSRV_KEYTAB_MACHINE=no` to leave them out); the identity role fails on AD without them; the module logs the client's KERB-TGT-REQUEST at INFO | `patches/freerdp/0004-*` (`fastrdp-freerdp3` 3.32.2-3); `broker/sbin/fastrdp-termsrv-keytab`, `termsrv.conf`; `roles/identity`; `broker/proxy-module/fastrdp_plugin.c` (`fastrdp_read_pdu()`), `fastrdp_spnego.h` (`fastrdp_tsrequest_krb5_tok()`) | `run_nla.sh` (22): AD-like MIT KDC (`TERMSRV/localhost` alias of `FASTRDP$`, kdcpolicy `kdc_adlike.c` refuses SPNs as AS clients): U2U-only client logs in with the machine account keys (fails without 0004 with the field report's error), fails with TERMSRV keys only and names them, works in MIT/FreeIPA mode with TERMSRV keys only; `test_spnego.c` (mstsc's 78-byte KERB-TGT-REQUEST, AP-REQ, bare and malformed tokens); `tests/identity/test_termsrv_helpers.py` |
| Server Status Info PDUs from the back-end reach the front client only when it set RNS_UD_CS_SUPPORT_STATUSINFO_PDU ([MS-RDPBCGR] 3.3.5.7.2); otherwise the proxy drops them and logs at DEBUG | `patches/freerdp/0006-*` (`fastrdp-freerdp3` 3.32.2-5), `server/proxy/pf_update.c` | No dedicated test (no test back-end sends the PDU); `run.sh` 39/39 against the patched build |
| Desktop picker on the waiting screen (`[broker] desktop_picker`, opt-in): input read during PostConnect (see "Waiting screen: Bitmap Updates"); FreeRDP handles PDUs read inside PostConnect as input instead of running PostConnect again | `patches/freerdp/0007-*` (`fastrdp-freerdp3` 3.32.2-6), `libfreerdp/core/peer.c`; `broker/proxy-module/fastrdp_plugin.c` (`ws_picker_*()`, `broker_call()`), `fastrdp_panel.h`; `broker/brokerd/fastrdp_broker/{server,ui,config,protocol}.py`; `roles/common`, `broker.toml.j2` | `run.sh` (73 checks, 71 without zxing-cpp): picker offered only with the waiting screen; top-row digit, keypad with NumLock, arrows + Enter, Esc, Unicode digit, click, countdown with and without a move, keys typed before the picker ignored, client closed during the picker (broker connection closed at once); `tests/proxy-module/test_panel.c`; `broker/brokerd/tests/test_desktop_picker.py`; `run_nla.sh` 24/24 and `run_smartcard.sh` 6/6 (p11-kit, SoftHSM) unchanged |

| Shutdown Request answered with Shutdown Request Denied once the session runs (1.3.1.4.1); before PostConnect accepted the client, still closed at once | `patches/freerdp/0008-*` (`fastrdp-freerdp3` 3.32.2-7), `libfreerdp/core/peer.c` | `run.sh` (78 checks without zxing-cpp; minimal local FreeRDP 3.32.2 build with 0001–0008, without Kerberos): the e2e client sends the PDU itself (`E2E_SHUTDOWN_AT_MS`, through the transport) and watches for the answer. During a session (`holdsession`: proxy A accepted the client, back-end proxy B still holds the login): Denied within 1 ms, the proxy keeps the connection, the client's own disconnect ends the session (session end at broker A, back-end connection closed); during the picker: closed at once, login abandoned. Without 0008 the two session checks fail (75/77, before the next check was added). Also new: the back-end ends a running session (proxy B closes with 0x400): the client gets the forwarded code, Deactivate All and an Ultimatum (reason 3 on the wire, see §5), not a bare close. `run_nla.sh` and `run_smartcard.sh` not rerun (no Kerberos in that build) |

Every e2e check failed against the old module, and passes with the new one (16/16, local
FreeRDP 3.32.2 build; 20/20 after R1; 28/28 after R3 and R8; 30/30 after R4, and
`run_nla.sh` 11/11; without `patches/freerdp/0002`/`0003` 29/30 and 6/11; `run_nla.sh`
16/16 after R5, 13/16 with the old module). Encoder tests: libx264, plus NVENC and VA-API falling back to
libx264, 17/17 each.

## 12. Recommended changes not made

| # | Where | Change | Why |
|---|---|---|---|
| R1 | `broker/brokerd/fastrdp_broker/server.py` | (done, [§11](#11-changes-made-in-this-review)) a machine-readable `"reason"` on every refusal while keeping `"error": "access denied"`: `denied`, `not_allowed`, `mfa_failed`, `mfa_timeout`, `backend`, documented in `protocol.py` | The module maps them to 0x7 / 0x9 / 0x7 / 0x409 / 0x400 (`errinfo_for_reply()`, `fastrdp_plugin.c:2164-2182`). |
| R2 | `server.py`, `grace.py` | (done, [§11](#11-changes-made-in-this-review), opt-in) MFA grace for reconnects: skip the second factor if the same user (and optionally the same client address or principal) passed MFA within N seconds (`[mfa] reconnect_grace`, default 0 = off; [auth-matrix.md](auth-matrix.md#reconnect-grace)) | Without ARC support every network drop costs a new push ([§6](#6-redirection-load-balancing-reconnect)). |
| R3 | `ansible/roles/freerdp_proxy` | (done, [§11](#11-changes-made-in-this-review)) When only the web path needs TLS (`fastrdp_web_enabled` and not `fastrdp_allow_tls_logins`), restrict TLS logins in the module to loopback peers (new `[FastRDP] AllowTlsFrom=127.0.0.1,::1`, Ansible `fastrdp_tls_login_sources`) | Before, any network client could open a TLS session up to the broker's refusal; now other peers get 0x7 from `tls_peer_allowed()` (`fastrdp_plugin.c:2249-2263`) before the broker sees them. |
| R4 | FreeRDP (`nego.c:1335-1360`) | (done, [§11](#11-changes-made-in-this-review), `patches/freerdp/0002`) On REDIRECTED_AUTHENTICATION_MODE_REQUIRED without support, answer RDP_NEG_RSP without the SUPPORTED flag instead of dropping TCP. Plus opt-in identity-only RCG (`AcceptRemoteGuard`) | Clear mstsc error for `/remoteGuard`. |
| R5 | `fastrdp_plugin.c` / [windows-clients.md](windows-clients.md) §5 #4 | (done, [§11](#11-changes-made-in-this-review)) Disable NTLM in the proxy's acceptor, without a FreeRDP change | NTLM attempts fail at the first CredSSP message, and the proxy log says the client had no Kerberos ticket and what to check. |
| R6 | broker (`conntype.py`, `[network]`), module (`apply_connection_type`), `gfx.toml.j2`, `roles/common` | (done) Options 4 + 5: `fastrdp_xrdp_autodetect_profile` (default `wan`) for auto-detect clients, `fastrdp_lan_networks` for clients that get `lan`; explicit client types kept; xrdp only. Applied as the connection type on the back-end hop, because xrdp 0.10.6.1 ignores `[*.autodetect]` (rendered anyway, equal to the profile). No xrdp patch needed | WAN mstsc got uncapped QP streams. |
| R7 | xrdp patch | Large monitors: cap the level (`level=51`, or ≤ 30 fps for > 1080p) or fall back to RFX for surfaces wider than 4096 px; flush the encoder (send NULL, drain) on "no output" instead of only forcing an IDR | After lab S12. |
| R8 | `fastrdp_plugin.c` | (done, [§11](#11-changes-made-in-this-review)) Make the broker call abortable when the front client disconnects: `broker_call()` polls the front socket (POLLRDHUP) and `pdata->abort_event` next to the broker socket (`abort_fds()`, `fastrdp_plugin.c:918-944`); the broker cancels the pending login | `ServerFetchTargetAddr` runs in the front peer's own thread, so nothing sets `abort_event` while it blocks; the front socket is what tells. Before, a user who closed mstsc during a push occupied a proxy thread until the broker answered. |
| R9 | [performance.md](performance.md) | (done) a note that the proxy is TCP only and does no connect-time auto-detection | Expectation management for WAN users. |
| R10 | `broker/brokerd/fastrdp_broker/identity.py` | none needed | The `fastrdp:` hint is stripped and validated against the desktop list; the module never forwards it. |

No changes are needed in `ansible/roles/identity/**` or `ansible/roles/base/**` for the
findings here. The certificate SAN and Kerberos items there are covered in
[windows-clients.md](windows-clients.md) §5.

## 13. Lab tests

| ID | Client / tool | Action | Expected / what to record |
|---|---|---|---|
| S1 | mstsc (W10, W11), `.rdp` `enablecredsspsupport:i:0` | Connect to: (a) NLA-only fastrdp; (b) `fastrdp_allow_tls_logins=true`; (c) web enabled but TLS logins off | (a) RDP_NEG_FAILURE 0x5, NLA-required dialog; (b) Client Info logon; without saved credentials ERRINFO 0x7; (c) ERRINFO 0x7 from `AllowTlsFrom` (proxy log `non-NLA login from <addr> refused`). Record the exact dialog texts |
| S2 | mstsc `/remoteGuard` (W10, W11); then with `fastrdp_accept_remote_guard: true` | Connect | Default: mstsc's own "not supported" error instead of a network error (R4); proxy log `REDIRECTED_AUTHENTICATION_MODE_REQUIRED but disabled, answering without ...`. Record the dialog text and that no CredSSP starts. With the option: login without a prompt, proxy log `Remote Credential Guard: identity only`, no TGT in the session; whether mstsc sends `supplementalCreds`. Before R4: a bare close |
| S3 | mstsc, Windows App (macOS/iOS), Remmina | NLA login with MFA push; approve after 20 s. Again with the waiting screen (`fastrdp_proxy_waiting_screen`, default on; push, `web` with a phone scanning the QR code, 16 bpp) and `fastrdp_proxy_status_info: true`. Then with `fastrdp_desktop_picker: always`: choose by digit, keypad, arrows + Enter, click and touch, let the countdown run out, close the client during the picker. With `fastrdp_mfa_mode: code_or_web`: the code field per [lab-waiting-screen-input.md](lab-waiting-screen-input.md) (layouts, keypad, soft keyboards, input trace) | What the client shows while waiting (empty window or progress dialog); reactivation after the back-end is connected. With the waiting screen: panel shown within 1 s, countdown updates, QR code scannable from the monitor, no panel remains after the desktop appears (also when the back-end picks another resolution); whether mstsc shows anything for Status Info PDUs. Picker: every way of choosing starts that desktop, keys typed during the push do not count, the pointer is visible over the panel, no stuck modifier key in the session |
| S4 | mstsc | Refusals: user not in `allow_groups`, wrong desktop group, MFA reject, MFA timeout, back-end unit failing, broker stopped | Dialog text for ERRINFO 0x7 / 0x9 / 0x400 / 0x409. Expected: 0x9 for `allow_groups` and desktop group (NLA, or TLS when no MFA is due), 0x7 for MFA reject, 0x409 for MFA timeout, 0x400 for a failing back-end or a stopped broker. Wireshark (RDP dissector, TLS keys via SSLKEYLOGFILE on a FreeRDP client) or FreeRDP `/log-level:TRACE` to see Set Error Info |
| S5 | Wireshark, mstsc | Connect; filter `rdp` / `udp.port==3389` | No SC_MULTITRANSPORT block in the GCC response, no Initiate Multitransport Request, no UDP 3389 packets from the client; connection time compared with the previous build |
| S6 | mstsc RemoteApp (`.rdp` `remoteapplicationmode:i:1`) | Connect | Error dialog (ERRINFO 0x7), no hang |
| S7 | mstsc `.rdp` `alternate shell:s:fastrdp:gnome`, `alternate shell:s:C:\Windows\notepad.exe`, `shell working directory:s:C:\` | Connect | gnome desktop / default desktop; nothing executed; no working directory in the xrdp/sesman log |
| S8 | mstsc | Pull the network for 30 s during a session, then restore | Whether mstsc auto-reconnects or shows "connection lost"; whether a new MFA push is needed (R2); session state preserved |
| S9 | mstsc (resize window, multimon), Windows App, Guacamole | Dynamic resize on xrdp, GNOME, Plasma (KRdp), wlroots | Display follows (xrdp, g-r-d); KRdp stays at its first size |
| S10 | `proxy.ini` with `AudioInput=false` (drdynvc intercept mode) | Connect with mstsc, use GFX | GFX still works through the intercepting drdynvc path |
| S11 | mstsc smartcard (PIV) over NLA | Login | Back-end hop Client Info flags without INFO_PASSWORD_IS_SC_PIN (FreeRDP proxy log at core.info DEBUG: "Client Info Packet Flags") |
| S12 | mstsc, Windows App, FreeRDP 3; GPU host with VA-API or NVENC | 3840×2160@60 single monitor; 5120×1440; 2×2560×1440 | Encoder log `opened for WxH`; level_idc (`ffprobe` on a dumped stream or the patch test with `W=3840`); MF decoder accepts level 5.2 or shows black or corruption; fallback for > 4096 px |
| S13 | mstsc with `connection type:i:7` (default) vs `:i:2` vs `:i:6`; once from an address in `fastrdp_lan_networks`, once from outside | Bandwidth-limited link (`tc netem rate 10mbit`), xrdp session | Proxy log `back-end connection type N (client sent 7)`; broker log `connection type wan towards xrdp`; bitrate: 7 outside the LAN ≈ `[*.wan]` cap (≤ 15 Mbit/s), 7 inside = uncapped, 2 = `[*.broadband_low]` everywhere; picture quality and latency at 10 Mbit/s with `wan` vs `broadband_high` to choose the site default (R6) |
| S14 | mstsc with a GPU encoder | Force output loss (temporarily lower `XRDP_GFX_MAX_COMPRESSED_BYTES`) | Picture recovers on the next frame (IDR) instead of at the next GOP |
| S15 | mstsc (W10, W11) against `fastrdp-freerdp3` ≥ 3.32.2-7, MFA mode `web` (or `code_or_web`) | During a session click the X in the connection bar; then *Connect* again in the same mstsc; also the X while the waiting screen shows. Then the same after logging out inside the session (GNOME: *Log Out*; xrdp desktop: its logout), without the X | mstsc's own "disconnect" dialog (its text) and a clean close; proxy log without `disconnect provider ultimatum sent to peer` for the session; the next *Connect* shows the waiting screen with the QR code and the approval lets it through (field report 2026-10-23: black window before the patch). The X during the waiting screen: the login is abandoned at once, broker log `abandoned`; record mstsc's behaviour. After the logout: mstsc's message (field report 2026-10-23, gnome-remote-desktop: the proxy forwarded 0x1, then Deactivate All, 0x1 and an Ultimatum that reads "user requested"; the next *Connect* in the same mstsc was closed by mstsc after 7.5 s while the login waited, cause unknown), then whether the next *Connect* in the same mstsc shows the panel. On the Windows client, Event Viewer → *Microsoft-Windows-TerminalServices-ClientActiveXCore/Operational* for both connections (disconnect reason codes) settles what mstsc made of the end and why it closed the next connection. Details: [lab-waiting-screen-input.md](lab-waiting-screen-input.md) F19 |

## Status summary

| Area | conforms | deviation | risk | unknown | fixed |
|---|---|---|---|---|---|
| 1 Security negotiation | 4 | 0 | 0 | 0 | 2 |
| 2 CredSSP | 3 | 0 | 0 | 0 | 1 |
| 3 Client Info / swap | 4 | 1 | 0 | 0 | 4 |
| 4 Licensing | 2 | 0 | 0 | 0 | 0 |
| 5 Session end / error info | 1 | 1 | 0 | 1 | 3 |
| 6 Redirection / reconnect | 1 | 0 | 1 | 0 | 1 |
| 7 Multitransport | 0 | 0 | 0 | 0 | 1 |
| 8 Channels | 6 | 0 | 0 | 0 | 1 |
| 9 Display control | 3 | 0 | 0 | 1 | 0 |
| 10 H.264 / AVC420 | 7 | 0 | 1 | 0 | 2 |
| **Total (52 rows)** | **31** | **2** | **2** | **2** | **15** |

The web path rows are in §1 (`security=tls`), §3 (AlternateShell hint via `initial-program`)
and §9 (`resize-method=display-update`). The webgate fix is listed in §11.
