# Windows clients (mstsc) – Kerberos NLA assessment

Status: analysis done on 2026-10-19. It covers FreeRDP 3.32.2 (`third_party/sources.yml`)
and the fastrdp module and broker at commit `fe9743c`. **No Windows machine was used.**
Everything below is one of three kinds of evidence:
- **verified**: from source code (file:line refers to the FreeRDP 3.32.2 tarball unless
  noted) or from a local harness run;
- **documented**: stated in Microsoft or RFC documents, with a link;
- **inference**: reasoning that a Windows lab test still has to confirm (§6, §7).

Follow-up fixes (2026-10-20, see §5): the broker takes the Kerberos principal as the
identity (UPN ≠ sAMAccountName, §3.6); the identity role enforces and checks AES keys,
registers the FreeIPA short name and optional alias SPNs (§3.2); the self-signed
certificate names the short name and aliases (§3.7).

## 1. Short answer

**Yes, with conditions.** A Windows 10/11 mstsc should be able to log in to fastrdp with
Kerberos NLA if all of the following hold:
1. The client gets a service ticket for `TERMSRV/<name it connects to>` from AD. That
   means the name is the FQDN or the short name, never an IP address or an unregistered
   alias, and a KDC is reachable (LAN, VPN or a KDC proxy).
2. That ticket and the session key are **AES**. RC4 sessions fail (verified, §3.4).
3. Windows puts MS-KRB5/KRB5 first in its SPNEGO list. That is the normal case for an AD
   user with a ticket, and the local harness reproduces it successfully.

  If Windows instead puts NegoEx first, a WinPR acceptor bug can break the exchange (§3.3).
  Whether a domain-joined Windows client ever does that has to be tested.

These cases always fail, by design:
- NTLM (IP address, no KDC, Entra-only devices);
- Remote Credential Guard.

Single sign-on without a typed password works as an NLA login. Such sessions get **no
Kerberos TGT** unless Windows delegates the password, and with Credential Guard (on by
default on Windows 11 22H2+ Enterprise) Windows does not delegate the logon password (§4).

## 2. Support matrix (expected)

| Client situation | Expected result | Session TGT (X11 / GNOME, Plasma) | Confidence |
|---|---|---|---|
| AD-joined, FQDN, password typed in the mstsc prompt | works (Kerberos, password delegated as TSPasswordCreds) | yes / no | high (code), lab pending |
| AD-joined, FQDN, SSO, GPO *Allow delegating default credentials* = `TERMSRV/*`, no Credential Guard | works without a prompt | yes / no | medium |
| AD-joined, FQDN, SSO, Credential Guard on (Win 11 22H2+ Enterprise default) | mstsc prompts for the password (SSO delegation blocked), then as row 1 | yes / no | documented by MS, lab pending |
| AD-joined, FQDN, **`mstsc /restrictedAdmin`** | works **without a prompt**: Kerberos with the logged-on user, empty TSPasswordCreds | no / no | medium |
| AD-joined, `mstsc /remoteGuard` or GPO "Require Remote Credential Guard" | **refused** at protocol negotiation (fastrdp does not advertise RCG) | – | high (code) |
| GPO "Restrict credential delegation" (RCG *or* Restricted Admin) | falls back to Restricted Admin, works | no / no | medium |
| AD-joined, short name (`rdp1`) | works (Identity role registers `TERMSRV/RDP1`); certificate name warning unless the short name is in the SAN | as above | medium |
| Any client, **IP address** | **refused**: no ticket → NTLM → module rejects NLA without Kerberos | – | high |
| DNS alias / load-balancer name not registered as SPN | **refused** (NTLM fallback) | – | high |
| Non-joined Windows, user `alice@lab.example.com`, KDC reachable | works like row 1 | yes / no | medium |
| Non-joined Windows, user `LAB\alice` (NetBIOS domain) | **likely NTLM** (KDC not locatable from the NetBIOS name) → refused | – | inference |
| Non-joined, off-network, no VPN, no KDC proxy | refused (NTLM) | – | high |
| Non-joined, off-network, GPO/registry KDC proxy (MS-KKDCP) | works if the KDC proxy is reachable and trusted | yes / no | inference |
| Entra-ID-only joined Windows (no on-prem AD ticket) | refused: Windows offers `[NegoEx, NTLM]` (FreeRDP #13168) | – | high |
| Smartcard / PIV / YubiKey PIV (mstsc PKINIT) | works like the FreeRDP smartcard path; PIN is not forwarded | no / no | medium |
| Windows Hello for Business, certificate trust | as smartcard | no / no | inference |
| Ticket/session key RC4-HMAC only | **fails** (pubKeyAuth/MIC format) | – | verified with MIT, §3.4 |
| User whose UPN prefix ≠ sAMAccountName, typed as UPN | works: the principal's account is logged in (fixed, §3.6) | yes / no | high (code), lab pending |

"Session TGT" means the X11 back-ends (xrdp, `pam_sss` through the one-time token) get a
TGT when a password was delegated. GNOME and Plasma never do (see
[auth-matrix.md](auth-matrix.md)).

## 3. Findings

### 3.1 SPNEGO from Windows: the acceptor's mechanism handling (Q1)

Windows SPNEGO initiators send a `negTokenInit` with mechTypes such as
`[MS-KRB5 1.2.840.48018.1.2.2, KRB5 1.2.840.113554.1.2.2, NegoEx 1.3.6.1.4.1.311.2.2.30, NTLMSSP]`
(seen in JDK-8078439). Devices without an AD ticket send `[NegoEx, NTLM]` (FreeRDP issue
#13168, Windows 11 Entra-joined). The optimistic `mechToken` always belongs to the
**first** OID.

WinPR acceptor (`winpr/libwinpr/sspi/Negotiate/negotiate.c`), verified:
- **MS-KRB5 is accepted.** `negotiate_GetMechByOID()` maps `kerberos_wrong_OID`
  (1.2.840.48018.1.2.2) to plain Kerberos (negotiate.c:200-218, OID at :96). The
  acceptor echoes the OID as received in `supportedMech`, which is what Windows expects.
- **NegoEx is skipped correctly since 3.31.0.**
  - NegoEx is not in `MechTable` (negotiate.c:109-113).
  - An optimistic NegoEx token makes the acceptor fall back to the next usable OID
    (negotiate.c:1127-1159), with `context->mic = TRUE` (:1142).
  - Before 3.31.0 this fallback passed an empty sub-context handle and failed with
    SEC_E_INVALID_HANDLE. That bug (#13168, fixed by PR #13169, ChangeLog 3.31.0) probably
    explains the unresolved FreeRDP issue #11189, "Kerberos not working with mstsc"
    (shadow server 3.11.1).
- **Duplicate Kerberos OIDs** are handled: "Microsoft may send two versions of the
  kerberos OID" (negotiate.c:1157).
- **Negotiated mechanism.** With an AD ticket the result is Kerberos, `supportedMech`
  MS-KRB5. The module sees package `Kerberos`
  (`nla_used_kerberos()`, `broker/proxy-module/fastrdp_plugin.c:142-161`).
- **mechListMIC.**
  - If the first OID is a Kerberos OID and its AP-REQ is accepted, the acceptor answers in
    one round with accept-completed and the AP-REP, without a MIC (negotiate.c:1185-1191
    and :1250-1263). RFC 4178 §5 requires no MIC when the initiator's first mechanism is
    selected.
  - Otherwise (NegoEx first, or no optimistic token) both sides exchange a MIC.

**Harness results.** The scratch harness feeds hand-built Windows-style tokens to the real
WinPR 3.32.2 acceptor (§8). The Kerberos AP-REQ comes from MIT GSSAPI.

| Scenario | Result |
|---|---|
| `[MS-KRB5, KRB5, NegoEx, NTLM]`, optimistic AP-REQ | **completes in 1 round**, accept-completed + AP-REP, no MIC; package `Kerberos`, identity `alice@REALM` |
| `[NegoEx, MS-KRB5, KRB5, NTLM]`, optimistic NegoEx | Kerberos selected (accept-incomplete, supportedMech MS-KRB5); AP-REP plus acceptor MIC, which MIT verifies. **Then the bug in §3.3.** |
| as above, no optimistic token | same as the previous row |
| `[NegoEx, NTLM]` | NTLM selected (request-mic) → refused later by the module |
| AP-REQ framed with the MS-KRB5 OID instead of KRB5 | Kerberos acceptor rejects the framing (`kerberos.c:1598-1608`, accepts only 1.2.840.113554.1.2.2 or U2U). Negotiate then **silently selects NTLM** → refused |

The last row matters only if Windows frames the AP-REQ with the MS OID. Heimdal's krb5
acceptor accepts only the standard OID in the framing, and Samba/Heimdal servers work
with Windows clients. So Windows almost certainly uses the standard OID there and lists
MS-KRB5 only in mechTypes/supportedMech (inference; MIT also accepts the MS OID, to be
safe). Still worth a robustness fix upstream (§5).

### 3.2 SPN, keytab, names (Q2)

- **AD** (`ansible/roles/identity/tasks/ad.yml:17-24`):
  - registers `TERMSRV/<ansible_fqdn>` and `TERMSRV/<SHORTNAME>` via `adcli update`;
  - `fastrdp-termsrv-keytab` copies all `TERMSRV/*` entries from `/etc/krb5.keytab`;
  - **Fixed:** the role checks that both SPNs (and the aliases) have an AES key at the
    newest kvno (`fastrdp-termsrv-check`, `klist -ke`) and fails otherwise;
    `tests/smoke/check-host.sh` runs the same check.
- **FreeIPA** (`ipa.yml`): `TERMSRV/<fqdn>`, and (**fixed**) the short name plus
  `fastrdp_termsrv_aliases` as principal aliases (`ipa service-add-principal`). Aliases
  share the canonical keys, so the keytab only holds `TERMSRV/<fqdn>`.
- **Key selection:**
  - The acceptor calls `krb5_rd_req(..., server=NULL, keytab)` (`kerberos.c:1639`), so MIT
    tries every keytab entry.
  - All SPNs of a computer account share the account's keys, so `TERMSRV/rdp1`,
    `TERMSRV/RDP1` and `TERMSRV/rdp1.lab.example.com` tickets all decrypt with any
    TERMSRV entry. SPN case does not matter.
- **Enctypes:** AES is mandatory (§3.4). **Fixed:** the role runs `adcli` with only
  `fastrdp_termsrv_enctypes` permitted (default AES256+AES128), so adcli writes AES keys
  and `msDS-SupportedEncryptionTypes` `0x18` (`0x1C` with `arcfour-hmac` in the list).
  adcli never widens an existing value: an account set to RC4 only (`0x4`) must be
  changed in AD first; the keytab check then fails with that hint.
- **IP address:**
  - Windows asks for `TERMSRV/<ip>`, which does not exist, and falls back to NTLM.
  - The WinPR NTLM acceptor has no SAM/hash callback in the proxy, so NTLM fails at
    `ntlm_compute.c:285` (SamOpen) or at the latest in the module:
    `fastrdp_server_peer_logon()` (`fastrdp_plugin.c:481-486`) refuses NLA that is not Kerberos.
  - **TLS logins do not help mstsc:** after a failed CredSSP, mstsc does not fall back to
    TLS. A TLS login also needs credentials in the Client Info PDU, which mstsc only sends
    with saved credentials and CredSSP disabled (`enablecredsspsupport:i:0`). The proxy has
    no logon screen (`fastrdp_fetch_target()`, `fastrdp_plugin.c:611-616`).
  - Options for IP access: none recommended. Windows 10 1507+ can do Kerberos to an IP if
    the client has the `TryIPSPN` registry value and the IP is registered as an SPN; avoid
    this.
- **Aliases / farms:** a shared name in front of several fastrdp hosts (DNS round robin,
  load balancer) needs one SPN `TERMSRV/<alias>`. An SPN can only belong to one account,
  so all hosts need the same keys: a dedicated service account plus a distributed keytab,
  not the computer accounts. Not covered by the identity role (gap). DNS aliases of a
  single host: `fastrdp_termsrv_aliases` (registered with the join account).
- **Cross-domain users:** a user from a child domain gets a ticket whose client realm
  is the child realm. The broker refuses realms not in `[auth] realms`
  (`server.py:63-64`).

### 3.3 Bug: duplicate mechListMIC from the WinPR acceptor (NegoEx-first / MIC path)

Verified with the harness. When a MIC exchange is needed, the WinPR acceptor sends its
MIC together with the AP-REP (round 2, `negState` absent).

When the initiator's final token carries only its mechListMIC and **no
`negState=accept-completed`**, the acceptor does two things:
- it verifies the MIC;
- it **generates a second MIC** (negotiate.c:647, the condition is only
  `input negState != ACCEPT_COMPLETED`) and returns SEC_E_OK *with* an output token.

This omission is allowed: RFC 4178 makes negState optional after the first reply. Samba's
initiator omits it, and Heimdal notes that Windows sometimes omits it.

`nla_server_authenticate()` then does the following (`libfreerdp/core/nla.c:899-913`):
1. it sends that token as a TSRequest without pubKeyAuth;
2. it **waits for another TSRequest**.

A CredSSP client sends pubKeyAuth in the same TSRequest as its final MIC (MS-CSSP 3.1.5).
It is then waiting for the server's pubKeyAuth, so the handshake stalls or the client
aborts.

- FreeRDP's own initiator sets accept-completed in that token, which is why FreeRDP↔FreeRDP
  works (harness scenario `negoex-cs`).
- FreeRDP clients never reach this path against fastrdp anyway: they offer U2U first and
  the acceptor serves it in one round (harness `winpr-init`).

**Impact on mstsc:** only when the Kerberos mechanism is not Windows' first choice
(NegoEx first) *and* Windows omits negState. Lab test L3 (§7) decides. A domain-joined
client with an AD ticket normally lists MS-KRB5 first and is not affected.

**Fix (proposed upstream to FreeRDP, not applied in fastrdp):** send our MIC once, and once
the peer's MIC verifies after ours was sent, return SEC_E_OK with no output. Tested in the
harness: the NegoEx scenarios then complete with no extra token; the Kerberos-first and
WinPR-initiator scenarios are unchanged. Patch in Appendix A. A complementary CredSSP
fix in `nla_server_authenticate()` would also make it robust: if pubKeyAuth arrived
together with the final negoToken, do not wait for another TSRequest; send the final
negoToken together with the server's pubKeyAuth.

### 3.4 CredSSP version, nonce, pubKeyAuth, token formats (Q3)

- **CredSSP v6.**
  - The server answers with version 6 (`nla.c:2420`).
  - It uses the client's version to choose the pubKeyAuth form: echo for v<5, SHA-256
    hash with `ClientServerHashMagic` + clientNonce + SubjectPublicKey for v5/v6
    (`nla.c:1126-1176`).
  - Windows 10/11 after the CVE-2018-0886 updates send v6 with clientNonce. Handled
    (verified by code; FreeRDP clients exercise the same path).
- **Server ASC flags:** mutual, confidentiality, connection, use-session-key, sequence
  detect, extended error (`nla.c:822-824`).
- **Wrap/MIC formats (verified):**
  - WinPR's Kerberos SSP implements only RFC 4121 (CFX) tokens: TOK_ID_WRAP
    (`kerberos.c:2330`) and TOK_ID_MIC (`kerberos.c:2511`), whatever the enctype.
  - For RC4-HMAC, Windows uses the RFC 4757 token format (MS-KILE 3.4.5), as MIT does.
  - Harness with an RC4 ticket and session key:
    - MIT `gss_verify_mic` rejects WinPR's MIC (GSS_S_DEFECTIVE_TOKEN);
    - `gss_unwrap` of WinPR's server pubKeyAuth Wrap token fails ("Decrypt integrity check
      failed").
  - With AES both succeed. **RC4 → login fails; AES is required.**
- **TSRequest size:** limited to 64 KiB by the 2-byte DER length parser
  (`transport.c:961-1015`). Large PACs (default MaxTokenSize 48000) fit.
- **TSCredentials** (`nla.c:1443-1611`):

  | What Windows sends | When | Proxy/module behaviour | Session |
  |---|---|---|---|
  | TSPasswordCreds (domain, user, password) | fresh or saved credentials (GPO default: allowed to `TERMSRV/*` after Kerberos/cert server auth), or default credentials if *Allow delegating default credentials* lists the SPN | password forwarded to the broker; X11: one-time token → `pam_sss` → TGT | TGT on X11 |
  | TSPasswordCreds with empty fields | Restricted Admin | no password; user = Kerberos principal (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:513-539`) | no TGT |
  | TSSmartCardCreds (PIN, CSP data, hints) | smartcard credentials | PIN dropped (`PasswordIsSmartcardPin`, `fastrdp_server_peer_logon()`, `fastrdp_plugin.c:527-537`; broker `server.py:72-77`) | no TGT |
  | TSRemoteGuardCreds | Remote Credential Guard | never reached: RDP_NEG_REQ with REDIRECTED_AUTHENTICATION_MODE_REQUIRED is refused because the proxy does not set `RemoteCredentialGuard` (`nego.c:1335-1360`) | refused |

  The delegated password is client-supplied and not verified by the broker on NLA
  (`server.py:58-78`); the Kerberos principal decides who the user is. A wrong delegated
  password only means `pam_sss` gets no TGT.
- **Restricted Admin** is accepted:
  - `RestrictedAdminModeSupported` defaults to TRUE (`settings.c:983`);
  - the server sets RESTRICTED_ADMIN_MODE_SUPPORTED in RDP_NEG_RSP (`nego.c:1628-1629`).

  There is no Windows-style "must be administrator" check; fastrdp's normal account and
  group policy applies. Acceptable, because authentication is still Kerberos, but it is a
  password-less SSO path that admins should know about.

### 3.5 Single sign-on (Q4)

- **No password typed:** NLA completes on the ticket alone. The module requires only a
  Kerberos identity (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:479-506`). The broker's NLA path needs no password
  (`server.py:58-78`) and runs the PAM *account* phase (`ad_gpo_map_remote_interactive`).
- **MFA:**
  - `push` / `otp_or_push` trigger privacyIDEA push with `password=None` (`mfa.py:58-65`).
    That needs the `triggerchallenge` service account
    (`fastrdp_privacyidea_service_user`); otherwise there is no challenge and the login is
    refused.
  - `otp` mode refuses every NLA login (`mfa.py:66`).
- **Desktop session:** the X11/GNOME/Plasma session starts without a TGT unless a password
  was delegated.
- **When Windows SSO actually delivers a password:**
  - only with GPO *Allow delegating default credentials* (not configured = not allowed, per
    Microsoft's ADMX_CredSsp docs);
  - and only **without Credential Guard**. Microsoft: "When Credential Guard is enabled,
    CredSSP is no longer able to use saved or SSO credentials, though cleartext credentials
    can still be supplied". Saved RDP credentials then fail with "Logon attempt failed".
    Credential Guard is on by default on Windows 11 22H2+ Enterprise/Education.
- **Assessment of auth-matrix.md row 2** ("X11 desktops only, and only if Windows delegates
  the password ('Allow delegating default credentials')"): correct but incomplete.
  - Without that GPO, mstsc does not do password-less SSO at all; it prompts (fresh
    credentials). The only password-less path then is Restricted Admin.
  - It should mention Credential Guard, Restricted Admin and the push service-account
    requirement.

### 3.6 User-name matching

**Fixed (2026-10-20).** The broker used to require `principal name ==
normalize(TSCredentials user)`. AD canonicalises the client name in tickets to the
sAMAccountName, so a UPN whose prefix differs (`alice.smith@example.com`, sAMAccountName
`asmith`) was refused.

Now the Kerberos principal is the identity for NLA (`identity.resolve_principal`): plain
principals resolve like before, enterprise principals by their UPN (never by its local
part), then `krb5_aname_to_localname()`. Realms outside `[auth] realms`, principals
without an account, root and multi-component principals are refused. The TSCredentials
user name is informational; when it resolves to a *different* account, the delegated
password is dropped. Details: [auth-matrix.md](auth-matrix.md), Kerberos specifics.

### 3.7 Server certificate and TLS (Q5)

- **Server TLS** (`libfreerdp/crypto/tls.c:929-950`, defaults `settings.c:1309-1315`):
  - TLS 1.2 minimum, no maximum (TLS 1.3 allowed), OpenSSL security level 2 (112-bit,
    `FREERDP_TLS_SECLEVEL_112BIT = 2`);
  - OpenSSL default cipher list, since `AllowedTlsCiphers` is unset;
  - `proxy.ini` `TlsSecLevel` applies only to the back-end client side.

  Windows 10/11 Schannel offers ECDHE-RSA-AES-GCM for TLS 1.2, and Windows 11 also offers
  TLS 1.3. Both are in OpenSSL 3's default list. Compatible (inference, high).
- **Certificate** (`ansible/roles/base/tasks/main.yml:53-74`): either provided
  (`fastrdp_front_cert_src`), or a lab self-signed RSA-3072 certificate with
  CN=`<fqdn>`, EKU serverAuth and (**fixed**) SAN = FQDN, short name and
  `fastrdp_termsrv_aliases`. Not covered: an internal CA (use `fastrdp_front_cert_src`).
- **mstsc behaviour:** mstsc checks the name (as typed), the chain to a trusted root, EKU
  and revocation.
  - Expected (inference): when Kerberos mutual authentication succeeds, mstsc treats the
    server as authenticated. The ADMX texts say "server authentication was achieved by
    using a trusted X509 certificate or Kerberos", so a self-signed cert may not prompt.
  - With NTLM (not possible here) or a name mismatch it warns. With
    `authentication level:i:1` it refuses.
- **Recommendation:**
  - issue the front certificate from the AD CS (or another internal) CA with SAN = FQDN,
    short name and aliases;
  - CRL/OCSP reachable from clients;
  - deploy the root via GPO;
  - keep `authentication level:i:2` until lab test L8 shows whether Kerberos suppresses
    warnings.

### 3.8 MFA with mstsc (Q6)

- **Push** works without interaction on any NLA login. The broker call runs in the
  proxy's PostConnect, i.e. after the front connection sequence has finished
  (Font Map sent), so mstsc probably shows an empty session window rather than
  "Configuring remote session…" while the broker waits (Timeout 120 s,
  `proxy.ini.j2`; lab test S3 in [rdp-spec-conformance.md](rdp-spec-conformance.md)).
- **OTP appended to the password does not work with NLA at all, not even when typed.**
  - With CredSSP+Kerberos the client uses the typed string as the Kerberos password for
    its AS-REQ. A password with an OTP suffix makes the KDC fail pre-authentication (and
    counts a bad password in AD) before fastrdp sees anything.
  - The broker also never splits OTPs on NLA: `first_factor()` returns `otp=None` for
    `method == "nla"` (`server.py:58-78`). `verify()` then uses push, or fails in `otp`
    mode (`mfa.py:54-66`).
  - Appended OTP works only on the TLS path (`server.py:96-115`), which mstsc cannot use
    in practice (§3.2).
  - The current auth-matrix row "NLA, user types a password (mstsc …)" with second factor
    `push` is consistent with this.

### 3.9 Smartcard from Windows (Q7)

mstsc does PKINIT locally with the card (or uses the smartcard logon TGT) and runs
ordinary Kerberos NLA, which looks the same to the acceptor. It then delegates
TSSmartCardCreds: PIN, TSCspDataDetail with keySpec, cardName, readerName, containerName,
cspName, and optional user/domain hints.

FreeRDP parses all of these (`nla.c:1500-1524`, `nla.c:1207-1231`). The module drops the
PIN, uses the Kerberos principal as the user if no hint is sent, and sets
`smartcard: true`. This is the same as the tested FreeRDP path ([smartcard-nla.md](smartcard-nla.md)).

The AD PKI requirements are unchanged: KDC certificates, NTAuth, UPN SAN. For MFA, use
"Smart card is required for interactive logon" plus an exempt group.

Confidence medium; real card + AD + mstsc is lab test L7.

### 3.10 Off-network clients: KDC proxy, RD Gateway (Q8)

- Without a reachable KDC, Windows cannot get the TERMSRV ticket and falls back to NTLM,
  which is refused. Options:
  1. **VPN** (simplest).
  2. **KDC proxy (MS-KKDCP).** Run an HTTPS KDC proxy in front of the DCs, for example
     `python-kdcproxy` behind Apache/nginx, or the Windows *KPS* service. Configure clients
     with GPO *Computer Configuration → Administrative Templates → System → Kerberos →
     Specify KDC proxy servers for Kerberos clients*: realm `LAB.EXAMPLE.COM` →
     `<https kdcproxy.lab.example.com:443:KdcProxy />`.
     - The proxy's TLS certificate must be trusted.
     - FreeRDP clients use `/kerberos:kdc-url:` ([client-guide.md](client-guide.md)).
     - fastrdp does not need to implement this. An optional Ansible role that deploys
       `python-kdcproxy` on the web gateway host would be a reasonable addition (gap).
  3. **RD Gateway (MS-TSGU):** fastrdp has no gateway; FreeRDP has no RD Gateway server.
     - A Windows Server RD Gateway can tunnel to fastrdp:3389 like to any RDP host.
     - The RD Gateway's built-in KDC proxy feature can carry the Kerberos traffic.
     - Not needed if VPN or a KDC proxy exists; untested (inference).
  4. The web path (Guacamole + Keycloak) needs no Kerberos on the client
     ([web-access.md](web-access.md)).

### 3.11 Known FreeRDP issues (Q9)

| Item | Relevance | Status in 3.32.2 |
|---|---|---|
| #13168 / PR #13169 "fix server-side SPNEGO mechanism fallback" (Windows 11 sends `[NEGOEX, NTLM]`; fallback failed with SEC_E_INVALID_HANDLE for every 3.x < 3.31) | NegoEx-first clients | **fixed** (3.31.0) |
| #11189 "Kerberos not working with mstsc" (shadow server 3.11.1, Win 11 23H2/24H2) | exactly this scenario | closed as stale, never root-caused; probably the bug above |
| #13254 NULL check of sub-credentials in the accepting context (gnome-remote-desktop crash) | robustness | fixed (3.31.0) |
| #12162 server-side `SECPKG_ATTR_AUTH_IDENTITY` for Kerberos | used by the module | present (3.22.0) |
| #11722 U2U filtering (`!u2u`) | FreeRDP clients only | present (3.17.0) |
| Duplicate acceptor mechListMIC (§3.3) | NegoEx-first mstsc, if Windows omits negState | **open**, found here |
| MS-KRB5 OID in the AP-REQ framing rejected (§3.1) | only if Windows used it (unlikely) | **open**, found here |
| No RFC 4757 (RC4) Wrap/MIC tokens (§3.4) | RC4 environments | **open**, found here |
| Server-side Remote Credential Guard | RCG clients | not supported by the proxy (only the client side is in progress: #13778, PR #13675) |

Most related reports concern gnome-remote-desktop, which uses the same server NLA. Their
failures are keytab permissions (GNOME Discourse t/34451) and NTLMv1 (g-r-d #244), not
mstsc Kerberos.

## 4. Required AD / client settings

**AD / server:**
- SPNs: `TERMSRV/<fqdn>` and `TERMSRV/<SHORT>` on the computer account (identity role).
  Every other name users type for this host: `fastrdp_termsrv_aliases` (on one account
  only).
- Keys: AES (`fastrdp_termsrv_enctypes`; the role sets `msDS-SupportedEncryptionTypes`
  through adcli and re-keys once if needed). `fastrdp-termsrv-check TERMSRV/<fqdn>
  TERMSRV/<SHORT>` (or `klist -ke /etc/fastrdp/termsrv.keytab`) must show aes256/aes128
  at the current kvno.
- Front certificate from the internal CA with SAN FQDN + short name (+ aliases).
- *Allow log on through Remote Desktop Services* for the RDP users, then
  `fastrdp_ad_gpo_access_control: enforcing`.
- MFA with SSO/Restricted Admin: a privacyIDEA service user with `triggerchallenge`.

**Client GPO (Computer Configuration → Administrative Templates → System → Credentials
Delegation)**, only where password-less SSO with a session TGT is wanted:
- *Allow delegating default credentials*: `TERMSRV/rdp1.lab.example.com` (or
  `TERMSRV/*.lab.example.com`).
- Leave *Allow delegating fresh/saved credentials* at their defaults (TERMSRV/* after
  mutual authentication).
- Do **not** set *Restrict delegation of credentials to remote servers* to "Require Remote
  Credential Guard". "Restrict credential delegation" or "Require Restricted Admin" work,
  but give no TGT.
- Credential Guard disables default-credential delegation regardless of this GPO.
- *Encryption Oracle Remediation*: any value works (server speaks CredSSP v6).

**.rdp / mstsc** (see [client-guide.md](client-guide.md)):
```
full address:s:rdp1.lab.example.com
enablecredsspsupport:i:1
authentication level:i:2
use redirection server name:i:0
prompt for credentials:i:0
```
`prompt for credentials:i:1` forces the fresh-credentials prompt, which delegates a
password (useful with Credential Guard). Clients should use the UPN (also
`marcel.ritter@corp.example.com` for account `mritter`) or `LAB.EXAMPLE.COM\alice`;
non-joined clients not `LAB\alice`.

## 5. Bugs and gaps (summary)

| # | Where | Kind | Proposal |
|---|---|---|---|
| 1 | WinPR negotiate acceptor: second mechListMIC (§3.3) | bug (upstream FreeRDP) | Appendix A patch; if lab L3 shows mstsc affected, carry it in `patches/freerdp/` and report upstream |
| 2 | WinPR Kerberos acceptor rejects MS-KRB5 framing OID, Negotiate then silently picks NTLM (§3.1) | robustness (upstream) | accept `1.2.840.48018.1.2.2` in `kerberos_AcceptSecurityContext()` like MIT does; echo it in the AP-REP |
| 3 | No RC4 (RFC 4757) Wrap/MIC (§3.4) | limitation (upstream) | document AES requirement (done here); optionally fail early with a clear log message when the session key is RC4 |
| 4 | NTLM is offered by the acceptor although the module always refuses it | UX | **open, documented.** No configuration-only fix: `proxy.ini` has no package option. The server's Negotiate honours `AuthenticationPackageList=!ntlm` only when its auth data is set, i.e. with `KerberosKeytab` (or an NTLM SAM file/hash callback) in the front settings (`credssp_auth_setup_server()`), while fastrdp passes the keytab as `KRB5_KTNAME`. A module hook (`ServerSessionInitialize`) setting both is possible without FreeRDP changes, but it changes the acceptor's keytab handling and needs the e2e suites. The WinPR registry key `ntlm=0` is process-wide and would also break the proxy's NTLM hop to GNOME/Plasma |
| 5 | Identity role: no AES enctype setting/check, no alias SPNs, FreeIPA without short name | gap | **fixed:** `fastrdp_termsrv_enctypes`, `fastrdp_termsrv_aliases`, FreeIPA short-name alias, `fastrdp-termsrv-check` in the role and in `check-host.sh` |
| 6 | Base role: self-signed cert covers only the FQDN | gap | **fixed:** SAN = FQDN, short name, aliases; internal CA via `fastrdp_front_cert_src` |
| 7 | Broker principal/user match fails for UPN ≠ sAMAccountName (§3.6) | probable bug | **fixed:** the principal is authoritative for NLA |
| 8 | No KDC proxy offering (§3.10) | gap | optional `kdcproxy` role |
| 9 | auth-matrix.md / client-guide.md: SSO row lacks Credential Guard/Restricted Admin; `LAB\alice` advice for non-joined clients | docs | **done** (UPN and FQDN recommended); revisit after the lab |

## 6. What only a Windows lab can settle

1. Does a domain-joined Windows 10/11 mstsc with a valid ticket put MS-KRB5 first (no MIC
   exchange), or NegoEx first? Also whether hybrid/Entra-registered devices differ.
2. If the MIC path happens: does Windows omit `negState` in its final MIC token, and does
   the unpatched proxy then hang or fail? Does the Appendix A patch fix it?
3. AP-REQ framing OID (expected standard KRB5).
4. Whether Kerberos mutual authentication suppresses the certificate warning for a
   self-signed or internal-CA certificate.
5. Restricted Admin TSCredentials layout, and mstsc's behaviour with it against a
   non-Windows server.
6. Smartcard/WHfB delegation format from a real card.
7. KDC proxy from a non-joined, off-network client.

## 7. Lab test plan

**Setup:**
- AD (Windows Server 2022/2025 DCs) and one fastrdp host joined via the identity role;
- `fastrdp_mfa_mode: none` first, then `push`;
- `wlog` at DEBUG for `com.freerdp.core.nla`, `com.winpr.negotiate` and
  `com.winpr.sspi.Kerberos` (`WLOG_FILTER=com.winpr.negotiate:DEBUG,...` in the unit);
- a Wireshark capture on the client. The CredSSP tokens are inside TLS, so read the
  SPNEGO details from the proxy's DEBUG log (negotiate.c logs every negTokenInit/Resp
  field it reads).

**Before each test:**
- `klist purge` on the client;
- record `klist` (ticket enctype!);
- `nltest /dsgetdc:` reachability.

**Clients:**
- W10: Windows 10 22H2, domain-joined, Credential Guard off;
- W11: Windows 11 24H2 Enterprise, domain-joined, Credential Guard on (default);
- W11-WG: Windows 11 workgroup;
- W11-E: Entra-joined only.

| ID | Client | Action | Expected |
|---|---|---|---|
| L1 | W10, W11 | mstsc to FQDN, type password | success; proxy log `NLA logon: principal alice@LAB…`, package Kerberos; X11 desktop: `klist` shows TGT; GNOME/Plasma: no TGT |
| L2 | W10 | GPO default credentials `TERMSRV/*.lab.example.com`, mstsc to FQDN, no prompt | success without prompt, TGT on X11 |
| L3 | W10, W11 | capture the negTokenInit: mechTypes order, optimistic token type; look for `NegoEx` first. If the MIC path is used: check that the client's last negTokenResp lacks negState and whether the login hangs | Kerberos first: 1-round SPNEGO. NegoEx first: unpatched → hang/failure (§3.3), patched → success |
| L4 | W11 (Credential Guard) | same as L2 | prompt appears (SSO blocked); after typing: success with TGT |
| L5 | W10, W11 | `mstsc /restrictedAdmin /v:rdp1.lab.example.com` | success without prompt, no TGT, broker log user = principal |
| L6 | W10, W11 | `mstsc /remoteGuard`; GPO "Require Remote Credential Guard"; GPO "Restrict credential delegation" | first two: connection refused (proxy log "REDIRECTED_AUTHENTICATION_MODE_REQUIRED but disabled"); third: Restricted Admin, success |
| L7 | W10 | smartcard/YubiKey PIV user, mstsc, select smart card, PIN | success, `smartcard: true`, no PIN in broker log, no TGT |
| L8 | W10, W11-WG | self-signed lab cert vs internal-CA cert; FQDN vs short name | record certificate prompts (Kerberos vs not) |
| L9 | any | connect by IP address | failure ("authentication error"/"logon attempt failed"); proxy log "NLA without Kerberos refused" or NTLM SAM error |
| L10 | W10 | connect by short name `rdp1` | Kerberos success (ticket `TERMSRV/rdp1`), cert name warning unless the SAN contains it |
| L11 | W11-WG | user `alice@lab.example.com` with DC reachable; then `LAB\alice` | UPN: success; NetBIOS: expect NTLM → refused |
| L12 | W11-WG off-network | KDC proxy GPO/registry set, VPN off | success via KDC proxy |
| L13 | W11-E | Entra-only device | refused (NTLM) |
| L14 | W10 | computer account temporarily RC4-only (`msDS-SupportedEncryptionTypes=0x4`), new ticket | failure at pubKeyAuth/MIC; restore AES |
| L15 | W10 | `fastrdp_mfa_mode: push`, L1 and L5 | push prompt, success after approval; L5 needs the service user |
| L16 | W10 | user with UPN prefix ≠ sAMAccountName, typed as UPN | expected refusal (§3.6) |
| L17 | any | `fastrdp_mfa_mode: otp`, password+OTP in the mstsc prompt | KDC pre-auth failure (bad password count +1), no login |

## 8. Local reproduction (no Windows)

The scratch harness used for this analysis (not part of the repo):
- builds WinPR 3.32.2 alone;
- runs a throwaway MIT KDC;
- drives `AcceptSecurityContext("Negotiate")` with hand-built Windows-style SPNEGO tokens.
  The AP-REQ comes from MIT's raw krb5 GSS mech, and MIT also verifies the acceptor's MIC
  and unwraps its Wrap token.

Scenarios:
- `krbfirst`, `msoid`, `negoex`, `negoex-cs`, `noopt`, `ntlm`;
- `winpr-init` / `winpr-init-nou2u` (FreeRDP client regression);
- `ENCTYPES=rc4` variant.

It would fit as `tests/winpr-spnego/` next to `tests/krb5-spnego/` if wanted.

## Appendix A – WinPR patch: send the acceptor mechListMIC once

Against FreeRDP 3.32.2. In the harness, the NegoEx scenarios then complete without an
extra token; the others are unchanged.

```diff
--- a/winpr/libwinpr/sspi/Negotiate/negotiate.h
+++ b/winpr/libwinpr/sspi/Negotiate/negotiate.h
@@ -45,6 +45,7 @@
 	const Mech* mech;
 	BOOL mic;
 	BOOL spnego;
+	BOOL micSent; /* our mechListMIC has been sent */
 } NEGOTIATE_CONTEXT;
--- a/winpr/libwinpr/sspi/Negotiate/negotiate.c
+++ b/winpr/libwinpr/sspi/Negotiate/negotiate.c
@@ -644,8 +644,9 @@
 		output_token->negState = ACCEPT_COMPLETED;
 	}
 
-	/* If peer expects a MIC then generate it */
-	if (input_token->negState != ACCEPT_COMPLETED)
+	/* If peer expects a MIC then generate it. Each side sends exactly one mechListMIC
+	 * (RFC 4178 section 5); never answer the peer's MIC with a second one. */
+	if (input_token->negState != ACCEPT_COMPLETED && !context->micSent)
 	{
 		/* Store the mic token after the mech token in the output buffer */
 		output_token->mic.BufferType = SECBUFFER_TOKEN;
@@ -662,6 +663,7 @@
 			return status;
 
 		output_token->mic = mic_buffers[1];
+		context->micSent = TRUE;
 	}
 
 	/* When using NTLM cipher states need to be reset after mic exchange */
@@ -1258,6 +1260,17 @@
 			status = negotiate_mic_exchange(context, &input_token, &output_token, output_buffer);
 			if (status != SEC_E_OK)
 				return status;
+
+			/* Our MIC went out earlier and the initiator's MIC verified: the initiator is
+			 * already complete and expects no further SPNEGO token (CredSSP clients send
+			 * pubKeyAuth together with their final MIC). */
+			if (output_token.negState == ACCEPT_COMPLETED && output_token.mic.cbBuffer == 0 &&
+			    output_token.mechToken.cbBuffer == 0)
+			{
+				if (output_buffer)
+					output_buffer->cbBuffer = 0;
+				return SEC_E_OK;
+			}
 		}
 		else
 			output_token.negState = ACCEPT_COMPLETED;
```

## References

- [MS-CSSP] Credential Security Support Provider Protocol, §2.2.1 TSRequest (version,
  clientNonce), §2.2.1.2 TSCredentials, §3.1.5 processing:
  https://learn.microsoft.com/openspecs/windows_protocols/ms-cssp/
- [MS-SPNG] SPNEGO extensions: https://learn.microsoft.com/openspecs/windows_protocols/ms-spng/
- [MS-NEGOEX]: https://learn.microsoft.com/openspecs/windows_protocols/ms-negoex/
- [MS-KILE] §3.4.5 GSS token formats (RFC 4121 for AES, RFC 4757 for RC4):
  https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/
- [MS-RDPBCGR] §2.2.1.1.1 RDP_NEG_REQ flags (RESTRICTED_ADMIN_MODE_REQUIRED,
  REDIRECTED_AUTHENTICATION_MODE_REQUIRED): https://learn.microsoft.com/openspecs/windows_protocols/ms-rdpbcgr/
- [MS-KKDCP] Kerberos KDC proxy: https://learn.microsoft.com/openspecs/windows_protocols/ms-kkdcp/
- RFC 4178 (SPNEGO) §5 mechListMIC; RFC 4121; RFC 4757.
- CredSSP delegation policies (ADMX_CredSsp):
  https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-credssp
- Credential Guard and CredSSP:
  https://learn.microsoft.com/windows/security/identity-protection/credential-guard/considerations-known-issues
- FreeRDP: #13168, PR #13169, #13254, #12162, #11722, #11189, #13778, PR #13675
  (https://github.com/FreeRDP/FreeRDP), ChangeLog 3.31.0.
- JDK-8078439 (Windows SPNEGO mech list incl. NegoEx): https://bugs.openjdk.org/browse/JDK-8078439
