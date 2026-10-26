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

Follow-up (2026-10-21, §5 #4): the proxy's NLA acceptor no longer offers NTLM. A client
without a Kerberos ticket is refused at its first CredSSP message, and the proxy log says
why (§3.13).

Follow-up (2026-10-21, §5 #10, field report): mstsc does Kerberos **user-to-user** under
CredSSP, which the assessment below had missed (§3.1 assumed an optimistic AP-REQ). With
AD the acceptor could not answer it, so Kerberos NLA from mstsc failed on every AD
host. Fixed in `fastrdp-freerdp3` 3.32.2-3 plus the machine account entry in the proxy
keytab (§3.14).

## 1. Short answer

**Yes, with conditions.** A Windows 10/11 mstsc should be able to log in to fastrdp with
Kerberos NLA if all of the following hold:
1. The client gets a service ticket for `TERMSRV/<name it connects to>` from AD. That
   means the name is the FQDN or the short name, never an IP address or an unregistered
   alias, and a KDC is reachable (LAN, VPN or a KDC proxy).
2. That ticket and the session key are **AES**. RC4 sessions fail (verified, §3.4).
3. Windows puts MS-KRB5/KRB5 first in its SPNEGO list. That is the normal case for an AD
   user with a ticket, and the local harness reproduces it successfully.
4. The proxy can answer Kerberos **user-to-user**, which mstsc always starts with under
   CredSSP: with AD, `fastrdp-freerdp3` ≥ 3.32.2-3 and the machine account's entries in
   `/etc/fastrdp/termsrv.keytab` (`fastrdp-termsrv-keytab` and the identity role do both,
   §3.14). Confirmed with mstsc against an AD-joined host (field report 2026-10-22).

  If Windows instead puts NegoEx first, a WinPR acceptor bug can break the exchange (§3.3).
  Whether a domain-joined Windows client ever does that has to be tested.

These cases always fail, by design:
- NTLM (IP address, no KDC, Entra-only devices). The proxy does not offer NTLM, so the
  login ends at the first CredSSP message, and the proxy log names the cause and the fix
  (§3.13);
- Remote Credential Guard, by default. The proxy now answers with a negotiation response
  that says "not supported", so mstsc can show its own message instead of a network
  error. With `fastrdp_accept_remote_guard: true` it logs in **identity only**: the
  forwarded Kerberos tickets are discarded and the session has no TGT (§3.11, §3.12).

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
| AD-joined, `mstsc /remoteGuard` or GPO "Require Remote Credential Guard" | default: **refused cleanly**, RDP_NEG_RSP without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED, mstsc reports the missing support itself (dialog: lab L6). With `fastrdp_accept_remote_guard: true`: **works, identity only** (Kerberos principal; tickets discarded) | – / – (default); no / no (option) | high (code, e2e with FreeRDP); mstsc lab pending |
| GPO "Restrict credential delegation" (RCG *or* Restricted Admin) | default: falls back to Restricted Admin, works. With `fastrdp_accept_remote_guard: true` the proxy offers both and mstsc presumably picks RCG: identity only, as above | no / no | medium |
| AD-joined, short name (`rdp1`) | works (Identity role registers `TERMSRV/RDP1`); certificate name warning unless the short name is in the SAN | as above | medium |
| Any client, **IP address** | **refused at once**: no ticket → Windows offers only NTLM, which the acceptor does not offer (§3.13); proxy log `client <addr> attempted NTLM` | – | high (code, e2e with FreeRDP) |
| DNS alias / load-balancer name not registered as SPN | **refused at once** (NTLM only, §3.13) | – | high |
| Non-joined Windows, user `alice@lab.example.com`, KDC reachable | works like row 1 (U2U as for every mstsc, §3.14) | yes / no | medium; field report 2026-10-21: failed before the U2U fix, retest pending |
| mstsc, AD, `fastrdp-freerdp3` ≥ 3.32.2-3, machine account entries in the proxy keytab | **works**: Kerberos user-to-user (§3.14) | as row 1 | verified (field report 2026-10-22, two clients) |
| Any mstsc, AD, `fastrdp-freerdp3` < 3.32.2-3 or proxy keytab without the machine account entry | **fails**: the acceptor cannot answer mstsc's user-to-user request (log `retrieveTgtForPrincipal ... Client 'TERMSRV/<host>@REALM' not found`, resp. `Kerberos user-to-user: no TGT`), Kerberos is dropped, no NTLM (§3.14) | – | verified (field report, e2e) |
| Non-joined Windows, user `LAB\alice` (NetBIOS domain) | **likely NTLM** (KDC not locatable from the NetBIOS name) → refused at once (§3.13) | – | inference |
| Non-joined, off-network, no VPN, no KDC proxy | refused at once (NTLM only, §3.13) | – | high |
| Non-joined, off-network, GPO/registry KDC proxy (MS-KKDCP) | works if the KDC proxy is reachable and trusted | yes / no | inference |
| Entra-ID-only joined Windows (no on-prem AD ticket) | refused at once: Windows offers `[NegoEx, NTLM]` (FreeRDP #13168), no Kerberos (§3.13) | – | high |
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
- **Optimistic token (correction, §3.14).** Under CredSSP the optimistic token is not an
  AP-REQ but a Kerberos user-to-user KERB-TGT-REQUEST (inner OID
  1.2.840.113554.1.2.2.3, TOK_ID `04 00`) under the MS-KRB5 mechType. The harness below
  fed AP-REQs and so did not see it.
- **Negotiated mechanism.** With an AD ticket the result is Kerberos, `supportedMech`
  MS-KRB5. The module sees package `Kerberos`
  (`nla_package_name()`, `broker/proxy-module/fastrdp_plugin.c:219-240`).
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
| `[NegoEx, NTLM]` | NTLM selected (request-mic) → refused later by the module. **fastrdp now:** no mechanism left, refused at the first message (§3.13) |
| AP-REQ framed with the MS-KRB5 OID instead of KRB5 | Kerberos acceptor rejects the framing (`kerberos.c:1598-1608`, accepts only 1.2.840.113554.1.2.2 or U2U). Negotiate then **silently selects NTLM** → refused. **fastrdp now:** no NTLM to fall back to, refused at the first message |

The harness drives a WinPR acceptor with default settings (NTLM enabled). fastrdp's proxy
disables NTLM in the acceptor (§3.13), so "NTLM selected" in the table is, for fastrdp,
"no acceptable mechanism".

The last row matters only if Windows frames the AP-REQ with the MS OID. Heimdal's krb5
acceptor accepts only the standard OID in the framing, and Samba/Heimdal servers work
with Windows clients. So Windows almost certainly uses the standard OID there and lists
MS-KRB5 only in mechTypes/supportedMech (inference; MIT also accepts the MS OID, to be
safe). Still worth a robustness fix upstream (§5).

### 3.2 SPN, keytab, names (Q2)

- **AD** (`ansible/roles/identity/tasks/ad.yml:17-24`):
  - registers `TERMSRV/<fqdn>` and `TERMSRV/<SHORTNAME>` via `adcli update`;
  - `fastrdp-termsrv-keytab` copies all `TERMSRV/*` entries from `/etc/krb5.keytab`, and
    the machine account's own entries (`<NAME>$`, same keys) for user-to-user (§3.14);
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
  - The proxy's acceptor does not offer NTLM (§3.13): the client's `[NegoEx, NTLM]` offer
    leaves no mechanism, and the login ends at the first CredSSP message. Before, NTLM ran
    to the end and failed at `ntlm_compute.c:285` (SamOpen), the module's check
    (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2463-2473`) being the last line.
  - **TLS logins do not help mstsc:** after a failed CredSSP, mstsc does not fall back to
    TLS. A TLS login also needs credentials in the Client Info PDU, which mstsc only sends
    with saved credentials and CredSSP disabled (`enablecredsspsupport:i:0`). The proxy has
    no logon screen (`fastrdp_fetch_target()`, `fastrdp_plugin.c:2630-2635`).
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
  | TSPasswordCreds with empty fields | Restricted Admin | no password; user = Kerberos principal (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2499-2527`) | no TGT |
  | TSSmartCardCreds (PIN, CSP data, hints) | smartcard credentials | PIN dropped (`PasswordIsSmartcardPin`, `fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2513-2525`; broker `server.py:72-77`) | no TGT |
  | TSRemoteGuardCreds (`KERB_TICKET_LOGON`: `HOST/<proxy>` service ticket + TGT as KRB-CRED, optional NTLM supplemental creds) | Remote Credential Guard | default: not offered. The RDP_NEG_RSP lacks REDIRECTED_AUTHENTICATION_MODE_SUPPORTED (`patches/freerdp/0002`), so mstsc gives up before CredSSP; such credentials sent anyway are refused by `fastrdp_remote_credentials()`. `AcceptRemoteGuard=true`: accepted after Kerberos NLA, tickets zeroed and discarded, the broker gets `"remote_guard": true` and no password (parsing without supplemental creds: `patches/freerdp/0003`) | refused / no TGT |

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
  Kerberos identity (`fastrdp_server_peer_logon()`, `fastrdp_plugin.c:2461-2490`). The broker's NLA path needs no password
  (`server.py:58-78`) and runs the PAM *account* phase (`ad_gpo_map_remote_interactive`).
- **MFA:**
  - `push` / `otp_or_push` trigger privacyIDEA push with `password=None` (`SecondFactor.verify()` → `SecondFactor.push()` in `mfa.py`).
    That needs the `triggerchallenge` service account
    (`fastrdp_privacyidea_service_user`); otherwise there is no challenge and the login is
    refused.
  - `otp` mode refuses every NLA login (`SecondFactor.verify()` in `mfa.py`).
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

mstsc (and the Windows App on Windows, same RDP/CredSSP stack [inference]) has no prompt
for a second factor once NLA has run, and fastrdp has no logon screen of its own. A
second factor therefore reaches fastrdp in one of three ways: an **out-of-band approval**
while mstsc waits (push, web approval), a **credential that is itself two factors** (smart
card, Windows Hello for Business certificate) proven to the KDC, or an **MFA gateway in
front** of the proxy.

| Option | mstsc → fastrdp | Status | User experience | Phishing resistance | Requirements |
|---|---|---|---|---|---|
| privacyIDEA **push** after Kerberos NLA | yes | **supported** (lab L15) | password or SSO, mstsc waits until the push is approved | low–medium: push fatigue, an attacker's push can be approved | privacyIDEA + app; `fastrdp_privacyidea_service_user` for SSO logins; proxy `Timeout` (180 s) ≥ push timeout (60 s) + session start (90 s) |
| **Web approval** (Keycloak passkey sign-in on the web gateway, approve the pending login) | yes, same waiting point as push | **supported** (`[mfa] mode = web` / `push_or_web`; real Keycloak + mstsc untested) | like push, approved in a browser | the factor is a passkey (origin-bound); the approval itself can still be talked into, like a push; the QR code on the waiting screen binds it to the login on the user's own screen ([auth-matrix.md](auth-matrix.md#login-bound-link-qr-code)) | Keycloak passkeys ([passkeys.md](passkeys.md) stage 1), reachable web gateway |
| **Smart card / PIV / YubiKey PIV** (PKINIT on the client, TSSmartCardCreds) | yes | **supported** (soft token e2e; real card + AD: lab L7) | insert card, PIN in mstsc | high (key on the card, KDC-bound) | AD PKI (KDC certificates, NTAuth, UPN SAN) and an AD rule that makes it MFA (§3.9) |
| **Windows Hello for Business certificate** (used as a virtual smart card) | yes, as a smart card [inference] | **possible**, untested (lab L19) | face/fingerprint/PIN in mstsc | high (TPM-bound key) | WHfB certificate trust, or a certificate in the WHfB container (AD CS / Intune, Passport KSP); same AD rule as smart cards |
| **MFA gateway in front**: rdpgw (open source, MS-TSGU) with Keycloak OIDC; Windows RD Gateway + NPS extension (Entra MFA) | yes [inference] | **possible**, untested (lab L20, L21) | rdpgw: Keycloak sign-in in the browser, then the downloaded `.rdp` in mstsc; RDG: Authenticator push while mstsc shows "Initiating remote connection" | rdpgw: passkey; RDG: push | §3.10 |
| WHfB key trust (Microsoft AD) | yes, as Kerberos SSO | **second factor per login** with `kdc_evidence_as_mfa` (K11; lab pending) | passwordless Windows sign-in, then SSO | strong at Windows sign-in | AD DCs 2016+ add S-1-18-4 (KEY_TRUST_IDENTITY) to the PAC, with PKINIT freshness enabled also S-1-18-3 [doc: MS-DTYP §2.4.2.4]; fastrdp counts it per login with `fastrdp_mfa_kdc_evidence_as_mfa` (backlog K11, lab pending). Samba AD adds neither S-1-18-4 nor AMA groups |
| FIDO2 key / cloud Kerberos trust (Entra Kerberos) | as the **first factor only** | works, no second factor for fastrdp | passwordless Windows sign-in, then SSO | strong at Windows sign-in, invisible to fastrdp | Entra hybrid/joined; whether the exchanged TGT carries any S-1-18-x SID is unverified (lab) |
| OTP appended to the password under NLA | **no** | impossible | – | – | the string becomes the Kerberos password (below) |
| OTP on the TLS path (no NLA) | practically **no** | server side exists (`fastrdp_allow_tls_logins`) | mstsc with `enablecredsspsupport:i:0` shows no prompt and sends only saved credentials (`cmdkey` with password+OTP before every connect); no logon screen at the proxy | low: secret sent to the server, no pre-connection authentication | lab S1; not recommended |
| FreeIPA OTP / passkey / idp pre-authentication with `nla_kdc_enforced` | **no** for Windows | impossible | – | – | Windows Kerberos lacks FreeIPA's OTP, passkey and idp pre-authentication (works for Linux clients, [passkeys.md](passkeys.md)) |
| Microsoft Entra authentication for RDP (`enablerdsaadauth:i:1`) | **no** | impossible | – | – | needs an Entra-joined Windows host; FreeRDP implements only the client side (`libfreerdp/core/aad.c`) |
| WebAuthn redirection (MS-RDPEWA) at login | **no** | not planned | – | – | the channel exists only inside a running session ([webauthn-redirection.md](webauthn-redirection.md)) |
| Windows credential providers (Duo for RDP, privacyIDEA CP, ...) | **no** | n/a | – | – | they run on a Windows RDP *host*; client-side providers do not help the server |

Since then implemented: web approval (`[mfa] mode = web` / `push_or_web`) and per-login
evidence from the Kerberos ticket (`fastrdp_mfa_kdc_evidence_as_mfa`, backlog K11: FreeIPA
authentication indicators, AD PAC SIDs such as S-1-18-4, S-1-18-3 or an AMA group), so smart
card and WHfB logins can skip push per login instead of through exempt groups or the global
`nla_kdc_enforced`. Open: a lab for the gateway option (backlog K12).

Notes on the options above:

- **Push** works without interaction on any NLA login. The broker call runs in the
  proxy's PostConnect, i.e. after the front connection sequence has finished
  (Font Map sent), so mstsc probably shows an empty session window rather than
  "Configuring remote session…" while the broker waits (Timeout 180 s,
  `proxy.ini.j2`; lab test S3 in [rdp-spec-conformance.md](rdp-spec-conformance.md)).
- **OTP appended to the password does not work with NLA at all, not even when typed.**
  - With CredSSP+Kerberos the client uses the typed string as the Kerberos password for
    its AS-REQ. A password with an OTP suffix makes the KDC fail pre-authentication (and
    counts a bad password in AD) before fastrdp sees anything.
  - The broker also never splits OTPs on NLA: `first_factor()` returns `otp=None` for
    `method == "nla"` (`server.py:58-78`). `verify()` then uses push, or fails in `otp`
    mode (`SecondFactor.verify()` in `mfa.py`).
  - Appended OTP works only on the TLS path (`server.py:96-115`), which mstsc cannot use
    in practice (§3.2).
  - The current auth-matrix row "NLA, user types a password (mstsc …)" with second factor
    `push` is consistent with this.
- **Waiting in mstsc.** Push and web approval run in the proxy's `ServerFetchTargetAddr`
  after the front connection sequence, so no CredSSP-phase timeout applies. No documented
  mstsc timeout for an activated connection without graphics was found; FreeRDP waited 60 s
  in a test ([freerdp-client.md](freerdp-client.md)). What mstsc shows meanwhile ("Configuring
  remote session…" per [client-guide.md](client-guide.md), or an empty window) is lab S3/L15.
  With `fastrdp_proxy_waiting_screen` (default `true`) the proxy draws its own panel into
  that window instead (Bitmap Updates, the one graphics output every client must accept):
  "Approve the sign-in" with a countdown, for web approval the approval URL, the login's
  code and a QR code for the phone (the page for this login), then "Connecting to your
  desktop…"; the panel is painted over in the background grey before the desktop arrives
  ([auth-matrix.md](auth-matrix.md#waiting-screen)). On by default since the first test
  with a real client showed only a black window during MFA without it; still to be
  confirmed with mstsc and the Windows App (lab S3/L15: panel visible, countdown
  updating, QR code scannable from the screen, no leftover after the desktop appears,
  also after a resize to another resolution). `fastrdp_proxy_waiting_screen: false`
  turns it off. With `fastrdp_desktop_picker` the
  same panel then lists the user's desktops, and mstsc's keys and clicks choose one
  before the session starts ([desktop-matrix.md](desktop-matrix.md#desktop-picker-in-the-rdp-window));
  lab S3 as well.
  The proxy waits up to `fastrdp_proxy_broker_timeout` (180 s) for the push or approval
  (60/90 s) and the session start after it ([auth-matrix.md](auth-matrix.md)).
  Timeout → Set Error Info 0x409, refusal → 0x7. After a network drop mstsc reconnects
  without auto-reconnect cookies: a new push or approval unless `reconnect_grace` is set.
- **Disconnect with the X in mstsc's connection bar.** mstsc sends a Shutdown Request PDU
  and expects a Shutdown Request Denied PDU while a user is logged on; it then
  disconnects itself ([MS-RDPBCGR] 1.3.1.4.1). Up to `fastrdp-freerdp3` 3.32.2-6 the
  proxy's FreeRDP disconnected instead ("provider initiated"). Field report 2026-10-23
  (mstsc, Kerberos NLA, web approval): the next *Connect* in the same mstsc showed a black
  window instead of the waiting screen, although the proxy sent it, until the login timed
  out; a restarted mstsc worked. 3.32.2-7 (`patches/freerdp/0008`) answers with the
  Denied PDU once the session runs [tested: e2e with a client that sends the request;
  not yet confirmed with mstsc, lab S15 in [rdp-spec-conformance.md](rdp-spec-conformance.md#13-lab-tests)].
  Until then: restart mstsc after a disconnect, or approve on `/web/approve` while the
  window is black (the login waits there with its code). The same report came after a
  **logout inside the session** (GNOME): there the proxy forwards gnome-remote-desktop's
  Set Error Info 0x1 ("administrative tool"; Windows sends 0xC on a logoff) and ends the
  connection with Deactivate All and a Disconnect Provider Ultimatum, a conforming
  sequence, and 0008 does not change it; the cause is open ([backlog.md](backlog.md#sessions)
  A5, lab S15).
- **TLS path with mstsc.** `enablecredsspsupport:i:0` (default 1) turns NLA off; "the
  client connects to the server and lets the server handle the authentication" [doc:
  Microsoft, RDP properties]. fastrdp has no logon screen, so only saved credentials reach
  it (§3.2, [rdp-spec-conformance.md](rdp-spec-conformance.md)). Trade-off: no
  authentication before the connection (brute force and DoS surface on the proxy), the
  password+OTP go to the server, server authentication rests on the TLS certificate alone.
- **No push for strong Windows logons, per login** (`fastrdp_mfa_kdc_evidence_as_mfa`,
  [passkeys.md](passkeys.md#kdc-evidence-per-login)): the proxy's FreeRDP keeps the
  verified PAC of mstsc's service ticket (`patches/freerdp/0005`), and the broker skips
  the second factor when it lists one of the configured group SIDs: `S-1-18-4` (Windows
  Hello for Business key trust), `S-1-18-3` (PKINIT with freshness) or an Authentication
  Mechanism Assurance group (certificate logons). mstsc does nothing differently; logins
  without such a SID get the push as before. The SIDs describe the Windows sign-in that
  produced the TGT, not this connection. Not yet seen with a real AD and mstsc (lab:
  user-to-user ticket PAC, §3.14).

### 3.9 Smartcard from Windows (Q7)

mstsc does PKINIT locally with the card (or uses the smartcard logon TGT) and runs
ordinary Kerberos NLA, which looks the same to the acceptor. It then delegates
TSSmartCardCreds: PIN, TSCspDataDetail with keySpec, cardName, readerName, containerName,
cspName, and optional user/domain hints.

FreeRDP parses all of these (`nla.c:1500-1524`, `nla.c:1207-1231`). The module drops the
PIN, uses the Kerberos principal as the user if no hint is sent, and sets
`smartcard: true`. This is the same as the tested FreeRDP path ([smartcard-nla.md](smartcard-nla.md)).

The AD PKI requirements are unchanged: KDC certificates, NTAuth, UPN SAN. To make the
smart card count as MFA:

- per login, from the ticket: an *Authentication Mechanism Assurance* group (issuance
  policy of the smart card certificates linked to a universal group) or, with the DC
  policy *KDC support for PKInit Freshness Extension*, `S-1-18-3`, listed in
  `fastrdp_mfa_kdc_evidence_as_mfa` ([passkeys.md](passkeys.md#kdc-evidence-per-login));
  the `smartcard` flag from TSSmartCardCreds is client-supplied and never counts; or

- "Smart card is required for interactive logon" on the accounts plus
  `fastrdp_mfa_exempt_groups` for them (push skipped for the group), or
- an AD authentication policy with **Authentication Mechanism Assurance** (AMA: the
  smart card certificate's issuance policy OID mapped to a group, the policy on the
  account that owns `TERMSRV/<host>` requires that group) plus
  `fastrdp_mfa_nla_kdc_enforced` with `fastrdp_mfa_nla_kdc_enforced_by_ad_policy`
  ([passkeys.md](passkeys.md)). Needs domain functional level 2012 R2+ and Kerberos
  armoring; fastrdp cannot check it from Linux (preflight warning only). The policy
  applies with mstsc's user-to-user exchange too, the SPN is the same [inference].

**Windows Hello for Business certificates.** WHfB RDP sign-in works "using the redirected
smart card capabilities" and needs a certificate in the WHfB container (certificate
trust, or AD CS / Intune with the Passport KSP); WHfB "emulates a smart card" [doc:
Microsoft, Remote Desktop sign-in with Windows Hello for Business]. Microsoft describes
Windows targets in the same forest; fastrdp only needs the Kerberos part (PKINIT on the
client), so this should work like a smart card [inference, lab L19]. Microsoft itself
recommends Remote Credential Guard instead, which fastrdp accepts identity-only and which
adds no factor.

**Evidence in the ticket.** Microsoft AD puts well-known SIDs into the PAC that say how
the TGT was obtained [doc: MS-DTYP §2.4.2.4 and its Appendix B notes]: S-1-18-1 for any AS
logon including passwords (no evidence of a second factor), S-1-18-3 for PKINIT with the
RFC 8070 freshness token (DC GPO "KDC support for PKInit Freshness Extension"; smart card,
WHfB certificate and key trust), S-1-18-4 for WHfB **key trust**, S-1-18-5 when the key
credential carries the MFA property. Samba AD adds only S-1-18-1/2/3 and has no AMA. fastrdp
reads the verified PAC (backlog K11, `fastrdp_mfa_kdc_evidence_as_mfa`), so key-trust and
smart card logons can skip push per login. Caveats: whoever can write a user's `msDS-KeyCredentialLink` can add a key
and obtain S-1-18-4 (and S-1-18-5) for that user ("shadow credentials"; restrict the
attribute's ACLs, audit event 5136), and the evidence describes the Windows sign-in that
produced the TGT, which may be hours old. *Cloud Kerberos trust* and FIDO2 keys via Entra
Kerberos: unknown whether any S-1-18-x SID appears (lab); first factor only for now.

Confidence medium; real card + AD + mstsc is lab test L7, WHfB certificate L19.

Windows Hello / WHfB in detail, including Samba AD domains: [windows-hello.md](windows-hello.md).

### 3.10 Off-network clients: KDC proxy, RD Gateway (Q8)

- Without a reachable KDC, Windows cannot get the TERMSRV ticket and falls back to NTLM,
  which the proxy does not offer (§3.13). Options:
  1. **VPN** (simplest).
  2. **KDC proxy (MS-KKDCP).** An HTTPS endpoint that forwards Kerberos messages to the
     DCs: fastrdp's own (`fastrdp_web_kdcproxy: true`, python3-kdcproxy behind the web
     gateway's nginx at `https://<fqdn>/KdcProxy`, only for `fastrdp_realm`;
     [web-access.md](web-access.md#kdc-proxy)), the Windows *KPS* service, or another
     python-kdcproxy.
     - Clients: GPO *Computer Configuration → Administrative Templates → System →
       Kerberos → Specify KDC proxy servers for Kerberos clients* (enabled), entry: value
       name = realm (`LAB.EXAMPLE.COM`), value = `<https rdp1.lab.example.com:443:KdcProxy />`.
       Windows uses the proxy when it cannot reach a DC itself. [doc]
     - The proxy's TLS certificate must be trusted by the client and match the name.
       Windows also checks its revocation; the GPO *Disable revocation checking for the
       SSL certificate of KDC proxy servers* (same folder) turns that off, e.g. for an
       internal CA without a reachable CRL. [doc]
     - FreeRDP and other MIT krb5 clients: `kdc = https://rdp1.lab.example.com/KdcProxy`
       in `krb5.conf` plus the package `krb5-k5tls`; FreeRDP's `/kerberos:kdc-url:` alone
       only covers the first ticket ([freerdp-client.md](freerdp-client.md) §7).
     - Exposure: the endpoint lets anyone on the internet send pre-authentication
       attempts (password guesses) to the DCs. Account lockout policy, pre-authentication
       for every account and the nginx rate limit matter
       ([web-access.md](web-access.md#kdc-proxy)).
     - mstsc through fastrdp's proxy, with AD as the KDC, is untested (lab); the MIT path
       is tested with a scratch KDC.
  3. **RD Gateway (MS-TSGU):** fastrdp has no gateway; FreeRDP has no RD Gateway server.
     A gateway in front can also be the place for MFA (§3.8):
     - **rdpgw** (open source, [github.com/bolkedebruin/rdpgw](https://github.com/bolkedebruin/rdpgw),
       v2.2.0): MS-TSGU server with OIDC (Keycloak), Kerberos, PAM or NTLM
       authentication and a built-in MS-KKDCP KDC proxy. OIDC flow: the user signs in
       to Keycloak in the browser (passkey), downloads an `.rdp` file with a short-lived
       signed token (optionally bound to the client IP, `VerifyClientIp`, and to allowed
       hosts) and opens it in mstsc. xrdp hosts are its reference targets; mstsc needs a
       trusted certificate and host names with `:3389` [project docs].
     - **Windows Server RD Gateway** tunnels to fastrdp:3389 like to any RDP host
       [inference]; its built-in KDC proxy can carry the Kerberos traffic. With the
       **NPS extension** (on a separate NPS server, RADIUS timeout raised to 30–60 s) it
       enforces Entra MFA at the gateway: Authenticator push or phone call only, no
       codes; mstsc shows "Initiating remote connection" while waiting [doc: Microsoft,
       NPS extension for RD Gateway]. RD Gateway → RADIUS → privacyIDEA push is reported
       as unreliable by privacyIDEA.
     - mstsc still runs CredSSP end to end to fastrdp, so it still needs a TERMSRV ticket
       (VPN, a KDC proxy or rdpgw's).
     - **Open design point:** fastrdp's identity is the Kerberos principal from NLA. A user
       who passed the gateway's MFA as A could present B's Kerberos credentials, so
       skipping fastrdp's own MFA for gateway connections needs a binding between the
       gateway user and the principal (rdpgw: user token in the RDP user name, per-user
       host templates). Without it, keep fastrdp's MFA behind the gateway (MFA twice).
     - Untested (lab L20, L21); not needed for MFA if push or web approval is used, nor
       for reachability if VPN or a KDC proxy exists.
  4. The web path (Guacamole + Keycloak) needs no Kerberos on the client
     ([web-access.md](web-access.md)).

### 3.11 Known FreeRDP issues (Q9)

| Item | Relevance | Status in 3.32.2 |
|---|---|---|
| #13168 / PR #13169 "fix server-side SPNEGO mechanism fallback" (Windows 11 sends `[NEGOEX, NTLM]`; fallback failed with SEC_E_INVALID_HANDLE for every 3.x < 3.31) | NegoEx-first clients | **fixed** (3.31.0) |
| #11189 "Kerberos not working with mstsc" (shadow server 3.11.1, Win 11 23H2/24H2) | exactly this scenario | closed as stale, never root-caused; the bug above, or the user-to-user TGT (§3.14) with an AD-joined server |
| #13254 NULL check of sub-credentials in the accepting context (gnome-remote-desktop crash) | robustness | fixed (3.31.0) |
| #12162 server-side `SECPKG_ATTR_AUTH_IDENTITY` for Kerberos | used by the module | present (3.22.0) |
| #11722 U2U filtering (`!u2u`) | FreeRDP clients only | present (3.17.0) |
| Duplicate acceptor mechListMIC (§3.3) | NegoEx-first mstsc, if Windows omits negState | **open**, found here |
| MS-KRB5 OID in the AP-REQ framing rejected (§3.1) | only if Windows used it (unlikely) | **open**, found here |
| U2U acceptor asks for a TGT of `TERMSRV/<host>` or `<fqdn>$`; AD refuses both (§3.14) | every mstsc against an AD-joined FreeRDP server | **open** upstream (also on master, 2026-10-21); fixed in fastrdp's build (`patches/freerdp/0004`) |
| No RFC 4757 (RC4) Wrap/MIC tokens (§3.4) | RC4 environments | **open**, found here |
| Server-side Remote Credential Guard | RCG clients | partly in FreeRDP 3.32.2: negotiation and parsing of `TSRemoteGuardCreds` into a `RemoteCredentials` callback exist (`nego.c`, `nla.c`, `peer.h`), but the server side of the MS-RDPEAR channel is not built. Two server bugs, fixed in fastrdp's build: an unsupported RCG request dropped the TCP connection (`patches/freerdp/0002`), and `TSRemoteGuardCreds` without the optional `supplementalCreds` (all FreeRDP clients) were rejected (`0003`). fastrdp refuses RCG by default and accepts it identity-only with `AcceptRemoteGuard=true` (§3.12). Using the forwarded credentials (phase 1: a session TGT through MS-RDPEAR) is **not implemented**. Client side: PR #13675 (open), #13778 |

Most related reports concern gnome-remote-desktop, which uses the same server NLA. Their
failures are keytab permissions (GNOME Discourse t/34451) and NTLMv1 (g-r-d #244), not
mstsc Kerberos.

### 3.12 Where a Windows RDP host's Kerberos credentials come from (comparison)

How a **Windows** RDP host gets Kerberos credentials for the user when mstsc logs in
with Kerberos (NLA), and how fastrdp compares. In short: the user's **TGT is not
forwarded**. In the normal case the client delegates the **password**, and the host
obtains its **own** TGT with it. Remote Credential Guard is the only mode without a
password, and even there the TGT's session key stays on the client.

CredSSP (MS-CSSP `TSCredentials`) knows only three kinds of credentials: password
(`TSPasswordCreds`), smartcard (`TSSmartCardCreds`) and Remote Credential Guard
(`TSRemoteGuardCreds`). There is no "here is my TGT" credential type. [MS-CSSP 2.2.1.2]

| mstsc → Windows RDP host | Credentials the host receives | Valid TGT for the user on the host? | Network access (SMB home, profiles) as |
|---|---|---|---|
| NLA, password typed | the **password** (`TSPasswordCreds`); LSA logs on (logon type 10, RemoteInteractive) | **yes**, obtained by the host from the DC | the user |
| NLA single sign-on, GPO "Allow delegating default credentials" (`TERMSRV/…`), **no** Credential Guard on the client | the logged-on user's password from the client's LSA | **yes** | the user |
| NLA single sign-on, **Credential Guard on** the client (default on Windows 11 22H2+ / Server 2025, Enterprise/Education) | nothing for SSO: mstsc prompts, then as row 1 | **yes**, after the prompt | the user |
| Smartcard (NLA) | `TSSmartCardCreds` (PIN + card data); the host runs PKINIT with the redirected card | yes [inferred] | the user |
| `mstsc /restrictedAdmin` (needs local admin on the host) | nothing reusable | **no** | the host's **computer account** (`HOST$`): homes/profiles with user ACLs fail |
| `mstsc /remoteGuard` (Remote Credential Guard) | `TSRemoteGuardCreds`: `KERB_TICKET_LOGON` with a service ticket and the TGT, **without the TGT's session key** | effectively yes, **while connected**: every operation that needs the TGT key is sent back to the client over the RDP channel MS-RDPEAR | the user, until disconnect |

Consequences on Windows:

- **Long sessions:** with a delegated password, LSA keeps a password-derived key and
  silently gets a new TGT when the old one expires. This key is what Credential Guard
  protects and what LSASS dumping targets.
- **Remote Credential Guard** constraints: Kerberos only, classic mstsc, AD-joined
  target, not through RD Gateway or Connection Broker, on an RD Session Host only for
  administrators; nothing can be refreshed after disconnecting.
- **Profiles:** roaming profiles and FSLogix open the share as the **user** (they fail
  under Restricted Admin); User Profile Disks use the hosts' computer accounts.

The same logins on fastrdp:

| Login | Session TGT on the fastrdp host | Notes |
|---|---|---|
| mstsc NLA with the password delegated (typed, or SSO without Credential Guard) | **yes**: xrdp via `pam_sss`, GNOME/Plasma via the broker's `fastrdp-tgt` | same as Windows; renewal up to `krb5_renewable_lifetime` (default 7 days), no silent re-acquisition after that |
| xfreerdp3 without `/p` (password typed) | **yes** | as above |
| xfreerdp3 `/p` (empty, SSO from the client's ticket), smartcard, browser | **no** (no password reaches the server) | Windows Restricted Admin falls back to `HOST$`; fastrdp has gssproxy S4U for NFS (`fastrdp_nfs_krb5_homes`, constrained delegation, [nfs-kerberos-homes.md](nfs-kerberos-homes.md)) or `kinit` in the session; `fastrdp_session_tgt: required` refuses such logins |
| `mstsc /restrictedAdmin` | **no** | accepted (row in §2) |
| `mstsc /remoteGuard` | default: – ; `fastrdp_accept_remote_guard: true`: **no** | default: **refused** with a negotiation response the client can report (R4 in [rdp-spec-conformance.md](rdp-spec-conformance.md)). With the option: identity only, like Restricted Admin. The proxy module zeroes and discards the `KERB_TICKET_LOGON` (service ticket + TGT); nothing is logged, kept or forwarded. Without MS-RDPEAR the TGT is useless to the host anyway (mstsc keeps its session key), and a FreeRDP client's complete TGT would be unconstrained delegation (below). gssproxy S4U for NFS still works; `fastrdp_session_tgt: required` refuses these logins |

Why not simply forward the TGT: on a multi-user terminal server a forwarded TGT is
*unconstrained delegation*. Root on the host could use every connected user's TGT
for any service while it is valid. That is exactly what Remote Credential Guard
avoids by keeping the TGT key on the client. For shared hosts, password → own TGT or
S4U for named services (constrained delegation) are the safer defaults.

**How Remote Credential Guard limits the risk, and what it leaves.** The host gets the
TGT only with an opaque key blob ([MS-CSSP] note 22: the KRB-CRED key is a
`KERB_RPC_ENCRYPTION_KEY`, "understood and consumed only by the CredSSP client",
[MS-RDPEAR] 2.2.1.2.8). Every operation that needs the TGT key is sent back to the
client over the `Microsoft::Windows::RDS::AuthRedirection` channel; the client acts as
a key oracle tied to the open connection. Credential Guard on the client is not
required, it only protects the client side.

| Mode | On the host | Host compromised during the session | After disconnect |
|---|---|---|---|
| Password delegation (default) | password, so NT hash, Kerberos keys, TGT | anything as the user, until the password changes | yes |
| Forwarded TGT (unconstrained delegation) | TGT with its session key | any service as the user, also from other machines | yes, until the TGT ends (renew lifetime) |
| Remote Credential Guard | TGT with an opaque key; service tickets with their keys; an opaque NTLM blob | any service as the user **while connected**; service tickets obtained can be passed | no new tickets; obtained service tickets until they expire (10 h default) |
| Restricted Admin | nothing of the user's (host's computer account) | local only | – |

Residual risks of Remote Credential Guard, also named by Microsoft ("Prevent use of
user's identity during connection" is not covered): a host owned during the session
acts as the user against any service and can pre-fetch service tickets; with SYSTEM on
the host, NTLMv1 responses can be obtained and possibly cracked to the NT hash
(SpecterOps, October 2025, not serviced by Microsoft); the client becomes the target (a
TGT stolen there can be used for `/remoteGuard` without a password); direct
connections only, admin-only on RD Session Hosts.

For fastrdp this means: the protections exist only because Windows clients send an
opaque key. FreeRDP's `/remoteGuard` currently sends the TGT key unencrypted, contrary
to the spec; keeping that TGT would be unconstrained delegation without any of these
protections, so fastrdp discards it (identity-only `AcceptRemoteGuard`, the security
equivalent of Restricted Admin). Equivalent protection would need the server side of
MS-RDPEAR with a host that never holds the TGT key ([backlog.md](backlog.md), not
planned).

Sources: [Remote Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard),
[SpecterOps: Catching Credential Guard off guard](https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/),
[How does Remote Credential Guard work (S. Syfuhs)](https://syfuhs.net/how-does-remote-credential-guard-work),
[Compass Security: securing connections to your Remote Desktop](https://blog.compass-security.com/2023/06/securing-connections-to-your-remote-desktop/),
[Pen Test Partners: abusing RCG with Rubeus](https://www.pentestpartners.com/security-blog/abusing-rdps-remote-credential-guard-with-rubeus-ptt/),
[Credential Guard known issues](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues),
[CredSSP policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-credssp),
[logon types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types),
[MS-CSSP TSCredentials](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94a1ab00-5500-42fd-8d3d-7a84e6c2cf03),
[MS-RDPEAR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/a32e17ec-5869-4fad-bdae-d35f342fcb6f),
[Kerberos credentials cache (LSA key refresh)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961958(v=technet.10)),
[RDS user data storage (UPD)](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-secure-data-storage).

### 3.13 Clients without a Kerberos ticket: what happens, what the user sees

**Server side (verified, e2e with a FreeRDP client).** The proxy's NLA acceptor offers
Kerberos and Kerberos U2U only:
- The module sets `FreeRDP_AuthenticationPackageList = "!ntlm"` on the front settings in
  `ServerSessionInitialize` (`fastrdp_server_session_init()`). WinPR's Negotiate acceptor
  honours the list only when `credssp_auth_setup_server()` passes auth data, i.e. with a
  keytab, an NTLM SAM file or an NTLM hash callback (`credssp_auth.c:356-386`). The
  module installs a hash callback (`fastrdp_ntlm_refused()`) for that: it changes nothing
  in the Kerberos acceptor, which keeps the default keytab (`KRB5_KTNAME` from the unit),
  and it refuses and logs if NTLM were ever selected.
- `negotiate_AcquireCredentialsHandleW()` then skips the NTLM sub-credential
  (`negotiate.c:1509`). A client whose negTokenInit lists no Kerberos OID gets no
  mechanism: `AcceptSecurityContext` fails at the first CredSSP message
  (`negotiate.c:1165-1166`), and the server answers with a TSRequest whose `errorCode` is
  STATUS_LOGON_FAILURE (`nla.c:882-894`, `nla.c:2123`: for CredSSP versions 3, 4 and 6), then closes.
  No NTLM CHALLENGE is sent, and the client never sends an NTLMv2 response for the
  user's password to the proxy.
- The module reads the mechanisms of that first TSRequest itself
  (`fastrdp_read_pdu()`, `fastrdp_spnego.h`) and logs, for a client that offers NTLM
  but no Kerberos:

  ```
  [WARN][proxy.modules.fastrdp] - [fastrdp_read_pdu]: [<session>] client 192.0.2.10 attempted
  NTLM (offered: NegoEx, NTLM); only Kerberos NLA is accepted: check that the client can
  reach the KDC (DNS SRV _kerberos._tcp.<domain>, ksetup /addkdc or a KDC proxy), connects
  to the server's FQDN (not an IP address or an alias without TERMSRV SPN) and gives the
  user name as UPN (user@domain)
  ```

  FreeRDP itself adds `AcceptSecurityContext status SEC_E_INTERNAL_ERROR` and
  `client authentication failure`. Before this change the log had
  `ntlm_fetch_ntlm_v2_hash: Could not find user in SAM database` and
  `AcceptSecurityContext status SEC_E_NO_CREDENTIALS` after a full NTLM exchange.
- The module's check after NLA (`fastrdp_server_peer_logon()`: package must be
  `Kerberos`) stays as defence in depth.
- The back-end hop is unaffected: `fastrdp_client_pre_connect()` replaces the copied
  package list (`!kerberos` towards GNOME Remote Desktop and KRdp, which authenticate the
  broker's one-time secret with NTLM).

**Client side.**
- FreeRDP (`/sec:nla /auth-pkg-list:'none,ntlm'`, or any client without a ticket that
  falls back to NTLM): `ERRCONNECT_LOGON_FAILURE [0x00020014]` after one round trip
  (verified, `run_nla.sh`).
- mstsc (inference, lab L9/L13): CredSSP gets STATUS_LOGON_FAILURE (0xC000006D) in the
  first server TSRequest, as it did before at the end of the NTLM exchange. The dialog is
  therefore expected to stay the generic "The logon attempt failed" / "Your credentials
  did not work", only sooner. The error text Windows shows is chosen by the client from
  that NTSTATUS; FreeRDP's server always sends STATUS_LOGON_FAILURE for SSPI failures, so
  a more specific dialog would need a FreeRDP change whose mstsc result is untested.
  Record the dialog in the lab.

**What to tell the user / helpdesk.** "The credentials did not work" right after the
password prompt, from a machine that is not on the corporate network or connects by IP
address, almost always means: no Kerberos ticket, not a wrong password. The proxy log
confirms it (`attempted NTLM`). Fixes, in this order:
1. Connect to the server's **FQDN** (`rdp1.lab.example.com`), not an IP address or a
   name without a `TERMSRV/` SPN (`fastrdp_termsrv_aliases`, §3.2).
2. Type the user as **UPN** (`alice@lab.example.com`), not `LAB\alice`, on machines that
   are not domain members.
3. Make the KDC reachable: domain DNS on the client (`nslookup -type=SRV
   _kerberos._tcp.lab.example.com`), or on a workgroup machine
   `ksetup /addkdc LAB.EXAMPLE.COM dc1.lab.example.com` (admin; may need a restart), or VPN.
4. Off-network: the KDC proxy (§3.10, `fastrdp_web_kdcproxy`).
5. Check on the client: `klist` after the attempt should list
   `TERMSRV/rdp1.lab.example.com@LAB.EXAMPLE.COM`. `klist purge` and retry after a fix.

Entra-only devices have no on-premises ticket at all; use the web path
([web-access.md](web-access.md)) or Microsoft's Entra Kerberos/cloud trust (untested).

### 3.14 mstsc uses Kerberos user-to-user; the acceptor needs the machine account's TGT

**Field report (2026-10-21).** Windows 11 mstsc, not domain-joined, user
`marcel@linux-ng.de`, AD realm `LINUX-NG.DE`, fastrdp host joined with realm/adcli. The
client could get the ticket (`runas /netonly /user:marcel@linux-ng.de cmd`, then
`klist get TERMSRV/fastrdp-server.linux-ng.de` succeeds), but every login, with a typed
password or from the `runas /netonly` window, ended in NTLM. Proxy log
(`WLOG_FILTER=com.winpr.negotiate:DEBUG,...`):

```
negotiate_AcceptSecurityContext: Mechanism: SPNEGO (1.3.6.1.5.5.2)
negotiate_read_neg_token: Reading negTokenInit...  mechTypes [0] (48 bytes)  mechToken [2] (78 bytes)
Requested mechanism: Kerberos (1.2.840.113554.1.2.2)
[ERROR][com.winpr.sspi.Kerberos] retrieveTgtForPrincipal: krb5_get_init_creds_keytab (Client
  'TERMSRV/fastrdp-server.linux-ng.de@LINUX-NG.DE' not found in Kerberos database [-1765328378])
Requested mechanism: Kerberos (1.2.840.113554.1.2.2)
Requested mechanism: NegoEx (1.3.6.1.4.1.311.2.2.30)
Requested mechanism: NTLM (1.3.6.1.4.1.311.2.2.10)
Accepted mechanism: NTLM
```

**What mstsc sends (documented + verified).** Under CredSSP, Windows does Kerberos
**user-to-user** on purpose: CredSSP calls `InitializeSecurityContext` with
`ISC_REQ_USE_SESSION_KEY`, and the Kerberos SSP honours that with U2U, so the session key
that protects the delegated credentials is unique to the process (Microsoft Open
Specifications blog, "How Kerberos user-to-user authentication works", section
"Deliberate Kerberos U2U from client: CredSSP in Remote Desktop Session", with a capture).
The client first gets an ordinary `TERMSRV/<host>` ticket it never uses (that is what
`klist` shows), then sends:
- mechTypes `[MS-KRB5 1.2.840.48018.1.2.2, KRB5, NegoEx, NTLM]`: 4 OIDs, 48 bytes;
- as optimistic mechToken a GSS token with the **U2U OID 1.2.840.113554.1.2.2.3**, TOK_ID
  `04 00` (KERB-TGT-REQUEST, msg-type 16) and `server-name TERMSRV/<host>`, no realm.
  For `TERMSRV/fastrdp-server.linux-ng.de` this is exactly **78 bytes**
  (`tests/proxy-module/test_spnego.c` builds it and checks the size). An AP-REQ would be
  1-2 KB.

This does not depend on the domain membership of the client: every mstsc Kerberos NLA
login starts this way.

**What the acceptor did (verified, FreeRDP 3.32.2).**
- Negotiate maps MS-KRB5 to the Kerberos package (`negotiate.c:200-218`) and passes it
  the optimistic token (`negotiate.c:1101-1128`).
- `kerberos_AcceptSecurityContext()` reads the inner OID: U2U OID → state TGT_REQ
  (`kerberos.c:1600-1604`); TOK_ID `0x0400` → `kerberos_rd_tgt_token()`, then
  `retrieveSomeTgt()` (`kerberos.c:1617-1622`). This is the only caller of
  `retrieveTgtForPrincipal()`.
- `retrieveSomeTgt()` (`kerberos.c:1476-1550`) asks the KDC for a TGT of
  `TERMSRV/<host>@<default realm>` with the keytab key (`krb5_get_init_creds_keytab`), and
  on MIT builds of `<host>$@REALM` built from the second name component, i.e.
  `fastrdp-server.linux-ng.de$`, which it looks up in the same keytab.
- In AD, `TERMSRV/<host>` is only a service principal name of the computer account
  `FASTRDP-SERVER$`; the KDC refuses it as an AS client ("Client not found",
  KDC_ERR_C_PRINCIPAL_UNKNOWN), and no account is called `<fqdn>$` (and the proxy keytab
  holds only `TERMSRV/*` anyway). The Kerberos sub-mechanism fails; Negotiate skips the
  second Kerberos OID (same package, `negotiate.c:1157-1159`) and NegoEx, and took NTLM.
  Since R5 (§3.13) there is no NTLM, so the login fails at that point.
- Which TGT is right: the KDC issues the U2U ticket only when the client of the TGT
  the server returns is the account that owns the requested name (MIT
  `check_tgs_u2u()`, "2ND_TKT_MISMATCH"; AD maps the SPN to its account). In the
  Microsoft capture the server answers with its own (machine) TGT. For fastrdp with AD
  that is `FASTRDP-SERVER$`'s TGT.
- FreeRDP clients are affected the same way, but they offer U2U as a mechanism of its
  own before plain Kerberos (`[U2U, KRB5, NTLM]`), so after the failed U2U attempt the
  acceptor picks Kerberos and they log in with an AP-REQ (the same ERROR line appears in
  their logs).

**Fix (`patches/freerdp/0004`, `fastrdp-freerdp3` 3.32.2-3).** `retrieveSomeTgt()` first
looks for a machine account entry in the acceptor's keytab (one name component ending in
`$`, same realm as the service) and gets its TGT; then, as before, the service principal
itself (MIT, FreeIPA: `TERMSRV/<host>` is a principal of its own and may get a TGT);
otherwise it logs `Kerberos user-to-user: no TGT for TERMSRV/<host>@REALM: the keytab
needs the keys of the account that owns this service name (Active Directory: the machine
account <NAME>$)`. The old `<fqdn>$` guess is gone (it is covered by the keytab search
when such an entry exists). `fastrdp-termsrv-keytab` now also copies the machine
account's entries (`<NAME>$@REALM`) into `/etc/fastrdp/termsrv.keytab`, but only those
whose kvno, enctype and key equal a TERMSRV entry's (`-n` /
`FASTRDP_TERMSRV_KEYTAB_MACHINE=no` leaves them out). The identity role fails on AD when
the proxy keytab has no machine account entry. The module logs at INFO
`client <addr> requested Kerberos user-to-user (KERB-TGT-REQUEST)` when the first token is
one (`fastrdp_tsrequest_krb5_tok()`).

**Security.** With AD the TERMSRV keys **are** the machine account's long-term keys: AD
keeps one key set per account and the SPNs are names of it (adcli writes the same keys
for all of them; the e2e KDC does the same). The proxy keytab could already be used to
get the machine account's TGT or to forge tickets for any SPN of the computer account
(silver tickets) – renaming the entry is all it takes. Adding the entries under the
account's own name gives the proxy user (`_fastrdp-proxy`) no new secret, and the script
checks that (same kvno, enctype and key). The alternatives were weighed and not taken:
- a root timer that keeps a machine-account TGT in a ccache for the proxy: it would
  limit a stolen credential to the TGT lifetime only if the proxy did not also hold the
  long-term keys, which it must (the same keys decrypt the AP-REQs); it adds a daemon, a
  renewal race at expiry and a WinPR change to read a ccache;
- a separate account (service user with its own keys) for TERMSRV: would separate the
  keys from the computer account, but needs AD rights to create and maintain it, and SPN
  moves; reasonable for farms (§3.2 aliases), not for the default.
Cost: one AS exchange with the DC per Windows login (the TGT is not cached). The real
protection of the keys stays the keytab mode (root:`_fastrdp-proxy` 0640) and the proxy's
systemd sandbox.

**Tests.** `run_nla.sh` makes the throwaway MIT KDC behave like AD (MIT ≥ 1.22:
`TERMSRV/localhost` is an alias of `FASTRDP$`, and the kdcpolicy module
`tests/proxy-e2e/kdc_adlike.c` refuses service principal names as AS clients). A
FreeRDP client restricted to U2U (`/auth-pkg-list:'none,u2u'`, the same first token as
mstsc but with `[U2U]` as mechTypes) logs in through a proxy whose keytab holds the
`FASTRDP$` entries; with the unpatched FreeRDP the same login fails with the field
report's error ("Client 'TERMSRV/localhost@TEST.FASTRDP' not found in Kerberos
database"). With TERMSRV keys only it fails and names the missing keys; with the KDC in
MIT/FreeIPA mode TERMSRV keys alone work.

**Confirmed with mstsc (field report 2026-10-22).** Two Windows clients logged in with
mstsc through the proxy of an AD-joined host (fastrdp 0.5.0, `fastrdp-freerdp3`
3.32.2-3); the proxy logged `client <addr> requested Kerberos user-to-user
(KERB-TGT-REQUEST)` for both, and NLA only offers Kerberos (§3.13), so the logins were
Kerberos U2U. So Windows accepts the machine account's TGT-REP, the AD KDC issues the U2U
ticket, and mstsc accepts WinPR's end of the SPNEGO exchange: accept-completed and the
AP-REP without a mechListMIC (the client's first mechanism was selected,
`negotiate.c:1250-1264`; optional per RFC 4178 §5), where Microsoft's own acceptor
answers accept-incomplete, the AP-REP and a MIC. Not recorded: whether mstsc sent a MIC
anyway (it did not trip `nla_server_authenticate()`, compare §3.3), and the DC-side
events of lab L18 (AS for `<NAME>$`, TGS with ENC-TKT-IN-SKEY).

### 3.15 Known display issues (A5, A9)

Two open problems that users of mstsc see; both are tracked in the
[backlog](backlog.md#sessions).

**Black window on the next *Connect* in the same mstsc ([backlog A5](backlog.md#sessions)).**
After a connection that reached a desktop, closing it (the X or a logout) and pressing
*Connect* again in the same mstsc window shows a black window instead of the waiting
screen until the second factor times out. A freshly started mstsc works. The proxy sends the same waiting screen in both cases; mstsc
does not show it, most likely because it keeps GFX output state of the previous
connection (findings: [a5-capture-2026-10-26.md](a5-capture-2026-10-26.md)). No fix yet.
Workarounds:
- Approve the login anyway: the push on the phone or the approval page
  (`https://<rdp-fqdn>/web/approve`) work while the window stays black; the login goes on
  and the desktop is expected to appear after the hand-over [inferred: the working
  connections of the lab run all repainted at the hand-over; not confirmed for a black
  one].
- Close mstsc completely and start it again before reconnecting.
- Administrators: a reconnect grace period (`fastrdp_mfa_reconnect_grace`,
  [auth-matrix.md](auth-matrix.md#reconnect-grace)) skips the second factor, and with it
  the waiting, for a quick reconnect from the same address.

**Stale rectangles on X11 desktops via xrdp ([backlog A9](backlog.md#sessions)).** On
xfce and other X11 desktops served by xrdp, moving windows can leave stale or wrong
rectangles behind when the client does not decode H.264: xrdp then encodes RemoteFX
Progressive, and that path glitches (mstsc with `AvcEnabled=0` in its event 1401, typical
for Windows VMs without hardware H.264 decoding; `xfreerdp3 /gfx:progressive` the same).
Clients with H.264 (mstsc on a PC with a GPU, `xfreerdp /gfx:AVC420`) are clean. GNOME
(gnome-remote-desktop) is not affected. No workaround on the server yet; an upstream
report is drafted ([upstream.md](upstream.md) §12).

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

mstsc and the Windows App have no desktop field: the desktop comes from
`alternate shell:s:fastrdp:<desktop>`, from the choice users make on the web
gateway's chooser page, which also offers these `.rdp` files for download
([web-access.md](web-access.md#rdp-apps)), or, with `fastrdp_desktop_picker`, from the
list the RDP window shows after sign-in for connections without an alternate shell
([desktop-matrix.md](desktop-matrix.md#desktop-picker-in-the-rdp-window)).
Touch input (Windows App on tablets) reaches the picker as mouse clicks; untested.

Sound and microphone (`audiomode:i:0`, `audiocapturemode:i:1`) have nothing to do with
Kerberos; the client always opts in. GPO *Remote Desktop Session Host → Device and
Resource Redirection* applies to Windows hosts, not to fastrdp; the server side is
`fastrdp_audio` / `fastrdp_audio_input` ([client-guide.md](client-guide.md#sound-and-microphone),
[audio.md](audio.md)).

## 5. Bugs and gaps (summary)

| # | Where | Kind | Proposal |
|---|---|---|---|
| 1 | WinPR negotiate acceptor: second mechListMIC (§3.3) | bug (upstream FreeRDP) | Appendix A patch; if lab L3 shows mstsc affected, carry it in `patches/freerdp/` and report upstream |
| 2 | WinPR Kerberos acceptor rejects MS-KRB5 framing OID, Negotiate then silently picks NTLM (§3.1) | robustness (upstream) | accept `1.2.840.48018.1.2.2` in `kerberos_AcceptSecurityContext()` like MIT does; echo it in the AP-REP |
| 3 | No RC4 (RFC 4757) Wrap/MIC (§3.4) | limitation (upstream) | document AES requirement (done here); optionally fail early with a clear log message when the session key is RC4 |
| 4 | NTLM is offered by the acceptor although the module always refuses it | UX | **fixed** (§3.13), no FreeRDP change: the module sets `AuthenticationPackageList=!ntlm` on the front in `ServerSessionInitialize` and installs a refusing NTLM hash callback, which makes `credssp_auth_setup_server()` pass the auth data that Negotiate needs to honour the list. The keytab handling is unchanged (`KRB5_KTNAME`), and the back-end hop gets its own list (`!kerberos` for the NTLM hop to GNOME/Plasma). The proxy logs `client <addr> attempted NTLM (offered: …)` with the fix-it hint. The WinPR registry key `ntlm=0` (process-wide) was not used. e2e: `run_nla.sh` |
| 5 | Identity role: no AES enctype setting/check, no alias SPNs, FreeIPA without short name | gap | **fixed:** `fastrdp_termsrv_enctypes`, `fastrdp_termsrv_aliases`, FreeIPA short-name alias, `fastrdp-termsrv-check` in the role and in `check-host.sh` |
| 6 | Base role: self-signed cert covers only the FQDN | gap | **fixed:** SAN = FQDN, short name, aliases; internal CA via `fastrdp_front_cert_src` |
| 7 | Broker principal/user match fails for UPN ≠ sAMAccountName (§3.6) | probable bug | **fixed:** the principal is authoritative for NLA |
| 8 | No KDC proxy offering (§3.10) | gap | **implemented, Windows lab pending:** `fastrdp_web_kdcproxy` (python3-kdcproxy behind the web gateway's nginx, [web-access.md](web-access.md#kdc-proxy)) |
| 9 | auth-matrix.md / client-guide.md: SSO row lacks Credential Guard/Restricted Admin; `LAB\alice` advice for non-joined clients | docs | **done** (UPN and FQDN recommended); revisit after the lab |
| 10 | WinPR U2U acceptor cannot get a TGT with AD: mstsc's KERB-TGT-REQUEST fails, Kerberos dropped (§3.14, field report) | bug (upstream FreeRDP) + keytab content | **fixed:** `patches/freerdp/0004` (machine account TGT from the keytab), `fastrdp-termsrv-keytab` copies the `<NAME>$` entries (same keys), identity role checks them, module logs U2U requests. e2e: `run_nla.sh` (AD-like MIT KDC). mstsc confirmed (field report 2026-10-22) |
| 11 | mstsc: black window instead of the waiting screen on the next *Connect* in the same process (§3.15) | open (mstsc behaviour) | backlog A5; workarounds in §3.15 |
| 12 | xrdp: stale rectangles with RemoteFX Progressive on X11 desktops (§3.15) | bug (upstream xrdp/xorgxrdp, inferred) | backlog A9; report drafted ([upstream.md](upstream.md) §12) |

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
7. KDC proxy from a non-joined, off-network client: the GPO (or `kdcproxyname` in the
   `.rdp` file) against `fastrdp_web_kdcproxy`, which realm spelling Windows sends, and
   the certificate/revocation checks (§3.10).
8. Kerberos user-to-user end to end (§3.14): the AD KDC issues the U2U ticket against the
   machine account's TGT, and mstsc accepts WinPR's accept-completed without a
   mechListMIC. (Confirmed 2026-10-22, §3.14.)
9. What mstsc shows, and how long it waits, while the broker waits for a push or a web
   approval (§3.8, L15); with `fastrdp_proxy_waiting_screen` the panel, its countdown
   and QR code, and that nothing of it stays once the desktop arrives; with
   `fastrdp_desktop_picker` that the picker's keys (top row, keypad, arrows, Enter, Esc)
   and clicks arrive, also from the Windows App on macOS/iOS (Unicode keys, touch); with
   `fastrdp_mfa_mode: code_or_web` that the code field gets the digits on every layout,
   keypad and soft keyboard. Detailed plan, with the lab-only input trace
   (`fastrdp_proxy_input_trace`): [lab-waiting-screen-input.md](lab-waiting-screen-input.md).
10. Windows Hello for Business certificates as a smart card toward fastrdp (§3.9, L19).
11. An MFA gateway in front of fastrdp: rdpgw with Keycloak, Windows RD Gateway with the
    NPS extension (§3.10, L20, L21).

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
| L1 | W10, W11 | mstsc to FQDN, type password | success; proxy log `requested Kerberos user-to-user` (INFO), then `NLA logon: principal alice@LAB…`, package Kerberos; X11 desktop: `klist` shows TGT; GNOME/Plasma: no TGT |
| L2 | W10 | GPO default credentials `TERMSRV/*.lab.example.com`, mstsc to FQDN, no prompt | success without prompt, TGT on X11 |
| L3 | W10, W11 | capture the negTokenInit: mechTypes order, optimistic token type; look for `NegoEx` first. If the MIC path is used: check that the client's last negTokenResp lacks negState and whether the login hangs | Kerberos first: 1-round SPNEGO. NegoEx first: unpatched → hang/failure (§3.3), patched → success |
| L4 | W11 (Credential Guard) | same as L2 | prompt appears (SSO blocked); after typing: success with TGT |
| L5 | W10, W11 | `mstsc /restrictedAdmin /v:rdp1.lab.example.com` | success without prompt, no TGT, broker log user = principal |
| L6 | W10, W11 | `mstsc /remoteGuard`; GPO "Require Remote Credential Guard"; GPO "Restrict credential delegation"; then the same with `fastrdp_accept_remote_guard: true` | default, first two: mstsc's own "Remote Credential Guard not supported" style error, not a network error (proxy log "REDIRECTED_AUTHENTICATION_MODE_REQUIRED but disabled, answering without"); record the dialog text. Third: Restricted Admin, success. With the option: success without a password prompt, proxy log "Remote Credential Guard: identity only", broker log "remote credential guard: identity only, credentials discarded", no TGT in the session; record whether mstsc sends supplementalCreds (FreeRDP log level DEBUG) and the third case's choice (RCG or Restricted Admin) |
| L7 | W10 | smartcard/YubiKey PIV user, mstsc, select smart card, PIN | success, `smartcard: true`, no PIN in broker log, no TGT |
| L8 | W10, W11-WG | self-signed lab cert vs internal-CA cert; FQDN vs short name | record certificate prompts (Kerberos vs not) |
| L9 | any | connect by IP address | failure right after the password prompt; record the dialog text (expected "logon attempt failed"/"credentials did not work", §3.13); proxy log `attempted NTLM (offered: NegoEx, NTLM)` or `(offered: NTLM)`, no NTLM SAM error |
| L10 | W10 | connect by short name `rdp1` | Kerberos success (ticket `TERMSRV/rdp1`), cert name warning unless the SAN contains it |
| L11 | W11-WG | user `alice@lab.example.com` with DC reachable; then `LAB\alice` | UPN: success; NetBIOS: expect NTLM → refused |
| L12 | W11-WG off-network | KDC proxy GPO/registry set, VPN off | success via KDC proxy |
| L13 | W11-E | Entra-only device | refused at once; proxy log `attempted NTLM (offered: NegoEx, NTLM)` |
| L14 | W10 | computer account temporarily RC4-only (`msDS-SupportedEncryptionTypes=0x4`), new ticket | failure at pubKeyAuth/MIC; restore AES |
| L15 | W10 | `fastrdp_mfa_mode: push`, L1 and L5 | push prompt, success after approval; L5 needs the service user |
| L16 | W10 | user with UPN prefix ≠ sAMAccountName, typed as UPN | expected refusal (§3.6) |
| L17 | any | `fastrdp_mfa_mode: otp`, password+OTP in the mstsc prompt | KDC pre-auth failure (bad password count +1), no login |
| L18 | W11-WG (`runas /netonly /user:alice@lab.example.com mstsc`, and typed UPN), W10 | Kerberos user-to-user (§3.14), `WLOG_FILTER=com.winpr.negotiate:DEBUG,com.winpr.sspi.Kerberos:DEBUG` | `/etc/fastrdp/termsrv.keytab` lists `<NAME>$@REALM`; proxy log `requested Kerberos user-to-user`, no `retrieveTgtForPrincipal` error, DC log: AS for `<NAME>$` and a TGS for `TERMSRV/<host>` with ENC-TKT-IN-SKEY; login succeeds. If it stops after the AP-REP: record whether mstsc sent a mechListMIC and negState (§3.3) |
| L19 | W11 (WHfB certificate trust or certificate in the WHfB container) | mstsc, choose the Windows Hello/smart card credential | success like L7: `smartcard: true`, principal from the certificate's UPN; no PIN or biometric data in the broker log |
| L20 | W11-WG off-network | rdpgw (OIDC with Keycloak, passkey) in front of fastrdp, `.rdp` from rdpgw | Keycloak sign-in, mstsc connects through the gateway (rdpgw's KDC proxy for the TERMSRV ticket), fastrdp's push or web approval still asked; record certificate prompts and whether the Windows App behaves the same |
| L21 | W10 | Windows RD Gateway + NPS extension (Entra MFA) in front of fastrdp | Authenticator push at the gateway, then Kerberos NLA to fastrdp; record mstsc's waiting text and the RADIUS timeout needed |

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
