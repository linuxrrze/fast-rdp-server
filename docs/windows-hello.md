# Windows Hello and Windows Hello for Business

Can users sign in to fastrdp from Windows with **Windows Hello** (face, fingerprint,
PIN), and does it count as MFA? With emphasis on **Samba AD** domains.

**Short answer:**
- fastrdp never sees Hello itself. Hello only unlocks a TPM-bound key on the client.
  What reaches an open-source server is what that key produces: a **Kerberos ticket
  obtained by PKINIT** (towards fastrdp's NLA) or a **passkey** (towards Keycloak).
- **Samba-only domain (no Entra ID, no AD FS): real Windows Hello for Business (WHfB)
  is not possible today.** Samba 4.24 has key-trust PKINIT in its KDC, but the Windows
  client provisions a WHfB credential only through Entra device registration or AD FS
  Enterprise DRS, and neither exists as open source.
- What works with Samba today: a **TPM virtual smart card or YubiKey PIV** with an
  open-source CA (path A, Hello-like, not Hello), and **Hello as a passkey** for the
  web path and web approval (path G). With an Entra tenant, a **WHfB certificate in
  the Hello container** should log in to Samba like a smart card (path B, lab L19).
- **Microsoft AD:** all WHfB models work with DCs 2016+; per-login evidence in the
  ticket (S-1-18-3/-4) is usable by fastrdp once backlog K11 (in progress) is done.

Nothing on this page has been tested with Windows. Markers: **[verified]** = read in
source or a specification, **[doc]** = vendor documentation, **[inference]** = follows
from the above, **[unverified]** = reported elsewhere or a guess, needs a lab. Samba
source references are to Samba 4.25.0. Context: [windows-clients.md](windows-clients.md)
§3.8 (MFA with mstsc) and §3.9 (smart cards), [smartcard-nla.md](smartcard-nla.md),
[passkeys.md](passkeys.md).

## 1. How Hello works

The PIN or biometric gesture only unlocks a key **locally**: a TPM-bound key in the
NGC container ("Microsoft Passport Key Storage Provider"). What the domain controller
sees depends on the deployment model [doc: how-it-works-authentication]:

| Model | What the client sends | What the DC checks |
|---|---|---|
| **Key trust** | PKINIT, signed with the Hello key, in a self-signed certificate | looks up the public key in the user's `msDS-KeyCredentialLink` |
| **Certificate trust** | ordinary PKINIT with a CA-issued certificate whose key lives in the Hello container | normal smart card checks (NTAuth, mapping) |
| **Cloud Kerberos trust** | Entra ID issues a partial TGT, the on-prem DC exchanges it for a full TGT | the partial TGT (no PKINIT at the DC) |
| **Entra-only** | no Kerberos at all | – |
| **Hello as a WebAuthn platform authenticator** | a per-site passkey | the web relying party (e.g. Keycloak; works today) |

No open-source software can be the Hello container; open-source servers can only use
what Hello produces. For RDP sign-in WHfB "emulates a smart card" [doc: Microsoft,
Remote Desktop sign-in with Windows Hello for Business], so towards fastrdp a WHfB
login looks like a smart card login (`smartcard: true`, [smartcard-nla.md](smartcard-nla.md)).

## 2. Evidence in the ticket

Well-known SIDs in the PAC that say how the TGT was obtained [verified: MS-DTYP §2.4.2.4]:

| SID | Meaning | Microsoft AD | Samba AD |
|---|---|---|---|
| S-1-18-1 | authentication authority asserted identity: every AS logon, **including passwords** (no evidence) | yes | yes |
| S-1-18-2 | service asserted identity (S4U) | yes | yes |
| S-1-18-3 | fresh public key identity: PKINIT with the RFC 8070 freshness token | only with the DC GPO "KDC support for PKInit Freshness Extension" (off by default) | whenever the client sends a valid freshness token, no setting [verified: `pac-glue.c:2581`, `wdc-samba4.c:100`, `kerberos5.c:2808`] |
| S-1-18-4 | key trust identity (WHfB key trust) | DCs 2016+ | **never** |
| S-1-18-5 | key property MFA (key credential carries the MFA property) | yes | **never** |
| S-1-18-6 | key property attestation (reserved) | – | **never** |

Samba also has no Authentication Mechanism Assurance (AMA). Windows clients attempt
the freshness extension since version 1607.

- **S-1-18-3 is not "hardware".** It means "PKINIT with current proof of possession";
  a software certificate gets it too.
- **Shadow credentials.** Whoever can write a user's `msDS-KeyCredentialLink` or
  `altSecurityIdentities` can add a key or mapping and obtain such logons for that
  user. Restrict the ACLs (Samba creates Key Admins ACEs), audit changes (Samba 4.24
  `dsdb_password_audit` logs "Auth info change"; AD event 5136).
- **Age.** The evidence describes the Windows sign-in that produced the TGT, which may
  be hours old.

**fastrdp use.** Today: an exempt group (`fastrdp_mfa_exempt_groups`) for accounts with
"smart card is required for interactive logon" ([windows-clients.md](windows-clients.md#39-smartcard-from-windows-q7)).
With backlog K11 (in progress): per-login items such as `sid:S-1-18-3` (Samba; MS AD
with freshness), `sid:S-1-18-4` (MS AD key trust) or an AMA group (MS AD).

## 3. Samba AD: what exists, what blocks

- **Samba 4.24** (2026-03-18) has key-trust PKINIT in its Heimdal KDC
  (`source4/kdc/db-glue.c` `get_key_trust_public_keys()`;
  `third_party/heimdal/kdc/pkinit.c` `pk_check_key_trust()`) and
  `samba-tool user keytrust` / `samba-tool computer keytrust` [verified].
- **Samba 4.25.0** (2026-09-24) adds nothing for Hello [verified].
- **The blocker is the Windows client.** It provisions a Hello credential only through
  Entra device registration (DRS) or AD FS Enterprise DRS; neither has an open-source
  implementation. Without them `dsregcmd /status` shows `PreReqResult: WillNotProvision`
  [doc: troubleshoot-device-dsregcmd, how-it-works-provisioning].

## 4. Paths

| | Path | Components | Samba support | Provisioning | mstsc → fastrdp | fastrdp MFA evidence | Effort / risk |
|---|---|---|---|---|---|---|---|
| **A** | **TPM virtual smart card** (`tpmvscmgr`; discouraged by Microsoft but shipped) or **YubiKey PIV** | open-source CA (step-ca, FreeIPA/Dogtag, adcs_python) | **works today** with Samba 4.24+ (PKINIT + strong certificate mapping, enforcement `full` by default) | admin: `tpmvscmgr create`, CSR with `certreq` and the smart card KSP, CA signs | yes, as a smart card (TSSmartCardCreds) | S-1-18-3 [unverified on the wire]; today exempt group / "smart card required" | low–medium. Hello-like (PIN-protected TPM key), but not Hello |
| **B** | **WHfB certificate in the Passport KSP** (certificate trust without AD FS) | Entra-joined/registered device with WHfB (Entra tenant, e.g. M365) + CA | PKINIT like a smart card [doc for Windows targets; inference for Samba; lab L19] | Intune SCEP/PKCS ("Enroll to Windows Hello for Business, otherwise fail") or manual (`Generate-CertificateRequest` → `certreq` → CA → `certreq -accept`) | yes, as a smart card [inference] | S-1-18-3 [inference] | medium |
| **C** | Classic on-prem certificate trust (AD FS enrolment agent + AD CS + Enterprise DRS) | AD FS, AD CS | impractical: AD FS on a Samba domain unreported, AD CS cannot be the enterprise CA | – | – | – | impractical |
| **D** | **Key trust**, hybrid (Entra Connect writes `msDS-KeyCredentialLink`) or manual `samba-tool user keytrust add <user> hello.cer` | Entra tenant, Samba 4.24+ | plausible but **probably blocked** (below) | Entra Connect writeback [unverified] or manual export + `keytrust add` | as Kerberos SSO / smart card [inference] | S-1-18-3 only | high, lab |
| **E** | On-prem key trust via AD FS DRS | AD FS | impractical | – | – | – | impractical |
| **F** | Cloud Kerberos trust | Entra tenant | Samba has RODC-TGT code paths; Entra partial TGTs untested; no KERB-KEY-LIST | Entra | first factor only (no PKINIT at the DC) | none | speculative |
| **G** | **Hello as a passkey** for the web path and web approval | Keycloak | independent of the DC: **works today** | user registers the passkey in Keycloak | yes: mstsc waits, the user approves on `/web/approve` after a Keycloak sign-in with Hello (`[mfa] mode = web` / `push_or_web`) | the web sign-in | low |
| **H** | Convenience PIN (`AllowDomainPINLogon`) | – | – | GPO | password logon underneath | S-1-18-1 only: **not MFA** | – |

Path A uses the TPM key through a virtual smart card [doc: virtual-smart-card-overview];
YubiKey PIV is the tested hardware alternative ([smartcard-nla.md](smartcard-nla.md)).
adcs_python is an open-source CEP/CES enrolment server; its README says it is not
audited and largely AI-generated.

**Path D in detail.** `samba-tool user keytrust add` accepts a certificate or a public
key (RSA 2048 only) and stores it as `KEY_USAGE_NGC` [verified]. Two obstacles:
- After the key matches, Samba's Heimdal still runs `_kdc_pk_check_client()`
  (`pkinit.c:2227`), which needs a Microsoft UPN SAN matching the account
  (`pkinit.c:2301-2321`) or an entry in `pkinit_mappings_file` (format
  `principal:subject DN`, loaded at KDC start) [verified]. Samba's own key-trust tests
  use certificates with a UPN SAN (`python/samba/tests/krb5/key_trust_tests.py:202-270`).
  MS-PKCA §3.1.5.2.1.4 maps by the key alone. A blog reports that Hello's self-signed
  certificate lacks the UPN [unverified, lab-critical]; then the KDC answers
  `KDC_ERR_CLIENT_NAME_MISMATCH`.
- Samba advertises `DS_10` (a 2016 DC) only at DC functional level 2016; the default is
  2008_R2. Raising it: `ad dc functional level = 2016` in smb.conf,
  `samba-tool domain functionalprep --function-level=2016`,
  `samba-tool domain level raise --domain-level=2016 --forest-level=2016`. Whether the
  Windows client checks for it is unverified.
- Tranquil IT reported Entra Connect working with Samba AD at sambaXP 2026 (vendor
  claim); whether key writeback works is unverified.

## 5. Recipe: path B (and path A)

Path A is identical from step 2 on, without Entra (steps 4-5 become `tpmvscmgr` /
YubiKey PIV enrolment). Untested end to end (lab L19).

1. **Samba DC 4.24+, KDC PKINIT.** `/etc/krb5.conf` on the DC, section `[kdc]` (read
   by Samba's embedded Heimdal KDC):
   ```ini
   [kdc]
       enable-pkinit = yes
       pkinit_identity = FILE:/var/lib/samba/private/tls/kdc.pem,/var/lib/samba/private/tls/kdc.key
       pkinit_anchors = FILE:/var/lib/samba/private/tls/ca.pem
       pkinit_principal_in_certificate = yes
       pkinit_win2k = no
       pkinit_win2k_require_binding = yes
       # optional, Heimdal option; whether Samba honours it is unverified:
       # require-pkinit-freshness = yes
   ```
   `smb.conf`: keep `strong certificate binding enforcement = full` (default), set
   `kdc require canonicalization = yes` [unverified]. See the Samba wiki
   [Samba AD Smart Card Login](https://wiki.samba.org/index.php/Samba_AD_Smart_Card_Login).
2. **KDC certificate.** EKUs KDC Authentication (1.3.6.1.5.2.3.5), Client
   Authentication, Server Authentication; SAN dNSName with the DC's FQDN and the domain
   name (MS-PKCA §3.1.5.1); Key Usage digitalSignature, keyEncipherment; a CRL
   distribution point over HTTP that clients can reach.
3. **Publish the CA** from a domain-joined Windows admin machine:
   ```
   certutil -dspublish -f ca.cer NTAuthCA
   certutil -dspublish -f ca.cer RootCA
   ```
   and distribute the root via GPO or Intune.
4. **WHfB on the client:** Entra-joined device, WHfB enabled by Intune policy;
   `dsregcmd /status` shows `NgcSet : YES`.
5. **User certificate into the Passport KSP:** Intune SCEP profile with KSP "Enroll to
   Windows Hello for Business, otherwise fail", EKUs Smart Card Logon + Client
   Authentication, SAN UPN; or manually with `Install-Script Generate-CertificateRequest`
   → `certreq` → CA signs → `certreq -accept`. Ideally the CA adds the SID extension
   (1.3.6.1.4.1.311.25.2) with the user's objectSid. Check: `certutil -store -user my`
   shows `Provider = Microsoft Passport Key Storage Provider`.
6. **Strong mapping** if the CA cannot add the SID extension: set
   `altSecurityIdentities` to `X509:<SKI><hex>` or
   `X509:<I><issuer DN><SR><serial in reversed byte order>`. Samba treats both as
   strong and reverses the serial like Windows (`db-glue.c:1466-1490`) [verified]. Samba
   does not support the URL-SAN SID form `tag:microsoft.com,2022-09-14:sid:`.
7. **mstsc to fastrdp:** choose the Hello credential, face/fingerprint/PIN; fastrdp sees
   a smart card login (`smartcard: true`).
8. **fastrdp MFA:** today an exempt group, with "smart card is required for interactive
   logon" on those accounts; with backlog K11 (in progress) `sid:S-1-18-3`.

**Path D lab sketch.** Export the user's self-signed Hello certificate (subject like
`CN=<SID>/<GUID>/login.windows.net/<tenant>/<UPN>`, Passport KSP), then
`samba-tool user keytrust add <user> hello.cer`, possibly raise the DC level to 2016
(§4). Expect `KDC_ERR_CLIENT_NAME_MISMATCH` if the UPN check bites; workarounds are a
`pkinit_mappings_file` entry or a Samba patch.

## 6. Microsoft AD (contrast)

- All WHfB models work with AD DS 2016+ [doc: hybrid-key-trust, What's new in Windows
  Server 2016].
- Key trust marks the ticket with S-1-18-4; certificate trust and smart cards can use
  AMA groups.
- fastrdp MFA today: exempt groups, or an AD authentication policy with
  `fastrdp_mfa_nla_kdc_enforced_by_ad_policy`; per-login evidence with K11 later.
  Details: [windows-clients.md](windows-clients.md#39-smartcard-from-windows-q7).

## 7. Recommendation

| Site | Now | Later |
|---|---|---|
| **Samba AD** | path A (TPM virtual smart card or YubiKey PIV + open-source CA); Hello passkeys + web approval (path G) | path B if an Entra tenant exists, after lab L19; `sid:S-1-18-3` with K11 |
| **Microsoft AD** | WHfB key trust or certificate trust; exempt groups / AD policy for MFA; path G regardless | K11 for per-login evidence (S-1-18-4, S-1-18-3, AMA group) |

Hello passkeys with web approval (path G) work regardless of the DC.

## 8. Open lab questions

- Windows client against a Samba 4.24 key-trust account (path D).
- Contents of Hello's self-signed key-trust certificate: does it carry a UPN SAN?
- Does the client require a `DS_10` (2016) DC?
- Entra Connect key writeback into Samba AD.
- AD FS on a Samba domain.
- Cloud Kerberos trust against Samba.
- Does S-1-18-3 actually appear for Windows → Samba PKINIT, and in service tickets?
- Which S-1-18-x SIDs Microsoft AD puts into `TERMSRV` tickets per WHfB model.

## Sources

- Microsoft: [How WHfB authentication works](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-authentication),
  [provisioning](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-provisioning),
  [Remote Desktop sign-in with WHfB](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/rdp-sign-in),
  [hybrid key trust](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-key-trust),
  [What's new in Windows Server 2016](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2016),
  [dsregcmd troubleshooting](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd),
  [virtual smart cards](https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-overview).
- Specifications: [MS-DTYP §2.4.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)
  (well-known SIDs), [MS-PKCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
  (§3.1.5.1, §3.1.5.2.1.4), MS-ADTS §2.2.20.4 (CUSTOM_KEY_INFORMATION), RFC 8070.
- Samba: [4.24.0 release notes](https://www.samba.org/samba/history/samba-4.24.0.html),
  [Samba AD Smart Card Login](https://wiki.samba.org/index.php/Samba_AD_Smart_Card_Login);
  source (4.25.0) as cited above.
- sambaXP: [2019, Farooqi, Windows Hello for Business](https://sambaxp.org/fileadmin/user_upload/sambaxp2019-slides/farooqi_sambaxp2019_WindowsHelloForBusiness.pdf);
  [2026, Cardons, Integrating Samba AD](https://sambaxp.org/fileadmin/user_upload/sambaxp2026-Slides/sambaXP2026_Cardons_Integrating_SambaAD.pdf).
- [adcs_python](https://github.com/tranquilit/adcs_python) (open-source CEP/CES enrolment server).
- SpecterOps, [Shadow credentials](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/).
- Blog [unverified]: [WHfB cloud Kerberos trust deployment](https://www.samuraj-cz.com/en/article/windows-hello-for-business-cloud-kerberos-trust-deployment/).
