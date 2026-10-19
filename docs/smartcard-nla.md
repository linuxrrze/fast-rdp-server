# Smartcard logon and NLA – assessment (phase 5)

Tested on 2026-10-19 with:
- FreeRDP 3.32.1 (client library, freerdp-proxy) and MIT Kerberos 1.22.1, all
  Ubuntu 26.04 builds;
- SoftHSM2 2.6.1 as a stand-in for a PIV card or YubiKey, plus OpenSC and p11-kit;
- xrdp at PR #3868 (`pr3868` head `0f9be1d`).

No physical cards or Active Directory were involved. The tests are reproducible
with `tests/proxy-e2e/run_smartcard.sh`.

## 1. Smartcard logon through fastrdp: works

With smartcard NLA the client obtains its Kerberos ticket from the KDC by **PKINIT**
(certificate + PIN on the card) and then authenticates to `TERMSRV/<host>` with
ordinary Kerberos. freerdp-proxy only sees the Kerberos part, so the existing design
covers it without new server-side crypto. Verified end to end:

| Check | Result |
|---|---|
| Client finds the cert on the token, gets a TGT via PKINIT | yes; the user has no password at all |
| Proxy accepts the Kerberos NLA, module binds the principal | yes, `alice@TEST.FASTRDP` (from the certificate SAN) |
| Wrong PIN | stops at PKINIT, never reaches the broker |
| Broker sees the login as `smartcard: true` | yes |

**Bug found and fixed in fastrdp:**
- **What happened:** with smartcard logon the client delegates TSSmartCardCreds, and
  FreeRDP stores the **PIN in the password setting**. The module forwarded it as
  `password`.
- **Consequence:** the PIN would have reached `pam_sss` (counting failed logons in
  AD, so lockout risk) or privacyIDEA.
- **Fix:** the module now checks `PasswordIsSmartcardPin` and never forwards the PIN,
  and the broker drops any password on smartcard logins. A regression test covers it.

**MFA policy:** the `smartcard` flag is a client statement made after Kerberos, so
it cannot by itself replace the second factor. The sound setup in AD:
- Set **"Smart card is required for interactive logon"** on the smartcard users'
  accounts. AD then gives them a random password, so a successful Kerberos login
  implies PKINIT.
- Put those users into a group listed in `fastrdp_mfa_exempt_groups`.

Other users keep their privacyIDEA push even when they use a card.

**Deployment requirements (AD):**
- KDC certificates on the DCs, the issuing CA in NTAuth, and user certificates with
  the UPN SAN. This is the standard Windows smartcard-logon PKI.
- On Linux clients: OpenSC (`opensc-pkcs11.so`) or `libykcs11.so` for YubiKey PIV,
  and the CA in `pkinit_anchors`.
- Windows mstsc uses the card natively. *mstsc against fastrdp is not tested yet.*

## 2. FreeRDP bug: PKCS#11 slot ID truncated to 16 bits

`libfreerdp/core/smartcardlogon.c`, `build_pkinit_args()`:

```c
"PKCS11:module_name=%s:slotid=%" PRIu16 ..., (UINT16)scCert->slotId
```

PKCS#11 slot IDs are `CK_SLOT_ID` (unsigned long). SoftHSM, for example, uses
`0x47c3da5d`, which becomes `slotid=55901`. MIT PKINIT then finds "no matching
tokens" and falls back to encrypted timestamp, so the logon fails. Cards behind
OpenSC have small slot IDs and work. Workaround for affected modules: use
`p11-kit-proxy.so` as the PKCS#11 module, which renumbers slots.

Draft upstream issue:

> **Smartcard logon: PKCS#11 slot id truncated to UINT16 in build_pkinit_args**
> `build_pkinit_args()` formats `slotid` with `PRIu16` and casts `scCert->slotId` to
> `UINT16`. CK_SLOT_ID is an unsigned long; modules such as SoftHSM2 use 32-bit
> slot ids (e.g. 0x47c3da5d → "slotid=55901"), so MIT PKINIT reports "PKCS#11 module
> has no matching tokens" and smartcard logon fails. Reproducer: SoftHSM2 token with
> cert+key, `/smartcard-logon /p11-module:libsofthsm2.so`, KRB5_TRACE on the client.
> Fix: keep the full slot id (`%lu` / `CK_SLOT_ID`).

## 3. xrdp PR #3868 (NLA): builds, but default FreeRDP clients fail

| Check | Result |
|---|---|
| Build with `--enable-nla` | yes. GSSAPI detection uses `krb5-config` only; a `pkg-config krb5-gssapi` fallback would help cross/sysroot builds |
| Kerberos NLA with FreeRDP 3.32.1 **default** settings | **fails**: `NLA: authentication failed: Invalid token was supplied` |
| Same client with `/auth-pkg-list:'kerberos,!u2u,!ntlm'` | **works**: `NLA authentication completed for bob`, then autologon with the delegated user |
| Smartcard (PKINIT) logon | fails as documented in the PR: `unsupported or malformed TSCredentials` |

What happens in the failing case:
1. WinPR's SPNEGO offers *Kerberos user-to-user* first, with an optimistic token,
   then Kerberos.
2. MIT selects Kerberos, which requires a mechListMIC.
3. The Kerberos exchange completes: MIT decrypts the AP-REQ and sends the AP-REP.
4. MIT then rejects the client's final `negTokenResp` (state *accept-completed* +
   mechListMIC) with `GSS_S_DEFECTIVE_TOKEN`.

freerdp-proxy (WinPR on both sides) accepts the same exchange. Which side computes or
checks the MIC wrongly needs investigation.

Draft comment for PR #3868 (and possibly a FreeRDP issue):

> Tested 0f9be1d with FreeRDP 3.32.1 (Ubuntu 26.04) against MIT krb5 1.22.1.
> Kerberos NLA fails with default client settings ("Invalid token was supplied"
> after the AP-REP round). FreeRDP's SPNEGO proposes Kerberos U2U first; MIT
> selects Kerberos and requests a mechListMIC; the client's final negTokenResp
> with mechListMIC is rejected. With `/auth-pkg-list:'kerberos,!u2u,!ntlm'` the
> same login succeeds. freerdp-proxy (WinPR acceptor) accepts the default
> exchange. Smartcard TSCredentials are rejected as documented.

## Consequences for fastrdp

- **Smartcard / YubiKey PIV logon is supported through the proxy** (needs validation
  with real cards, AD PKI and mstsc). The auth matrix is updated.
- **Keep NLA at the proxy.** Even after #3868 is merged, xrdp's NLA would only cover
  X11 sessions. It would currently break FreeRDP Kerberos clients unless they
  disable U2U, and it has no smartcard support. The proxy covers all back-ends and
  smartcards today.
- Report both upstream issues above. Track #3868 for direct-xrdp deployments without
  fastrdp.
