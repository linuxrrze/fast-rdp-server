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

`build_pkinit_args()` prints the slot id as `UINT16`. Modules with 32-bit slot ids
(SoftHSM2) therefore fail PKINIT; cards behind OpenSC have small slot ids and work.
Workaround for affected modules: use `p11-kit-proxy.so` as the PKCS#11 module, which
renumbers slots. A fix is in `patches/freerdp/`; details and the reproducer
(`SC_MODULE=softhsm tests/proxy-e2e/run_smartcard.sh`) are in
[upstream.md](upstream.md#1-freerdp-pkcs11-slot-id-truncated-to-16-bits).

## 3. xrdp PR #3868 (NLA): builds, but default FreeRDP clients fail

| Check | Result |
|---|---|
| Build with `--enable-nla` | yes. GSSAPI detection uses `krb5-config` only; a `pkg-config krb5-gssapi` fallback would help cross/sysroot builds |
| Kerberos NLA with FreeRDP 3.32.1 **default** settings | **fails**: `NLA: authentication failed: Invalid token was supplied` |
| Same client with `/auth-pkg-list:'kerberos,!u2u,!ntlm'` | **works**: `NLA authentication completed for bob`, then autologon with the delegated user |
| Smartcard (PKINIT) logon | fails as documented in the PR: `unsupported or malformed TSCredentials` |

**Root cause:** an MIT krb5 regression, not xrdp or FreeRDP. MIT 1.21.0–1.22.1 looks for
the client's SPNEGO mechListMIC under the wrong ASN.1 tag. The MIC is only needed
because FreeRDP offers Kerberos U2U first and MIT selects plain Kerberos. MIT fixed it
in 1.22.2 (ticket 9183). Debian 13 and Ubuntu 26.04 ship affected versions. Details,
reproducer (`tests/krb5-spnego/run.sh`) and report texts:
[upstream.md](upstream.md#2-mit-krb5-1210-1221-spnego-acceptor-ignores-the-initiators-mechlistmic).

## Consequences for fastrdp

- **Smartcard / YubiKey PIV logon is supported through the proxy** (needs validation
  with real cards, AD PKI and mstsc). The auth matrix is updated.
- **Keep NLA at the proxy.** Even after #3868 is merged, xrdp's NLA would only cover
  X11 sessions. On distributions with MIT krb5 < 1.22.2 it breaks FreeRDP Kerberos
  clients unless they disable U2U, and it has no smartcard support. The proxy covers
  all back-ends and smartcards today.
- Upstream reports: see [upstream.md](upstream.md). Track #3868 for direct-xrdp
  deployments without fastrdp.
