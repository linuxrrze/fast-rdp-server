# Passkeys (FIDO2/WebAuthn) – assessment

Can users log in to fastrdp with **passkeys**, meaning FIDO2/WebAuthn discoverable
credentials? This page covers hardware keys (YubiKey) and software passkeys (KeePassXC,
Bitwarden, Windows Hello, iCloud Keychain, Google Password Manager, phones via hybrid/QR).

Assessed on 2026-10-20 against these sources:
- Keycloak 26.8.1, privacyIDEA 3.14 and the privacyIDEA Credential Provider 3.8.0.0;
- FreeRDP 3.32.2, xrdp 0.10.6.1, KeePassXC 2.7.12;
- FreeIPA (master) and [MS-RDPEWA] revision 3.0.

No hardware keys, FreeIPA or Windows were available. Keycloak 26.8.1 was tested for
stage 1 (dev mode, headless Chromium with a virtual authenticator; see
[Stage 1 results](#stage-1-results-keycloak-2681)). Statements are marked:
- **[verified]**: read in source code or a specification;
- **[docs]**: taken from vendor documentation only;
- **[inferred]**: reasoning from the above, to be confirmed in a lab;
- **[tested]**: run against Keycloak 26.8.1 in `make test-keycloak`.

## Summary

| Path | Passkeys today? | How |
|---|---|---|
| **Web** (Keycloak → webgate → Guacamole) | **Yes, configuration only** | Keycloak is a full passkey relying party. A passkey with user verification (PIN or biometric) counts as MFA. fastrdp only needs the right Keycloak flow so that `acr` says `mfa` ([recipe](#recipe-a-acrmfa-via-a-forced-flow-recommended)); `fastrdp_web_passkeys: true` sets it up (opt-in, [tested]). The webgate refuses single-factor `amr` settings. |
| **RDP, native** (mstsc, xfreerdp → proxy, Kerberos NLA) | **No direct way**; **indirect ways** with FreeIPA (Linux clients) or AD + Entra ID (Windows clients) | CredSSP/NLA has no FIDO2 mechanism. A passkey can only produce the **Kerberos TGT** that NLA then uses: FreeIPA passkey pre-authentication (sssd) on Linux clients, or Windows passkey/FIDO2 sign-in with Microsoft Entra Kerberos. The KDC can enforce this for `TERMSRV/<host>` with FreeIPA authentication indicators; `fastrdp_mfa_nla_kdc_enforced` then skips the push ([below](#kdc-enforced-strong-authentication-for-nla)). Lab stage. **As the second factor, any client:** with `fastrdp_mfa_mode: web` (or `push_or_web`) the user approves the waiting RDP login on the web gateway after a Keycloak sign-in, which can be a passkey ([web approval](#passkeys-as-the-rdp-second-factor-web-approval)). |
| **Inside the session** (websites in the remote desktop) | **Only software passkeys that live in the session** (KeePassXC or Bitwarden in the session's browser) | No server back-end (xrdp, gnome-remote-desktop, KRdp) implements WebAuthn redirection ([MS-RDPEWA]). USB redirection is disabled. Local platform authenticators and phones cannot reach the session. Feasibility design + codec prototype: [webauthn-redirection.md](webauthn-redirection.md). |

YubiKey **PIV** smartcard logon (PKINIT) keeps working as documented in
[smartcard-nla.md](smartcard-nla.md). It is **not** a passkey (see [PIV vs. FIDO2](#yubikey-piv-vs-fido2)).

## Support matrix

✔ works today · ◐ works with configuration or a prototype, needs a lab · ✘ not possible

| Authenticator | Web path (Keycloak) | RDP native (NLA) | Inside the session |
|---|---|---|---|
| **YubiKey FIDO2** (5 series, Bio, Security Key) | ✔ passkey (resident key, PIN/UV) or 2nd factor; attestation (Yubico root) allows a "hardware only" policy | ◐ FreeIPA: passkey → TGT via sssd on a **Linux** client → `xfreerdp /sec:nla /p` (empty `/p`) uses the TGT. ◐ AD + Entra hybrid: FIDO2 Windows sign-in → AD TGT → mstsc SSO. ✘ Samba AD / plain AD without Entra | ✘ today (no RDPEWA server, no USB redirection); ◐ R&D: RDPEWA bridge |
| **YubiKey PIV** (smartcard) | ✘ not a WebAuthn credential (only as a client certificate, if Keycloak X.509 auth is set up; not assessed) | ✔ PKINIT, documented in [smartcard-nla.md](smartcard-nla.md) | ◐ smartcard redirection (xrdp chansrv has PC/SC redirection; not validated in fastrdp) |
| **KeePassXC** (≥ 2.7.7, browser extension) | ✔ as a synced/software passkey (attestation `none`, AAGUID `fdb141b2-…`); refused by a hardware-only policy | ✘ browser-only API, no CTAP device | ✔ if KeePassXC + KeePassXC-Browser run **in the session** (synced database); see [security notes](#security-notes) |
| **Bitwarden** (extension, mobile app) | ✔ software passkey (attestation `none`, AAGUID `d548826e-…`) | ✘ | ✔ extension in the session's browser |
| **Windows Hello** (platform) | ✔ on Windows clients | ◐ as **Windows Hello for Business** (AD key/cert/cloud trust) → Kerberos SSO into mstsc, i.e. today's "NLA SSO" row. This is not a WebAuthn passkey | ✘ (◐ RDPEWA R&D, mstsc can redirect to Hello) |
| **macOS / iCloud Keychain** | ✔ on Apple clients (attestation `none`) | ✘ | ✘ |
| **Android / Google Password Manager** | ✔ on the phone, or as a hybrid authenticator for a desktop browser | ✘ | ✘ |
| **Phone via hybrid (QR + Bluetooth)** | ✔ when the **client's** browser supports hybrid (Chrome/Edge, Safari; needs Bluetooth on the client; Linux browsers to confirm) | ✘ (libfido2/sssd have no hybrid transport) | ✘ (proximity check is against the server, which has no Bluetooth link to the phone) |

## Terms

- **Passkey** = a FIDO2/WebAuthn *discoverable* credential (resident key). It is bound to
  an **RP ID**, a domain such as `keycloak.example.com`, and used with **user
  verification** (UV: PIN, biometric or device unlock).
  - **Device-bound**: YubiKey, or a non-syncing TPM.
  - **Synced**: iCloud Keychain, Google Password Manager, Bitwarden, KeePassXC. The
    authenticator data flags BE/BS say "backup eligible / backed up".
- **Phishing resistance** comes from the browser, which puts the real **origin** into
  `clientDataJSON` and enforces that the RP ID matches the origin. Wherever a
  non-browser component computes the client data (an RDP server, a credential provider,
  the fastrdp broker), origin binding is only as good as that component.
- **Attestation**: a signed statement about the authenticator model (AAGUID +
  certificate chain). Hardware keys provide it. Synced/software passkeys send `none`.
  Some (KeePassXC, Bitwarden) report a fixed AAGUID **without** proof.

## 1. Web path

### What Keycloak supports [verified, Keycloak 26.8.1]

| Mode | Keycloak component | Policy used |
|---|---|---|
| WebAuthn as **second factor** | *WebAuthn Authenticator* (`webauthn-authenticator`), credential type `webauthn` | *WebAuthn Policy* |
| **Passwordless / passkey**, modal ("Sign in with Passkey") | *WebAuthn Passwordless Authenticator* (`webauthn-authenticator-passwordless`), credential type `webauthn-passwordless` | *WebAuthn Passwordless Policy* (defaults: UV **required**, discoverable credential **required**) |
| **Passkeys integrated into the login forms**: conditional UI (autofill) + modal button | *Username Password Form*, *Username Form*, *Password Form* when the realm switch **Enable Passkeys** is on (feature `passkeys`, default-enabled) | Passwordless policy; *Passkey Mediation* `conditional` (default), `optional`, `required`, `none`, `silent` |

Details from the source:
- A passkey login in the *Username Form* makes the following *Password Form* succeed
  without a password (`UsernamePasswordForm.alreadyAuthenticatedUsingPasswordlessCredential`).
- The default browser flow skips *Browser – Conditional 2FA* through **Condition –
  credential** (`conditional-credential`, credential `webauthn-passwordless`, "not
  included") once a passkey was used (`docs/.../passkeys.adoc`).

In short, Keycloak itself treats a passkey with UV as sufficient.

**UV is enforced by the server.** `WebAuthnAuthenticator` checks the UV flag when the
policy's *User Verification Requirement* is `required`. A browser or authenticator that
skips UV is refused.

### Is a passkey alone MFA? Policy for fastrdp

Yes, when **user verification is required**:
- the private key on the authenticator is *something you have*;
- the PIN or biometric checked by that authenticator is *something you know/are*.

NIST classifies such authenticators as multi-factor cryptographic authenticators:
- synced passkeys reach **AAL2** (SP 800-63B supplement 1);
- device-bound hardware keys can reach **AAL3**.

Proposed fastrdp policy:

| Credential | Counts as MFA for fastrdp? |
|---|---|
| Passkey, passwordless policy with **UV = required** | **yes** |
| Passkey or WebAuthn **without** UV (UV `preferred`/`discouraged`) | no; only together with a password (= WebAuthn as 2nd factor) |
| Password + WebAuthn 2nd factor (any UV) | yes |
| KeePassXC passkey | yes **by policy**, with a caveat: KeePassXC always sets UV = true when the database is unlocked (`BrowserPasskeys.cpp`, flags `UV`, `UP`, `BE`, `BS` hard-coded). UV is therefore self-asserted. The second factor is the database master password, and the key is exportable. Exclude it with the hardware-only policy if that is not acceptable |
| "Hardware only" required (AAL3-like) | attestation `direct` + Yubico roots in the Keycloak truststore + *Acceptable AAGUIDs* (see below) |

**What Keycloak puts into the token.**
- **`acr`**: the level of authentication (LoA) mapped through the client's *ACR to LoA
  mapping*, e.g. `mfa` → 2.
- **`amr`**: **only** if the client has the *Authentication Method Reference (AMR)*
  mapper (`oidc-amr-mapper`). It then contains the **configured reference value of each
  completed execution** (`AmrUtils.getAuthenticationExecutionReferences`). There are no
  built-in defaults.
- Consequences for `amr`:
  - It cannot say "hwk" vs. "swk": Keycloak does not know which authenticator was used,
    and synced passkeys have no attestation.
  - With passkeys **integrated into the Username (Password) Form**, `amr` is
    **misleading**. The passkey completes the *Username Form* execution, and the
    skipped *Password Form* is marked successful, so its `pwd` reference appears
    although no password was typed.
  - Each reference has a *max age*. The default `0` keeps the value only within the
    second of authentication, so it usually disappears before the code exchange.
    Set e.g. `36000`.

**Therefore fastrdp should rely on `acr` (its default, `required_acr = ["mfa"]`), not
on `amr`, when passkeys are integrated into the forms.**

### Recipe A: `acr=mfa` via a forced flow (recommended)

Keycloak's own documentation recommends this when levels need *different* methods
rather than cumulative ones (`flows.adoc`, "Using Client Policies to Select an
Authentication Flow"). Step-up LoA sub-flows do not fit passkeys:
- a passkey completes the level-1 sub-flow;
- a level-2 sub-flow whose only content is skipped does **not** succeed
  (`DefaultAuthenticationFlow.processFlow`).

1. **Realm → Authentication → Policies → WebAuthn Passwordless Policy:**

   | Setting | Value |
   |---|---|
   | User verification requirement | `required` |
   | Discoverable credential | `required` |
   | Attestation conveyance | `none` (all passkeys) or `direct` (hardware only, see below) |
   | Enable Passkeys (realm *Login* tab) | on; mediation `conditional` |

   Enable the required action **WebAuthn Register Passwordless**.
2. **Flow `fastrdp-mfa`** (Authentication → Create flow, type basic). **Do not add
   *Cookie*:**
   - The forced flow sets LoA 2 when it completes, whatever happened inside
     (`AuthenticationProcessor.authenticationComplete` →
     `AcrStore.setAuthFlowLevelAuthenticatedToCurrentRequest`).
   - Without *Cookie* every web login authenticates again; there is no SSO into the
     webgate.
   - Measured on 26.8.1 [tested]: even a flow *with* a Cookie step did not upgrade a
     password-only SSO session, because `CookieAuthenticator` refuses step-up when the
     requested level (`acr_values=mfa` → LoA 2 through the client's ACR map) is above
     the session's level. That protection depends on the ACR map and on Keycloak
     keeping this check, so the flow stays without Cookie (defence in depth), and the
     automation removes a Cookie step it finds.

   ```
   fastrdp-mfa (top level)
   ├─ Username Form                                     REQUIRED  (passkey via autofill/modal)
   ├─ Password Form                                     REQUIRED  (skipped after a passkey)
   └─ 2FA unless passkey                                CONDITIONAL (sub-flow)
      ├─ Condition - credential                         REQUIRED  credentials: webauthn-passwordless, included: off
      └─ second factor                                  REQUIRED  (sub-flow)
         ├─ OTP Form                                    ALTERNATIVE
         ├─ WebAuthn Authenticator                      ALTERNATIVE (security key as 2nd factor)
         └─ privacyIDEA (keycloak-provider), optional   ALTERNATIVE
   ```

   - Do **not** add *Condition – user configured*: it would let users without a
     second factor through with a password only.
   - Users without any second factor are **refused** [tested, 26.8.1]: the
     second-factor ALTERNATIVEs are not configured, Keycloak does not offer their setup
     there and ends the flow with an error ("Invalid username or password", event
     `invalid_user_credentials`). Enroll a factor beforehand (Account Console, admin, or
     privacyIDEA), see [Security notes](#security-notes).
3. **Client policy** (Realm settings → Client policies):
   - profile `fastrdp-mfa-flow`, executor `auth-flow-enforcer` with
     `auth-flow-alias = fastrdp-mfa`, `auth-flow-loa = 2`;
   - policy `fastrdp-mfa`, condition `acr-condition` with `acr-property = mfa`.
4. **Client `fastrdp-web` → Advanced → ACR to LoA mapping:** `mfa` → `2`.
5. **fastrdp:** nothing to change. The defaults `fastrdp_web_required_acr: [mfa]` and
   `fastrdp_web_required_amr_any: []` apply:
   - the webgate sends `acr_values=mfa`, which triggers the policy;
   - it refuses any ID token whose `acr` is not `mfa`.

**Automated:** `fastrdp_web_passkeys: true` in the inventory makes the web_gateway
role apply steps 1–4 through the admin REST API, idempotently, merging client
profiles/policies and the ACR map instead of replacing them ([web-access.md](web-access.md#passkeys-through-ansible-opt-in)).
Without Ansible the same script runs by hand, and the client itself is importable as
JSON; Keycloak's partial import cannot carry flows or client policies
([web-access.md](web-access.md#sample-client-json-import)).

Manual admin REST equivalent (replace `lab`; **these PUTs replace all existing client
profiles and policies**, which the automation avoids by merging):

```sh
kcadm.sh update realms/lab -s webAuthnPolicyPasswordlessUserVerificationRequirement=required \
  -s webAuthnPolicyPasswordlessResidentKey=required -s webAuthnPolicyPasswordlessPasskeysEnabled=true \
  -s webAuthnPolicyPasswordlessMediation=conditional
kcadm.sh update realms/lab/client-policies/profiles -b '{"profiles":[{"name":"fastrdp-mfa-flow",
  "executors":[{"executor":"auth-flow-enforcer","configuration":{"auth-flow-alias":"fastrdp-mfa","auth-flow-loa":2}}]}]}'
kcadm.sh update realms/lab/client-policies/policies -b '{"policies":[{"name":"fastrdp-mfa","enabled":true,
  "conditions":[{"condition":"acr-condition","configuration":{"acr-property":"mfa"}}],"profiles":["fastrdp-mfa-flow"]}]}'
CID=$(kcadm.sh get clients -r lab -q clientId=fastrdp-web --fields id --format csv --noquotes)
kcadm.sh update clients/$CID -r lab -s 'attributes."acr.loa.map"="{\"mfa\":2}"'
```

### Recipe B: `amr` with explicit executions (alternative, other IdPs)

Use this if you prefer `amr`, or your IdP emits RFC 8176 values natively.
- Keycloak: do **not** enable the integrated passkey forms. Build explicit alternatives
  and give each execution a reference value and a max age (e.g. 36000):
  - `Username Form` (no reference), then a sub-flow with the ALTERNATIVEs
    - `WebAuthn Passwordless Authenticator` (`mfa`),
    - "password + 2nd factor" (`Password Form` `pwd` + `OTP Form` `otp` /
      `WebAuthn Authenticator` `hwk`).
  - Add the *AMR* mapper to the client.
- fastrdp:
  ```yaml
  fastrdp_web_required_acr: []
  fastrdp_web_required_amr_any: [mfa, otp, hwk, swk]
  ```
- RFC 8176 values for passkeys:
  - `hwk`: hardware-secured key;
  - `swk`: software-secured key;
  - `user`: presence;
  - `pin`, `fpt`, `face`: the UV method;
  - `mfa`: several factors.
- Keycloak can attach only one static value per execution, so `mfa` is the honest value
  for a UV passkey. Use `hwk` only if the policy admits hardware authenticators only.
- **New webgate check (this change):**
  - `required_amr_any` accepts a token when *any* listed value is present. The webgate
    therefore refuses to start if the list contains `pwd`, `kba`, `pin`, `user`, `wia`,
    `rba` or `geo`, which never prove a second factor on their own.
  - It also refuses `required_acr = ["0"]`.

### Hardware-only policy (attestation, AAGUIDs) [verified + docs]

- **Attestation conveyance `direct`:** `WebAuthnRegister.createWebAuthnRegistrationManager`
  then drops the `none` verifier, so registrations without attestation are refused.
  This excludes iCloud, Google Password Manager, Bitwarden and KeePassXC.
- **Trust anchors:** packed/TPM/U2F statements are checked against the **Keycloak
  truststore**. Import the Yubico FIDO attestation roots (and those of other permitted
  vendors).
- **Acceptable AAGUIDs:**
  - With a list set, self-attestation is disabled.
  - Take the AAGUIDs from the FIDO Metadata Service, from Yubico's AAGUID list, or
    from *Show data…* on a test registration.
  - The list is only checked at **registration**. Credentials registered before the
    policy change stay valid, so delete them.
- **Policy scope:** apply this to the passwordless policy (passkeys = hardware only)
  and/or the 2FA policy. Note that Windows Hello attestation depends on the TPM.
- **privacyIDEA:**
  - its **passkey** token type does **no** attestation validation and has no AAGUID
    allow-list (only archives the certificate; `passkey_allowed_authenticator_device_types`
    is self-reported);
  - for hardware-only, use its **WebAuthn** token with
    `webauthn_authenticator_attestation_level=trusted` (leaf signed by a configured
    root, no chain traversal, no MDS) and an AAGUID selection list (`doc/tokens/tokentypes/{passkey,webauthn}.rst`).

### Authenticators on the web path

Everything here happens in the **user's local browser** against Keycloak's origin, so
any authenticator that the browser can use works. Nothing reaches the RDP leg:
Guacamole and the one-time token are unchanged.

| Authenticator | Notes |
|---|---|
| YubiKey FIDO2 | PIN must be set for UV. Discoverable-credential slots are limited (25–100 depending on firmware); one Keycloak RP ID uses one slot per user |
| KeePassXC | Needs KeePassXC-Browser with passkeys enabled. Firefox/Chromium on Linux, Windows, macOS |
| Bitwarden | Extension or mobile app (Android 14+/iOS 17+ credential provider) |
| Windows Hello, iCloud Keychain, Google PM | Platform authenticators; work with the default (none-attestation) policy |
| Phone (hybrid) | The desktop browser shows a QR code and the phone connects over the cloud relay plus a **Bluetooth proximity check** with the desktop. Supported by Chrome/Edge and Safari; Chrome on Linux and Firefox on Linux not confirmed here [inferred] |

### privacyIDEA on the web path

Alternative to storing passkeys in Keycloak: privacyIDEA ≥ 3.11 has a **passkey**
token. The privacyIDEA Keycloak provider supports it, including a "Passkey Only" mode and
enrollment via multichallenge (`keycloak-provider` README/Changelog) [docs]. Benefit:
one credential store for web (Keycloak) and the factors the broker uses for RDP (push,
OTP). Put the provider execution into the `second factor` sub-flow of recipe A or use
its passkey-only mode in a separate forced flow.

## 2. RDP path

### Why there is no direct passkey NLA [verified/inferred]

- **CredSSP** carries SPNEGO (Kerberos or NTLM), then TSPasswordCreds,
  TSSmartCardCreds or TSRemoteGuardCreds. There is no FIDO2/WebAuthn credential type.
- fastrdp's NLA point is **freerdp-proxy**, which accepts only Kerberos (no NTLM).
- **Windows**:
  - "passkey sign-in to Windows" and RDP to Entra-joined hosts use the **RDS AAD auth
    protocol** (Entra ID issues an RDP access token). That needs an Entra-joined
    Windows host, so it is not usable for a Linux server.
  - Windows Hello for Business uses Kerberos (key trust, certificate trust or cloud
    Kerberos trust). It reaches fastrdp only as an ordinary Kerberos ticket (see below).
- **privacyIDEA in the broker cannot do WebAuthn.**
  - The broker can only use `/validate/check` and `/validate/triggerchallenge`.
  - A WebAuthn/passkey challenge needs an authenticator **at the client** that signs
    `clientDataJSON` for the configured RP ID.
  - privacyIDEA takes the expected origin from the calling client's HTTP `Origin`
    (`passkeytoken.py`, `HTTP_ORIGIN`).
  - Nothing typed into the RDP password field can carry an assertion (~300+ bytes of
    binary signature data, computed over a server challenge).
  - **Push (privacyIDEA Authenticator app) stays the RDP MFA method.** The push app is
    not a passkey.
- **privacyIDEA Credential Provider for Windows** (3.7+) does FIDO2/passkeys "in RDP
  scenarios by using Windows Hello", which "handles the tunneling of the FIDO data to the
  local device" (`doc/configuration.rst`). This is WebAuthn redirection (MS-RDPEWA)
  into a **Windows** RDP target. It does not apply to a Linux target behind fastrdp.

### Passkey → Kerberos TGT → NLA (the practical route)

Kerberos NLA only needs a TGT in the client's credential cache. Both FreeRDP and mstsc
use an existing TGT without asking for a password:
- FreeRDP: `winpr/libwinpr/sspi/Kerberos/kerberos.c`, `krb5_cc_cache_match` /
  `krb5_cc_retrieve_cred` before any `get_init_creds`;
- mstsc: through LSA [verified for FreeRDP].

So the question is which KDCs issue TGTs for passkeys.

**FreeIPA + Linux clients (prototype candidate)** [docs + verified for indicators]
- **sssd passkey pre-authentication:**
  - The client needs SSSD ≥ 2.7/2.9 and a libfido2 device, which in practice means
    **USB/NFC security keys only** (no platform authenticators, no hybrid).
  - sssd's krb5 pre-auth plugin and `passkey_child` sign the KDC's challenge.
  - The FreeIPA KDC verifies it via ipa-otpd.
  - FAST armor is required.
- **Getting the TGT:** either by the desktop login (GDM/PAM via sssd: the TGT lands in
  KCM), or manually:
  ```sh
  kinit -n @IPA.TEST -c FILE:/tmp/armor.ccache
  kinit -T FILE:/tmp/armor.ccache alice@IPA.TEST    # PIN + touch
  xfreerdp3 /v:rdp1.ipa.test /u:alice /d:IPA.TEST /p /sec:nla    # empty /p: use the TGT
  ```
  Without the empty `/p` FreeRDP asks for a password. With several principals in a KCM
  collection run `kswitch -p alice@IPA.TEST` first. Switches and errors:
  [freerdp-client.md](freerdp-client.md) §2 and §4.
- **The KDC can enforce it:**
  - FreeIPA tags the TGT with authentication indicator `passkey`.
  - `ipa service-mod TERMSRV/rdp1.ipa.test --auth-ind=passkey --auth-ind=pkinit
    --auth-ind=otp` makes the KDC issue `TERMSRV` tickets only to such TGTs.
  - Source: `ipaserver/plugins/service.py` and `daemons/ipa-kdb/ipa_kdb_kdcpolicy.c`;
    `passkey` is a valid indicator.
  - Per-indicator ticket lifetimes: `ipa krbtpolicy-mod --passkey-maxlife …`.
- **Consequences for fastrdp:**
  - With `auth-ind` set on `TERMSRV`, *every* Kerberos NLA login has passed a strong
    pre-auth (passkey, smartcard or IPA OTP), enforced by the KDC, not by a
    client-supplied flag.
  - Password-only users can then no longer use NLA. They keep TLS logins
    (password + OTP/push via the broker), if enabled.
  - The broker still asks for push unless `fastrdp_mfa_nla_kdc_enforced: true`
    ([below](#kdc-enforced-strong-authentication-for-nla)).
  - Indicators are not carried across realms and block S4U2Self to the protected
    service (krbdev, 2020). fastrdp uses neither.
- **Windows clients cannot use FreeIPA passkey pre-auth.** Windows' Kerberos has no
  `passkey` pre-auth.

**Active Directory** [docs/inferred]
- **Without Entra ID:** AD has no FIDO2/passkey pre-auth.
- **With Entra ID** (Entra-joined or hybrid-joined Windows 10 2004+, *Microsoft Entra
  Kerberos* server object):
  1. a FIDO2 security key or passkey sign-in to Windows yields a partial TGT;
  2. an on-premises DC exchanges it for a full AD TGT;
  3. that TGT can request `TERMSRV/<fastrdp-host>` like any SSO login.
  This is the existing "NLA single sign-on from a domain-joined Windows client" row,
  with the user having logged in to Windows with a passkey. Needs a lab.
- **Samba AD** cannot act as the on-premises side of Entra Kerberos [inferred].
- **Windows Hello for Business** (key trust, certificate trust, cloud Kerberos trust)
  gives the same result: an AD TGT without a password.
- AD has no authentication indicators like MIT/FreeIPA, but its PAC says something about
  the logon: S-1-18-4 for a key trust logon (Windows Hello for Business), S-1-18-3 for
  PKINIT with freshness, *Authentication Mechanism Assurance* groups for certificate
  logons. `fastrdp_mfa_kdc_evidence_as_mfa` can count them per login
  ([below](#kdc-evidence-per-login)); FIDO2/passkey via Entra Kerberos is not known to
  leave such a trace. Otherwise keep privacyIDEA push for these users, or an exempt
  group, as for smartcards.

### WebAuthn redirection (MS-RDPEWA) [verified]

- **Protocol:** dynamic virtual channel **`WebAuthN_Channel`**. The **server** sends
  CBOR WebAuthn requests: CTAP makeCredential/getAssertion with **RP ID and
  clientDataHash computed by the server**, plus `filterHybridTransport` etc. The
  **client** forwards them to its local authenticators (platform or roaming) and returns
  the response.
- **Implementations:**
  - Windows 10 1809+/11, Server 2019+ (spec Appendix A);
  - mstsc `.rdp` property `redirectwebauthn:i:1`.
- **FreeRDP client** (3.25.0+): `channels/rdpewa`, **client side only**.
  - It uses **libfido2**, i.e. USB/NFC security keys; no platform authenticator, no
    hybrid, no KeePassXC.
  - It is opt-in at build time (`CHANNEL_RDPEWA` default OFF, needs libfido2 ≥ 1.14 +
    libcbor). fastrdp's packaged build does not enable it;
    `FASTRDP_FREERDP_WEBAUTHN=1 third_party/build-freerdp.sh` does.
  - At runtime it is enabled through `redirectwebauthn` in an `.rdp` file, or the
    dynamic channel `rdpewa`.
- **Servers:** FreeRDP has no `rdpewa` server part. xrdp 0.10.6.1 has no WebAuthn
  channel (it does have PC/SC smartcard redirection). Nothing comparable was found in
  gnome-remote-desktop or KRdp.
- **freerdp-proxy:** passes dynamic channels it does not know through when
  `PassthroughIsBlacklist=true` with an empty list, which is fastrdp's `proxy.ini`.
  So the proxy would not block RDPEWA once a back-end offered it [verified from
  `pf_channel_drdynvc.c`; not tested].
- **Could a Linux session use it?**
  - A back-end channel alone is not enough: Linux browsers talk CTAP2 to `/dev/hidraw*`.
  - A bridge would expose a per-session virtual FIDO HID device (uhid) whose CTAP
    requests go through `WebAuthN_Channel` to the client. The browser computes
    `clientDataJSON`, so the origin stays correct.
  - Needed: xrdp chansrv support plus a privileged per-user uhid helper (multi-user
    isolation of hidraw nodes on a terminal server), for each back-end.
  - **Large effort.** It would give YubiKeys (FreeRDP) and Windows Hello/phones (mstsc)
    inside the session.
- **Security:** with RDPEWA the client signs whatever RP ID the server asks for.
  - The client sees only a hash of the client data; newer revisions add
    `clientDataJSON`/origin, which only an honest server fills in.
  - A compromised session host could therefore request assertions for **other** sites
    (e.g. the user's e-mail account) while the user believes they are logging in
    somewhere else. Each request still needs a touch/UV.
  - Enable it only for trusted hosts, and treat it as a **per-user opt-in**.

### Using RDPEWA for fastrdp's own MFA? [inferred]

In theory:
1. the proxy module opens `WebAuthN_Channel` to the client after NLA;
2. the broker obtains a privacyIDEA passkey challenge, builds `clientDataJSON` with
   privacyIDEA's origin, and has the client's authenticator sign it;
3. the broker submits the result.

This would add FIDO2 as an RDP second factor for mstsc and new FreeRDP clients. However:
- dynamic channels only exist after the connection is up, while the broker decides
  before connecting the back-end;
- the proxy module API can intercept channels but not create its own server DVC on the
  front connection;
- origin binding would rest on the broker.

**Not recommended.** Push already works for all clients, and web approval (next
section) brings passkeys to every RDP client without a new channel.

### Passkeys as the RDP second factor: web approval

`fastrdp_mfa_mode: web` (or `push_or_web`, together with a privacyIDEA push) makes the
broker hold an RDP login that owes its second factor until the user approves it on
`https://<host>/web/approve`. That page signs the user in at Keycloak afresh
(`prompt=login`, `max_age=0`, `acr=mfa`), so the passkey flow of
[recipe A](#recipe-a-acrmfa-via-a-forced-flow-recommended) is what proves the second
factor, for mstsc, xfreerdp3 and Remmina alike (NLA or TLS) and without anything on the
client. Origin binding stays with the browser and Keycloak; the broker only checks that
the approving sign-in is recent (`auth_time`) and belongs to the same account.

Limits: the passkey proves the user signed in to the web page, not which RDP client
they approved; the page shows the client address and refuses approval while two logins
of the user wait (`fastrdp_mfa_web_approval_single_pending`). Users must not approve a
login they did not start (social engineering). Details and settings:
[auth-matrix.md](auth-matrix.md#web-approval), [web-access.md](web-access.md#approving-rdp-logins).

### YubiKey PIV vs. FIDO2

| | PIV (smartcard, PKINIT) | FIDO2 passkey |
|---|---|---|
| Standard | NIST SP 800-73 PIV applet, X.509 + PKINIT (RFC 4556) | W3C WebAuthn + FIDO CTAP2 |
| Used by fastrdp | **RDP NLA today** (Kerberos via PKINIT) | **web path** (Keycloak); RDP only via FreeIPA/Entra TGT |
| Credential | key pair + **certificate from your CA** (UPN SAN, KDC trust, NTAuth in AD) | key pair per RP ID, created by the key; no PKI |
| PIN | PIV PIN (6–8 chars, retry counter, PUK) | FIDO2 PIN (separate, ≥ 4 chars, retry counter, no PUK: reset wipes all FIDO credentials) |
| Phishing resistance | the KDC proves itself (PKINIT reply signed by the KDC certificate); not origin-bound, but the key only works with the realm's KDC | origin/RP ID bound by the browser |
| Management | CA, issuance, revocation (CRL/OCSP), card management (ykman, minidriver) | self-service registration in Keycloak/privacyIDEA; revoke = delete credential |
| Works with | mstsc, FreeRDP (`/smartcard-logon`), any PKINIT client | browsers, platform logon (sssd passkey, Windows/Entra) |

A YubiKey 5 can do both at once (separate applets, separate PINs).

## 3. Inside the session

| Option | Works? | Notes |
|---|---|---|
| KeePassXC (+ KeePassXC-Browser) running **in the session** | ✔ | Works like on a desktop. The database must be in the session (synced copy in `$HOME`). The decrypted vault lives in the server's memory; root and anyone with ptrace rights over the user's processes can read it. Use a separate database that holds only the passkeys needed in the session |
| Bitwarden extension in the session's browser | ✔ | Same trust consideration; vault unlocked on the shared host |
| Hardware YubiKey via **USB redirection** | ✘ | FreeRDP `urbdrc` is disabled in fastrdp's build (`third_party/build-freerdp.sh`, `-DCHANNEL_URBDRC=OFF`). None of the Linux back-ends implements USB redirection. Even if they did, a raw USB device on a multi-user server is a large attack surface |
| **WebAuthn redirection** (RDPEWA) | ✘ today | Client side exists (mstsc, FreeRDP ≥ 3.25 with libfido2); no Linux server side (see above) |
| **PIV via smartcard redirection** | ◐ | Possible for applications using PC/SC/PKCS#11 in the session (TLS client certificates, `kinit` with PKINIT). xrdp chansrv has PC/SC redirection; not validated in fastrdp. Not a WebAuthn path |
| Phone hybrid inside the session | ✘ | The proximity check is via Bluetooth between the phone and the **server**, and the server has no such link |
| Windows Hello / iCloud / Google PM | ✘ | Bound to the local OS |

## Security notes

- **Web path:** everything security-relevant stays at Keycloak (origin-bound). The
  webgate's checks are unchanged:
  - ID token from the token endpoint over verified TLS;
  - nonce and PKCE;
  - `acr`/`amr`.
- **No `Cookie` in the forced flow** (recipe A). Keycloak 26.8.1's step-up check
  already stopped a password-only SSO session from becoming `acr=mfa` in the test, but
  only as long as the client's ACR map gives `mfa` a higher level than the session.
- **Registration is the weak point.** A user who logs in with a password only can
  register a passkey through a required action. Ways to restrict that:
  - registering as a required action at the fastrdp login runs only after the full
    `fastrdp-mfa` flow;
  - registering in the *Account Console* uses that client's login flow, so require MFA
    there too (realm browser flow or the same client policy);
  - pre-register;
  - in privacyIDEA, enroll via multichallenge after MFA.
- **Synced passkeys:** security follows the sync provider account (Apple, Google,
  Bitwarden, the KeePassXC database file). Use the hardware-only policy for
  administrators.
- **KeePassXC/Bitwarden in the session**, and **RDPEWA**: see the tables above. Both
  move trust to the terminal server.

## Recommendation and staged plan

### Stage 1: web path with Keycloak passkeys — done (automation + test)
1. Keycloak: passwordless policy (UV required, discoverable required, passkeys enabled,
   mediation `conditional`), flow `fastrdp-mfa` without *Cookie*, client policy
   `acr-condition: mfa` → `auth-flow-enforcer` (loa 2), client ACR mapping `mfa → 2`.
   This is recipe A, now automated: `fastrdp_web_passkeys: true`
   ([web-access.md](web-access.md#passkeys-through-ansible-opt-in)).
2. fastrdp: keep the defaults `fastrdp_web_required_acr: [mfa]`,
   `fastrdp_web_required_amr_any: []`.
3. Admins / high-value accounts: `fastrdp_web_passkeys_hardware_only: true` with
   `fastrdp_web_passkeys_aaguids` = the YubiKey models in use, plus the Yubico roots in
   Keycloak's truststore (separate realm if only some users need it: the policy is
   per realm).
4. Users: register a passkey (YubiKey, Windows Hello, phone, Bitwarden/KeePassXC) via
   *Account Console → Signing in*; tell them about the RDP limits below.

#### Stage 1 results (Keycloak 26.8.1)

`make test-keycloak` (tests/keycloak/run.sh, manual: JDK + Keycloak + Chromium) starts
Keycloak 26.8.1 in dev mode, applies the role's Keycloak tasks with
`ansible-playbook`, then drives headless Chromium with a CDP virtual authenticator
(CTAP 2.1, resident keys, user verification) against the **real webgate code**
(config parser, OIDC provider, HTTP handler; a fake broker answers the desktop list).
Result on 2026-10-22: 25 passed, 0 failed.

| Case | Result |
|---|---|
| Sample client [keycloak-fastrdp-web-client.json](examples/keycloak-fastrdp-web-client.json) imported and read back unchanged; the test client is made from it | ✔ |
| Role: check mode lists the changes, writes nothing; first run changes; second run `changed=0` | ✔ |
| Role: unrelated client profile/policy, other ACR map entry and RP entity name kept | ✔ |
| Role: a Cookie step added to `fastrdp-mfa` is detected and the flow rebuilt | ✔ |
| Password + TOTP → webgate accepts, `acr=mfa`; passkey registered on the way (required action) | ✔ |
| Passkey only ("Sign in with Passkey", UV) → webgate accepts, `acr=mfa`, no password typed | ✔ |
| Password only, user with OTP → stops at the OTP form, no token | ✔ |
| Password only, user without a second factor → Keycloak error page, no token (no setup offered) | ✔ |
| Password-only ID token from an ordinary login (no `acr_values`) → `acr="1"`, webgate refuses it | ✔ |
| Existing password-only SSO session → webgate login asks again, password alone gives no token | ✔ |
| Existing password+OTP SSO session → webgate login still asks again (no Cookie: no SSO) | ✔ |
| Control: flow *with* Cookie + the same password-only session → still asked again (LoA step-up check) | ✔ |
| Hardware-only (attestation `direct` + AAGUID list): virtual authenticator's registration refused (`invalid cert path`, attestation not trusted) | ✔ |
| Hardware-only: a passkey registered **before** still logs in (the list applies at registration only) | ✔ (documented caveat) |

Observations:
- Without the AMR mapper the ID tokens carry no `amr`; `acr` alone decides.
- "Enable Passkeys" is a realm setting: the realm's ordinary browser flow (Account
  Console, other clients) also offers "Sign in with Passkey" afterwards, with the
  same UV-required policy.
- A refused registration still left a new discoverable credential for the same user
  on the authenticator, replacing the old one (same RP ID and user handle; Keycloak
  sends no `excludeCredentials` unless *Avoid same authenticator registration* is on).
  On a real key the user's existing passkey for that RP would be overwritten.
- The hardware-only refusal came from the attestation trust check; the AAGUID list
  itself was not exercised separately (that needs a trusted attestation root).

Not covered (no hardware, no other browsers here): conditional-UI autofill in
Firefox/Safari, real YubiKey attestation with the Yubico roots, KeePassXC/Bitwarden,
phone hybrid.

### Stage 2: prototypes — implemented, lab validation pending

#### KDC-enforced strong authentication for NLA

`fastrdp_mfa_nla_kdc_enforced: true` (broker `[mfa] nla_kdc_enforced`, default
`false`):
- **What it does.** Kerberos NLA logins skip privacyIDEA. The broker logs
  `<user>: Kerberos NLA login (principal …); second factor skipped: [mfa]
  nla_kdc_enforced` and warns at start-up that the option is on.
- **Gating.** Only `method = nla`, which the proxy module reports only after a
  Kerberos (never NTLM) NLA with a KDC-validated principal. Only principals of
  `[auth] realms` (the config refuses the option with an empty list): a trusted foreign
  realm's KDC does not apply this realm's indicators. TLS logins (with or without a
  client-supplied `principal`/`smartcard` field) and web tokens are unaffected; so are
  `exempt_groups` and `session_tgt = required` (a passkey login has no password, so
  `required` still refuses it). With `mode = none` the option has no effect.
- **Why it is safe on FreeIPA.** The proxy accepts only tickets for
  `TERMSRV/<host>` (its keytab holds nothing else). With
  `ipa service-mod TERMSRV/<host> --auth-ind=passkey --auth-ind=pkinit` the KDC issues
  such tickets only to TGTs from passkey or PKINIT pre-authentication.
- **Ansible.** `fastrdp_mfa_nla_kdc_auth_indicators` (default `[passkey, pkinit]`; also
  `otp`, `radius`, `idp`; `hardened` is refused because it is a password). The identity
  role sets them with the join account (`fastrdp_mfa_nla_kdc_set_auth_ind: true`) and
  on every run reads them back with the host keytab and **fails the deployment** if the
  service has none or any outside the list. Preflight (read-only) reads them with the
  join account and reports FAIL/WARN.
- **Consequences.** Password-only Kerberos users can no longer use NLA (the KDC
  refuses the `TERMSRV` ticket); they keep TLS + OTP/push if allowed. Sessions from
  passkey logins get no Kerberos TGT (no password).
- **Active Directory / Entra ID: keep it off.** AD has no authentication indicators:
  the TGS cannot tell a passkey/FIDO2 (Entra Kerberos), Windows Hello for Business or
  smartcard TGT from a password TGT, and fastrdp sees only an ordinary service ticket.
  The option is therefore refused on `fastrdp_identity_provider: ad` unless
  `fastrdp_mfa_nla_kdc_enforced_by_ad_policy: true` asserts that AD policy guarantees
  it for **every** account that can log in, e.g.:
  - *Smart card is required for interactive logon* on all those accounts (their
    password is random and unknown; mind NTLM and the hash, rotate it), or
  - an authentication policy on the fastrdp computer account that allows service
    tickets only for users with an *Authentication Mechanism Assurance* group claim
    (certificate logons only; FIDO2 via Entra Kerberos does not produce it), together
    with Kerberos armoring.
  Neither can be checked from the fastrdp host; preflight then only warns.
- Tests: `broker/brokerd/tests/test_kdc_enforced.py`; `tests/ansible` (broker.toml
  variant, `roles/common` refusals for `hardened`, empty list, AD without the
  assertion).

#### KDC evidence per login

`fastrdp_mfa_kdc_evidence_as_mfa` (broker `[mfa] kdc_evidence_as_mfa`, default `[]` =
off) decides per login, from what the KDC wrote into the ticket, where
`nla_kdc_enforced` asserts it for every Kerberos NLA login:

```yaml
fastrdp_mfa_kdc_evidence_as_mfa: ["ind:pkinit", "ind:passkey"]            # FreeIPA / MIT
fastrdp_mfa_kdc_evidence_as_mfa: ["sid:S-1-18-4", "sid:S-1-5-21-…-1300"]   # AD: WHfB key trust, AMA group
fastrdp_mfa_kdc_evidence_as_mfa: ["sid:S-1-18-3"]                          # Samba AD / AD with freshness: PKINIT
```

- **What it does.** A Kerberos NLA login whose ticket carries one of the items skips
  privacyIDEA, logged as `<user>: Kerberos NLA login (principal …); second factor from
  KDC evidence ind:pkinit`. A login without a matching item keeps its second factor
  exactly as before (push, or refusal in `otp` mode), with the line `KDC evidence in the
  ticket: …; none of [mfa] kdc_evidence_as_mfa`. Nothing changes for the client: no
  prompt, no setting, mstsc as before.
- **Items.**
  - `ind:<indicator>`: an authentication indicator (MIT krb5 ≥ 1.16, FreeIPA). FreeIPA's
    KDC tags PKINIT TGTs with `pkinit` and passkey TGTs with `passkey` (also `otp`,
    `radius`, `idp`); a plain MIT KDC needs `pkinit_indicator = pkinit` in `kdc.conf`.
    The KDC copies a TGT's indicators into the service tickets it issues from it.
  - `sid:<SID>`: an enabled group SID from the PAC (AD, Samba AD, FreeIPA): domain
    groups, ExtraSids and resource groups. Useful in AD ([MS-DTYP] 2.4.2.4):
    - `sid:S-1-18-4` (KEY_TRUST_IDENTITY): logon with a key from `msDS-KeyCredentialLink`,
      i.e. Windows Hello for Business key trust;
    - `sid:S-1-18-3` (FRESH_PUBLIC_KEY_IDENTITY): PKINIT with a valid RFC 8070
      freshness token, i.e. current proof of possession of the certificate's key (smart
      card, WHfB certificate or key trust; Windows clients since 1607 ask for it).
      Microsoft AD adds it only with the DC policy *KDC support for PKInit Freshness
      Extension* (off by default); Samba AD (4.25) whenever the client sends the token,
      without any option. It is **not hardware-bound**: a certificate in software gets it
      too, so restrict certificate enrolment and writes to `altSecurityIdentities` and
      `msDS-KeyCredentialLink`. For Samba AD it is the only per-login evidence: Samba
      never adds S-1-18-4/-5/-6 and has no AMA;
    - an *Authentication Mechanism Assurance* group: the universal group an issuance
      policy of the logon certificate is linked to (`msDS-OIDToGroupLink`); AD adds it
      to the PAC only for logons with such a certificate (smart cards, WHfB certificate
      trust);
    - `sid:S-1-18-5` (KEY_PROPERTY_MFA) exists, but see the caveats.
  - Refused by the broker and `roles/common`: `ind:hardened` (a password with FAST or
    SPAKE), `sid:S-1-18-1` (every AS logon, passwords included), `sid:S-1-18-2`
    (S4U2Self), Everyone, Authenticated Users, Users and Domain Users (RID 513).
- **Where it comes from.** The proxy's WinPR Kerberos acceptor keeps the evidence of
  the ticket it accepted (`patches/freerdp/0005`, `fastrdp-freerdp3` ≥ 3.32.2-4) and
  checks that the KDC signed it for this service: indicators only from a CAMMAC (RFC
  7751) whose svc-verifier checks out with the key that decrypted the ticket, the PAC
  only when its server signature does (`krb5_pac_verify()`). Authorization data a client
  adds to its own TGS-REQ therefore never counts. The module parses the PAC's
  `KERB_VALIDATION_INFO` (`fastrdp_pac.h`, bounds-checked NDR) and sends the broker
  `"kdc_evidence": ["ind:pkinit", "sid:S-1-…", …]` (at most 512 items, ExtraSids before
  domain groups; a longer list loses items, so such a login falls back to its second
  factor). The `smartcard` flag (TSSmartCardCreds) is client-supplied and never counts.
- **Gating.** Only `method = nla` (Kerberos, never NTLM) with a principal of `[auth]
  realms`; the broker refuses the option with an empty list. TLS logins and web
  tokens ignore the field. With `mode = none` it has no effect.
- **With the other options.**
  - `exempt_groups` and `nla_kdc_enforced` are checked first; with `nla_kdc_enforced` on,
    the evidence decides nothing for principals of `[auth] realms`.
  - A login whose second factor came from the evidence earns reconnect grace like a
    push (factor `kdc ind:pkinit`, [auth-matrix.md](auth-matrix.md#reconnect-grace)).
  - `session_tgt = required` still refuses logins without a password, before MFA.
  - In `otp` mode, NLA logins with matching evidence now pass; all other NLA logins are
    refused as before.
- **Caveats.**
  - *Freshness:* the evidence describes the pre-authentication of the TGT the client
    used, possibly hours old (Windows: the TGT from the sign-in, renewed for up to the
    ticket lifetime). It does not mean the user touched the card for this connection.
  - *Shadow credentials (AD):* whoever can write a user's `msDS-KeyCredentialLink` can
    add a key, log on with it and get S-1-18-4; S-1-18-5 can be crafted the same way.
    Restrict write access to the attribute and audit it (event 5136).
  - *Not verified with a real AD:* the PAC of mstsc's user-to-user tickets (§3.14 of
    [windows-clients.md](windows-clients.md)), AD's signature over it and which SIDs
    WHfB and smart cards produce are lab items.
  - *No-code alternative on AD (unverified):* an authentication policy on the fastrdp
    computer account whose access condition requires `Member_of {SID(S-1-18-4)}` (or the
    AMA group), with Kerberos armoring, plus `fastrdp_mfa_nla_kdc_enforced` and
    `fastrdp_mfa_nla_kdc_enforced_by_ad_policy`: the KDC then refuses the other logins
    instead of fastrdp asking them for a push.
- **Preflight** (`make preflight`, check *MFA from KDC evidence*): items as above, realm
  set, `fastrdp-freerdp3` ≥ 3.32.2-4 installed or available from the APT sources (FAIL
  when older); AD: WARN for indicator items, and per DC software (anonymous rootDSE
  `vendorName` via `ldapsearch`, when installed) the Samba or Microsoft AD caveats of
  `sid:S-1-18-3` above. `scripts/fastrdp-setup` asks for the items in production runs.
- Tests: `broker/brokerd/tests/test_kdc_evidence.py`; `tests/proxy-module/test_pac.c`
  (Windows PACs from MIT's test suite, synthetic PAC with ExtraSids and resource groups,
  truncated and mutated buffers); `tests/proxy-e2e/run_smartcard.sh` (MIT KDC with
  `pkinit_indicator`: the broker gets `["ind:pkinit"]`), `run_nla.sh` (password logins:
  `[]`, every CAMMAC and PAC verified), `run.sh` (TLS: no field); `tests/ansible`;
  `scripts/tests/test_preflight.py`, `scripts/tests/test_fastrdp_setup.py`.

#### FreeIPA passkey → TGT → NLA (lab)

`tests/lab/freeipa-passkey-nla.sh [--setup] USER FASTRDP_FQDN` on an enrolled Linux
client with a FIDO2 key. Runbook:
1. `--setup` (IPA admin ticket): `ipa user-mod USER --user-auth-type=passkey
   --user-auth-type=password`, `ipa user-add-passkey USER --register` (PIN + touch),
   `ipa service-mod TERMSRV/<fqdn> --auth-ind=passkey --auth-ind=pkinit`.
2. Password TGT (`kinit -n` armor, `kinit -T`): `kvno TERMSRV/<fqdn>` must fail with a
   KDC policy error.
3. Passkey TGT (`kinit -n @REALM` armor, `kinit -T armor USER`, PIN + touch): `kvno`
   must succeed.
4. `xfreerdp3 /v:<fqdn> /u:USER /d:REALM /p /sec:nla /auth-pkg-list:kerberos,!ntlm`
   (empty `/p`: use the ticket; [freerdp-client.md](freerdp-client.md) §2, §4) stays
   connected.
5. With `SSH_TARGET`, the broker journal must show `second factor skipped` and the
   session, and no push.

Deploy with `fastrdp_mfa_nla_kdc_enforced: true` and `fastrdp_mfa_mode: push` first.
Not run: no FreeIPA, client or key here.

#### Other stage-2 items
1. **AD + Entra Kerberos / Windows Hello for Business:** verify that mstsc SSO from a
   passkey-signed-in Windows client reaches fastrdp (the existing SSO path). Lab.
2. **RDPEWA, client side:** `FASTRDP_FREERDP_WEBAUTHN=1 third_party/build-freerdp.sh
   SRC` builds `xfreerdp` with `-DCHANNEL_RDPEWA=ON` (`--deps` then adds libfido2-dev,
   libcbor-dev; the packaged build is unchanged). Use: `.rdp` `redirectwebauthn:i:1` or
   `/dvc:rdpewa` ([freerdp-client.md](freerdp-client.md) §12). Only useful towards
   Windows hosts. Not built here (no libfido2/libcbor headers, no root).

### Stage 3: research — design and codec prototype done, decide later
- **RDPEWA server side for Linux sessions**: [webauthn-redirection.md](webauthn-redirection.md)
  (message flow, where it would live, how the session's browser reaches it, security
  model, effort). Prototype of the protocol-independent core (RDPEWA codec with the
  specification's examples, CTAPHID framing, bridge policy) in
  `prototypes/webauthn-redirection/` (`make test-prototypes`); not integrated.

### Reject
- WebAuthn/passkey as a typed second factor on the RDP password field: impossible.
- FIDO2 as the RDP second factor via an RDPEWA channel opened by the proxy: complex, and
  push already covers it.
- USB redirection of FIDO keys into sessions.
- Treating `amr: ["hwk"]` from Keycloak as proof of *hardware*: it is a static label
  unless attestation is enforced.
- Accepting `pwd`, `pin` or `user` in `required_amr_any`: refused by the webgate.
- `fastrdp_mfa_nla_kdc_enforced` on AD without a policy that guarantees strong logon.

### fastrdp changes for passkeys
- Webgate: refuses single-factor RFC 8176 values in `required_amr_any` and `acr` `"0"`
  (`broker/webgate/fastrdp_webgate/config.py`).
- Stage 1: `roles/web_gateway/tasks/keycloak_passkeys.yml`,
  `roles/web_gateway/files/fastrdp_keycloak_passkeys.py`, defaults in
  `roles/web_gateway/defaults/main.yml`; tests `tests/keycloak/` (offline unit tests in
  `make test-ansible`, end to end in `make test-keycloak`).
- Stage 2: broker `[mfa] nla_kdc_enforced` (`config.py`, `server.py`), Ansible
  `fastrdp_mfa_nla_kdc_*` (roles common, broker, identity), preflight check; per login
  `[mfa] kdc_evidence_as_mfa` (`patches/freerdp/0005`, `fastrdp_pac.h`,
  `fastrdp_plugin.c` `kdc_evidence()`, `server.py`, `fastrdp_mfa_kdc_evidence_as_mfa`),
  `FASTRDP_FREERDP_WEBAUTHN` in `third_party/build-freerdp.sh`,
  `tests/lab/freeipa-passkey-nla.sh`.
- Stage 3: [webauthn-redirection.md](webauthn-redirection.md),
  `prototypes/webauthn-redirection/`.
- Web approval (passkeys as the RDP second factor): broker `[mfa] mode = "web"` /
  `"push_or_web"` (`mfa.py` `WebApprovals`, ops `mfa_pending`/`mfa_decide` in
  `server.py`), webgate `<prefix>/approve` (`app.py`, fresh sign-in in `oidc.py`),
  Ansible `fastrdp_mfa_web_approval_*`; tests `broker/brokerd/tests/test_web_approval.py`,
  `broker/webgate/tests/test_approve.py`.

## Open points (need a lab)

- Keycloak 26.8: recipe A end to end — **done** with a virtual authenticator
  ([results](#stage-1-results-keycloak-2681)). Still open: conditional UI with
  Chrome/Firefox/Safari and real platform authenticators.
- KeePassXC 2.7.12 / Bitwarden: registration and login against the passwordless policy
  with UV required; refused with attestation `direct`.
- YubiKey 5 (FW 5.4/5.7): attestation with the Yubico roots in the Keycloak truststore,
  AAGUID allow-list (accepted and refused models).
- Phone hybrid from Linux Chrome and from Windows.
- FreeIPA passkey → TGT → `xfreerdp3 /sec:nla` against fastrdp with
  `fastrdp_mfa_nla_kdc_enforced`: `tests/lab/freeipa-passkey-nla.sh`; `auth-ind` on
  `TERMSRV`; the proxy's acceptor (it only sees a normal service ticket); FreeIPA ACI
  for reading `krbprincipalauthind` with the host keytab (read from the
  `System: Read Services` permission in the source, not run).
- AD + Entra Kerberos and WHfB cloud trust → mstsc SSO to fastrdp (AD-joined).
- `fastrdp_mfa_kdc_evidence_as_mfa` with AD and mstsc: which SIDs a smart card, WHfB key
  trust and certificate trust logon put into the `TERMSRV` user-to-user ticket's PAC
  (S-1-18-3/-4, AMA group), that the PAC's server signature verifies, and that a
  password logon has none of them. FreeIPA: `ind:pkinit` / `ind:passkey` from real
  clients.
- RDPEWA: confirm that freerdp-proxy passes `WebAuthN_Channel` through between mstsc and
  a Windows back-end (proxy in front of Windows); whether mstsc accepts requests
  without `clientDataJSON` ([webauthn-redirection.md](webauthn-redirection.md)).

## References

- W3C, *Web Authentication Level 3*, incl. §13 Security Considerations: https://www.w3.org/TR/webauthn-3/
- FIDO Alliance, *Client to Authenticator Protocol (CTAP)* and Metadata Service: https://fidoalliance.org/specifications/
- RFC 8176, *Authentication Method Reference Values*: https://www.rfc-editor.org/rfc/rfc8176
- OpenID Connect Core 1.0, §2 (`acr`, `amr`): https://openid.net/specs/openid-connect-core-1_0.html
- NIST SP 800-63B-4 (syncable authenticators; previously SP 800-63B Supplement 1): https://pages.nist.gov/800-63-4/sp800-63b.html
- Microsoft, [MS-RDPEWA] Remote Desktop Protocol: WebAuthn Virtual Channel Protocol, rev. 3.0 (2026-03-30): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/68f2df2e-7c40-4a93-9bb0-517e4283a991
- Microsoft Learn, *Passwordless security key sign-in to on-premises resources* (Entra Kerberos): https://learn.microsoft.com/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises
- Palo Alto Unit 42, *WebAuthn added to browser-based RDP* (RDPEWA client data handling): https://unit42.paloaltonetworks.com/webauthn-added-to-browser-based-rdp/
- Keycloak 26.8.1 source (github.com/keycloak/keycloak, tag `26.8.1`):
  - `docs/documentation/server_admin/topics/authentication/{passkeys,webauthn,flows}.adoc`
  - `services/.../protocol/oidc/mappers/AmrProtocolMapper.java`, `protocol/oidc/utils/AmrUtils.java`
  - `services/.../authentication/authenticators/browser/{UsernamePasswordForm,PasswordForm,WebAuthnAuthenticator,WebAuthnPasswordlessAuthenticator,WebAuthnConditionalUIAuthenticator}.java`
  - `services/.../authentication/authenticators/conditional/{ConditionalCredentialAuthenticator,ConditionalLoaAuthenticator}.java`, `authenticators/util/AcrStore.java`
  - `services/.../authentication/{DefaultAuthenticationFlow,AuthenticationProcessor}.java`
  - `services/.../services/clientpolicy/executor/AuthenticationFlowSelectorExecutor.java`, `clientpolicy/condition/AcrCondition.java`
  - `services/.../authentication/requiredactions/WebAuthnRegister.java`
- privacyIDEA 3.14: `doc/tokens/tokentypes/passkey.rst`, `webauthn.rst`, `privacyidea/lib/tokens/passkeytoken.py`
- privacyIDEA Credential Provider 3.8.0.0: `doc/configuration.rst` (FIDO, RDP), `Changelog.md`
- privacyIDEA Keycloak provider: `README.md`, `Changelog.md` (passkey, Passkey Only)
- FreeRDP 3.32.2: `channels/rdpewa/` (client), `ChangeLog` (3.25.0: "[channels,rdpewa] add WebAuthn virtual channel support"), `client/common/file.c` (`redirectwebauthn`), `server/proxy/channels/pf_channel_drdynvc.c`, `winpr/libwinpr/sspi/Kerberos/kerberos.c`
- xrdp 0.10.6.1: `sesman/chansrv/smartcard*.c` (PC/SC redirection; no WebAuthn channel)
- KeePassXC 2.7.12: `src/browser/BrowserPasskeys.{cpp,h}` (AAGUID, flags)
- Passkey provider AAGUIDs: https://github.com/passkeydeveloper/passkey-authenticator-aaguids (`aaguid.json`)
- FreeIPA: design pages *Passkeys* (https://freeipa.readthedocs.io/en/latest/designs/passkeys.html) and *Policies by authentication indicators*; source `ipaserver/plugins/{service,krbtpolicy}.py`, `daemons/ipa-kdb/ipa_kdb_kdcpolicy.c`
- SSSD design page *Passkey Kerberos integration*: https://sssd.io/design-pages/passkey_kerberos.html
- Red Hat, RHEL 9 *Managing IdM users…*, "Retrieving an IdM ticket-granting ticket as a passkey user" (`kinit -n` armor + `kinit -T`)
- MIT krbdev, *authentication indicators and S4U2Self* (2020-05): https://mailman.mit.edu/pipermail/krbdev/2020-May/013261.html
