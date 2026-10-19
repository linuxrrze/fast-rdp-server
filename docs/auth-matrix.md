# Authentication and MFA

## What each login path gives you

| Client / method | First factor | Second factor (privacyIDEA) | Session gets a Kerberos TGT | Notes |
|---|---|---|---|---|
| NLA, user types a password (mstsc, xfreerdp3 `/u /p`, Remmina) | Kerberos (client gets a ticket with the password) | `push` (`otp_or_push`/`push`) | yes, the delegated password reaches `pam_sss` | **Recommended.** The client must reach a KDC (VPN, or a KDC proxy in FreeRDP). |
| NLA, single sign-on from a domain-joined Windows client | Kerberos ticket of the logged-on user | `push` | only if Windows delegates the password ("Allow delegating default credentials") | Without a password: xrdp sessions have no TGT (`kinit` inside the session) |
| TLS, password+OTP in one field | PAM `fastrdp` (SSSD) | OTP appended to the password (`otp`, `otp_or_push`) | yes | For clients without Kerberos. Needs `fastrdp_allow_tls_logins: true`. |
| Web: Guacamole + Keycloak | Keycloak (OIDC) | at Keycloak (OTP, WebAuthn/FIDO2, privacyIDEA), proven by `acr`/`amr` | no | `fastrdp_web_enabled`; see [web-access.md](web-access.md) |
| Smartcard / PIV / YubiKey PIV (NLA) | Kerberos via **PKINIT** (certificate + PIN) | `push`, or exempt group for "smart card required" accounts | no (PIN is never forwarded) | Tested with a software token; real cards/AD/mstsc to validate. See [smartcard-nla.md](smartcard-nla.md) |

YubiKeys work in three ways:
- **PIV smartcard** (NLA logon via PKINIT);
- **YubiKey OTP** (44 modhex characters appended to the password, detected
  automatically);
- TOTP/HOTP tokens enrolled in privacyIDEA.

FIDO2/WebAuthn is available on the web path (at Keycloak).

## MFA modes (`fastrdp_mfa_mode`)

| Mode | NLA logins | TLS logins |
|---|---|---|
| `none` | – | – |
| `otp` | **refused** (no channel for an OTP) | OTP must be appended to the password |
| `push` | push challenge | push challenge |
| `otp_or_push` | push challenge | appended OTP if present, otherwise push |

During a push the client simply waits ("connecting…"). `fastrdp_proxy_broker_timeout`
(default 120 s) must be larger than `push_timeout` (default 60 s).

### Splitting password and OTP

The broker separates the OTP from the end of the password field:

1. A trailing 44-character modhex string is taken as a YubiKey OTP.
2. Otherwise the configured TOTP length (`fastrdp_otp_lengths`, default `[6]`) is
   taken from the end, if those characters are all digits.

Configure **one** TOTP length. With `[6, 8]`, a password that ends in digits can be
split in the wrong place.

### privacyIDEA configuration

- Realm `fastrdp_privacyidea_realm` reading the same AD/LDAP users.
- For OTP: policy `otppin=none` for this client. The PIN is checked by PAM/Kerberos
  instead.
- For push without the user's password (Kerberos SSO): a service admin with the
  `triggerchallenge` right (`fastrdp_privacyidea_service_user`). Without it, push is
  triggered by `/validate/check` with the user's password, which requires policy
  `otppin=userstore`.
- `exempt_groups` skips MFA (e.g. break-glass accounts). Use sparingly.

## Kerberos specifics

- Clients must connect to the **FQDN** of the server. The proxy accepts tickets for
  `TERMSRV/<fqdn>` (and `TERMSRV/<SHORTNAME>` on AD).
  - AD: the Ansible `identity` role adds these SPNs to the computer account
    (`adcli update --add-service-principal`). A path unit re-extracts the keys
    whenever sssd rotates the machine password.
  - FreeIPA: `ipa service-add TERMSRV/<fqdn>` + `ipa-getkeytab`.
- Accepted realms: `fastrdp_realm` (broker `[auth] realms`). Principals from other
  realms are refused even if a cross-realm trust exists.
- Sessions use `KCM:` credential caches. sssd renews TGTs for up to 7 days
  (`krb5_renewable_lifetime`), which is long enough for long-running terminal-server
  sessions.

## Account policy

The broker runs PAM service `fastrdp` (`pam_sss` + `pam_faillock`) for TLS
password checks and the PAM *account* phase for every login. In AD, sssd maps this
service (plus `xrdp-sesman` and `fastrdp-session`) to the **"Allow log on through
Remote Desktop Services"** GPO right (`ad_gpo_map_remote_interactive`).

The Ansible default is `ad_gpo_access_control = permissive`: denials are only
logged. Check the logs, then switch to `enforcing`.
