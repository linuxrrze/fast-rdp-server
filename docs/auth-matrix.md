# Authentication and MFA

## What each login path gives you

| Client / method | First factor | Second factor (privacyIDEA) | Session gets a Kerberos TGT | Notes |
|---|---|---|---|---|
| NLA, user types a password (mstsc, xfreerdp3 `/u /p`, Remmina) | Kerberos (client gets a ticket with the password) | `push` (`otp_or_push`/`push`) | **yes, every RDP back-end.** xrdp (incl. wlroots): the delegated password reaches `pam_sss` through the xrdp PAM stack. GNOME, Plasma: the broker gets the TGT through PAM `fastrdp-tgt` before the session starts (`fastrdp_session_tgt: auto`); the back-ends themselves see only a per-session random secret | **Recommended.** The client must reach a KDC (VPN, or a KDC proxy in FreeRDP). |
| NLA, single sign-on from a domain-joined Windows client | Kerberos ticket of the logged-on user | `push` (needs `fastrdp_privacyidea_service_user`: no password reaches the server) | only if Windows delegates the password: GPO "Allow delegating default credentials" **and no Credential Guard** (on by default on Windows 11 22H2+ Enterprise/Education; it blocks delegating SSO and saved credentials, mstsc then prompts and delegates the typed password); then as the row above, for every back-end. `mstsc /restrictedAdmin` logs in without a prompt but never delegates a password | Without the GPO mstsc prompts instead of SSO. Remote Credential Guard (`/remoteGuard`) is refused. Without a password no session has a TGT (`kinit` inside the session); `fastrdp_session_tgt: required` refuses such logins. See [windows-clients.md](windows-clients.md) §3.5 |
| TLS, password+OTP in one field | PAM `fastrdp` (SSSD) | OTP appended to the password (`otp`, `otp_or_push`) | yes, every RDP back-end (as above) | For clients without Kerberos. Needs `fastrdp_allow_tls_logins: true`. |
| Web: Guacamole + Keycloak | Keycloak (OIDC) | at Keycloak (OTP, WebAuthn/FIDO2, privacyIDEA), proven by `acr`/`amr` | no (refused with `fastrdp_session_tgt: required`) | `fastrdp_web_enabled`; see [web-access.md](web-access.md) |
| NLA with a passkey-derived TGT (FreeIPA, Linux client) | Kerberos: passkey pre-authentication at the KDC (`kinit -T` / sssd), TGT carries indicator `passkey` | `push`; **skipped** with `fastrdp_mfa_nla_kdc_enforced: true` when the KDC requires `passkey`/`pkinit` for `TERMSRV` (FreeIPA auth indicators; checked by preflight and the identity role) | no (no password) | Lab stage: [passkeys.md](passkeys.md) stage 2, `tests/lab/freeipa-passkey-nla.sh`. Not for AD (no auth indicators) |
| Smartcard / PIV / YubiKey PIV (NLA) | Kerberos via **PKINIT** (certificate + PIN) | `push`, or exempt group for "smart card required" accounts | no (PIN is never forwarded; refused with `fastrdp_session_tgt: required`) | Tested with a software token; real cards/AD/mstsc to validate. See [smartcard-nla.md](smartcard-nla.md) |

### Kerberos TGT per back-end

| Back-end | Who gets the TGT | Logins that give one | Renewal |
|---|---|---|---|
| xrdp (X11, wlroots) | xrdp-sesman's PAM stack (`pam_fastrdp_token` hands the password to `pam_sss`) | NLA with delegated password, TLS | sssd (domain), sssd-kcm; each reconnect with a password gets a new TGT |
| GNOME, Plasma | the broker, before the session starts: PAM service `fastrdp-tgt` (`pam_sss` only), checked with `klist -s` as the user | NLA with delegated password, TLS (`[broker] session_tgt = auto` or `required`) | as xrdp; each login with a password, including a reconnect to the running session, gets a new TGT |
| Web | nobody | – | – |

`fastrdp_session_tgt` (`[broker] session_tgt`): `auto` (default) logs a failed TGT
request and continues; `required` refuses failed requests and refuses logins without
a password (SSO without delegation, smartcard, web) before MFA; `off` never asks.
Details: [backends/gnome.md](backends/gnome.md#kerberos-ticket-tgt),
[nfs-kerberos-homes.md](nfs-kerberos-homes.md).

YubiKeys work in three ways:
- **PIV smartcard** (NLA logon via PKINIT);
- **YubiKey OTP** (44 modhex characters appended to the password, detected
  automatically);
- TOTP/HOTP tokens enrolled in privacyIDEA.

FIDO2/WebAuthn is available on the web path (at Keycloak).
Passkeys (YubiKey FIDO2, KeePassXC, Bitwarden, Windows Hello, phones) per login path: [passkeys.md](passkeys.md).
FreeRDP and Remmina settings for each login path (exact switches, errors): [freerdp-client.md](freerdp-client.md).

## MFA modes (`fastrdp_mfa_mode`)

| Mode | NLA logins | TLS logins |
|---|---|---|
| `none` | – | – |
| `otp` | **refused** (no channel for an OTP) | OTP must be appended to the password |
| `push` | push challenge | push challenge |
| `otp_or_push` | push challenge | appended OTP if present, otherwise push |

**`fastrdp_mfa_nla_kdc_enforced`** (broker `[mfa] nla_kdc_enforced`, default off):
Kerberos NLA logins whose principal is in `[auth] realms` skip the second factor,
logged as `second factor skipped: [mfa] nla_kdc_enforced`. TLS and web logins are
unchanged. Only safe when the KDC refuses `TERMSRV/<host>` tickets to password-only
TGTs: FreeIPA `ipa service-mod TERMSRV/<host> --auth-ind=passkey --auth-ind=pkinit`
(the identity role sets and verifies this; preflight reads it). Details, the AD case
and the security review: [passkeys.md](passkeys.md#kdc-enforced-strong-authentication-for-nla).

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
  `TERMSRV/<fqdn>`, `TERMSRV/<SHORTNAME>` and `TERMSRV/<alias>` for each name in
  `fastrdp_termsrv_aliases` (role `common`, default `[]`).
  - AD: the Ansible `identity` role adds these SPNs to the computer account
    (`adcli update --add-service-principal`; aliases need the join account, since a
    computer may only register SPNs of its own names). A path unit re-extracts the
    keys whenever sssd rotates the machine password.
  - FreeIPA: `ipa service-add TERMSRV/<fqdn>` + `ipa-getkeytab`; the short name and
    the aliases become principal aliases (`ipa service-add-principal`, FreeIPA 4.6+),
    which share the FQDN principal's keys.
  - An alias belongs to one host. A shared name in front of several hosts needs a
    service account and one keytab distributed to all hosts (provider `none`), not
    covered by the role.
- **Keys must be AES.** FreeRDP's acceptor fails with RC4 tickets
  ([windows-clients.md](windows-clients.md) §3.4). `fastrdp_termsrv_enctypes` (role
  `identity`, default `[aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96]`):
  - AD: the role runs `adcli` with only these types permitted. adcli then writes the
    keytab and `msDS-SupportedEncryptionTypes` (`0x18`; with `arcfour-hmac` added,
    `0x1C`), never wider than the value already on the account. When a TERMSRV
    principal or its AES key is missing, the role re-keys the account once
    (`--computer-password-lifetime=0`).
  - FreeIPA: `ipa-getkeytab -e`.
  - The role fails, listing the principals, if `/etc/fastrdp/termsrv.keytab` lacks an
    AES key at the newest kvno (`fastrdp-termsrv-check` from `fastrdp-broker`, also run
    by `tests/smoke/check-host.sh`).
- The self-signed lab certificate (`fastrdp_front_cert_src: ""`) names the FQDN, the
  short name and the aliases. An existing `/etc/fastrdp/front.crt` is kept: delete it
  to get a new one. In production, use a certificate from your CA with the same names.
- Accepted realms: `fastrdp_realm` (broker `[auth] realms`). Principals from other
  realms are refused even if a cross-realm trust exists.
- **Who is logged in (NLA):** the account of the Kerberos principal, never the user
  name the client typed. Windows users may type a UPN whose local part differs from
  the account name (`marcel.ritter@corp.example.com` → `mritter`), or `DOMAIN\user`;
  the ticket names the account (`mritter@CORP.EXAMPLE.COM`). The broker maps the
  principal to a local account in this order:
  1. plain principal `name@REALM`: NSS `name`, then `name@realm` (with
     `strip_realm = false` the other way round);
  2. enterprise principal (`marcel.ritter\@corp.example.com@REALM`, if the KDC did not
     canonicalise the name): NSS lookup of the UPN, which SSSD resolves by its
     `userPrincipalName`. The UPN's local part alone is never used, since it may be
     somebody else's account name;
  3. otherwise `krb5_aname_to_localname()`: `auth_to_local` rules in `krb5.conf` and
     SSSD's localauth plugin.

  No match, root, or a multi-component principal (`alice/admin`): refused. The typed
  user name is only logged; if it names a *different* existing account, the delegated
  password is dropped (no TGT for the session) instead of being used for the
  principal's account. TLS logins still use the typed name, as there is no principal.
- Home directories on NFS with `sec=krb5`/`krb5i`/`krb5p` need a TGT (or gssproxy
  impersonation) before the session starts: see
  [nfs-kerberos-homes.md](nfs-kerberos-homes.md) for which logins work.
- Sessions use `KCM:` credential caches. sssd renews TGTs for up to 7 days
  (`krb5_renewable_lifetime`), which is long enough for long-running terminal-server
  sessions. sssd-kcm also renews TGTs that users get with `kinit` in a session
  (`[kcm] tgt_renewal`, `fastrdp_kcm_tgt_renewal`); `/etc/krb5.conf.d/fastrdp` asks for
  renewable tickets (`renew_lifetime`).

## Account policy

The broker runs PAM service `fastrdp` (`pam_sss` + `pam_faillock`) for TLS
password checks and the PAM *account* phase for every login. PAM service
`fastrdp-tgt` (`pam_sss` only) is used after a successful login only to get the
GNOME/Plasma session's TGT; it has no `pam_faillock`, so a stale delegated password
does not lock the account for fastrdp (the KDC still counts the failure). In AD, sssd maps this
service (plus `xrdp-sesman` and `fastrdp-session`) to the **"Allow log on through
Remote Desktop Services"** GPO right (`ad_gpo_map_remote_interactive`).

The Ansible default is `ad_gpo_access_control = permissive`: denials are only
logged. Check the logs, then switch to `enforcing`.
