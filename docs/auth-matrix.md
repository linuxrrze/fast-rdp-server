# Authentication and MFA

## What each login path gives you

| Client / method | First factor | Second factor (privacyIDEA) | Session gets a Kerberos TGT | Notes |
|---|---|---|---|---|
| NLA, user types a password (mstsc, xfreerdp3 `/u /p`, Remmina) | Kerberos (client gets a ticket with the password) | `push` (`otp_or_push`/`push`) | **yes, every RDP back-end.** xrdp (incl. wlroots): the delegated password reaches `pam_sss` through the xrdp PAM stack. GNOME, Plasma: the broker gets the TGT through PAM `fastrdp-tgt` before the session starts (`fastrdp_session_tgt: auto`); the back-ends themselves see only a per-session random secret | **Recommended.** The client must reach a KDC: VPN, or the KDC proxy on the web gateway (`fastrdp_web_kdcproxy`, [web-access.md](web-access.md#kdc-proxy); Windows by GPO, FreeRDP/MIT in `krb5.conf`). |
| NLA, single sign-on from a domain-joined Windows client | Kerberos ticket of the logged-on user | `push` (needs `fastrdp_privacyidea_service_user`: no password reaches the server) | only if Windows delegates the password: GPO "Allow delegating default credentials" **and no Credential Guard** (on by default on Windows 11 22H2+ Enterprise/Education; it blocks delegating SSO and saved credentials, mstsc then prompts and delegates the typed password); then as the row above, for every back-end. `mstsc /restrictedAdmin` logs in without a prompt but never delegates a password | Without the GPO mstsc prompts instead of SSO. Remote Credential Guard (`/remoteGuard`): see its own row. Without a password no session has a TGT (`kinit` inside the session); `fastrdp_session_tgt: required` refuses such logins. See [windows-clients.md](windows-clients.md) §3.5, and §3.12 for how a Windows RDP host gets its Kerberos credentials in each mode |
| NLA, single sign-on from a Linux ticket (`xfreerdp3 … /p` with an empty value, after `kinit` or a desktop login with a TGT) | Kerberos ticket from the client's cache | `push` (needs `fastrdp_privacyidea_service_user`: no password reaches the server) | **no** (no password is delegated; `kinit` inside the session). Without `/p`, xfreerdp3 prompts and the typed password gives the session a TGT, as in the first row | Refused with `fastrdp_session_tgt: required`. Details: [freerdp-client.md](freerdp-client.md) §2 |
| TLS, password+OTP in one field | PAM `fastrdp` (SSSD) | OTP appended to the password (`otp`, `otp_or_push`) | yes, every RDP back-end (as above) | For clients without Kerberos. Needs `fastrdp_allow_tls_logins: true`; `fastrdp_tls_login_sources` (proxy `AllowTlsFrom`) can limit it to client networks. Without it, TLS is offered only for the web path and accepted from loopback only. |
| Web: Guacamole + Keycloak | Keycloak (OIDC) | at Keycloak (OTP, WebAuthn/FIDO2, privacyIDEA), proven by `acr`/`amr` | no (refused with `fastrdp_session_tgt: required`) | `fastrdp_web_enabled`; see [web-access.md](web-access.md) |
| NLA with a passkey-derived TGT (FreeIPA, Linux client) | Kerberos: passkey pre-authentication at the KDC (`kinit -T` / sssd), TGT carries indicator `passkey` | `push`; **skipped** with `fastrdp_mfa_nla_kdc_enforced: true` when the KDC requires `passkey`/`pkinit` for `TERMSRV` (FreeIPA auth indicators; checked by preflight and the identity role) | no (no password) | Lab stage: [passkeys.md](passkeys.md) stage 2, `tests/lab/freeipa-passkey-nla.sh`. Not for AD (no auth indicators) |
| NLA, Remote Credential Guard (`mstsc /remoteGuard`, GPO "Require Remote Credential Guard"; FreeRDP `/remoteGuard`) | Kerberos ticket of the logged-on user; then TSRemoteGuardCreds (service ticket + TGT) instead of a password | as SSO: `push` with `fastrdp_privacyidea_service_user`, skipped with `fastrdp_mfa_nla_kdc_enforced` | **no.** The proxy module discards the forwarded tickets (identity only); refused with `fastrdp_session_tgt: required`. gssproxy S4U for NFS works as for SSO | **Refused by default**: the proxy answers the negotiation with "not supported" and mstsc shows its own error. `fastrdp_accept_remote_guard: true` accepts it identity only; the broker logs `remote credential guard: identity only, credentials discarded` (request field `remote_guard`). Using the credentials (MS-RDPEAR) is not implemented. [windows-clients.md](windows-clients.md) §3.12 |
| Smartcard / PIV / YubiKey PIV (NLA) | Kerberos via **PKINIT** (certificate + PIN) | `push`, or exempt group for "smart card required" accounts; **skipped per login** when the ticket carries an item of `fastrdp_mfa_kdc_evidence_as_mfa` (FreeIPA `ind:pkinit`; AD an AMA group or `sid:S-1-18-3`) | no (PIN is never forwarded; refused with `fastrdp_session_tgt: required`) | Tested with a software token; real cards/AD/mstsc to validate. See [smartcard-nla.md](smartcard-nla.md) |

### Kerberos TGT per back-end

| Back-end | Who gets the TGT | Logins that give one | Renewal |
|---|---|---|---|
| xrdp (X11, wlroots) | xrdp-sesman's PAM stack (`pam_fastrdp_token` hands the password to `pam_sss`) | NLA with delegated password, TLS | sssd (domain), sssd-kcm; each reconnect with a password gets a new TGT |
| GNOME, Plasma | the broker, before the session starts: PAM service `fastrdp-tgt` (`pam_sss` only), checked with `klist -s` as the user | NLA with delegated password, TLS (`[broker] session_tgt = auto` or `required`) | as xrdp; each login with a password, including a reconnect to the running session, gets a new TGT |
| Web | nobody | – | – |

`fastrdp_session_tgt` (`[broker] session_tgt`): `auto` (default) logs a failed TGT
request and continues; `required` refuses failed requests and refuses logins without
a password (SSO without delegation, Remote Credential Guard, smartcard, web) before MFA;
`off` never asks. `fastrdp_session_tgt_groups` (`[broker.session_tgt_groups]`,
group = mode) sets the mode per group: members of listed groups get the strictest mode
of their groups (`required` > `auto` > `off`), everybody else `fastrdp_session_tgt`;
e.g. `required` only for users with Kerberized homes
([nfs-kerberos-homes.md](nfs-kerberos-homes.md#c-require-a-typed-password-for-users-with-kerberized-homes)).
Details: [backends/gnome.md](backends/gnome.md#kerberos-ticket-tgt),
[nfs-kerberos-homes.md](nfs-kerberos-homes.md).

**Who is about to lose Kerberos access:** `sudo fastrdpctl status` lists, for each
account with a session, the TGT in the user's default credential cache (the cache the
session's processes use): principal, expiry and renewal limit (UTC, with the time left)
and a state: `ok`, `expiring` (less than 1 h left), `not_renewable_soon` (not
renewable, or renewal ends within 24 h: the next login with a password gets a new one),
`expired`, `none` (no TGT, e.g. SSO or smartcard login) or `unknown` (klist failed).
`fastrdpctl tickets [USER]` shows only that table, also for an account without a
session; `--json` for scripts. Only metadata: no ticket or key data
([nfs-kerberos-homes.md](nfs-kerberos-homes.md#q4-ticket-lifetime-and-renewal)).

**Sessions longer than the renewable lifetime** (`fastrdp_krb5_renewable_lifetime`,
default 7 days after the last login with a password): sssd cannot renew the TGT any
further, and the session loses Kerberized NFS/SMB homes and shares. Users see a desktop
notification 24 h and 2 h before that and once when the TGT has expired
(`fastrdp_tgt_notify*`, every desktop; nothing without a TGT). What renews: a reconnect
with a password (every back-end, also to the running session) or `kinit` in the
session; lock/unlock is no reliable way in fastrdp sessions. Without any of this:
gssproxy impersonation for the mounts
([nfs-kerberos-homes.md](nfs-kerberos-homes.md#long-running-sessions)).

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
| `web` | approval on the web gateway's `/web/approve` page | approval on `/web/approve` |
| `push_or_web` | push challenge **and** approval on `/web/approve`; the first answer wins | as NLA (an appended OTP is not split off) |

`web` and `push_or_web` need `fastrdp_web_enabled: true`; `web` needs no privacyIDEA
([Web approval](#web-approval)). Web logins (Guacamole) are unaffected by every mode:
their second factor is at Keycloak.

**`fastrdp_mfa_nla_kdc_enforced`** (broker `[mfa] nla_kdc_enforced`, default off):
Kerberos NLA logins whose principal is in `[auth] realms` skip the second factor,
logged as `second factor skipped: [mfa] nla_kdc_enforced`. TLS and web logins are
unchanged. Only safe when the KDC refuses `TERMSRV/<host>` tickets to password-only
TGTs: FreeIPA `ipa service-mod TERMSRV/<host> --auth-ind=passkey --auth-ind=pkinit`
(the identity role sets and verifies this; preflight reads it). Details, the AD case
and the security review: [passkeys.md](passkeys.md#kdc-enforced-strong-authentication-for-nla).

**`fastrdp_mfa_kdc_evidence_as_mfa`** (broker `[mfa] kdc_evidence_as_mfa`, default `[]`):
the same per login, from what the KDC wrote into the ticket. A Kerberos NLA login of a
principal in `[auth] realms` whose ticket carries one of the listed items skips the
second factor, logged as `second factor from KDC evidence <item>`: `ind:<indicator>`
(FreeIPA/MIT authentication indicators such as `ind:pkinit`, `ind:passkey`) or
`sid:<SID>` (AD PAC group SIDs such as `sid:S-1-18-4` for Windows Hello for Business key
trust, or an Authentication Mechanism Assurance group). Logins without a matching item
keep their second factor unchanged; the client sees no difference. The proxy's FreeRDP
checks the KDC's signature over the evidence (`patches/freerdp/0005`); the client's
`smartcard` flag never counts. Such a login earns reconnect grace like a push. Items,
refusals, caveats (freshness, shadow credentials):
[passkeys.md](passkeys.md#kdc-evidence-per-login).

### Reconnect grace

**`fastrdp_mfa_reconnect_grace`** (broker `[mfa] reconnect_grace`, seconds, default
`0` = off, at most 3600) and **`fastrdp_mfa_reconnect_grace_same_address`**
(`[mfa] reconnect_grace_same_address`, default `true`). `scripts/fastrdp-setup` does
not ask for them; add them to the generated `group_vars/all/main.yml` by hand.

Why: neither the proxy nor xrdp supports RDP auto-reconnect cookies
([rdp-spec-conformance.md](rdp-spec-conformance.md#6-redirection-load-balancing-reconnect)).
After every network drop (Wi-Fi roaming, VPN reconnect, laptop lid) mstsc reconnects
with a full login: NLA, silent with a Kerberos ticket, and then a new push. With a
grace period the broker skips the second factor for such a reconnect and logs

```
alice: nla login from 192.0.2.10; second factor skipped: reconnect grace (push passed 212s ago from 192.0.2.10)
```

How it works:

- **What earns grace:** only a login whose second factor privacyIDEA confirmed (OTP or
  push), the user approved on the web approval page, or the KDC's evidence in the ticket
  (`kdc_evidence_as_mfa`, factor `kdc <item>`), *and* whose session then started (the
  broker handed the target to the proxy).
  Refusals, wrong or missing OTPs, push timeouts, privacyIDEA errors and back-end errors
  record nothing. Logins that never asked privacyIDEA record nothing either: exempt
  groups, `nla_kdc_enforced`, web logins (their MFA is at Keycloak), `mode = "none"`.
- **What must match** (all of it):
  - the local account;
  - the login method, i.e. the class of the first factor: `nla` (a Kerberos ticket for
    `TERMSRV`) or `tls` (password checked by PAM). A push approved for an NLA login never
    lets a TLS password login skip it, and the other way round: the two are stolen in
    different ways (a ticket cache or a delegated credential vs. a typed password), so
    holding one kind must not ride on MFA that was passed with the other. mstsc
    reconnects with the method it used before, so this costs nothing;
  - NLA: the Kerberos principal from the ticket (as the KDC canonicalised it). The
    `principal` field of a TLS login is client-supplied and ignored, and so is the
    `smartcard` flag (a PKINIT and a password-derived ticket for the same principal are
    the same class: the broker cannot tell them apart);
  - with `reconnect_grace_same_address = true`: the client address the proxy sees
    (the TCP peer, not the client-supplied ClientAddress). A login without a known
    address then never uses or earns grace.
- **Absolute, not sliding:** the period counts from the last *real* second factor, also
  when the session took a while to start. Logins that used grace do not extend it; the
  next real push or OTP starts a new period. A sliding window would let somebody who
  keeps reconnecting stay MFA-free forever.
- **Still checked on every login:** the first factor (Kerberos NLA, or the PAM password
  check for TLS), `[auth] allow_groups`, the PAM account phase (expired, locked,
  `pam_access`, AD GPO logon right), `session_tgt = "required"`, realms. Grace replaces
  the privacyIDEA call and nothing else.
- **TLS with OTPs:** mstsc reconnects with the stored `password+OTP`. Within the grace
  period the appended (now used) OTP is split off and not sent to privacyIDEA, so the
  reconnect is not refused as an OTP replay. In `otp` mode a TLS reconnect without an
  appended OTP is accepted too while grace applies; without grace it is refused before
  the password check, as before.
- **Memory only:** entries live in the broker process (pruned when they expire).
  `systemctl restart fastrdp-brokerd` (and every upgrade) forgets all of them; the next
  login of each user asks for the second factor again.
- **Revoking:** `fastrdpctl clear-grace alice` forgets alice's entries (local account
  name as in the broker log), `fastrdpctl clear-grace` everybody's. A login whose second
  factor was passed before the clear and whose session is still starting records
  nothing. `fastrdpctl status` shows `mfa_grace_entries`. `fastrdpctl logout` does not
  clear grace; on a suspected compromise run both, and lock the account or revoke the
  token.

Security review:

- **What it weakens:** within the period, a second login from the same address needs
  only the first factor. An attacker who has the user's Kerberos ticket (or can obtain
  one: the password) **and** connects from the same address (shared NAT, VPN
  concentrator, the user's own compromised machine) right after the user passed MFA
  gets in without a push. With `reconnect_grace_same_address = false` any address will
  do, i.e. MFA is effectively "once per N seconds per user and method": use that only
  where clients' addresses change on every reconnect (mobile networks) and the period
  is short.
- **What it does not weaken:** the first factor, account and group checks, the realm
  check, and the binding to the principal. Grace never starts from a login that did
  not pass privacyIDEA (or present matching KDC evidence), so it cannot extend
  `nla_kdc_enforced`, exempt groups or the web path, and a refused login (R1 reasons `denied`, `not_allowed`, `mfa_failed`,
  `mfa_timeout`, `backend`) never creates an entry. The reply to a refused login is the
  same with or without grace.
- **A compromised client machine** already controls the running session, so grace
  adds little there. A malicious push approved by mistake (push fatigue) is
  extended by the period: `fastrdpctl clear-grace` limits that once noticed.
- **`session_tgt`:** grace does not touch it. A grace login with a password (TLS, NLA
  with delegation) still gets a fresh TGT for GNOME/Plasma; with
  `session_tgt = "required"` (globally or for one of the user's
  `session_tgt_groups`) a passwordless login is still refused.
- **Recommended values:** `300`–`900` seconds with the address binding on. That covers
  a network drop, a VPN reconnect or moving between meeting rooms, but not the next
  morning. Keep it `0` where every login must show a fresh second factor (e.g. admin
  hosts). The 3600 s limit keeps this a reconnect aid, not a replacement for MFA.
- **Not covered:** a broker restart forgets grace (safe direction); several proxy hosts
  each have their own broker and grace; the web path is unchanged.

During a push the client simply waits ("connecting…"). `fastrdp_proxy_broker_timeout`
(default 180 s, proxy.ini `[FastRDP] Timeout`, at most 600) is one wait for the whole
broker call: the push (privacyIDEA `push_timeout`, default 60 s) or web approval
(`fastrdp_mfa_web_approval_timeout`, default 90 s) **plus** the session start that
follows it (broker `session_start_timeout`, 90 s; first GNOME/Plasma starts can take
most of it). With web approval the common checks require
`fastrdp_proxy_broker_timeout` ≥ `fastrdp_mfa_web_approval_timeout` + 90; for push,
keep it at least `push_timeout` + 90 (privacyIDEA's setting is not checked).

### Web approval

**`fastrdp_mfa_mode: web`** (broker `[mfa] mode = "web"`): an RDP login that owes its
second factor waits in the broker, as during a push, until the user approves it in a
browser. **`push_or_web`** sends a privacyIDEA push at the same time; whichever answers
first wins and the other is cancelled. Both need the web gateway
(`fastrdp_web_enabled: true`, [web-access.md](web-access.md#approving-rdp-logins)).

1. The user starts the login in mstsc/xfreerdp3 (NLA or TLS). The first factor, groups
   and account are checked as always; the client shows "connecting…".
2. The broker logs `web approval pending for alice from 192.0.2.10` and keeps the login
   pending (memory only).
3. The user opens `https://<host>/web/approve`. The webgate sends them to Keycloak for a
   **fresh** sign-in (`prompt=login`, `max_age=0`) with the usual MFA proof
   (`acr`/`amr`: passkey, TOTP, WebAuthn, privacyIDEA), and checks the ID token's
   `auth_time`, so an existing Keycloak session does not count.
4. The page lists the user's pending logins with client address, start time and login
   method. **Approve** lets the broker continue (session start or reuse, as after a
   push); **Deny** fails the login with `mfa_failed` (Set Error Info 0x7). Without a
   decision within `fastrdp_mfa_web_approval_timeout` the login fails with
   `mfa_timeout` (0x409). Closing the RDP client removes the pending login.

| Variable (broker key) | Default | Meaning |
|---|---|---|
| `fastrdp_mfa_web_approval_timeout` (`web_approval_timeout`) | `90` | seconds a login waits for the decision, 10..510. In `push_or_web` it bounds the whole wait (keep `push_timeout` below it). `fastrdp_proxy_broker_timeout` (default 180) must be at least this plus 90 s for the session start after the approval (`session_start_timeout`; checked): raise the proxy's timeout along with this one. 510 = the module's 600 s limit minus the session start |
| `fastrdp_mfa_web_approval_max_auth_age` (`web_approval_max_auth_age`) | `30` | the approving sign-in may be at most this many seconds older than the pending login (0..300). Signing in first and starting the login afterwards works only within this window; otherwise the page asks to sign in again |
| `fastrdp_mfa_web_approval_single_pending` (`web_approval_single_pending`) | `true` | with two or more pending logins of one user, none can be approved (each can still be denied); the user denies them and starts one new login |

**Why `single_pending`:** whoever has the user's password (or Kerberos ticket) can start
an RDP login of their own at the moment the user starts theirs. The page shows both,
and the user cannot reliably tell which one is theirs (a shared NAT address looks the
same). Refusing approval while more than one is pending turns that race into a visible
warning instead of a coin toss.

**What the broker checks** for each decision (ops `mfa_pending`/`mfa_decide`, accepted
only from the webgate's uid, `[web] gateway_user`): the request belongs to the account
the webgate signed in (another user's request looks unknown); it is still pending
(already approved, denied, timed out or abandoned requests get a clear refusal);
`auth_time` and `single_pending` as above, for Approve. Deny is always accepted.

**Reconnect grace:** a login passed by web approval records the factor `web`; reconnects
within `fastrdp_mfa_reconnect_grace` skip the approval like they skip a push.
Exempt groups and `fastrdp_mfa_nla_kdc_enforced` skip it before it starts, as for push.

Security notes:
- **Social engineering:** an attacker who has the password may call the user and ask
  them to "approve the login on the web page". The page says to approve only a login
  the user started themselves just now, from the address shown, and to deny everything
  else. A denied login is logged (`web approval for alice from … DENIED`); treat
  unexpected denials as a stolen password.
- The approval sign-in needs the same MFA proof as the browser path (passkey, TOTP,
  WebAuthn at Keycloak), so web approval is as strong as that, and lets users with
  only a passkey reach RDP logins ([passkeys.md](passkeys.md)).
- The approval cookie (`fastrdp_web_approve`, 5 minutes) only allows decisions, no
  desktop access, and is separate from the desktop chooser's sign-in.
- `fastrdpctl status` shows the number of pending approvals
  (`mfa_pending_approvals`). Pending logins are memory only: a broker restart fails them.

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

- Clients must connect to the **FQDN** of the server: `fastrdp_fqdn`, by default the
  inventory name when that is an FQDN (otherwise Ansible's `fqdn` fact, which comes from a
  reverse lookup). Preflight fails if it differs from `hostname -f` or from that fact. The proxy accepts tickets for
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
- **mstsc uses Kerberos user-to-user** (CredSSP, every Windows client): the proxy answers
  with the TGT of the account that owns `TERMSRV/<host>`. AD: the machine account
  `<NAME>$`, whose entries `fastrdp-termsrv-keytab` copies into the proxy keytab (the
  same keys as the TERMSRV entries; the role fails without them; needs
  `fastrdp-freerdp3` ≥ 3.32.2-3). FreeIPA and MIT: the TERMSRV principal itself. FreeRDP
  clients fall back to plain Kerberos. [windows-clients.md](windows-clients.md) §3.14.
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
  1. plain principal `name@REALM`: NSS `name`, then `name@realm` and
     `name@<domain>` (`[auth] domains`); with `strip_realm = false` (fully qualified
     names, [below](#short-or-fully-qualified-account-names)) the qualified names first;
  2. enterprise principal (`marcel.ritter\@corp.example.com@REALM`, if the KDC did not
     canonicalise the name): NSS lookup of the UPN, which SSSD resolves by its
     `userPrincipalName`. The UPN's local part alone is never used, since it may be
     somebody else's account name;
  3. otherwise `krb5_aname_to_localname()`: `auth_to_local` rules in `krb5.conf` and
     SSSD's localauth plugin.

  No match, root, or a multi-component principal (`alice/admin`): refused. The typed
  user name is only logged; if it names a *different* existing account, the delegated
  password is dropped (no TGT for the session) instead of being used for the
  principal's account. TLS and web logins use the typed name (`alice`, `DOMAIN\alice`,
  `alice@example.com`), as there is no principal: the short name and the short name
  qualified with the realm/domain, in the same order as 1.
- Home directories on NFS with `sec=krb5`/`krb5i`/`krb5p` need a TGT (or gssproxy
  impersonation) before the session starts: see
  [nfs-kerberos-homes.md](nfs-kerberos-homes.md) for which logins work. SMB homes and
  shares with `sec=krb5,multiuser` likewise (gssproxy for `cifs.upcall`,
  `fastrdp_smb_krb5_homes`): [smb-kerberos-homes.md](smb-kerberos-homes.md).
- Sessions use `KCM:` credential caches. sssd renews TGTs for up to 7 days
  (`krb5_renewable_lifetime`), which is long enough for long-running terminal-server
  sessions. sssd-kcm also renews TGTs that users get with `kinit` in a session
  (`[kcm] tgt_renewal`, `fastrdp_kcm_tgt_renewal`); `/etc/krb5.conf.d/fastrdp` asks for
  renewable tickets (`renew_lifetime`).

### Short or fully qualified account names

`fastrdp_sssd_fully_qualified_names` (default `false`) sets SSSD's
`use_fully_qualified_names` (AD: `sssd.conf`; FreeIPA: `conf.d/50-fastrdp.conf`, which
overrides the enrolment's `sssd.conf`; provider `none`: your `sssd.conf` must say the
same, the identity role checks it) and the broker's `[auth] strip_realm` (the opposite)
from one variable.

| | short names (`false`) | fully qualified names (`true`) |
|---|---|---|
| Account of `alice@EXAMPLE.COM` | `alice` | `alice@example.com` |
| `ls -l`, `ps`, `who`, sudoers, ACLs, `fastrdpctl logout`/`clear-grace` | `alice` | `alice@example.com` |
| Local account `alice` in `/etc/passwd` | **shadows** the directory user: NSS asks `files` before `sss`, so the principal `alice@EXAMPLE.COM` logs in as the *local* `alice` | a different account; the directory user is always `alice@example.com` |
| Groups (`id`, `getent group`) | `rdp-users` | `rdp-users@example.com`; group names in `fastrdp_allow_groups`, `fastrdp_mfa_exempt_groups`, `fastrdp_desktop_groups`, `fastrdp_group_desktops` may stay short (they also match `<name>@<domain>`) or be written qualified to exclude a local group of the same name |
| Several domains / trusts | names may collide between domains | unique |
| Home directory | `/home/alice` | `/home/alice` (`fallback_homedir = /home/%u`, `%u` is the short name; AD `unixHomeDirectory` and FreeIPA `homeDirectory` win when set) |
| privacyIDEA user | `alice` | `alice` (the broker strips our own domain) |

Short names are what users and admins know, and what scripts and tools that build
paths or mail addresses from `$USER` expect. Fully qualified names cost that
convenience but make the account of a directory user unambiguous: no local account,
created by a package, an admin or an earlier setup, can take its place, and users of
several domains cannot collide. Choose it for new hosts with local accounts besides the
directory, or when in doubt about them; the user types the same as before (`alice`,
`DOMAIN\alice`, `alice@example.com`, or Kerberos SSO).

Users without a qualified directory account still log in with their short name
(local accounts, last candidate), also with `strip_realm = false`; if SSSD cannot
answer at all (not running), a local account of the same short name would match then.

Switching on a running host renames every directory user: their running sessions are
recorded under the old name (`fastrdpctl status`), so log everybody out first
(`fastrdpctl logout <user>`) or reboot after the run. sudoers, file ACLs and scripts
that name directory users or groups need the new names. Home directories stay.
`fastrdpctl logout` and `clear-grace` take the name as the broker logs it.

## Account policy

The broker runs PAM service `fastrdp` (`pam_sss` + `pam_faillock`) for TLS
password checks and the PAM *account* phase for every login. PAM service
`fastrdp-tgt` (`pam_sss` only) is used after a successful login only to get the
GNOME/Plasma session's TGT; it has no `pam_faillock`, so a stale delegated password
does not lock the account for fastrdp (the KDC still counts the failure). In AD, sssd maps this
service (plus `xrdp-sesman` and `fastrdp-session`) to the **"Allow log on through
Remote Desktop Services"** GPO right (`ad_gpo_map_remote_interactive`), and GDM's
`gdm-autologin` (GNOME headless sessions) too; GNOME's `grdctl` step also runs PAM
service `login` (interactive right), see [gnome.md](backends/gnome.md).

The Ansible default is `ad_gpo_access_control = permissive`: denials are only
logged. Check the logs, then switch to `enforcing`.

### KDC proxy and password guessing

With the KDC proxy (`fastrdp_web_kdcproxy`, [web-access.md](web-access.md#kdc-proxy))
anyone on the internet can send Kerberos pre-authentication attempts to the KDCs
through the web gateway, without touching the RDP port, privacyIDEA or `pam_faillock`:
- Only the KDC's own **account lockout policy** counts these failures (AD: account
  lockout threshold; FreeIPA: `ipa pwpolicy-mod --maxfail`; MIT: policy `maxfailure`).
  A lockout also lets an attacker lock users out.
- Accounts must **require pre-authentication**; otherwise the KDC hands out
  crackable replies and logs no failure.
- The nginx rate limit (`fastrdp_web_kdcproxy_rate_per_minute`, per client address)
  slows a single source only. The KDC logs the gateway's address as the client; the
  real address is in `/var/log/nginx/fastrdp-web.log`.
- With MFA on (`fastrdp_mfa_mode` other than `none`) a guessed password alone still
  gives no RDP session: NLA logins need the second factor as before (with
  `fastrdp_mfa_nla_kdc_enforced` the KDC itself requires passkey/PKINIT for
  `TERMSRV`). It does give Kerberos tickets for other services in the realm.
