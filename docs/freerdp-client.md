# FreeRDP 3 client reference: logging in to fastrdp

How to make **xfreerdp3** / **sdl-freerdp3** (and Remmina, which uses the FreeRDP
library) use each login method fastrdp supports. Short version for end users:
[client-guide.md](client-guide.md). Server side of each method:
[auth-matrix.md](auth-matrix.md).

Verified on 2026-10-20 against:
- **FreeRDP 3.32.2**, the version fastrdp vendors (`third_party/sources.yml`, with
  `patches/freerdp/`). Every switch and sub-option below was checked against
  `client/common/cmdline.h` and the code that parses it (appendix A). `make test-docs`
  repeats that check (appendix B);
- **Remmina 1.4.43** (`plugins/rdp/rdp_plugin.c`, `rdp_settings.c`);
- the fastrdp proxy module, broker and e2e tests in this repository.

Evidence markers:
- **[e2e]**: the FreeRDP settings that the switch sets are exercised by
  `tests/proxy-e2e/` (`client.c` sets them through the library, not the command line);
- **[src]**: read in the FreeRDP / Remmina / fastrdp source only;
- **[lab]**: still needs a test with real hardware or a real KDC setup (list at the end).

Client binaries and versions:
- `xfreerdp3`, `sdl-freerdp3`, `wlfreerdp3`: Debian 13 and other distributions with
  versioned binary names. They all use the same command-line parser. **Ubuntu 26.04's
  `freerdp-x11` package (3.32.1) installs the client as `xfreerdp`.**
- `/opt/fastrdp/bin/xfreerdp`: fastrdp's own build (package `fastrdp-freerdp3`), X11
  only, with H.264 and the PKCS#11 slot-id fix (§3).
- **Debian 13 ships FreeRDP 3.15.0.** Older versions lack some of the options below,
  e.g. the `u2u` package name (§8). Check yours with `xfreerdp3 /version` and
  `xfreerdp3 /help`.

## Methods at a glance

All commands use the server's FQDN; `rdp1.lab.example.com`, realm `LAB.EXAMPLE.COM`.

| # | Method | Command | Session gets a Kerberos TGT | MFA (`fastrdp_mfa_mode`) |
|---|---|---|---|---|
| 1 | Kerberos NLA, typed password | `xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /auth-pkg-list:'kerberos,!ntlm'` (asks for the password) | **yes**, every RDP back-end | push (`push`, `otp_or_push`); `otp` refuses NLA |
| 2 | Kerberos NLA, single sign-on with an existing ticket | `kinit alice@LAB.EXAMPLE.COM`, then the same command plus `/p` (empty) | no | push, needs `fastrdp_privacyidea_service_user` |
| 3 | Smartcard / PIV / YubiKey PIV (PKINIT) | `xfreerdp3 /v:rdp1.lab.example.com /sec:nla /auth-pkg-list:'kerberos,!ntlm' /smartcard-logon /kerberos:pkcs11-module:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` (asks for the PIN) | no | push, or an exempt group |
| 4 | Passkey → TGT (FreeIPA) | `kinit -n` armor + `kinit -T` with the passkey, then method 2 | no | push |
| 5 | TLS, password + OTP in one field | `xfreerdp3 /v:rdp1.lab.example.com /u:alice /sec:tls` (type `password123456`) | **yes**, every RDP back-end | appended OTP (`otp`, `otp_or_push`) or push |

Append the display options you want, e.g. `/gfx:avc444 /network:auto /dynamic-resolution
+clipboard` ([client-guide.md](client-guide.md), [performance.md](performance.md)).

**Video bitrate of X11 (xrdp) sessions.** `/network:auto`, or no `/network:` at all,
sends "auto-detect". The proxy does not measure the link; the server uses `lan`
(uncapped) for client addresses in `fastrdp_lan_networks` and
`fastrdp_xrdp_autodetect_profile` (default `wan`, 12–15 Mbit/s) for all others. An
explicit `/network:lan`, `/network:wan`, `/network:broadband-high`,
`/network:broadband-low` or `/network:modem` is always kept. `/network:` also sets
FreeRDP's own performance flags (wallpaper, themes, font smoothing) for the session.
GNOME and Plasma sessions ignore the connection type
([performance.md](performance.md#bitrate-profile-of-x11-xrdp-sessions)).

## 0. Parts every Kerberos login shares

**Server name.**
- Connect to the FQDN. FreeRDP asks the KDC for `TERMSRV/<name>`, where `<name>` is
  `/server-name:` if given, else the host of `/v:` (`nla.c:472`, `kerberos.c:1235`).
  [src]
- An IP address or a DNS alias that is not in `fastrdp_termsrv_aliases` has no
  principal. The login then fails with `Server not found in Kerberos database`.
- For an SSH tunnel or a NAT port, keep Kerberos and TLS on the real name:
  ```sh
  xfreerdp3 /v:localhost:13389 /server-name:rdp1.lab.example.com /sec:nla /auth-pkg-list:'kerberos,!ntlm' /u:alice /d:LAB.EXAMPLE.COM
  ```
  `/server-name:` also replaces the host name in the certificate check (`tls.c:774-776`).

**Security protocol.**
- `/sec:nla` enables NLA and disables all other protocols (TLS, RDP, ext, aad).
- `/sec:nla:on` would only toggle NLA and leave the others as they are
  (`cmdline.c:3408-3481`). fastrdp's proxy never offers RDP security
  (`ServerRdpSecurity=false`) and offers TLS only when `fastrdp_allow_tls_logins` or
  the web path is enabled.

**Authentication packages: `/auth-pkg-list:'kerberos,!ntlm'`.**
- Without it, WinPR's Negotiate offers Kerberos U2U, Kerberos and NTLM, in that order
  (`negotiate.c:109-113`, defaults `negotiate.c:319-338`).
- fastrdp's proxy does not offer NTLM. A client that falls back to NTLM fails at its
  first CredSSP message with `ERRCONNECT_LOGON_FAILURE`, and the proxy logs
  `client <addr> attempted NTLM (offered: NTLM); only Kerberos NLA is accepted: check …`
  ([windows-clients.md](windows-clients.md) §3.13).
- With `!ntlm`, a Kerberos problem (no KDC, wrong name) fails on the client with the
  Kerberos error, which says what went wrong. Without it, FreeRDP falls back to NTLM and
  reports only the logon failure.
- Package names: `kerberos`, `u2u`, `ntlm`, and `none` (only as the first entry: "all
  off, then enable the following") (`negotiate.c:44-47, 259-316`).
  - `kerberos` does not switch `u2u` off.
  - `none,kerberos` is the same as `kerberos,!u2u,!ntlm`.
- Quote the value (`'...'`): `!` is special in interactive bash.

**User name forms** (`cmdline.c:1294-1333`; Kerberos side `kerberos.c:417-481`). [src]

| You type | Kerberos principal FreeRDP uses | Notes |
|---|---|---|
| `/u:alice /d:LAB.EXAMPLE.COM` | `alice@LAB.EXAMPLE.COM` | recommended. `/d` is the realm; FreeRDP upper-cases it and makes it the default realm for this login. **Exception** (FreeRDP 3.32.2 and later; Ubuntu 26.04's 3.24.2 and 3.32.1 always build `alice@<D>`): if `default_realm` in the client's `krb5.conf` is set to *another* realm, FreeRDP treats a dotted `/d` as a UPN suffix (row 3); then use `/u:alice@LAB.EXAMPLE.COM` |
| `/u:alice@LAB.EXAMPLE.COM` (no `/d`) | `alice@LAB.EXAMPLE.COM` | FreeRDP upper-cases the part after `@`, so `/u:alice@lab.example.com` also works when realm = DNS domain |
| `/u:marcel.ritter /d:corp.example.com` (UPN suffix ≠ realm) | enterprise principal `marcel.ritter\@corp.example.com@<default_realm>` (FreeRDP ≥ 3.32.2; older: `marcel.ritter@CORP.EXAMPLE.COM`, which fails) | when `/d` contains a dot and differs from `default_realm` in `krb5.conf`, FreeRDP builds an enterprise name, as Windows does. Needs `default_realm` = the AD realm. [lab] |
| `/u:marcel.ritter@corp.example.com` (UPN suffix ≠ realm) | `marcel.ritter@CORP.EXAMPLE.COM` | **fails**: `CORP.EXAMPLE.COM` is no realm. Use the row above |
| `/u:LAB\alice` | `alice@LAB` | **fails** unless `krb5.conf` knows a realm `LAB`. NetBIOS names are no realms |

fastrdp logs in the account of the principal in the ticket, never the typed name. If the
typed name is clearly another account, the delegated password is dropped and the session
gets no TGT ([auth-matrix.md](auth-matrix.md), Kerberos specifics).

**Passwords on the command line.**
- `/p:secret` is visible in the process list. FreeRDP warns about it, and also about
  `/p` without a value and `/smartcard-logon` (`cmdline.c:81-87, 5707-5735`).
- Prefer the prompt: `xfreerdp3` asks on the terminal, `sdl-freerdp3` opens a dialog.
- Alternatives: `/from-stdin` (read the credentials from stdin), `/args-from:` (all
  arguments from a file, fd or environment variable), or the environment variable
  `FREERDP_ASKPASS` (a GUI helper asks).

## 1. Kerberos NLA with a typed password (recommended)

```sh
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /auth-pkg-list:'kerberos,!ntlm'
```

**What happens** [e2e: `run_nla.sh`, same settings through the library]
1. FreeRDP asks for the password (no `/p`) and gets a TGT for `alice@LAB.EXAMPLE.COM`
   from the KDC. It uses a private in-memory credential cache, which is discarded on
   exit; your own cache is untouched unless you name one with `/kerberos:cache:` (§7).
   If a valid TGT for that principal is already in your default cache, FreeRDP uses it
   and the typed password is not needed for Kerberos (`kerberos.c:492-581`).
   The client then never checks the typed password: a wrong one still logs in through
   Kerberos, but fastrdp gets the wrong password, so the session has no TGT
   (`fastrdp_session_tgt: auto`) or the login is refused (`required`).
2. It authenticates to `TERMSRV/rdp1.lab.example.com` (Kerberos, mutual authentication).
3. It then delegates `TSPasswordCreds` (user, domain, password) to fastrdp
   (`nla.c:1836-1849`).

**Server.**
- Always available: `ServerNlaSecurity=true`.
- The keytab must hold AES keys for every name clients use (`fastrdp_termsrv_aliases`,
  `fastrdp_termsrv_enctypes`).
- `fastrdp_realm` must list the user's realm.

**Session TGT: yes**, for every RDP back-end.
- xrdp (X11 and wlroots): the delegated password reaches `pam_sss` through xrdp's PAM
  stack.
- GNOME, Plasma: the broker gets the TGT through PAM `fastrdp-tgt` before the session
  starts (`fastrdp_session_tgt: auto`).
- Not if you add `-credentials-delegation`: FreeRDP then sends empty `TSPasswordCreds`
  (`cmdline.c:4906-4910`, `nla.c:1836-1838`). The password never reaches the server,
  and the session has no TGT.

**MFA.**
- `push` and `otp_or_push` send a push and wait for it (§6).
- `otp` refuses every NLA login.
- An OTP appended to the password cannot work with NLA: the KDC would reject the
  password before fastrdp sees it.

**Errors.** Errors from Kerberos are logged as `<krb5 function> (<MIT message> [<code>])`
(`kerberos.c:132-155`).

| Symptom | Cause |
|---|---|
| `krb5glue_get_init_creds (Preauthentication failed ...)` | wrong password |
| `Cannot find KDC for realm` / `Cannot contact any KDC for realm` | realm unknown or KDC unreachable: VPN, DNS SRV records, `krb5.conf`, or a KDC proxy (§7) |
| `krb5_get_credentials (Server not found in Kerberos database ...)` | no `TERMSRV/<name>` principal: IP address or unregistered alias (§0) |
| `Clock skew too great` | client clock more than 5 minutes off |
| window opens, then closes | refused after authentication. The error code says roughly why: `ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES` (0x9) not allowed (group, account policy, desktop); `ERRINFO_SERVER_DENIED_CONNECTION` (0x7) MFA rejected or policy; `ERRINFO_CB_CONNECTION_CANCELLED` (0x409) push not approved in time; `ERRINFO_CB_DESTINATION_NOT_FOUND` (0x400) session could not be started ([client-guide.md](client-guide.md#when-the-server-refuses-the-login)). The exact reason is in `journalctl -u fastrdp-proxy -u fastrdp-brokerd`, e.g. `denied (not_allowed): ...` |

## 2. Kerberos NLA single sign-on (existing ticket, no password)

```sh
kinit alice@LAB.EXAMPLE.COM          # or the TGT from your desktop login (sssd/KCM)
klist                                # krbtgt/LAB.EXAMPLE.COM@LAB.EXAMPLE.COM, still valid
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /p /sec:nla /auth-pkg-list:'kerberos,!ntlm'
```

**Which flags make FreeRDP use the cache, and when it prompts.** [src]
- `/u` + `/d` (or `/u:alice@REALM`) name the principal.
- FreeRDP looks for a credential cache of that principal in the cache collection
  (`krb5_cc_cache_match`). It then uses a valid TGT (`kerberos.c:492-518, 560-581`).
- **`/p` with no value** sets an empty password. FreeRDP then skips its password prompt
  (`cmdline.c:5082-5092`, `utils.c:213-220`).
- Without `/p`, FreeRDP prompts for a password (`nla.c:331-336`). Pressing Enter at the
  prompt also continues with the ticket.
- Without `/u`, FreeRDP asks for the user name too. Give `/u`.
- If no valid TGT is found, FreeRDP tries to get one with the empty password. That fails
  with a pre-authentication error, which the KDC may count as a failed logon. Run
  `kinit` first.

**Which cache.** FreeRDP uses MIT krb5's default cache:
- `KRB5CCNAME` (e.g. `FILE:/tmp/krb5cc_1000`, `KCM:`, `DIR:...`) if set;
- otherwise `default_ccache_name` in `krb5.conf`. With sssd-kcm that is `KCM:`, where
  the desktop login's TGT lands.

  ```sh
  KRB5CCNAME=FILE:/tmp/alice.cc xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /p /sec:nla /auth-pkg-list:'kerberos,!ntlm'
  ```
- **Collections with several principals (KCM, DIR):**
  - FreeRDP 3.32.2 checks that a cache for the principal exists, then reads the TGT
    from the **default (primary)** cache (`kerberos.c:495-517`: the matched cache is replaced
    by `krb5_cc_default`).
  - Make the right one primary first: `kswitch -p alice@LAB.EXAMPLE.COM`. Otherwise
    FreeRDP falls back to a password login as above.
  - With a typed password in that case, FreeRDP stores the new TGT in your primary
    cache (`krb5glue_mit.c` `set_out_ccache`), which then holds the other principal's
    tickets no longer [inferred from MIT ccache semantics].
- `/kerberos:cache:<ccache>` sets the default cache for this connection (§7).

**What the server gets.**
- The Kerberos login, plus `TSPasswordCreds` with an empty password. FreeRDP never
  forwards a TGT (`kerberos.c:1254`, "delegation not implemented").
- So there is **no Kerberos TGT in the session**, on any back-end ([auth-matrix.md](auth-matrix.md)).
  Run `kinit` inside the session if you need one.
- With `fastrdp_session_tgt: required` (e.g. Kerberized NFS homes,
  [nfs-kerberos-homes.md](nfs-kerberos-homes.md)) such logins are refused before MFA,
  with `login without a password, but [broker] session_tgt = required` in the broker log.

**MFA.**
- Push, triggered without the user's password. That needs the privacyIDEA service
  account `fastrdp_privacyidea_service_user`; without it the login is refused.
- `otp` mode refuses the login.

**Errors.**
- `krb5glue_get_init_creds (Preauthentication failed ...)`: no usable TGT found. It is
  expired, belongs to another principal, is not the primary cache of the collection, or
  `KRB5CCNAME` points elsewhere. `klist -A` lists all caches.

## 3. Smartcard / PIV / YubiKey PIV (PKINIT)

```sh
xfreerdp3 /v:rdp1.lab.example.com /sec:nla /auth-pkg-list:'kerberos,!ntlm' \
    /smartcard-logon /kerberos:pkcs11-module:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    /kerberos:pkinit-anchors:FILE:/etc/ssl/certs/lab-ca.pem
```

[e2e: `run_smartcard.sh`, SoftHSM token, through p11-kit and directly]

**What FreeRDP does** (`smartcardlogon.c`, `nla.c:233-313`). [src]
1. **PKCS#11 module.**
   - `/kerberos:pkcs11-module:<path>` loads that module (`smartcardlogon.c:590-631`).
   - Without it, FreeRDP tries `p11-kit-proxy.so`, then `opensc-pkcs11.so`
     (`ncrypt_pkcs11.c:1543`).
   - YubiKey PIV works through OpenSC, or with Yubico's `libykcs11.so`; check the path
     with `dpkg -L ykcs11`.
   - FreeRDP 3.32.2 has no `/p11-module` switch, and no `pkcs11-module:` sub-option of
     `/smartcard-logon`. It is a `/kerberos:` sub-option.
2. **Certificate selection.**
   - Only certificates whose EKU extension contains the Microsoft *Smart Card Logon* EKU
     (1.3.6.1.4.1.311.20.2.2) count (`smartcardlogon.c:218`, `x509_utils.c:775-803`).
     That also holds against a FreeIPA/MIT KDC, which itself would accept the PKINIT
     client EKU (1.3.6.1.5.2.3.4) alone: issue user certificates with both.
   - The user comes from the UPN in the SAN, or else the e-mail address
     (`smartcardlogon.c:160-199`).
   - `/u` and `/d` act as **filters**, compared case-sensitively with the UPN's user and
     suffix (`smartcardlogon.c:231-247`). `/d:LAB.EXAMPLE.COM` therefore discards a
     certificate with the UPN `alice@lab.example.com`. **Leave out `/u` and `/d`**:
     FreeRDP fills them from the certificate (`smartcardlogon.c:978-990`).
   - With more than one matching certificate, `xfreerdp3` lists them and asks for a
     number; `sdl-freerdp3` shows a dialog.
   - `/list:smartcard` lists what FreeRDP sees, e.g.
     `xfreerdp3 /list:smartcard:pkcs11-module:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
     (`cmdline.c:1845-1880`).
3. **PIN.**
   - Asked as `Smartcard-Pin:` (`client.c:635-638`).
   - Or give it with `/smartcard-logon:pin:<pin>` or `/p:<pin>`. Both are visible in the
     process list.
   - A wrong PIN stops at PKINIT on the client. Nothing reaches fastrdp.
4. **PKINIT.**
   - FreeRDP passes `PKCS11:module_name=<module>:slotid=<n>[:certid=<id>]` to MIT
     PKINIT (`smartcardlogon.c:252-279`).
   - The KDC certificate must chain to an anchor: `pkinit_anchors` in `krb5.conf`
     (`[realms]` or `[libdefaults]`), or `/kerberos:pkinit-anchors:FILE:<ca.pem>` for
     this connection. MIT needs the `FILE:` / `DIR:` prefix.
5. `/smartcard-logon` sub-options (`cmdline.c:3783-3819`):
   - `cert:`, `key:` (a software certificate and key instead of a card);
   - `pin:`;
   - `csp:`, `reader:`, `card:`, `container:`.

**p11-kit vs. direct module, and the slot-id fix.**
- FreeRDP 3.32.2 truncated the PKCS#11 slot id to 16 bits. Modules with large slot ids,
  such as SoftHSM2 and some HSM or cloud modules, then fail with "PKCS#11 module has no
  matching tokens" in `KRB5_TRACE`.
- Not affected: OpenSC (PIV cards, YubiKey PIV), `libykcs11.so` and `p11-kit-proxy.so`.
  They number slots from 0.
- fastrdp's own client, `/opt/fastrdp/bin/xfreerdp`, carries the fix
  (`patches/freerdp/0001-...`, [patches/freerdp/README.md](../patches/freerdp/README.md)).
- With a distribution client and an affected module, use `p11-kit-proxy.so` as the
  module.
- The server side never runs this code.

**Smartcard *logon* vs. smartcard *redirection*.**
- `/smartcard-logon` uses the card on the client to get the Kerberos ticket (this
  section).
- `/smartcard[:<name>]` redirects the local PC/SC readers into the session
  (`cmdline.h:469-470`, the rdpdr channel), so that programs **inside** the session can
  use the card.
- fastrdp's proxy passes the device-redirection channel (`DeviceRedirection=true`).
  xrdp's chansrv implements PC/SC redirection. **Not validated in fastrdp** [lab]. The
  two switches are independent.

**Server.**
- Nothing to enable: the proxy sees ordinary Kerberos.
- AD PKI: KDC certificates, the CA in NTAuth, user certificates with the UPN SAN
  ([smartcard-nla.md](smartcard-nla.md)).

**Session TGT: no.** FreeRDP delegates `TSSmartCardCreds`: the PIN plus card details
(`nla.c:1925-1930`). fastrdp never uses the PIN as a password (`PasswordIsSmartcardPin`,
broker). The session has no TGT; `fastrdp_session_tgt: required` refuses the login.

**MFA.** Push. The usual alternative for accounts with "Smart card is required for
interactive logon" in AD: put them into a group in `fastrdp_mfa_exempt_groups`
([smartcard-nla.md](smartcard-nla.md)).

**Errors.**

| Message | Cause |
|---|---|
| `unable to open provider given by pkcs11 module` | wrong `pkcs11-module:` path, or the module cannot be loaded |
| `no suitable smartcard certificates were found` | no certificate with the Smart Card Logon EKU, no card inserted, or `/u`/`/d` filtered it out (see above). `/log-level:DEBUG` shows each discarded certificate |
| `unable to get smartcard certificate for logon` | follows one of the two above (`nla.c:248-251`) |
| `krb5glue_get_init_creds (...)` with `KRB5_TRACE` showing `PKINIT loading identity ...` and `no matching tokens` | slot id (see above), wrong PIN, or the KDC certificate does not chain to `pkinit-anchors` |

## 4. Passkey-derived TGT (FreeIPA)

FreeRDP cannot do passkey pre-authentication itself: its Kerberos prompter only fills
password and pre-authentication prompts with the password it has (`kerberos.c:239-258`),
and nothing drives a FIDO2 device [inferred from source]. So get the TGT with `kinit`
(or the desktop login), then use method 2. This is stage 2 of
[passkeys.md](passkeys.md). [lab]

```sh
kinit -n @IPA.TEST -c FILE:/tmp/armor.ccache        # anonymous PKINIT armor (FAST)
kinit -T FILE:/tmp/armor.ccache alice@IPA.TEST      # PIN + touch on the security key
xfreerdp3 /v:rdp1.ipa.test /u:alice /d:IPA.TEST /p /sec:nla /auth-pkg-list:'kerberos,!ntlm'
```

- The passkey TGT carries the authentication indicator `passkey`. With
  `ipa service-mod TERMSRV/rdp1.ipa.test --auth-ind=passkey --auth-ind=pkinit`, the KDC
  issues `TERMSRV` tickets only to such TGTs.
- **Session TGT:** no (as method 2). **MFA:** push, as method 2, unless the site sets
  `fastrdp_mfa_nla_kdc_enforced: true` (broker `[mfa] nla_kdc_enforced`): then Kerberos
  NLA logins skip the push because the KDC already required passkey/PKINIT for the
  `TERMSRV` ticket ([passkeys.md](passkeys.md), stage 2). Lab script:
  `tests/lab/freeipa-passkey-nla.sh`.
- `/kerberos:armor:FILE:/tmp/armor.ccache` exists too. It only applies when FreeRDP itself
  runs the AS exchange with a password (§7), not to passkeys.

## 5. TLS: password and OTP in one field

```sh
xfreerdp3 /v:rdp1.lab.example.com /u:alice /sec:tls /cert:fingerprint:sha256:<fingerprint>
# Password: Secret123456      (password "Secret" + TOTP "123456")
```

[e2e: `run.sh`, TLS logins and certificate pinning]

**Server.**
- Needs `fastrdp_allow_tls_logins: true` (the default).
- With `false` and the web path off, the proxy does not offer TLS. FreeRDP then fails
  with `HYBRID_REQUIRED_BY_SERVER` ("The server requires Network Level Authentication,
  but it is not enabled.", `nego.c:1565-1569`, `errconnect.c:99-100`).
- With `false` and the web path on, TLS is offered, but the broker refuses passwords
  (`password logins without NLA are disabled`).

**How it works.**
- FreeRDP sends user name and password in the Client Info PDU, inside TLS.
- The broker strips the realm/domain from the user name (`alice`, `LAB\alice` and
  `alice@lab.example.com` all mean `alice`).
- The broker splits a trailing OTP off the password:
  - a 44-character YubiKey OTP;
  - otherwise `fastrdp_otp_lengths` digits.
- It checks the password with PAM `fastrdp` (sssd, `pam_faillock`).
- No KDC is needed on the client.

**Session TGT: yes**, every RDP back-end (the password is known).

**MFA.**
- `otp`: the OTP must be appended.
- `otp_or_push`: an appended OTP, or a push without one.
- `push`: push.
- `web` / `push_or_web`: approve the waiting login on `https://<host>/web/approve`
  (with a push at the same time for `push_or_web`); an appended OTP is not split off
  ([auth-matrix.md](auth-matrix.md#web-approval)).

**Security caveats.**
- The server is authenticated **only by its certificate**. There is no Kerberos mutual
  authentication. Pin the certificate (`/cert:fingerprint:`, §9), or use a certificate
  from a CA the client trusts.
  - `/cert:ignore` here hands your password to any machine in the path.
- The password itself goes to the server: inside TLS, but in clear text to fastrdp.
- The login is exposed to password guessing like any password form. `pam_faillock` and
  the AD lockout policy apply.
- Prefer NLA (methods 1-3) wherever the client can reach a KDC.

## 6. Push MFA: what the client must allow

**Nothing has to be set on the client.** [src]
- fastrdp asks the broker, and so privacyIDEA, only when FreeRDP's connection sequence
  is already complete:
  - the proxy calls the broker from `ServerPostConnect`;
  - that runs after the client's Font List has been answered with the Font Map
    (`peer.c:740-760, 1133-1153`, `activation.c:787-803`);
  - FreeRDP counts the connection as active once it has sent Confirm Active
    (`connection.c:1990-2010`).
- During the push the client shows its (empty) window and waits. After approval the
  desktop appears; after a denial or a timeout the server closes the connection.

**FreeRDP's own timeouts do not cover that wait.**
- `/timeout:<ms>` (0-600000) sets `TcpAckTimeout` and `TcpConnectTimeout`
  (`cmdline.c:5249-5258`). Defaults: 9000 ms and 15000 ms (`settings.c:1268-1269`).
- They bound:
  - the TCP connect (`nego.c:416-453`);
  - the wait for activation (`connection.c:239-292`);
  - unacknowledged TCP data (`TCP_USER_TIMEOUT`, `tcp.c:1082-1090`).
- None of these runs while the broker waits. Raise `/timeout` only for slow links,
  e.g. `/timeout:60000` over a satellite connection.

**Server side.** `fastrdp_proxy_broker_timeout` (default 120 s) must be larger than
privacyIDEA's `push_timeout` (default 60 s) ([auth-matrix.md](auth-matrix.md)).

A real 60-second push wait with FreeRDP and Remmina is still to be confirmed [lab].

## 7. Reaching the KDC; all `/kerberos:` sub-options

`/kerberos:` takes a comma-separated list. FreeRDP 3.32.2 has exactly these sub-options
(`cmdline.h:313-316`, `cmdline.c:1074-1103`):

| Sub-option | Used for | Effect [src] |
|---|---|---|
| `kdc-url:<host>[:<port>]` | KDC proxy (MS-KKDCP) | FreeRDP writes `kdc = https://<value>/KdcProxy` for the principal's realm into a temporary krb5 profile (`krb5glue_mit.c:178-230`). **Give the host, not a URL**: `https://...` is added by FreeRDP |
| `lifetime:<time>` | TGT lifetime | `krb5_get_init_creds_opt_set_tkt_life` |
| `renewable-lifetime:<time>` | renewable lifetime | `..._set_renew_life` |
| `start-time:<time>` | postdated TGT | start time passed to `krb5_init_creds_init`, i.e. a TGT that only becomes valid later. No use for an interactive login [inferred]; leave it out |
| `cache:<ccache>` | credential cache | becomes the default cache for this connection (`kerberos.c:483-489`). A TGT that FreeRDP obtains is stored there, so later SSO logins (method 2) can use it. If that cache holds another principal, FreeRDP **re-initialises** it (`kerberos.c:492-509`) |
| `armor:<ccache>` | FAST armor | armor ccache for FreeRDP's AS exchange (`..._set_fast_ccache_name`), e.g. from `kinit -n` |
| `pkinit-anchors:<anchors>` | PKINIT trust | `X509_anchors`, e.g. `FILE:/etc/ssl/certs/lab-ca.pem` |
| `pkcs11-module:<module>` | smartcard | PKCS#11 module for `/smartcard-logon` (§3) |

- `<time>` is seconds (`36000`), `<n>d<n>h<n>m<n>s` (`10h`, `1d12h`) or `h:m[:s]`
  (`credssp_auth.c:1086-1190`). Invalid values are only logged.
- Everything except `cache:` and `pkcs11-module:` applies **only when FreeRDP runs the
  AS exchange itself**: typed password or smartcard, and no usable TGT in the cache.
  With SSO (methods 2 and 4) they do nothing.

Example (typed password, off-network, 10-hour TGT kept in a file cache):

```sh
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /auth-pkg-list:'kerberos,!ntlm' \
    /kerberos:kdc-url:kdcproxy.lab.example.com,lifetime:10h,cache:FILE:/tmp/alice.cc
```

**The KDC proxy option alone is not enough off-network.** [src]
- `kdc-url:` is used only for the **initial TGT** (AS exchange, temporary context in
  `krb5glue_mit.c`).
- The service ticket for `TERMSRV/<host>` is requested afterwards with the normal krb5
  context (`kerberos.c:1235-1251`), i.e. with the KDCs from `krb5.conf` or DNS.
- Without a reachable KDC, that request fails with `krb5_get_credentials (Cannot contact
  any KDC ...)`.
- Configure the KDC proxy in `krb5.conf`; MIT krb5 accepts MS-KKDCP URLs as KDC
  addresses:
  ```
  [realms]
      LAB.EXAMPLE.COM = {
          kdc = https://kdcproxy.lab.example.com/KdcProxy
      }
  ```
  Then `kinit` and FreeRDP both work off-network, with or without `/kerberos:kdc-url:`.
  Add `kpasswd_server = https://kdcproxy.lab.example.com/KdcProxy` for password changes.
- MIT needs its TLS plugin for `https://` KDCs: on Debian/Ubuntu the package
  `krb5-k5tls` (`krb5-user` only suggests it). Without it every request fails with
  `Cannot contact any KDC for realm ...`, and `KRB5_TRACE=/dev/stderr` shows `Could not
  find tls plugin module named 'k5tls'`. [lab: krb5 1.22.1]
- The proxy's TLS certificate must be trusted by the client's OpenSSL and match the
  host in the URL; for a private CA add `http_anchors = FILE:/path/ca.pem` to the realm.
- fastrdp's own KDC proxy: `fastrdp_web_kdcproxy: true` on the web gateway; the URL is
  `https://<rdp-fqdn>/KdcProxy`, so `/kerberos:kdc-url:<rdp-fqdn>`
  ([web-access.md](web-access.md#kdc-proxy)). It forwards only the site's realm. Tested
  with `kinit`/`kvno` against a scratch MIT KDC; FreeRDP itself through it is a lab item.

**Realm mapping.**
- FreeRDP builds the service name with `krb5_sname_to_principal(<host>, "TERMSRV",
  KRB5_NT_SRV_HST)`. Host-name canonicalisation (`dns_canonicalize_hostname`, `rdns`) and
  the realm (`[domain_realm]`, referrals) follow `krb5.conf`.
- `KRB5_TRACE=/dev/stderr` shows the principal requested and the KDCs contacted.
- `/spn-class:` would replace `TERMSRV`; fastrdp only has `TERMSRV` principals.

## 8. Kerberos U2U

- **What it is.** User-to-user Kerberos (RFC 4120 §2.9.2): the service ticket is
  encrypted with the session key of the server's TGT instead of its long-term key.
- **FreeRDP's default.**
  - FreeRDP's Negotiate offers it first, before plain Kerberos (`negotiate.c:109-113`).
  - It is on unless `/auth-pkg-list` says `!u2u` or starts with `none`
    (`negotiate.c:319-338`).
  - fastrdp's acceptor (freerdp-proxy, WinPR) handles this. The e2e suites run with
    `kerberos,!ntlm`, i.e. U2U offered.
- **When `!u2u` is needed: only against MIT-GSSAPI acceptors with the SPNEGO mechListMIC
  bug** (MIT krb5 1.21.0-1.22.1, fixed in 1.22.2).
  - Example: xrdp's own NLA (PR #3868) on Debian 13 / Ubuntu 26.04, where the default
    FreeRDP client fails with `Invalid token was supplied`
    ([smartcard-nla.md](smartcard-nla.md) §3, [upstream.md](upstream.md) §2).
  - There use `/auth-pkg-list:'kerberos,!u2u,!ntlm'`.
  - For fastrdp it is harmless, but not needed.
- The package name `u2u` exists since FreeRDP 3.17.0 ([windows-clients.md](windows-clients.md)
  §3.11). WinPR 3.15 (Debian 13) does not know it and still offers U2U
  ([upstream.md](upstream.md) §2); 3.32.2 logs unknown names as `Unknown authentication
  package name: <name>, ignoring` (`negotiate.c:307`).

## 9. Server certificate and trust

`/cert:` takes a comma-separated list (`cmdline.h:98-111`, `cmdline.c:3516-3567`):

| Option | Effect |
|---|---|
| (none) | verify against the system CAs and the client's certificate store; on a problem, ask (`Do you trust the above certificate? (Y/T/N)`) |
| `tofu` | accept and store an unknown certificate without asking (`tls.c:2008-2012`). A **changed** certificate is still shown and asked about; combine with `deny` (`/cert:tofu,deny`) to refuse it instead (`tls.c:2078-2082`) |
| `deny` | never ask; abort when the certificate cannot be verified (unknown or changed) |
| `ignore` | no check at all. FreeRDP logs `[DANGER] ...`. Never with TLS logins (§5) |
| `name:<name>` | check the certificate and the stored entry against `<name>` instead of the host name |
| `fingerprint:<hash>:<hex>` | accept exactly this certificate; can be repeated |

**Fingerprint pinning** (recommended for TLS logins, scripts and kiosks):
- The pin is checked before the CA and name checks (`tls.c:1847-1851`).
- `<hash>` is an OpenSSL digest name (`sha256`).
- `<hex>` is matched case-insensitively, with or without colons (`tls.c:1560-1620`).

```sh
# on the fastrdp host
openssl x509 -in /etc/fastrdp/front.crt -noout -fingerprint -sha256
# sha256 Fingerprint=AB:CD:...:EF
xfreerdp3 /v:rdp1.lab.example.com ... /cert:fingerprint:sha256:AB:CD:...:EF
```

- With the web gateway enabled, `/etc/fastrdp/front.fingerprint` already holds the
  `sha256:...` form ([backends/web.md](backends/web.md)).
- From a client: the first connection prints `Thumbprint: ...` (SHA-256). Compare it
  with the value from the host over a trusted channel before you accept it.
- Each run of the `base` role keeps an existing `front.crt`. A new certificate means a
  new pin.

**Aliases.**
- `/cert:name:<name>` only affects the TLS check.
- Kerberos still needs `TERMSRV/<the name you connect to>`.
- For an alias in `fastrdp_termsrv_aliases`, both exist: principal and certificate SAN.
- For anything else, use `/server-name:<fqdn>` (§0). It fixes the Kerberos name and the
  TLS name together.

**`.rdp` files:** `authentication level:i:0` switches certificate checks off
(`tls.c:1892`). Keep the default 2 (warn, `settings.c:1026`).

## 10. Choosing the desktop: `/shell:`

```sh
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /auth-pkg-list:'kerberos,!ntlm' /shell:fastrdp:gnome
```

- `/shell:` sets the alternate shell (`cmdline.c:5196-5200`); `.rdp`:
  `alternate shell:s:fastrdp:gnome`.
- The module sends it to the broker as a hint and never forwards it to the back-end
  (`fastrdp_fetch_target()`, `fastrdp_plugin.c:928`; `fastrdp_client_pre_connect()`, `fastrdp_plugin.c:1049-1050`).
- The `fastrdp:` prefix is optional (`identity.py` `hinted_desktop`).
- Order (`choose_desktop`):
  1. the hint, if that desktop exists and the user may use it (`fastrdp_desktop_groups`);
  2. the desktop chosen on the web gateway's chooser page
     ([web-access.md](web-access.md#rdp-apps));
  3. `~/.config/fastrdp/desktop`;
  4. the group default (`fastrdp_group_desktops`);
  5. `fastrdp_default_desktop`.
- An unknown or forbidden hint is ignored silently. You then get the next desktop in
  that order, not an error.
- Names: `fastrdp_desktops` in the inventory.

## 11. Restricted Admin, Remote Credential Guard, credential delegation

<!-- freerdp-doc-check: optional remoteGuard -->

| Switch | FreeRDP | fastrdp |
|---|---|---|
| `/restricted-admin` | sets `RESTRICTED_ADMIN_MODE_REQUIRED` in the negotiation and sends empty `TSPasswordCreds` (`cmdline.c:5034-5040`, `nego.c:1203-1204`, `nla.c:1836-1849`). Also sets the console-session flag. Kerberos credentials are still needed: typed password (only used locally) or `/p` + ticket | **accepted**: the proxy advertises Restricted Admin support ([windows-clients.md](windows-clients.md) §3.4). Kerberos login, **no TGT** in the session, push MFA. No "must be administrator" check |
| `/remoteGuard` | Remote Credential Guard: `REDIRECTED_AUTHENTICATION_MODE_REQUIRED`, then `TSRemoteGuardCreds` instead of a password. Unlike mstsc, FreeRDP sends a **complete TGT**: a `HOST/<target>` service ticket plus the TGT as KRB-CRED from `krb5_fwd_tgt_creds` (`kerberos.c:1989-2061`), which needs a **forwardable** TGT in the client's cache; the MS-RDPEAR channel is loaded too. **Only in builds with `CHANNEL_RDPEAR_CLIENT`** (`cmdline.h:426-429`; `-DCHANNEL_RDPEAR=ON`, default off: `channels/rdpear/ChannelOptions.cmake`). fastrdp's vendored build does not enable it | **Default: refused** with a negotiation response without RCG support (`patches/freerdp/0002`); the client stops with `remote credential guard requested but not supported, terminating`, proxy log `REDIRECTED_AUTHENTICATION_MODE_REQUIRED but disabled, answering without ...`. **`fastrdp_accept_remote_guard: true`**: Kerberos NLA login, identity only. The proxy module zeroes and discards the forwarded TGT, so the session has **no TGT**, and push MFA applies as for SSO. Using the forwarded credentials ("phase 1") is not implemented. Tested with the e2e client (`tests/proxy-e2e/run_nla.sh`) |
| `-credentials-delegation` | empty `TSPasswordCreds`, without the Restricted Admin flag | as Restricted Admin: login works, no TGT |

## 12. WebAuthn redirection (MS-RDPEWA)

FreeRDP 3.32.2 has a client-side WebAuthn channel, `rdpewa`:
- **Build.** It is built only with `-DCHANNEL_RDPEWA=ON` (default off,
  `channels/rdpewa/ChannelOptions.cmake`) and needs libfido2 ≥ 1.14 and libcbor ≥
  0.10.2 (`channels/rdpewa/CMakeLists.txt`). fastrdp's packaged build does not enable
  it; build it yourself with `FASTRDP_FREERDP_WEBAUTHN=1 third_party/build-freerdp.sh`
  (adds `-DCHANNEL_RDPEWA=ON`; `--deps` then also lists libfido2-dev and libcbor-dev).
- **No dedicated switch.** Enable it with `redirectwebauthn:i:1` in an `.rdp` file
  (`file.c:342, 2396-2400`; loaded by `cmdline.c:6234-6235`), or load the channel by
  name: `/dvc:rdpewa`.
- **The client side.** It talks to USB/NFC security keys through libfido2. `xfreerdp3`
  prints `Touch the security key` and asks for `FIDO2 PIN:` (`client.c:152-163,
  639-642`).
- **Against fastrdp it does nothing today.** No fastrdp back-end implements the server
  side of the channel ([passkeys.md](passkeys.md), WebAuthn redirection). It is only
  useful towards Windows hosts. Enable it only for hosts you trust: the host chooses
  the relying party the key signs for.

## 13. Remmina

Remmina (1.4.43, RDP plugin on FreeRDP 3) maps to the same FreeRDP settings.
Profiles are `~/.local/share/remmina/*.remmina`, group `[remmina]`; global preferences
are `~/.config/remmina/remmina.pref`, group `[remmina_pref]`. [src]

| Need | Remmina GUI | `.remmina` key | FreeRDP setting |
|---|---|---|---|
| NLA | Advanced → *Security protocol negotiation* → *NLA protocol security* | `security=nla` | NLA only (`rdp_plugin.c:2079-2104`) |
| TLS login (method 5) | same → *TLS protocol security* | `security=tls` | TLS only |
| user, domain | Basic → *Username*, *Domain* | `username=`, `domain=` | as `/u`, `/d` |
| SSO with a ticket (method 2) | Username + Domain, empty Password, Advanced → *Allow sending empty password* | `allow_empty_pass=1` | as `/p` without value (`rdp_plugin.c:1829-1843`) |
| `kerberos,!ntlm` | Preferences → RDP → *FreeRDP auth-pkg-list* (all RDP profiles) | `remmina.pref`: `rdp_auth_filter=kerberos,!ntlm` | `/auth-pkg-list` (`rdp_plugin.c:2807-2811`) |
| smartcard logon (method 3) | Basic → *Use a smartcard for logon*; *Smartcard PIN* (optional, else a dialog asks) | `smartcard-logon=1`, `smartcard_pin=` | `/smartcard-logon`, **plus smartcard redirection** (`rdp_plugin.c:2112-2116`) |
| smartcard redirection only | Advanced → *Share a smart card*, *Name of smart card* | `sharesmartcard=1`, `smartcardname=` | `/smartcard` |
| Restricted Admin | Basic → *Restricted admin mode* | `restricted-admin=1` | `/restricted-admin` |
| desktop | Advanced → *Start-up program*: `fastrdp:gnome` | `exec=fastrdp:gnome` | `/shell:` |
| timeout | Advanced → *Connection timeout in ms* | `timeout=` | `TcpAckTimeout` only (`rdp_plugin.c:2266-2273`); not needed for push (§6) |
| logs | Advanced → *FreeRDP log level*, *FreeRDP log filters* | `freerdp_log_level=`, `freerdp_log_filters=` | `/log-level`, `/log-filters` |
| certificate | Remmina asks on first use; Advanced → *Ignore certificate* (don't) | `cert_ignore=` | `/cert:ignore` |

**Not in Remmina** (1.4.43):
- `/kerberos:` options. Configure the KDC proxy and `pkinit_anchors` in `krb5.conf`
  (§7, §3).
- The PKCS#11 module choice. FreeRDP's default search applies: `p11-kit-proxy.so`, then
  `opensc-pkcs11.so`. p11-kit loads every module registered in `/usr/share/p11-kit/modules/`.
- Fingerprint pinning.
- `/server-name:`.

Remmina's RD Gateway fields do not apply; fastrdp has no gateway.

## 14. `.rdp` files with FreeRDP

`xfreerdp3 fastrdp.rdp [options]`:
- The file must be the **first** argument. Later options override it
  (`cmdline.c:5783-5797`).
- FreeRDP reads these keys relevant to fastrdp (`client/common/file.c`):

| Key | Effect |
|---|---|
| `full address:s:rdp1.lab.example.com` | `/v` |
| `username:s:alice@LAB.EXAMPLE.COM`, `domain:s:` | `/u`, `/d` |
| `enablecredsspsupport:i:1` | enables NLA, but does not disable TLS (`file.c:1986-1993`); add `/sec:nla` to force it |
| `authentication level:i:2` | warn on certificate problems; `0` switches checks off |
| `alternate shell:s:fastrdp:plasma` | `/shell:` |
| `kdcproxyname:s:kdcproxy.lab.example.com` | `/kerberos:kdc-url:` (host form, as mstsc) |
| `redirectsmartcards:i:1` | `/smartcard` (redirection, not logon) |
| `redirectwebauthn:i:1` | §12 |

There are no `.rdp` keys for `/auth-pkg-list`, `/smartcard-logon`, the PKCS#11 module or
certificate pins; add them on the command line:

```sh
xfreerdp3 fastrdp.rdp /sec:nla /auth-pkg-list:'kerberos,!ntlm' /cert:fingerprint:sha256:<fingerprint>
```

## 15. Logs and troubleshooting

| What | How |
|---|---|
| FreeRDP log level | `/log-level:DEBUG` (or `TRACE`); same as `WLOG_LEVEL=DEBUG` in the environment |
| only some modules | `/log-filters:com.freerdp.core.nla:DEBUG,com.winpr.sspi.Kerberos:DEBUG` or `WLOG_FILTER=...` |
| Kerberos library | `KRB5_TRACE=/dev/stderr xfreerdp3 ...`: KDCs, principals, PKINIT, ccache |
| server side | `journalctl -u fastrdp-proxy -u fastrdp-brokerd` (refusals, MFA), `sudo fastrdpctl status` |

Useful log tags:
- `com.freerdp.core.nego`: security negotiation;
- `com.freerdp.core.nla` and `com.freerdp.core.auth`: CredSSP;
- `com.winpr.negotiate` and `com.winpr.sspi.Kerberos`: SPNEGO and Kerberos;
- `com.freerdp.smartcardlogon` and `com.winpr.ncryptp11`: smartcard;
- `com.freerdp.crypto`: TLS and certificates.

The tag names come from the `TAG` definitions of the files cited above.

| Client message | Meaning |
|---|---|
| `Error: HYBRID_REQUIRED_BY_SERVER` | you asked for TLS, the server only offers NLA (§5) |
| `Kerberos` errors `(... [code])` | see §1-§3 |
| `[DANGER] Certificate not checked, /cert:ignore in use.` | remove `/cert:ignore` |
| `restricted-admin mode requested but not supported, terminating` | not expected against fastrdp; the server did not advertise Restricted Admin |
| `Timeout waiting for activation` | network too slow for the 9-second default; raise `/timeout:` (§6) |
| window opens, then closes after a while | refused after authentication: MFA denied or timed out, account/GPO policy, `session_tgt = required`; see the broker log |

## 16. Sound and microphone

The server offers audio out on X11/wlroots (xrdp) and GNOME desktops and the client's
microphone to applications there, unless the administrator switched them off
([audio.md](audio.md)). Plasma (KRdp) has no audio. FreeRDP sends neither unless asked:

```sh
# sound and microphone through PipeWire's (or PulseAudio's) server
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /auth-pkg-list:'kerberos,!ntlm' \
    /sound:sys:pulse /microphone:sys:pulse
```

| Switch | Effect |
|---|---|
| `/sound[:sys:pulse\|alsa\|oss\|fake,dev:<dev>,...]` | audio out on the client: static `rdpsnd` (xrdp) and the dynamic playback channel (GNOME); without `sys:` the first back-end the build has |
| `/audio-mode:redirect` (`0`, the default with `/sound`), `server` (`1`), `none` (`2`) | play on the client, on the server (fastrdp hosts usually have no sound card), or not at all |
| `/microphone[:sys:pulse,dev:<source>]` | offers the client's microphone (`AUDIO_INPUT`); applications record from `xrdp-source` (xrdp) or `grd_remote_audio_source` (GNOME) |

- Remmina: Advanced → *Audio output mode* → *Local*, and *Redirect local microphone*.
- `/drive` and `/smartcard` load the `rdpsnd` channel with the `fake` back-end on their
  own (no sound, but the channel exists).
- The X11 desktops' microphone is uncompressed PCM, 44.1 kHz stereo (about 1.4 Mbit/s).
- fastrdp's own build (`/opt/fastrdp/bin/xfreerdp`) has no PulseAudio/ALSA back-end:
  use the distribution's client for sound. [src: `third_party/build-freerdp.sh`]
- Not yet tested through fastrdp with a real session ([audio.md](audio.md#open-questions-lab)).

## Open points (need a lab)

1. Smartcard logon with real PIV cards and YubiKey PIV (OpenSC and `libykcs11`) against
   AD PKI. Also the `/u`/`/d` filter behaviour with real UPNs.
2. FreeIPA passkey → TGT → SSO (method 4), and `--auth-ind` on `TERMSRV`.
3. A KDC proxy (`fastrdp_web_kdcproxy`, or Windows KPS): xfreerdp3 with
   `/kerberos:kdc-url:` alone vs. the `krb5.conf` entry (§7). `kinit`/`kvno` through
   fastrdp's proxy work (scratch MIT KDC).
4. A real push with a 60-second approval delay through xfreerdp3, sdl-freerdp3 and
   Remmina (§6).
5. The enterprise-principal form `/u:<upn-prefix> /d:<upn-suffix>` against AD with a UPN
   suffix that differs from the realm (§0).
6. SSO from a KCM collection with several principals (§2).
7. Smartcard redirection (`/smartcard`) into xrdp sessions through the proxy (§3).

## Appendix A: verification (FreeRDP 3.32.2, file:line)

All paths are relative to the FreeRDP 3.32.2 tree from `third_party/fetch.sh freerdp
<dir>` (with `patches/freerdp/` applied).

| Item | Where |
|---|---|
| `/auth-pkg-list`, `/cert`, `/credentials-delegation`, `/d`, `/dvc`, `/kerberos`, `/list`, `/log-filters`, `/log-level`, `/p`, `/restricted-admin`, `/remoteGuard` (`#ifdef CHANNEL_RDPEAR_CLIENT`), `/sec`, `/server-name`, `/shell`, `/smartcard`, `/smartcard-logon`, `/spn-class`, `/timeout`, `/u`, `/v`, `/from-stdin`, `/args-from` | `client/common/cmdline.h:71, 98, 148, 150, 162, 313, 319, 325, 327, 379, 424, 426-429, 439, 458, 460, 469, 471, 482, 495, 534, 543, 191, 186` |
| `/cert-ignore`, `/cert-name`, `/cert-tofu`, `/cert-deny`, `/sec-nla` etc. are deprecated aliases (only with `WITH_FREERDP_DEPRECATED_COMMANDLINE`) | `cmdline.h:112-122, 444-453` |
| `/kerberos:` sub-options and their settings | `cmdline.c:1074-1103` |
| `/smartcard-logon:` sub-options (`cert key pin csp reader card container`) | `cmdline.c:3783-3819` |
| `/list:smartcard:` sub-options | `cmdline.c:1845-1880` |
| `/cert:` options | `cmdline.c:3516-3567`; checks `crypto/tls.c:1560-1620, 1840-2100` |
| `/sec:` parsing | `cmdline.c:3408-3481` |
| `/timeout` → `TcpAckTimeout`, `TcpConnectTimeout` | `cmdline.c:5249-5258`; defaults `core/settings.c:1268-1269` |
| `/restricted-admin`, `/remoteGuard` | `cmdline.c:5034-5049`; `core/nego.c:1203-1207, 1335-1360` |
| `/p` without value = empty password | `cmdline.c:5082-5092`; prompt logic `core/nla.c:317-447`, `core/utils.c:191-220` |
| user name parsing (`DOMAIN\user`, `user@domain`) | `cmdline.c:1294-1333` |
| Kerberos principal, enterprise names, ccache selection, AS exchange | `winpr/libwinpr/sspi/Kerberos/kerberos.c:343-600` |
| `kdc-url` → `https://<value>/KdcProxy`, lifetime, renew, start time, armor, anchors | `winpr/libwinpr/sspi/Kerberos/krb5glue_mit.c:122-250` |
| TGS request for `TERMSRV/<host>` with the normal context | `kerberos.c:1225-1251` |
| time format of `lifetime`/`start-time`/`renewable-lifetime` | `core/credssp_auth.c:954-960, 1086-1190` |
| Negotiate: package names, defaults, U2U first | `winpr/libwinpr/sspi/Negotiate/negotiate.c:44-47, 109-113, 259-338` |
| smartcard: EKU filter, UPN, user/domain filter, PKINIT args, default modules, chooser | `core/smartcardlogon.c:160-279, 579-631, 876-990`; `winpr/libwinpr/ncrypt/ncrypt_pkcs11.c:1543` |
| delegated credentials (password, smartcard, Remote Guard) | `core/nla.c:1825-1990` |
| server: when PostConnect (fastrdp's broker call) runs | `core/peer.c:740-760, 1133-1153`; `core/activation.c:787-803`; client active state `core/connection.c:1990-2010` |
| `.rdp` keys | `client/common/file.c` (key names 232-342, `kdcproxyname` 1381/2646-2648, `enablecredsspsupport` 1986-1993, `redirectwebauthn` 2396-2400) |
| RDPEWA channel option, dependencies, loading | `channels/rdpewa/ChannelOptions.cmake`, `channels/rdpewa/CMakeLists.txt`, `cmdline.c:6234-6235` |
| HYBRID_REQUIRED_BY_SERVER | server `core/connection.c:1530-1550`, client `core/nego.c:1537-1575`, text `core/errconnect.c:99-100` |

Remmina 1.4.43 (`plugins/rdp/`): settings arrays `rdp_plugin.c:3234-3336`; security
`2079-2104`; empty password `1829-1843`; smartcard logon `2112-2116`; timeout
`2266-2273`; auth filter `2807-2811` and `rdp_settings.c:730-748`; preference file
`src/remmina_pref.c:288-291, 1285-1297`.

fastrdp: `broker/proxy-module/fastrdp_plugin.c` (NTLM refusal 284-287, desktop hint 405,
shell not forwarded 509-510, broker refusal 431); `broker/brokerd/fastrdp_broker/server.py`
(`first_factor`, `require_credential`); `identity.py` (`normalize_rdp_user`,
`hinted_desktop`, `choose_desktop`).

### Corrections to earlier guidance

<!-- freerdp-doc-check: invalid p11-module cert-ignore cert-name cert-tofu cert-deny sec-nla -->

- `docs/client-guide.md` gave `kdc-url:` a full URL
  (`https://kdcproxy.lab.example.com/KdcProxy`). FreeRDP 3.32.2 adds the scheme and the
  path itself (`krb5glue_mit.c:189`), so the URL form produced
  `https://https://.../KdcProxy/KdcProxy`. Fixed to the host form; §7 also explains why
  the TGS request needs the KDC proxy in `krb5.conf`.
- There is no `/p11-module` switch in FreeRDP 3.32.2: the PKCS#11 module is
  `/kerberos:pkcs11-module:`.

## Appendix B: regression test

`tests/docs/test_freerdp_switches.sh` (`make test-docs`) extracts every switch from the
command lines (`xfreerdp3`, `xfreerdp`, `sdl-freerdp3`, `wlfreerdp3`) in this file's code
blocks, and every inline switch such as `/sec:nla`. It checks each one against FreeRDP:
- the switch exists and is not a deprecated alias;
- flag vs. value;
- the sub-options of `/kerberos:`, `/smartcard-logon:`, `/cert:`, `/sec:`,
  `/auth-pkg-list:` and `/list:smartcard:`;
- `kdc-url:` is a host, not a URL;
- build-dependent switches are declared, e.g. `/remoteGuard` with
  `<!-- freerdp-doc-check: optional remoteGuard -->`.

Sources it checks against:
- the FreeRDP source from `third_party/fetch.sh` (network, or `FASTRDP_SOURCES_CACHE`);
- or `FREERDP_SRC=<tree>`;
- or the `/help` output of an installed client (`FREERDP_HELP_CMD=xfreerdp3`).

[client-guide.md](client-guide.md) is checked too.
