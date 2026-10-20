# Tests

Every automated test in the repository: what regression it catches, how to run it,
what it needs, and where CI runs it. CI is one workflow,
[`.github/workflows/packages.yml`](../.github/workflows/packages.yml). Every job runs in
`ubuntu:26.04` (resolute) and `debian:trixie` containers.

| CI job | Runs |
|---|---|
| `tests` | `make test-all` with `FASTRDP_TESTS_STRICT=1`; `make test-docs`; actionlint (resolute only) |
| `vendored` | builds `fastrdp-freerdp3` / `fastrdp-xrdp` + lintian. The xrdp row also runs `make test-xrdp-encoder` against the build tree |
| `build` | builds `fast-rdp-server` (its `dh_auto_test` runs the broker, webgate and PAM tests again) + lintian, installs every package, runs `tests/packaging/check-installed.sh` |
| `e2e` | installs the `fastrdp-freerdp3` artifact and runs the four proxy e2e suites with `FREERDP_PREFIX=/opt/fastrdp` |
| `krb5-spnego` | `tests/krb5-spnego/run.sh`, informational |
| `publish` | needs `tests`, `build` and `e2e` |

```sh
make test       # unit tests, PAM, lint (the old default)
make test-all   # everything that runs locally without root (see the table)
```

A shell test whose tools are missing prints `SKIP <file>: missing ...` and exits 0.
With `FASTRDP_TESTS_STRICT=1`, as in CI, it fails instead. The Python template test
does the same with `ansible-playbook`.

## Inventory

### Unit and functional tests (no root, no network)

| Test | Regression it catches | Run locally | Dependencies | CI |
|---|---|---|---|---|
| `broker/brokerd/tests/test_units.py` | **Config:** example parses; unknown keys, xrdp desktop without xsession, MFA without URL and unknown default desktop are rejected. **Also:** OTP split (TOTP/YubiKey), one-time tokens and expiry, `/proc/net` parsing, principal/username normalisation, desktop choice and restrictions, back-end port reservation | `make test-broker` | python3 ≥ 3.11 | `tests`, `build` (dh_auto_test) |
| `broker/brokerd/tests/test_server.py` | Broker protocol over real sockets. **Logins:** NLA login; smartcard PIN never used as a password; the principal, not the typed user, is logged in; foreign realm denied; TLS password check; OTP split and verify; NLA in OTP mode; push. **Sockets:** token socket and `status` are root-only; garbage is dropped. **Web tokens:** single use, client-address and user binding, not valid for xrdp PAM, refused when web is disabled | `make test-broker` | python3 | `tests`, `build` |
| `broker/brokerd/tests/test_conntype.py` | Connection type for the xrdp hop (`[network]`, R6). **Matching:** IPv4, IPv6 (with scope id), IPv4-mapped IPv6 (`::ffff:10.1.2.3`) against `lan_networks`; unparsable addresses. **Policy:** client types 1–6 never overridden; 0, 7 and invalid values get `lan` or `xrdp_autodetect_profile`; empty list = profile only; `default` = no change. **Config:** invalid CIDRs (host bits, prefix length, non-strings, a string instead of a list) and unknown profiles refused. **Login reply:** `target.connection_type` for xrdp desktops only, not GNOME | `make test-broker` | python3 ≥ 3.11 | `tests`, `build` |
| `broker/brokerd/tests/test_gaps.py` | Branches the two files above miss. **Config and protocol:** every config validation error; `fastrdp-brokerd --check` exit codes; protocol framing and field limits; OTP length order and YubiKey switch. **MFA:** exempt groups, each MFA mode, privacyIDEA outage, push timeout; privacyIDEA client (realm, errors, service-user token cache, polling). **Accounts and state:** user resolution and `allow_groups`; preference-file safety; `sessions.json` mode and corruption. **System and back-ends:** sysutil `run`/listener/cert checks; xrdp/GNOME/Plasma start and stop error paths and port release; secret only on stdin. **Server policy:** server policy matrix (TLS/NLA/web, root, restricted desktops). **Refusal reasons:** each refusal path gives its `reason` (`denied`, `not_allowed`, `mfa_failed`, `mfa_timeout`, `backend`) with a generic `error`; unknown user and wrong password give the same reply; `not_allowed` withheld from a TLS login that still owes MFA | `make test-broker` | python3 | `tests`, `build` |
| `broker/brokerd/tests/test_session_tgt.py` | **Session TGT** (`[broker] session_tgt`): GNOME/Plasma logins with a password get a TGT through PAM `fastrdp-tgt` before the back-end starts, also on a reconnect to the running session; none without a password (SSO, smartcard) or for xrdp; password only in the PAM conversation (fake libpam), never in `klist`'s argv or environment; `klist` runs with the user's uid/gid, no supplementary groups, `HOME=/`; `auto` only warns, `required` refuses failures and password-less logins (also web) before MFA; `off`; config validation; `fastrdp-tgt` stack has no `pam_faillock` | `make test-broker` | python3 | `tests`, `build` |
| `broker/brokerd/tests/test_principal.py` | **NLA identity = Kerberos principal** (Windows UPN ≠ sAMAccountName, docs/windows-clients.md §3.6), with NSS faked like SSSD (name, name@domain, UPN). **Accepted:** UPN with another local part, `DOMAIN\user`, enterprise principals (by UPN, never by the UPN's local part), `krb5_aname_to_localname()` fallback (also through the real libkrb5 with a throwaway `krb5.conf`), unknown typed names. **Refused:** foreign realm, principal without account, root, multi-component principals. **Password:** dropped when the typed name is another account. **TLS path unchanged** | `make test-broker` | python3 (libkrb5 optional) | `tests`, `build` |
| `broker/brokerd/tests/test_kdc_enforced.py` | **`[mfa] nla_kdc_enforced`** (passkey/PKINIT enforced by the KDC, docs/passkeys.md stage 2). **Skips the push:** Kerberos NLA logins of `[auth] realms`, also smartcard (PIN still dropped); logged with the principal. **Keeps MFA:** option off; TLS logins, also with a forged `principal`/`smartcard` field; principals of unlisted realms; web tokens unchanged; `mode = none` unaffected; `session_tgt = required` still refuses. **Config:** default off, must be bool, needs `[auth] realms`; start-up warning | `make test-broker` | python3 | `tests`, `build` |
| `broker/webgate/tests/test_webgate.py` | Guacamole JSON crypto (round trip, tamper, byte-identical to Guacamole's reference via `openssl`); ID token checks (aud/azp, acr/amr MFA proof); config MFA requirement; username domain rules; certificate pin; full OIDC → Guacamole flow; CSRF; unknown desktop; no MFA, no session; bad Content-Length; logout; forged cookie | `make test-webgate` | python3, python3-cryptography, openssl | `tests`, `build` |
| `broker/webgate/tests/test_gaps.py` | **Cookies:** purpose binding, expiry, wrong key, CSRF binding. **Config:** https rule, unknown or missing fields, normalisation, empty secrets. **OIDC:** PKCE; discovery (issuer mismatch, plain-http endpoints); HTTP/timeout errors; `acr_values`; logout URL. **HTTP flow:** IdP error, state mismatch, replayed code, expired session, broker refusal/garbage/missing socket (403 "not allowed" only for `not_allowed`, 503 when the broker is unreachable), oversize body. **Broker client:** replies and refusal reasons | `make test-webgate` | as above | `tests`, `build` |
| `tests/gpu/test_session_report.py` | `session_report.py` verdicts (renderer, H.264 encoder) on fake `/proc` trees | `make test-gpu` | python3 | `tests` |
| `broker/pam_fastrdp_token/test/run_test.sh` | PAM module through real libpam with a fake broker. **Accepted:** a valid token passes, the real password goes to the next module. **Refused:** bad token, token for another user, plain password | `make test-pam` | gcc, libpam0g-dev, libcjson-dev, libpam-modules (pam_exec, pam_permit), python3 | `tests`, `build` |
| `tests/packaging/test_fetch.sh` | `third_party/fetch.sh` against a throwaway `sources.yml` with file:// URLs. **Exit codes:** unknown name 2; sha256 mismatch 3; non-applying patch 4. **Parsing:** `--print` fields, quotes stripped, no key leaks between entries, prefix names. **Fetch:** patch applied exactly once on re-fetch; cache used when verified, re-downloaded when corrupt. **Real tree:** `sources.yml` fields (https, 64-hex sha256, series files exist); every `*.patch` is listed in its series | `make test-scripts` | bash, curl, patch, tar | `tests` |
| `tests/packaging/test_build_key.sh` | `third_party/build-key.sh`. **Shape:** 16 hex digits; deterministic; same key from another directory. **Changes when:** a patch, the series, `sources.yml`, `fetch.sh` or the build script changes. **Unaffected:** the other build's inputs (FreeRDP vs xrdp). **Errors:** unknown build exits 2; missing patch file fails | `make test-scripts` | bash | `tests` |
| `tests/packaging/test_ci_scripts.sh` | **check-build-deps.sh:** missing Build-Depends fails and is named; version constraints ignored; a new `--deps` entry must reach `debian/control`. **prepare-vendored.sh:** tree layout and `vendored.mk`; changelog behind `sources.yml` refused; usage and unknown package exit 2. **set-version.sh:** suffix, distribution, previous entries kept; invalid version exits 2; version order `stable < testing < next`. **upstream-version.sh:** tag and main versions, UTC commit time; pre-release tags refused. **make-source-archive.sh:** contents, SHA256SUMS verifies and is complete, reproducible and sorted, root-owned; wrong upstream sha256 fails; refuses trees with `debian/tmp`, `obj-*` or `*.o` at any depth | `make test-scripts` | dpkg-dev, curl, patch, xz-utils, python3 (git optional) | `tests` |
| `tests/packaging/test_publish.sh` | `packaging/apt/publish.sh` with a throwaway passphrase-protected GPG key and dummy packages. **1. Stable:** suites, no dbgsym, pool matches `Packages`, InRelease/Release.gpg verify with SHA512, public key only, sources per vendored package, index.html. **2. Testing:** stable carried over unchanged; an unchanged vendored `.deb` is one pool file. **3. Next stable:** old FreeRDP leaves the pool and its `sources/` are pruned, stale sources too. **4. Refusals:** vendored package without source, distro without packages, unknown channel, no key id, wrong passphrase. **5. apt:** `apt-get update` through a `file:` source with `Signed-By`, versions visible, `apt-get download` verifies hashes; another key in Signed-By fails | `make test-publish` | reprepro, gnupg, gpgv, dpkg-dev, apt | `tests` |
| `tests/ansible/test_templates.py` (+ `render.yml`) | Renders the role templates with the lab inventory, role defaults and overrides through `ansible-playbook`, then parses them. **gfx.toml (TOML):** vaapi/nvenc/qsv/x264 and auto on mesa, nvidia and none; FFmpeg section, fallback libx264, rate control; x264 always present; `[ffmpeg.autodetect]` / `[x264.autodetect]` equal to `fastrdp_xrdp_autodetect_profile` (default `wan`; also satellite, modem, default, lan), the other profiles unchanged by that choice. **proxy.ini (INI):** TLS logins/web/NLA-only → `ServerTlsSecurity`/`AllowTls`, module required. **broker.toml:** lab and MFA/wlroots/group-default variants, through the broker's own `config.parse`; `[network]` defaults and a `lan_networks` / `xrdp_autodetect_profile` variant; roles/common refuses an unknown profile and non-CIDR `fastrdp_lan_networks`. **webgate.toml:** through the webgate's `config.parse`, rdp_parameters as strings. **Identity/base roles:** TERMSRV principals per provider and aliases, self-signed certificate SAN (FQDN, short name, aliases; accepted by `openssl req`); broker.toml `nla_kdc_enforced` variant and its roles/common refusals (`hardened`, empty list, AD without `fastrdp_mfa_nla_kdc_enforced_by_ad_policy`); `fastrdp-termsrv-check` against fake `klist -ke` output (AES at the newest kvno, RC4-only, missing principal, realm/case matching); alias names checked by roles/common. **Others:** xrdp.ini, sesman.ini, xorg.conf (glamor) **Ticket renewal:** `[kcm] tgt_renewal` for ad/ipa/none, FreeIPA domain renewal options, `krb5.conf` `renew_lifetime`; broker.toml `session_tgt` | `make test-ansible` | ansible-core, python3 ≥ 3.11 | `tests` |
| `tests/keycloak/test_keycloak_passkeys.py` | Keycloak automation (`roles/web_gateway/files/fastrdp_keycloak_passkeys.py`) against an in-memory fake of the admin API. **Settings refused:** no credentials, plain http, hardware-only without AAGUIDs, Cookie/password/user-configured as second factor, acr 1. **Merge:** other client profiles/policies and ACR map entries kept; realm PUT carries all passwordless fields and nothing else; second run writes nothing; check mode writes nothing; changed profile replaced in place; hardware-only on and off. **Flow:** built-in alias refused, matching flow untouched, Cookie step detected | `make test-ansible` | python3 ≥ 3.11 | `tests` |
| `prototypes/webauthn-redirection/tests/` | Prototype only (docs/webauthn-redirection.md). **CBOR:** RFC 8949 Appendix A, CTAP2 canonical order, hostile input. **[MS-RDPEWA]:** every request example of §4 re-encodes byte for byte; response examples decode. **CTAPHID:** framing, reassembly errors. **Bridge:** RP ID allow-list, rate limit, consent, cancel, timeouts, session separation | `make test-prototypes` (part of `make test`) | python3 ≥ 3.11 | `tests` |
| `ansible-playbook --syntax-check site.yml` | broken playbook/role syntax, missing roles | `make test-ansible` | ansible-core | `tests` |

### Lint

| Test | Regression it catches | Run locally | Dependencies | CI |
|---|---|---|---|---|
| `ansible-lint site.yml` (production profile) | Ansible style and safety rules | `make lint` | ansible-lint 26.10.1 | `tests` |
| shellcheck (session launchers, all test scripts, `third_party/`, `packaging/`, `debian/bin`) | shell bugs (quoting, unset variables, ...) | `make lint` | shellcheck 0.11 | `tests` |
| `packaging/ci/check-build-deps.sh` | vendored Build-Depends lag behind `build-*.sh --deps` | `make lint` | bash | `tests` |
| actionlint | workflow syntax, expressions, shellcheck of `run:` blocks | `make lint-ci` | actionlint 1.7.7 | `tests` (resolute) |
| `tests/docs/test_freerdp_switches.sh` (+ `check_freerdp_switches.py`) | FreeRDP switches in `docs/freerdp-client.md` and `docs/client-guide.md` that FreeRDP does not have: unknown or deprecated switches, flag/value misuse, unknown `/kerberos:`, `/smartcard-logon:`, `/cert:`, `/sec:`, `/auth-pkg-list:` sub-options, `kdc-url:` given as a URL, undeclared build-dependent switches (`/remoteGuard`); a self-test feeds it known-bad lines first | `make test-docs` (not in `test-all`: downloads the vendored FreeRDP source via `third_party/fetch.sh`; offline with `FASTRDP_SOURCES_CACHE`, `FREERDP_SRC=<tree>` or `FREERDP_HELP_CMD=xfreerdp3`) | python3, curl, patch | `tests` |
| lintian `--fail-on error` | policy errors in the 3 source packages | see docs/packaging.md | lintian | `vendored`, `build` |

### Integration tests (real FreeRDP/xrdp, no root)

| Test | Regression it catches | Run locally | Dependencies | CI |
|---|---|---|---|---|
| `tests/proxy-e2e/run.sh` (TLS, 23 checks) | Module inside the real `freerdp-proxy`, two chained proxies. **Connection type:** the front login reports the client's type (7, or 2 with `E2E_CONNECTION_TYPE`); a broker `connection_type: "lan"` reaches the back-end as 6; none or an unknown name keeps the client's. **Credentials:** TLS credentials and hints reach the broker; the back-end receives the broker token, never the password. **Addresses and pinning:** client address is the socket peer; certificate pin in webgate format accepted, wrong pin refused. **Refusals and end:** refused login never reaches the back-end; session end reported; RemoteApp and TLS smartcard PIN refused before the broker. **Error info:** the Set Error Info code the client receives per broker `reason` (`denied`/`mfa_failed`/unknown 0x7, `not_allowed` 0x9, `mfa_timeout` 0x409, `backend` 0x400, also without `reason`) and for an unreachable back-end; no multitransport offered | `FREERDP_PREFIX=/opt/fastrdp make test-e2e` | gcc, libcjson-dev, openssl, python3, FreeRDP 3.32+ with headers (`fastrdp-freerdp3`, or freerdp3-dev + freerdp-proxy) | `e2e` |
| `tests/proxy-e2e/run_nla.sh` (3) | Kerberos NLA with a throwaway MIT KDC: principal reported, delegated password passed, wrong password stops at NLA | `FREERDP_PREFIX=/opt/fastrdp make test-e2e-nla` | + krb5-kdc, krb5-admin-server, krb5-user | `e2e` |
| `tests/proxy-e2e/run_smartcard.sh` (4) | Smartcard PKINIT (SoftHSM via p11-kit): principal from the certificate, smartcard flag, PIN never forwarded, wrong PIN stops at PKINIT | `FREERDP_PREFIX=/opt/fastrdp make test-e2e-smartcard` | + krb5-pkinit, softhsm2, opensc, p11-kit-modules | `e2e` |
| `SC_MODULE=softhsm run_smartcard.sh` (4) | **`patches/freerdp` slot id fix**: libsofthsm2 directly has 32-bit slot ids, which unpatched FreeRDP truncates (logon fails) | `FREERDP_PREFIX=/opt/fastrdp make test-e2e-smartcard-softhsm` | as above | `e2e` |
| `patches/xrdp/test/run_test.sh` | **`patches/xrdp` FFmpeg encoder:** libx264 through the same code path (decodable pictures, SPS/IDR, PSNR, resize, partial updates, overflow); h264_vaapi/h264_nvenc without GPU fall back to libx264; with `fallback = ""` create() refuses | `make test-xrdp-encoder XRDP_SRC=<patched, built xrdp>` | cc, pkg-config, libavcodec-dev, libavutil-dev (libx264 in libavcodec); built xrdp tree | `vendored` (xrdp, when rebuilt) |
| `tests/packaging/check-installed.sh` | **Installed packages.** **Users and paths:** users/groups; module in fastrdp-freerdp3's plugin directory. **Libraries:** all resolve, FreeRDP from `/opt/fastrdp/lib`; DT_RPATH `$ORIGIN/../lib` on the vendored binaries; module RUNPATH `$ORIGIN/../..` and its exported entry point. **Software:** PAM module; Python imports; `fastrdp-brokerd --check` on the example; xrdp `--enable-ffmpeg`; units shipped | `tests/packaging/check-installed.sh` (after installing all packages) | binutils, python3 | `build` |
| `tests/krb5-spnego/run.sh` | Whether the distribution's MIT krb5 has the SPNEGO mechListMIC bug (krb5 #9183). Exit 1 = affected (CI: warning), ≥ 2 = setup failure (CI: fails) | `make check-krb5-spnego` | gcc, libwinpr3-dev, libkrb5-dev, krb5-kdc, krb5-admin-server | `krb5-spnego` (informational) |
| `tests/wlroots/run.sh` (15) | `wlroots-in-x` with Sway/labwc/Wayfire on Xvfb: X11 backend start, output follows root size, clipboard both ways, stale socket | `make test-wlroots` | xvfb, xwayland, wlr-randr, wl-clipboard, xclip, x11-utils + compositors | no (heavy desktop dependencies) |

### Host, hardware and performance checks (manual)

| Test | Purpose | Run | CI |
|---|---|---|---|
| `tests/smoke/check-host.sh [user]` | Deployed host: services, listeners (xrdp loopback only), sockets and modes, nftables, keytab (AES keys for TERMSRV/<fqdn> and TERMSRV/<SHORT>), FreeRDP/module/PAM install, config, time sync, back-end port isolation, NSS/PAM for a user | `sudo tests/smoke/check-host.sh alice` | no (needs a deployed host) |
| `tests/keycloak/run.sh` (24 checks) | **Passkeys on the web path, end to end** (docs/passkeys.md stage 1): Keycloak 26.8.1 in dev mode, the web_gateway role's Keycloak tasks through `ansible-playbook` (check mode, apply, idempotence, merge, Cookie step removed), then headless Chromium with a CDP virtual authenticator against the real webgate code: passkey and password+TOTP give `acr=mfa`; password only gives no token; a password-only token is refused; password-only SSO sessions are not upgraded (also with a Cookie step, as a control); hardware-only refuses the virtual authenticator | `make test-keycloak` (`CHROME=…`, optional `KEYCLOAK_HOME`, `JAVA_HOME`, `CHROME_LIBS`, `FONTCONFIG_FILE`; downloads Keycloak + Temurin 21 with sha256 checks otherwise) | JDK 21, Keycloak 26.x, Chromium, ansible-core, python3-cryptography, curl | no (manual: ~1 GB downloads, ~2 min) |
| `tests/lab/freeipa-passkey-nla.sh [--setup] USER FQDN` | FreeIPA passkey → TGT → fastrdp NLA with `fastrdp_mfa_nla_kdc_enforced`: password TGT refused for `TERMSRV`, passkey TGT accepted, `xfreerdp3 /p /sec:nla` connects, broker log shows the skipped push | on an enrolled Linux client with a FIDO2 key | no (lab only: FreeIPA, client, security key) |
| `tests/gpu/session_report.py` | which renderer/H.264 encoder a live session really uses | in a session, docs/performance.md | no (needs GPU host) |
| `tests/perf/proxy-overhead.sh`, `compare-host.sh`, `rdpbench`/`perfload` | proxy overhead and fps/latency measurements | `make perf-tools perf-proxy` | no (measurements, not pass/fail) |

## What only CI (or real hardware) verifies

- **CI only:**
  - the e2e suites against the vendored FreeRDP build;
  - the xrdp encoder test against the vendored xrdp build;
  - lintian;
  - the install test;
  - the krb5 SPNEGO check. These need FreeRDP/xrdp dev packages or root.
- **The xrdp encoder test in CI** runs only when the `vendored` xrdp build runs, i.e.
  on a cache miss. Its inputs (`patches/xrdp/**`, including the test) are part of the
  cache key.
- **Real hardware:**
  - VA-API/NVENC/QSV encoding on GPUs;
  - real smartcards/AD;
  - GNOME/Plasma back-ends and full xrdp sessions (docs/desktop-matrix.md, docs/performance.md).

## Writing tests

- **Shell tests:**
  - plain bash, sourcing `tests/lib.sh` (`check`, `expect_exit`, `output_has`, `need`, `finish`);
  - one `ok`/`FAIL` line per check;
  - work in `$T` (removed on exit);
  - no network: file:// URLs and fixtures.
- **Python tests:** stdlib `unittest`.
- **New tests:** add each to the Makefile (`test-all` if it runs without root), and to this table.
