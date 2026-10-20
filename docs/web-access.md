# Web access (browser) – Keycloak + Guacamole

Optional path for users without an RDP client. Enable with `fastrdp_web_enabled: true`
(Ansible role `web_gateway`).

```
browser ──https──▶ nginx :443
                    ├── /web/        ─▶ fastrdp-webgate (127.0.0.1:8090)
                    │                    1. OIDC login at Keycloak (code flow + PKCE, MFA proven by acr/amr)
                    │                    2. broker: web_token(user) ─▶ one-time "fastrdp-web1:…" token
                    │                    3. encrypted, signed Guacamole connection (30 s) ─▶ redirect
                    └── /guacamole/  ─▶ Guacamole (JSON auth only) ─▶ guacd
                                                                         │ RDP/TLS, user + web token
                                                                         ▼
                                                     fastrdp proxy 127.0.0.1:3389 ─▶ broker ─▶ session
```

## Why it is built this way

- With OIDC, Guacamole never sees a password. Kerberos NLA is impossible from guacd,
  so it connects with TLS and a **one-time web token** instead.
- The broker only accepts a web token:
  - if it was issued to the **webgate's uid** (`[web] gateway_user`);
  - for the **same user**, **once**, within **60 s**;
  - on a login arriving from **guacd's address** (`allowed_clients`, loopback).
- Guacamole only runs the **JSON auth extension**:
  - There are no Guacamole users or passwords.
  - Each login is a connection blob that the webgate signs (HMAC-SHA256) and
    encrypts (AES-128-CBC) with a key only the host knows. Unit tests check that
    the format is byte-identical to Guacamole's `encrypt-json.sh`.
  - A blob is valid for 30 s and carries the single-use web token.
- **MFA happens at Keycloak.** The webgate refuses ID tokens whose `acr` (or `amr`)
  does not prove it, and the broker therefore skips privacyIDEA for web tokens.
- Everything Guacamole-related stays on loopback:
  - guacd is forced to `-b 127.0.0.1`.
  - Tomcat (8080), guacd (4822) and the webgate (8090) are dropped on other
    interfaces by nftables.
  - nginx logs paths only, so OIDC codes and blobs never reach a log file; pages
    send `Referrer-Policy: no-referrer`.

## Hardening after review

- **Web tokens are bound to guacd's real address.** The broker checks the TCP peer
  address of the RDP connection, not the client-supplied *clientAddress* from the
  RDP Client Info PDU. An end-to-end test sends a forged address.
- **The webgate cannot read the proxy's secrets.** `broker.sock` belongs to its own
  group `_fastrdp-broker` (proxy + webgate). The keytab and RDP TLS key stay with
  `_fastrdp-proxy`.
- **The Guacamole key never appears in unit files.** podman reads it at start from
  the root-only `/etc/fastrdp/guacamole.env`. Both containers run with
  `UserNS=auto`, so no container process shares a uid with a local user.
- **guacd pins the proxy certificate** (`cert-fingerprints`, derived from
  `front.crt` on every run) instead of ignoring it. A local process that grabs
  port 3389 while the proxy restarts therefore receives nothing. The format is
  verified against FreeRDP in the end-to-end test.
- **The webgate refuses to start without an MFA proof requirement**
  (`required_acr` / `required_amr_any`), and `amr` must be a list.
- **Username claims:** `user@domain` is accepted only for `fastrdp_web_strip_domains`;
  other domains are refused, so `alice@gmail.com` never maps to `alice`. Use a
  directory-backed claim (Keycloak LDAP/AD federation) so users cannot edit it.
- **Logout** is a CSRF-protected POST. The webgate's own login cookie lasts 15 min
  (`fastrdp_web_session_lifetime`); RDP sessions are not affected.

Residual risks:
- guacd (4822) has no authentication. It is reachable from local users on the host
  (remote access is blocked by nftables), who could use it to open outbound
  connections. Run the web path on hosts without untrusted shell users, or put
  guacd on a separate gateway host.
- The `?data=` URL is in the browser history for its 30-second lifetime. The web
  token inside is single-use.

## Keycloak setup

1. Client `fastrdp-web`:
   - OpenID Connect, *Client authentication: on* (confidential), standard flow only.
   - Valid redirect URI: `https://<rdp-fqdn>/web/callback`.
   - Post-logout redirect URI: `https://<rdp-fqdn>/web/`.
   - Put the client secret into `vault_fastrdp_web_oidc_client_secret`.
2. MFA via step-up (recommended):
   - Client → Advanced → **ACR to LoA mapping**: `mfa` → `2`.
   - Browser flow with **Condition – Level Of Authentication**: level 1 = username
     and password (LDAP/AD federation), level 2 = OTP, WebAuthn (FIDO2, YubiKey),
     or the privacyIDEA authenticator.
   - The webgate sends `acr_values=mfa` and requires `acr == "mfa"` in the ID token
     (`fastrdp_web_required_acr`).
   - Alternatively use `fastrdp_web_required_amr_any` (e.g. `[otp, hwk]`) if your
     IdP sets `amr`. Single-factor values (`pwd`, `pin`, `user`, …) are refused.
   - **Passkeys** (passwordless): a level-2 sub-flow cannot be satisfied by a passkey
     used at level 1. Use a client policy that forces an MFA-only flow for `acr=mfa`
     instead: [passkeys.md](passkeys.md#recipe-a-acrmfa-via-a-forced-flow-recommended).
     Ansible can set this up (next section).

### Passkeys through Ansible (opt-in)

`fastrdp_web_passkeys: true` makes the web_gateway role configure Keycloak itself
(recipe A of [passkeys.md](passkeys.md)), once per run, from the controller, through
the admin REST API (`roles/web_gateway/files/fastrdp_keycloak_passkeys.py`). With the
default `false` Keycloak is never contacted.

| Variable | Default | Meaning |
|---|---|---|
| `fastrdp_web_passkeys` | `false` | switch |
| `fastrdp_keycloak_admin_url`, `fastrdp_keycloak_realm` | from `fastrdp_web_oidc_issuer` | Keycloak base URL and realm |
| `fastrdp_keycloak_client_id` | `fastrdp_web_oidc_client_id` | client that gets the ACR map |
| `vault_fastrdp_keycloak_admin_client_secret` | – | preferred: service-account client (`fastrdp_keycloak_admin_client_id`, realm `fastrdp_keycloak_admin_realm`) with *manage-realm* + *manage-clients* |
| `fastrdp_keycloak_admin_user` + `vault_fastrdp_keycloak_admin_password` | – | alternative: admin user (password grant via `admin-cli`) |
| `fastrdp_keycloak_mfa_flow`, `_acr`, `_loa` | `fastrdp-mfa`, `mfa`, `2` | forced flow, ACR value (must be in `fastrdp_web_required_acr`), level |
| `fastrdp_keycloak_second_factors` | `[auth-otp-form, webauthn-authenticator]` | alternatives after a password (add the privacyIDEA provider's id) |
| `fastrdp_web_passkeys_mediation` | `conditional` | passkey autofill |
| `fastrdp_web_passkeys_hardware_only`, `fastrdp_web_passkeys_aaguids` | `false`, `[]` | attestation `direct` + AAGUID allow-list |

What it writes, and nothing else:
- the realm's WebAuthn **passwordless** policy (UV required, discoverable credential
  required, passkeys enabled, mediation; attestation `none` or, hardware-only,
  `direct` + AAGUIDs) and the required action *Webauthn Register Passwordless*;
- the flow `fastrdp-mfa` without a *Cookie* step (rebuilt when it differs, e.g. when
  someone added a Cookie step; a built-in flow of that name is refused);
- client profile `fastrdp-mfa-flow` (`auth-flow-enforcer`) and policy `fastrdp-mfa`
  (`acr-condition: mfa`). Keycloak's PUT replaces all client profiles/policies, so the
  role reads, merges and writes back: other profiles and policies stay;
- the client's ACR-to-LoA map entry `mfa → 2`, other entries kept.

`--check` lists what would change and writes nothing; a second run reports
`changed=0`. Hardware-only also needs the vendors' attestation roots in Keycloak's
truststore (server option `truststore-paths`, not settable over REST): without them
every registration fails with `invalid cert path`. Run only this part:
`ansible-playbook site.yml --tags keycloak`.

Tested end to end against Keycloak 26.8.1 with headless Chromium and a virtual
authenticator (`make test-keycloak`, tests/keycloak/run.sh; results in
[passkeys.md](passkeys.md#stage-1-results-keycloak-2681)).
3. User names: the `preferred_username` claim must equal the Linux account name (as
   SSSD resolves it). A `@realm` suffix is stripped. Use `fastrdp_web_username_claim`
   for a different claim.

## Limits

- **No H.264 in the browser path.** The official `guacamole/guacd:1.6.0` image is
  built with FreeRDP 2 and without FFmpeg/OpenH264. guacd re-encodes the screen
  as images for the browser anyway. Expect noticeably lower frame rates than native
  clients; the web path is for convenience and occasional use.
- **No Kerberos ticket** in sessions started from the browser (no password ever
  reaches the server). Users can run `kinit` inside the session.
- **Clipboard, audio and file transfer** follow Guacamole's capabilities; printing
  and USB redirection are not available.
- **Images** are pulled from Docker Hub by tag (`fastrdp_guacamole_version`). Mirror
  or pin by digest for production.

## Files and services

| | |
|---|---|
| `fastrdp-webgate.service` | `broker/webgate/` (Python, needs `python3-cryptography`), user `_fastrdp-web` |
| `fastrdp-guacd.service`, `fastrdp-guacamole.service` | podman quadlets in `/etc/containers/systemd/` |
| `/etc/fastrdp/webgate.toml` | config (example: `broker/webgate/config/webgate.toml.example`) |
| `/etc/fastrdp/guacamole-json.key` | 128-bit key shared by webgate and Guacamole (generated once) |
| `/etc/fastrdp/webgate-cookie.secret` | signs the webgate's session cookies (generated once) |
| `/etc/nginx/sites-enabled/fastrdp-web.conf` | TLS front (same certificate as the RDP front-end) |
