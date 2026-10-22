# Web path (Keycloak → fastrdp-webgate → Guacamole → proxy)

Not a back-end of its own: a second way **into** the proxy. After the proxy, the login
goes to the xrdp, GNOME or Plasma driver like any RDP login. Design rationale, Keycloak
setup and residual risks are in [web-access.md](../web-access.md); this page covers
the mechanics and how the path interacts with the back-ends.

Enable with `fastrdp_web_enabled: true` (role `web_gateway`).

## How it works

```
browser ─https─▶ nginx :443 ─/web/──────▶ fastrdp-webgate 127.0.0.1:8090 (_fastrdp-web)
                            └─/guacamole/─▶ Guacamole (Tomcat :8080, podman, host network)
                                               └─▶ guacd 127.0.0.1:4822 (podman)
                                                     └─RDP/TLS─▶ proxy 127.0.0.1:3389 ─▶ broker ─▶ back-end
```

1. `GET /web/`: no session cookie → redirect to Keycloak (code flow, PKCE, state and
   nonce in a signed 10-minute cookie `fastrdp_web_login`).
2. `GET /web/callback`: code exchange, ID-token checks, **MFA proof** (`acr` in
   `required_acr` or an `amr` entry in `required_amr_any`), username from
   `username_claim`; `user@domain` only for domains in `strip_domains`, which are
   removed. The broker maps the short name to the account like a TLS login (with
   `fastrdp_sssd_fully_qualified_names`: `user@<domain>` first). Session cookie
   `fastrdp_web`, lifetime `session_lifetime` (900 s).
3. Desktop chooser: the list is `[webgate] desktops` (`fastrdp_web_desktops`, default
   = `fastrdp_desktops`) plus "default".
4. `POST /web/connect` (CSRF token required):
   1. the webgate sends `{"op":"web_token","user":…}` to `/run/fastrdp/broker.sock`.
      The broker accepts it only from uid `_fastrdp-web` (`[web] gateway_user`), resolves
      the user, checks `allow_groups` and PAM account (`fastrdp`), and issues a
      `fastrdp-web1:…` token (60 s, single use, memory only);
   2. the webgate builds a Guacamole JSON-auth connection: `hostname 127.0.0.1`, `port
      fastrdp_listen_port`, `username`, `password = <web token>`, `security tls`,
      `resize-method display-update`, `cert-fingerprints` (proxy certificate, from
      `/etc/fastrdp/front.fingerprint`), `initial-program fastrdp:<desktop>` if a
      desktop was chosen, plus `fastrdp_web_rdp_parameters`. Signed (HMAC-SHA256) and
      encrypted (AES-128-CBC) with `/etc/fastrdp/guacamole-json.key`, valid 30 s
      (`data_ttl`);
   3. redirect to `/guacamole/?data=…`.
5. Guacamole decrypts the blob and has guacd connect to the proxy with TLS.
6. Proxy (`AllowTls=true`, forced on when the web path is enabled; with
   `fastrdp_allow_tls_logins: false` also `AllowTlsFrom=127.0.0.1,::1`, so only guacd on
   loopback gets a TLS login at all) → broker `login`
   with `method = "tls"` and the web token as password. The broker:
   - requires `[web] enabled`;
   - requires the **TCP peer address** seen by the proxy to be in `allowed_clients`
     (`127.0.0.1`, `::1`); the client-supplied Client Info address is ignored;
   - redeems the token for that user (single use);
   - runs the PAM account check;
   - skips privacyIDEA (`second factor … already verified by idp`).
7. Desktop choice uses `initial-program` as the alternate-shell hint, then the normal
   rules. The chosen back-end's `ensure()` runs with **no password**.

### Effect on each back-end

| Back-end | Behaviour for web logins |
|---|---|
| xrdp / wlroots | token issued without password → `pam_fastrdp_token` returns `PAM_IGNORE` → no TGT. Same X session as RDP logins: a user can start in the browser and continue in mstsc |
| GNOME / Plasma | unchanged (they never get the password); same session as RDP logins |

### Users and ports

| Component | User | Listens |
|---|---|---|
| nginx | `www-data` (distro) | `:443`, `:80` (redirect) |
| `fastrdp-webgate.service` | `_fastrdp-web`, supplementary group `_fastrdp-broker` | `127.0.0.1:8090` |
| `fastrdp-guacamole.service` (quadlet) | container, `UserNS=auto` | `:8080` (Tomcat binds all addresses; nftables drops non-loopback) |
| `fastrdp-guacd.service` (quadlet) | container, `UserNS=auto` | `127.0.0.1:4822` |

## Components on a deployed host

| Path | Content |
|---|---|
| `/usr/lib/fastrdp/python/fastrdp_webgate/` | webgate (build: role; apt: `fastrdp-webgate`) |
| `/etc/systemd/system/fastrdp-webgate.service` (build) / `/usr/lib/systemd/system/` (apt) | unit |
| `/etc/fastrdp/webgate.toml` (root:`_fastrdp-web` 0640) | `webgate.toml.j2` |
| `/etc/fastrdp/webgate-oidc.secret`, `webgate-cookie.secret`, `guacamole-json.key` (root:`_fastrdp-web` 0640) | OIDC client secret, cookie key, Guacamole JSON key |
| `/etc/fastrdp/guacamole.env` (root 0600) | `JSON_SECRET_KEY` for the Guacamole container |
| `/etc/fastrdp/front.fingerprint` | SHA-256 of `/etc/fastrdp/front.crt`, recomputed on every role run |
| `/etc/fastrdp/webgate-idp-ca.pem` | optional IdP CA (`fastrdp_web_oidc_ca_src`) |
| `/etc/containers/systemd/fastrdp-guacd.container`, `fastrdp-guacamole.container` | podman quadlets |
| `/etc/nftables.d/fastrdp-web.nft` | table `inet fastrdp_web`: drop new non-loopback connections to 4822, 8080, 8090 |
| `/etc/nginx/sites-available/fastrdp-web.conf` (+ `sites-enabled` link) | TLS front, paths-only access log `/var/log/nginx/fastrdp-web.log` |
| `/etc/subuid`, `/etc/subgid` | `containers:2147483647:2147483648` for `UserNS=auto` |

## Configuration

Role `web_gateway` (`ansible/roles/web_gateway/defaults/main.yml`):

| Variable | Default | Renders |
|---|---|---|
| `fastrdp_web_enabled` | `false` | runs the role; broker `[web] enabled`; proxy `ServerTlsSecurity` and `AllowTls` on |
| `fastrdp_tls_login_sources` (roles/common) | `[127.0.0.1, "::1"]` if web on and `fastrdp_allow_tls_logins` off, else `[]` (any) | proxy `[FastRDP] AllowTlsFrom`: peers allowed to log in over TLS (addresses/CIDRs) |
| `fastrdp_web_public_url` | `https://{{ fastrdp_fqdn }}` | `[webgate] public_url` (redirect URI = `<url>/web/callback`); role common, as the proxy's waiting screen names `<url>/web/approve` (`fastrdp_ui_approve_url`) |
| `fastrdp_web_oidc_issuer` | `https://keycloak.lab.example.com/realms/lab` | `[oidc] issuer` |
| `fastrdp_web_oidc_client_id` | `fastrdp-web` | `[oidc] client_id` |
| `fastrdp_web_oidc_client_secret` | `vault_fastrdp_web_oidc_client_secret` | `/etc/fastrdp/webgate-oidc.secret` (role fails if empty) |
| `fastrdp_web_oidc_ca_src` | `""` | `[oidc] ca_file` |
| `fastrdp_web_username_claim` | `preferred_username` | `[oidc] username_claim` |
| `fastrdp_web_strip_domains` | `[fastrdp_domain]` | `[oidc] strip_domains` |
| `fastrdp_web_required_acr` | `[mfa]` | `[oidc] required_acr` |
| `fastrdp_web_required_amr_any` | `[]` | `[oidc] required_amr_any` |
| `fastrdp_web_desktops` | `fastrdp_desktops` | `[webgate] desktops` (chooser list) |
| `fastrdp_web_session_lifetime` | `900` | `[webgate] session_lifetime` (webgate login only) |
| `fastrdp_guacamole_version` | `1.6.0` | image tags |
| `fastrdp_guacamole_image`, `fastrdp_guacd_image` | `docker.io/guacamole/{guacamole,guacd}:<version>` | quadlets |
| `fastrdp_web_rdp_parameters` | `enable-font-smoothing: "true"`, `color-depth: "32"` | `[guacamole.rdp_parameters]` |
| `fastrdp_audio_input` (roles/common) | `true` | `[guacamole.rdp_parameters]` `enable-audio-input` (unless set in `fastrdp_web_rdp_parameters`) |
| `fastrdp_web_notify_backends` | `[]` | `[notify] backends`: approval notifications via `ntfy` / `webpush` ([notifications.md](../notifications.md); the other `fastrdp_web_notify_*` variables there) |
| `fastrdp_web_notify_ntfy_token` | `vault_fastrdp_web_notify_ntfy_token` | `/etc/fastrdp/webgate-ntfy.token` (only with ntfy) |

Broker `[web]` (`broker.toml.j2`): `gateway_user = "_fastrdp-web"`,
`allowed_clients = ["127.0.0.1", "::1"]`; `token_ttl` stays at the `config.py`
default 60.

## GPU and performance path

The back-end encodes as usual (H.264 or RFX towards guacd). guacd 1.6.0 (official image,
FreeRDP 2, no FFmpeg/OpenH264) decodes and re-encodes the screen as images for the
browser. Expect much lower frame rates than with native clients; the GPU path of the
back-end matters less here. `session_report.py` inside the session works as for the
native back-end.

## Security properties

Summary (details and residual risks in [web-access.md](../web-access.md)):
- Web tokens: issued only to `_fastrdp-web`, bound to the user, single use, 60 s,
  accepted only from loopback peers; MFA proven by the IdP.
- Guacamole has only JSON auth; blobs expire after 30 s.
- guacd pins the proxy certificate.
- Ports 4822, 8080, 8090 are dropped on non-loopback interfaces. guacd itself has no
  authentication and is reachable by local users on the host.
- `broker.sock` is group `_fastrdp-broker`, so the webgate cannot read the keytab or
  the proxy TLS key (group `_fastrdp-proxy`).

## Limitations and known issues

- No H.264 in the browser; low fps.
- No Kerberos TGT in sessions started from the browser.
- The chooser asks the broker (`web_desktops`, only from the webgate's uid) and lists
  only the desktops the user may use, intersected with `fastrdp_web_desktops`, with
  their `fastrdp_desktop_labels` and the user's default preselected. A request for a
  desktop the user may not use is refused (403) instead of starting the default.
- Images are pulled by tag from Docker Hub; pin by digest for production.
- End-to-end with real Keycloak, Guacamole and a back-end: to validate.

## Troubleshooting

| Symptom | Checks |
|---|---|
| Browser error page "You are not allowed to use remote desktops." | `journalctl -u fastrdp-webgate -g "broker refused"`; broker: `journalctl -u fastrdp-brokerd -g denied` (group, account) |
| "Login was not accepted." | `journalctl -u fastrdp-webgate -g "OIDC login refused"` (issuer, audience, missing `acr`/`amr`) |
| "Your account name cannot be used here." | username claim with a domain not in `fastrdp_web_strip_domains`, or invalid characters |
| Guacamole shows a connection error | `journalctl -u fastrdp-guacd -u fastrdp-guacamole`; proxy: `journalctl -u fastrdp-proxy`; broker: `web token from unexpected client address`, `invalid or reused web token`, `web token presented but [web] is disabled` |
| Certificate error in guacd | `/etc/fastrdp/front.fingerprint` vs. `openssl x509 -in /etc/fastrdp/front.crt -noout -fingerprint -sha256`; re-run the role after a certificate change |
| Webgate health | `curl -s http://127.0.0.1:8090/web/healthz` → `ok` |
| Session itself fails | see the back-end page ([xrdp](xrdp.md#troubleshooting), [gnome](gnome.md#troubleshooting), [plasma](plasma.md#troubleshooting)) |

## Tests

| Test | What |
|---|---|
| `make test-webgate` (CI) | Guacamole JSON format byte-identical to Guacamole's reference, OIDC checks (`acr`/`amr`, audiences), domain stripping, cert pinning parameter, full flow to the Guacamole redirect, CSRF, unknown desktop, forged cookie |
| `make test-broker` (CI) | `WebTokenTests`: single use, skips MFA, wrong client address, bound to user, web token not valid at the xrdp token socket; `WebDisabledTests` |
| `make test-e2e` (manual) | proxy peer address used instead of the claimed client address; `cert-fingerprints` format accepted/refused by FreeRDP |

No test runs real Keycloak, Guacamole or guacd.
