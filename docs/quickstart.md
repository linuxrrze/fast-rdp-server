# Quick start

Every deployment takes the same four steps, all run from a checkout of this repository
on your admin machine:

```
scripts/fastrdp-setup   ->  make preflight  ->  make deploy  ->  smoke test + first connection
(asks, writes the          (read-only checks      (site.yml)
 inventory + vault)         on the target)
```

Without Ansible: [manual-setup.md](manual-setup.md) does the same by hand on a host
that installs the packages; the playbook remains the tested path.

**Admin machine:** `ansible-core` (2.16 or newer, it includes `ansible-vault`),
Python 3 and SSH key access to the target as root or as a user who can `sudo`.
`scripts/fastrdp-setup` only needs the Python standard library.

**Target:** a fresh **Ubuntu 26.04** or **Debian 13** (amd64) host that has its
**FQDN** in DNS, and a directory: Samba/Windows AD, FreeIPA, or an MIT KDC with a
keytab you provide. The roles always configure Kerberos and SSSD, so a host with
only local users cannot be deployed (see *No directory yet?* below).

---

## Path A: 10-minute lab

One host, self-signed certificate, an existing AD, XFCE.

*10 minutes* is the time you spend. With `install method: build` the playbook also
compiles FreeRDP and xrdp on the host, which takes another 10-20 minutes unattended.
`apt` skips that, but only once the APT repository is published for your release
(`scripts/fastrdp-setup` checks and tells you; see [packaging.md](packaging.md)).

### 1. Answer the questions

```sh
make setup                  # = scripts/fastrdp-setup
```

Press Enter to keep a default. Your answers (except passwords) are saved after each
question in `ansible/inventories/.setup-last-answers.json`, also when you cancel with
Ctrl-C, and are offered as defaults the next time; `scripts/fastrdp-setup --fresh`
starts from the built-in defaults instead. A lab run looks like this:

```
Deployment type (lab / production) [lab]:
RDP server(s), fully qualified, comma-separated: rdp1.lab.example.com
Inventory name (ansible/inventories/<name>) [rdp1]: mylab
SSH user on the host(s) (empty = from ~/.ssh/config) [you]: admin
Does this user need a password for sudo? (y/n) [n]:
Directory: ad (Samba/Windows AD) / ipa (FreeIPA) / none (MIT KDC, keytab provided) [ad]:
DNS domain of the realm [lab.example.com]:
Kerberos realm [LAB.EXAMPLE.COM]:
Join account [Administrator]:
Join password (stored in the encrypted vault):
Groups allowed to log in (comma-separated, empty = every directory user) [none]:
Desktops (comma-separated) [xfce]:
Default desktop [xfce]:
GPU: auto / nvidia / mesa (Intel, AMD) / none [auto]:
Sound in sessions? (y/n) [y]:
Second factor for RDP logins: none / web / code_or_web (Keycloak) / push / otp / otp_or_push (privacyIDEA) / push_or_web (both) [none]:
Browser access via Keycloak/OIDC + Guacamole? (y/n) [n]:
Install method: apt (packages, recommended) / build (compile on the host) [build]:
RDP certificate: self-signed (lab) / provided (PEM files) [self-signed]:
New ansible-vault password for vault.yml:
```

With browser access (`y`, the default for MFA modes `web`, `push_or_web` and `code_or_web`) the web
questions follow. Keycloak must mark the sign-in as MFA (`acr=mfa`): the client's ACR map
alone is not enough, Keycloak needs a level-2 step for it. The assistant explains this and
offers to let Ansible configure it (`fastrdp_web_passkeys`, [web-access.md](web-access.md#passkeys-through-ansible-opt-in)):

```
Browser access via Keycloak/OIDC + Guacamole? (y/n) [y]:
OIDC issuer URL (e.g. https://keycloak.example.com/realms/main): https://sso.lab.example.com/realms/lab
OIDC client id [fastrdp-web]:
OIDC client secret (stored in the vault):
CA certificate of the IdP on this machine (empty = system trust store) [none]:
Let Ansible configure Keycloak's MFA flow (incl. passkeys)? (y/n) [n]: y
Keycloak admin login: client (service account, recommended) / user (admin user) [client]:
Realm of the Keycloak admin client or user [master]:
Service-account client id: fastrdp-admin
Secret of the service-account client (stored in the vault):
```

`n` keeps Keycloak as it is and prints: *Make sure Keycloak enforces MFA for acr=mfa (a
level-2 step, docs/web-access.md#keycloak-setup), otherwise every web sign-in is refused.*

With MFA mode `code_or_web` (the code from the authenticator app typed into the RDP
window, checked by Keycloak; passkeys on the approval page) two questions follow the
IdP's CA. Production first asks for the realm (default: the web gateway's) and, for
another realm, its CA:

```
Keycloak realm URL for the code check [https://sso.lab.example.com/realms/lab]:   (production)
Client id of the code check [fastrdp-otp-check]:
Secret of the code check's client (stored in the vault):
```

The client is created by hand from
`docs/examples/keycloak-fastrdp-otp-check-client.json`; the closing notes say so, and
remind of brute-force detection and single-use OTP codes in the realm. With
`web_passkeys` = y the role also sets up the client's direct grant flow (username +
code, no password) in the web gateway's realm; otherwise, or for another realm, the
notes point to the steps by hand
([keycloak-mfa/README.md](examples/keycloak-mfa/README.md#code-in-the-rdp-window-code_or_web)).

It writes `ansible/inventories/mylab/`:

| File | Contents |
|---|---|
| `hosts.yml` | the host(s) in group `rdp_servers`, SSH user |
| `group_vars/all/main.yml` | only the variables the roles need without a default, plus the ones that differ from the role defaults; each with a comment |
| `group_vars/all/vault.yml` | the secrets (join password, privacyIDEA service password, OIDC client secret, Keycloak admin secret, the code check's client secret), encrypted with `ansible-vault` |
| `setup-answers.json` | your answers without secrets; `scripts/fastrdp-setup --answers .../setup-answers.json --force` regenerates the inventory |

At the end it prints the next commands with your inventory filled in.

### 2. Preflight (read-only)

```sh
make preflight INVENTORY=mylab                    # asks for the vault password
# = cd ansible && ansible-playbook -i inventories/mylab/hosts.yml preflight.yml --ask-vault-pass
```

`ansible/preflight.yml` changes nothing on the host. It prints one line per check,
with the fix for each WARN/FAIL, and fails if any check FAILs:

```
PASS  inventory variables: all required variables set
PASS  operating system: Ubuntu 26.04 (resolute, x86_64)
PASS  sudo: become works
FAIL  FQDN / forward DNS: FQDN resolves only to loopback 127.0.1.1  ->  fix: ... remove a 127.0.1.1 <fqdn> line from /etc/hosts
PASS  realm / KDC: KDC dc1.lab.example.com, LDAP dc1.lab.example.com
PASS  ports: free: 3389,3390
WARN  RDP certificate: self-signed certificate will be generated (lab only: clients warn)  ->  fix: ...
```

| Check | What it looks at |
|---|---|
| inventory variables | every variable the roles use without a default is set; realm/domain/desktop consistency; vault loaded |
| operating system | Ubuntu 26.04+ or Debian 13+ |
| sudo | `become` works (otherwise add `-K`) |
| FQDN / forward DNS | hostname is an FQDN in the realm domain, resolves on the host and from the admin machine, not only to 127.x; AD short name at most 15 characters |
| reverse DNS | PTR of the host address (WARN only) |
| time sync | clock offset to the admin machine (FAIL above 5 min, the Kerberos limit) and NTP state |
| realm / KDC | `_kerberos._tcp` (and for AD/IPA `_ldap._tcp`) SRV records, TCP 88/389 reachable. krb5.conf finds KDCs via DNS only |
| keytab / sssd.conf | provider `none`: the TERMSRV keytab and an sssd.conf exist |
| home directories | the home of `fastrdp_preflight_user` (set it in the inventory or with `-e`) and of the join account: every path component exists (FAIL for a missing parent such as `/autofs` without `fastrdp_autofs`/`fastrdp_sssd_override_homedir`), no hung mounts; the fixed part of `fastrdp_sssd_override_homedir` exists |
| ports | 3389 and 3390 free (443/80 with web access), unless already used by fastrdp itself |
| GPU | requested vs detected GPU, render nodes, NVIDIA driver, Secure Boot, Debian non-free |
| CPU / RAM / disk | rough minimum and recommended sizes for the chosen desktops and install method |
| privacyIDEA | `<url>/healthz/` answers from the host |
| MFA from KDC evidence | `fastrdp_mfa_kdc_evidence_as_mfa`: items well-formed, realm set, `fastrdp-freerdp3` ≥ 3.32.2-4 installed or available (`build`: patch 0005 in the checkout); Samba/Microsoft AD caveats for `sid:S-1-18-3` (INFO when unused) |
| web / OIDC | issuer discovery answers and reports the same issuer; client secret set |
| Keycloak MFA for acr=mfa | `fastrdp_web_passkeys: true`: admin credentials set (FAIL without). Otherwise the discovery document's `acr_values_supported`: WARN unless it lists `mfa` or a level ≥ 2 (Keycloak shows only the realm's ACR map and the levels of the realm's browser flow; the client's ACR map and client policies are not visible, so a WARN may be a false alarm) |
| MFA code check (Keycloak) | `code_or_web`: the code check's realm answers discovery from the host with the same issuer and a token endpoint; client secret set; CA file present; waiting screen on. WARN when the flow is to be set up by hand (`fastrdp_web_passkeys` off, or another realm than the web gateway's) |
| install method | `apt`: repository suite and key reachable from the host |
| RDP certificate | provided: valid, not expiring within 30 days, SAN contains the FQDN, key matches |

### 3. Deploy

```sh
make deploy INVENTORY=mylab
# = cd ansible && ansible-playbook -i inventories/mylab/hosts.yml site.yml --ask-vault-pass
```

Add `ANSIBLE_ARGS=-K` if sudo needs a password, `VAULT_PASSWORD_FILE=~/.fastrdp-vault`
to avoid the vault prompt. Re-running is safe; use `ANSIBLE_ARGS='--tags desktops'` and
similar for one part only (tags are in `ansible/site.yml`).

### 4. Smoke test and first connection

```sh
# runs tests/smoke/check-host.sh on the host(s) as root, for directory user alice
cd ansible && ansible -i inventories/mylab/hosts.yml rdp_servers -b --ask-vault-pass \
    -m ansible.builtin.script -a '../tests/smoke/check-host.sh alice'
```

Every line must say `ok`. Then connect **to the FQDN** (details in
[client-guide.md](client-guide.md)):

```sh
# FreeRDP 3 (Linux/macOS), Kerberos NLA; /cert:tofu accepts the self-signed certificate once.
# It asks for the password even when you have a Kerberos ticket: typing it gives the session
# a TGT (NFS/SMB homes). Single sign-on without a prompt: add /p (no TGT in the session),
# see client-guide.md.
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /cert:tofu \
    /gfx:avc444 /network:auto /dynamic-resolution +clipboard

# without a reachable KDC: password (+OTP) over TLS (needs fastrdp_allow_tls_logins: true)
xfreerdp3 /v:rdp1.lab.example.com /u:alice /sec:tls /cert:tofu /gfx:avc444
```

```bat
:: Windows: mstsc, domain-joined clients use Kerberos automatically
mstsc /v:rdp1.lab.example.com
```

```sh
# Remmina (Linux): one-off connection; set Security protocol "NLA" and
# colour depth "GFX AVC444" in the profile for daily use
remmina -c rdp://alice@rdp1.lab.example.com
```

### No directory yet?

fastrdp needs Kerberos accounts. The fastest lab directory is a Samba AD DC in a
second VM (Ubuntu 26.04 / Debian 13, static IP, hostname `dc1.lab.example.com`):

```sh
sudo apt install samba winbind krb5-user smbclient
sudo systemctl disable --now smbd nmbd winbind && sudo systemctl unmask samba-ad-dc
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.orig
sudo samba-tool domain provision --realm=LAB.EXAMPLE.COM --domain=LAB \
    --server-role=dc --dns-backend=SAMBA_INTERNAL --adminpass='Admin-Passw0rd'
sudo cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
sudo systemctl enable --now samba-ad-dc
sudo samba-tool user create alice 'Alice-Passw0rd'
```

Point the RDP host's DNS resolver at the DC (the realm join and Kerberos need its SRV
records), then start with step 1. Use FreeIPA instead with `ipa` as the directory.

---

## Path B: production checklist

Run `make setup` and answer **production**. It then also asks for allowed groups,
short or fully qualified account names, the AD GPO mode, the microphone, MFA exempt groups,
the web approval settings, KDC evidence as the second factor, TLS logins and the APT key
checksum, and defaults to a provided certificate. Work through the list before `make deploy`;
`make preflight` checks the items marked (P).

**Directory and names**
- [ ] Each host has its final FQDN as hostname, an A record and a PTR record (P).
- [ ] The host resolves the realm's SRV records: AD/IPA DNS as resolver, or SRV records
      in your DNS (P). There is no variable for static KDC addresses.
- [ ] Time: NTP towards the DCs/IPA servers (P). The playbook enables chrony.
- [ ] Join account: AD: an account that may create computer objects in the target OU
      (not Domain Admin); FreeIPA: an enrolment user. Used on the first run only;
      remove it from the vault afterwards if you like.
- [ ] `allow_groups`: a group such as `rdp-users`; empty allows every directory user.
- [ ] Short (`alice`) or fully qualified (`alice@example.com`) account names
      (`fastrdp_sssd_fully_qualified_names`, asked by setup): qualified names keep local
      accounts from standing in for directory users, short ones are what tools and
      people expect ([auth-matrix.md](auth-matrix.md#short-or-fully-qualified-account-names)).
      Decide before users log in; switching renames every directory user.
- [ ] AD: grant "Allow log on through Remote Desktop Services" to that group by GPO.
      The role starts in `permissive` mode (denials only logged in the sssd log); check,
      then re-run setup with `enforcing`.
- [ ] Provider `none` (MIT): `TERMSRV/<fqdn>` keytab exported and `/etc/sssd/sssd.conf`
      installed before the run (P).

**Certificates**
- [ ] A certificate for the FQDN (SAN), with full chain, and its key as PEM files on the
      admin machine (P). The web path uses the same certificate.

**MFA** ([auth-matrix.md](auth-matrix.md))

Which mode to choose for the second factor of RDP logins:

| You want the second factor from | Mode | Users confirm by |
|---|---|---|
| nobody (password / Kerberos only) | `none` | – |
| **Keycloak** (passkey, Windows Hello, TOTP, WebAuthn) | `web` | signing in at `https://<fqdn>/web/approve` (or scanning the QR code in the RDP window) and clicking Approve |
| **privacyIDEA** | `push` | the push in the privacyIDEA app |
| privacyIDEA, code typed with the password | `otp` (TLS logins only), `otp_or_push` | appending the code to the password |
| both, whichever answers first | `push_or_web` | the push, or the approval page |
| **Keycloak**, code in the RDP window or passkey | `code_or_web` | typing the authenticator code on the waiting screen, or approving on the approval page with a passkey |

Browser logins (Guacamole) always use Keycloak's MFA, independent of this choice.

- [ ] privacyIDEA realm reading the same users; `otppin=none` for OTP.
- [ ] For push after Kerberos SSO: a service admin with the `triggerchallenge` right.
- [ ] A break-glass group in `mfa_exempt_groups`, used sparingly.
- [ ] privacyIDEA reachable from the RDP host over HTTPS (P); its CA file if private.
- [ ] Mode `otp` refuses NLA logins: prefer `push` or `otp_or_push`.
- [ ] Modes `web` and `push_or_web` (approval on `https://<fqdn>/web/approve` after a
      fresh MFA sign-in at Keycloak) need browser access; `web` needs no privacyIDEA.
      Setup asks for the wait (`fastrdp_mfa_web_approval_timeout`, 90 s), the maximum age
      of the approving sign-in (30 s) and whether two pending logins block approval (yes),
      and raises `fastrdp_proxy_broker_timeout` to the wait plus 90 s for the session start
      ([auth-matrix.md](auth-matrix.md#web-approval)). The RDP window shows the URL, the
      login's code and a QR code for the phone (the waiting screen, on by default:
      `fastrdp_proxy_waiting_screen`).
- [ ] Mode `code_or_web` ([auth-matrix.md](auth-matrix.md#code-on-the-waiting-screen)):
      as `web`, plus a confidential Keycloak client for the code check (sample
      `docs/examples/keycloak-fastrdp-otp-check-client.json`, its secret in the vault),
      its direct grant flow (`web_passkeys` = y sets it up in the web gateway's realm),
      brute-force detection on and OTP codes single-use in the realm (P). Needs the
      waiting screen; real RDP clients are still to be validated
      ([lab-waiting-screen-input.md](lab-waiting-screen-input.md)).
- [ ] KDC evidence (`fastrdp_mfa_kdc_evidence_as_mfa`, default none): Kerberos NLA logins
      whose ticket shows smart card/passkey pre-authentication skip the second factor.
      FreeIPA: `ind:pkinit`, `ind:passkey`; Microsoft AD: `sid:S-1-18-4` (Windows Hello for
      Business key trust), `sid:S-1-18-3` (needs the DC policy *KDC support for PKInit
      Freshness Extension*) or an Authentication Mechanism Assurance group; Samba AD:
      `sid:S-1-18-3` only, which is not hardware-bound. Setup refuses items that password
      logons carry too (`ind:hardened`, `sid:S-1-18-1`/`-2`, Domain Users, ...); preflight
      checks that `fastrdp-freerdp3` passes the evidence on, ≥ 3.32.2-4 (P)
      ([passkeys.md](passkeys.md#kdc-evidence-per-login)).

**Audio** ([audio.md](audio.md))
- [ ] Sound (`fastrdp_audio`, default yes) and the microphone (`fastrdp_audio_input`,
      default yes; asked in production). The microphone works only when the user also
      allows it on the client (mstsc *Record from this computer*, FreeRDP `/microphone`,
      the browser's permission); no loads the PipeWire xrdp module speaker-only and keeps
      it off the web path. A default, not a policy: users can load the module themselves.

**GPU** ([performance.md](performance.md))
- [ ] `auto` picks NVIDIA, else Intel/AMD (Mesa), else none (P shows what it detects).
- [ ] NVIDIA: the playbook installs the driver; **reboot** afterwards. With Secure Boot,
      enrol the module signing key (P warns). Debian: enable `non-free` (P warns).

**Client networks** ([performance.md](performance.md#bitrate-profile-of-x11-xrdp-sessions))
- [ ] `lan_networks`: the CIDRs of office LANs and VPN pools as the server sees them
      (after NAT). X11 sessions from there get uncapped video; all others get the WAN
      cap (`fastrdp_xrdp_autodetect_profile`) unless the client chose a connection type.

**Web access** ([web-access.md](web-access.md))
- [ ] Keycloak client (confidential, standard flow), redirect URI
      `https://<fqdn>/web/callback`, ACR mapping `mfa`.
- [ ] Keycloak enforces MFA for `acr=mfa` (a level-2 step; the ACR mapping alone gives
      `acr` 1 and every web sign-in is refused): `web_passkeys` = y (Ansible configures it,
      needs a service-account client with *manage-realm* + *manage-clients*, or an admin
      user) or a step-up flow by hand ([web-access.md](web-access.md#keycloak-setup)) (P).
- [ ] Users have a second factor registered in Keycloak (passkey, security key or
      authenticator app).
- [ ] Issuer URL exactly as the discovery document reports it (P); ports 443/80 free (P).

**Install method** ([packaging.md](packaging.md))
- [ ] `apt` (recommended once published): the suite for your release is reachable (P);
      pin the key with its `sha256:` checksum.
- [ ] `build`: 4+ vCPUs and 10 GiB free disk help the first run.

**Operations**
- [ ] Keep the vault password in a password manager or a root-only file
      (`VAULT_PASSWORD_FILE=`); never commit an unencrypted `vault.yml`.
- [ ] Commit the inventory directory to your own (private) repository.
- [ ] Firewall: clients need TCP 3389 (and 443 for the web path); back-end ports stay local.
- [ ] Sizing: preflight prints a rough capacity; set `fastrdp_user_memory_max` /
      `fastrdp_user_cpu_quota` per user ([performance.md](performance.md)).

Then: `make preflight`, `make deploy`, the smoke test and a first connection as in
Path A, with MFA (approve the push, or the login on the approval page, while the RDP
window shows the waiting screen).

### Scripted setup (CI, many sites)

All questions can come from an answers file (JSON, or YAML when PyYAML is installed)
and `--set key=value`; secrets come from the environment. `--non-interactive` fails
on missing or invalid answers instead of asking.

```json
{
  "profile": "production",
  "hosts": ["rdp1.corp.example.com", "rdp2.corp.example.com"],
  "name": "corp",
  "ssh_user": "deploy",
  "become_password": true,
  "identity_provider": "ipa",
  "domain": "corp.example.com",
  "allow_groups": ["rdp-users"],
  "desktops": ["xfce", "gnome", "plasma"],
  "default_desktop": "gnome",
  "gpu": "auto",
  "lan_networks": ["10.0.0.0/8", "2001:db8:100::/48"],
  "mfa_mode": "otp_or_push",
  "privacyidea_url": "https://pi.corp.example.com",
  "privacyidea_realm": "corp",
  "privacyidea_service_user": "fastrdp-svc",
  "mfa_exempt_groups": ["breakglass"],
  "web_enabled": true,
  "web_oidc_issuer": "https://sso.corp.example.com/realms/corp",
  "web_passkeys": true,
  "keycloak_admin_client_id": "fastrdp-admin",
  "install_method": "apt",
  "tls": "provided",
  "tls_cert": "/secure/rdp.corp.example.com.fullchain.pem",
  "tls_key": "/secure/rdp.corp.example.com.key"
}
```

```sh
export FASTRDP_JOIN_PASSWORD=... FASTRDP_PRIVACYIDEA_SERVICE_PASSWORD=... FASTRDP_WEB_OIDC_CLIENT_SECRET=...
export FASTRDP_KEYCLOAK_ADMIN_CLIENT_SECRET=...      # web_passkeys (or FASTRDP_KEYCLOAK_ADMIN_PASSWORD)
export FASTRDP_MFA_KEYCLOAK_CLIENT_SECRET=...        # mfa_mode code_or_web
scripts/fastrdp-setup --non-interactive --answers corp.json --vault-password-file ~/.fastrdp-vault
scripts/fastrdp-setup --help            # all answer keys
```

Without `ansible-vault` on the machine the assistant refuses to write secrets unless
you pass `--plaintext-vault` (file mode 0600; encrypt it later with `ansible-vault encrypt`).

Tests: `make test-setup` (unit tests of the assistant, static checks of the preflight)
and `make lint-setup` (ansible-lint, production profile). Both are part of `make test`
and `make lint`.

---

## Troubleshooting first runs

| Symptom | Cause and fix |
|---|---|
| `Attempting to decrypt but no vault secrets found` | `vault.yml` is encrypted: add `--ask-vault-pass` or `VAULT_PASSWORD_FILE=` (the make targets add `--ask-vault-pass` automatically) |
| `Missing sudo password` / preflight `FAIL sudo` | `ANSIBLE_ARGS=-K` (or `--ask-become-pass`) |
| `UNREACHABLE` | SSH: check `ansible_user` in `hosts.yml`, your key, the host name; `ssh <user>@<host>` must work without a prompt |
| preflight `FQDN resolves only to loopback` | Debian/Ubuntu installers write `127.0.1.1 <fqdn>` into `/etc/hosts`. Replace it with the real address or remove it |
| preflight `no _kerberos._tcp SRV records` / `realm join` says *No such realm found* | The host does not use the directory's DNS. Point its resolver at the DCs/IPA servers |
| `realm join` fails with *Insufficient permissions* or a clock error | Join account rights in the OU; time offset above 5 min (preflight *time sync*) |
| NLA login fails, client falls back to NTLM or reports *logon attempt failed*; proxy log `client <addr> attempted NTLM` | The client has no Kerberos ticket. Connect to the **FQDN**, not an IP or alias (`TERMSRV/<fqdn>`); user as UPN; the client must reach a KDC (VPN or KDC proxy, [client-guide.md](client-guide.md), [windows-clients.md](windows-clients.md) §3.13); on the host `klist -k /etc/fastrdp/termsrv.keytab` lists `TERMSRV/` keys (smoke test) |
| Certificate warning on every connect | Self-signed lab certificate: accept once (`/cert:tofu`) or set a CA certificate (`tls: provided`) |
| preflight `ports: in use: 3389` | A stock `xrdp` or a system-wide `gnome-remote-desktop` listens there: `sudo ss -ltnp 'sport = :3389'`, then disable or `apt purge xrdp` (fastrdp installs its own) |
| preflight `sudo`: `Timeout (12s) waiting for privilege escalation prompt` (with `-K`) | The host's `sudo` is **sudo-rs** (Ubuntu 26.04 default), which never shows the password prompt Ansible waits for. Use classic sudo, installed next to it: `ansible_become_exe: sudo.ws` under `vars:` in `hosts.yml` (`fastrdp-setup` asks for it when sudo needs a password), or give the SSH user passwordless sudo |
| preflight `sudo`: `sudo: interactive authentication is required` / `a password is required` | sudo needs a password and none was given: `make preflight INVENTORY=… ANSIBLE_ARGS=-K` (the same for `make deploy`) |
| Client: `krb5_get_credentials (Server not found in Kerberos database)`; `kvno TERMSRV/<fqdn>` fails; the certificate names another host (e.g. `CN = example.com`) | The server registered its TERMSRV name under a wrong host name. Before 0.4 the roles took Ansible's `fqdn` fact, which comes from a reverse lookup: a PTR record or `/etc/hosts` line pointing at the bare domain gave `TERMSRV/example.com`. Now the inventory name is used (`fastrdp_fqdn`) and preflight fails on a mismatch. Fix the PTR record or `/etc/hosts` (`<address> <fqdn> <short name>`), delete `/etc/fastrdp/front.crt` and `front.key`, deploy again, and remove the wrong name: `adcli update --domain=<domain> --remove-service-principal=TERMSRV/<wrong name>` |
| `apt` install: 404 for `InRelease` | The APT repository is not published for your release/channel yet: set `install_method` to `build` (re-run `scripts/fastrdp-setup --set install_method=build --force --answers .../setup-answers.json`) or try channel `testing` |
| Login accepted, then the session closes | `journalctl -u fastrdp-brokerd -u fastrdp-proxy -u xrdp-sesman -b`; `sudo fastrdpctl status`; is the user in `allow_groups` and allowed by the GPO (`permissive` logs denials in the sssd log)? |
| Login accepted, then *ERRINFO_CB_DESTINATION_NOT_FOUND*; broker log `home directory /autofs/... of USER does not exist (parent /autofs missing: automount not set up?)` | The directory (AD `unixHomeDirectory`) names a home under an automount root this host does not have. Set up autofs (`fastrdp_autofs: sssd` for directory maps, `files` for your own) or use local homes (`fastrdp_sssd_override_homedir: /home/%u`); preflight samples a user with `-e fastrdp_preflight_user=USER`. [nfs-kerberos-homes.md](nfs-kerberos-homes.md#where-homes-are) |
| MFA push: client waits, then fails | privacyIDEA unreachable from the host (preflight), no service admin for SSO logins, or the push was not approved within `push_timeout` (60 s) |
| Black screen or no GPU acceleration with NVIDIA | Reboot after the first run (driver + `nvidia-drm modeset=1`); Secure Boot needs the module key enrolled |
| Web login: *issuer mismatch* or MFA required | `fastrdp_web_oidc_issuer` must equal the issuer in Keycloak's discovery document; configure the ACR mapping `mfa` ([web-access.md](web-access.md)) |
| Web sign-in or `/web/approve`: page *Second factor required*; journal `OIDC login of alice refused: acr '1' does not prove MFA` | Keycloak has no level-2 (MFA) step for `acr=mfa` (the client's ACR map alone is not enough), or the user signed in without a second factor. Set `fastrdp_web_passkeys: true` with admin credentials (or re-run the assistant with `web_passkeys` = y) and deploy, or configure a step-up flow ([web-access.md](web-access.md#symptom-acr-1-does-not-prove-mfa)); users register a second factor in Keycloak's account console (`<issuer>/account`) |
