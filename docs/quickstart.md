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
MFA with privacyIDEA: none / push / otp / otp_or_push [none]:
Browser access via Keycloak/OIDC + Guacamole? (y/n) [n]:
Install method: apt (packages, recommended) / build (compile on the host) [build]:
RDP certificate: self-signed (lab) / provided (PEM files) [self-signed]:
New ansible-vault password for vault.yml:
```

It writes `ansible/inventories/mylab/`:

| File | Contents |
|---|---|
| `hosts.yml` | the host(s) in group `rdp_servers`, SSH user |
| `group_vars/all/main.yml` | only the variables the roles need without a default, plus the ones that differ from the role defaults; each with a comment |
| `group_vars/all/vault.yml` | the secrets (join password, privacyIDEA service password, OIDC client secret), encrypted with `ansible-vault` |
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
| web / OIDC | issuer discovery answers and reports the same issuer; client secret set |
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
short or fully qualified account names, the AD GPO mode, MFA exempt groups, TLS logins and the APT key checksum, and
defaults to a provided certificate. Work through the list before `make deploy`;
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
- [ ] privacyIDEA realm reading the same users; `otppin=none` for OTP.
- [ ] For push after Kerberos SSO: a service admin with the `triggerchallenge` right.
- [ ] A break-glass group in `mfa_exempt_groups`, used sparingly.
- [ ] privacyIDEA reachable from the RDP host over HTTPS (P); its CA file if private.
- [ ] Mode `otp` refuses NLA logins: prefer `push` or `otp_or_push`.

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
Path A, with MFA (approve the push while the client shows "connecting").

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
  "install_method": "apt",
  "tls": "provided",
  "tls_cert": "/secure/rdp.corp.example.com.fullchain.pem",
  "tls_key": "/secure/rdp.corp.example.com.key"
}
```

```sh
export FASTRDP_JOIN_PASSWORD=... FASTRDP_PRIVACYIDEA_SERVICE_PASSWORD=... FASTRDP_WEB_OIDC_CLIENT_SECRET=...
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
| NLA login fails, client falls back to NTLM or reports *logon attempt failed* | Connect to the **FQDN**, not an IP or alias (`TERMSRV/<fqdn>`); the client must reach a KDC (VPN or KDC proxy, [client-guide.md](client-guide.md)); on the host `klist -k /etc/fastrdp/termsrv.keytab` lists `TERMSRV/` keys (smoke test) |
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
