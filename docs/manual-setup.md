# Manual setup (without Ansible)

**Ansible remains the recommended and tested path** ([quickstart.md](quickstart.md)):
the roles check the site settings, are idempotent, and `make preflight` and CI test them.
This guide does the same work by hand on a host that installs the packages from the
APT repository ([packaging.md](packaging.md)). It mirrors the roles **as of 0.2.0**
(`main`; v0.1.0 differs in the TERMSRV helpers, the `krb5.conf` layout and the xrdp
configuration files) with `fastrdp_install_method: apt`. Every file below was rendered from the role
template with the role defaults and the example values in the next table. If you
update fastrdp, compare the role files in the table below with your host.

| Section | Role files it mirrors |
|---|---|
| [1 Prerequisites](#1-prerequisites) | `ansible/preflight.yml` |
| [2 Base system and packages](#2-base-system-and-packages) | `roles/base/tasks/main.yml`, `roles/base/tasks/apt_repo.yml`; package tasks of `broker`, `freerdp_proxy`, `xrdp` |
| [3 Kerberos, SSSD, domain join](#3-kerberos-sssd-domain-join) | `roles/identity/tasks/{main,ad,ipa,ipa_krb5,none}.yml`, `roles/identity/templates/*`, `roles/identity/defaults/main.yml`; `broker/sbin/*` (TERMSRV helpers) |
| [4 Front TLS certificate](#4-front-tls-certificate) | `roles/base/tasks/main.yml` (certificate tasks), `roles/base/defaults/main.yml` (`fastrdp_front_cert_san`) |
| [5 Firewall and kernel settings](#5-firewall-and-kernel-settings) | `roles/base/templates/nftables-fastrdp.nft.j2`, `roles/base/tasks/main.yml`, `roles/freerdp_proxy/tasks/main.yml` (front placeholder) |
| [6 GPU](#6-gpu) | `roles/gpu/tasks/main.yml`, `roles/gpu/defaults/main.yml` |
| [7 Desktops](#7-desktops) | `roles/desktops/*`, `roles/gnome_rd/*`, `roles/plasma_krdp/*` |
| [8 Tuning](#8-tuning) | `roles/tuning/*` |
| [9 Broker](#9-broker) | `roles/broker/tasks/main.yml`, `roles/broker/templates/broker.toml.j2` |
| [10 xrdp](#10-xrdp) | `roles/xrdp/tasks/main.yml`, `roles/xrdp/templates/*`, `roles/xrdp/defaults/main.yml` |
| [11 Proxy](#11-proxy) | `roles/freerdp_proxy/tasks/main.yml`, `roles/freerdp_proxy/templates/proxy.ini.j2` |
| [12 Start the services](#12-start-the-services) | service tasks of all roles, order of `ansible/site.yml` |
| [13 Verify](#13-verify), [14 First connection](#14-first-connection) | `tests/smoke/check-host.sh`, quickstart step 4 |
| [15 Optional parts](#15-optional-parts) | `roles/mfa_privacyidea`, `roles/web_gateway`, `roles/identity/tasks/nfs_krb5.yml` |

## Example values

All commands and files use these values. Replace them with your own everywhere; the
ones marked **site** are always site-specific.

| Item | Example | Role variable |
|---|---|---|
| Kerberos realm (**site**) | `EXAMPLE.COM` | `fastrdp_realm` |
| DNS domain (**site**) | `example.com` | `fastrdp_domain` |
| Host FQDN / short name (**site**) | `rdp1.example.com` / `rdp1` (AD account `RDP1$`) | facts `ansible_fqdn`, `ansible_hostname` |
| Directory | Samba/Windows AD (FreeIPA and MIT: deltas in 3.6, 3.7) | `fastrdp_identity_provider: ad` |
| Join account (**site**) | `Administrator` | `fastrdp_join_user` |
| Allowed groups | none (every directory user) | `fastrdp_allow_groups: []` |
| Desktop | XFCE only | `fastrdp_desktops: [xfce]` |
| GPU | none: x264 on the CPU, software rendering | `fastrdp_gpu` (auto-detected) |
| MFA / web access | off / off | `fastrdp_mfa_mode: none`, `fastrdp_web_enabled: false` |
| Front certificate | self-signed (lab only) | `fastrdp_front_cert_src: ""` |
| Ports | 3389 (front), 3390 (xrdp, loopback), 33900-34899 (GNOME/Plasma back-ends, loopback) | `fastrdp_listen_port`, `fastrdp_xrdp_port`, `fastrdp_backend_port_range` |

Run everything as root (`sudo -i`) on the RDP host.

## What the packages already do

Do not repeat these steps; the rest of this guide covers what the packages leave out.

| Package | Provides |
|---|---|
| `fastrdp-broker` | broker code, `fastrdp-brokerd` and `fastrdpctl` in `/usr/sbin`, `fastrdp-brokerd.service` (disabled), `/etc/pam.d/fastrdp` and `/etc/pam.d/fastrdp-tgt`, `/etc/fastrdp/`, group `_fastrdp-broker`, example `broker.toml` in `/usr/share/doc/fastrdp-broker/examples/`; TERMSRV keytab helpers `fastrdp-termsrv-check` and `fastrdp-termsrv-keytab` in `/usr/sbin`, their settings `/etc/fastrdp/termsrv.conf`, `fastrdp-termsrv-keytab.path`/`.service` (disabled) |
| `fastrdp-proxy-module` | proxy module, `fastrdp-proxy.service` (disabled; sets `KRB5_KTNAME=FILE:/etc/fastrdp/termsrv.keytab`), user `_fastrdp-proxy` |
| `fastrdp-freerdp3` | FreeRDP in `/opt/fastrdp` (`freerdp-proxy`, `xfreerdp`) |
| `libpam-fastrdp-token` | `pam_fastrdp_token.so` |
| `fastrdp-session` | `/usr/libexec/fastrdp/*` (`startwm.sh`, Plasma and wlroots launchers), `fastrdp-plasma@.service`, `/etc/pam.d/fastrdp-session`, KWin user drop-in, `/usr/share/xsessions/fastrdp-{sway,labwc,wayfire}.desktop`, the token-only xrdp PAM stack as a template in `/usr/share/fastrdp-session/pam.d/xrdp-sesman` |
| `fastrdp-xrdp` | xrdp + xorgxrdp (replaces the distribution `xrdp`/`xorgxrdp`), units (disabled), user `xrdp`; `postinst` creates `/etc/xrdp/cert.pem`, `/etc/xrdp/key.pem` (`root:xrdp 0640`) and `rsakeys.ini`, and the files of section 10 from upstream's defaults in `/usr/share/fastrdp-xrdp/default-config/` where they are missing (they are not conffiles: replace them, dpkg never asks about them) |
| `fastrdp-webgate` | web gateway code and unit (disabled), user `_fastrdp-web` |

Every daemon is installed **disabled and stopped**. The stock `/etc/xrdp/xrdp.ini`
listens on 3389 on all addresses, so do not start xrdp before section 10.

---

## 1. Prerequisites

Supported: **Ubuntu 26.04** or **Debian 13**, amd64. Check by hand what
`make preflight` checks:

```sh
hostnamectl set-hostname rdp1.example.com      # the FQDN is the hostname
hostname -f                                    # -> rdp1.example.com
getent ahosts rdp1.example.com                 # the real address, not 127.0.1.1
grep 127.0.1.1 /etc/hosts                      # remove a "127.0.1.1 rdp1.example.com" line
getent hosts <host address>                    # PTR record (recommended)
dig +short SRV _kerberos._tcp.example.com      # KDCs (apt install bind9-dnsutils)
dig +short SRV _ldap._tcp.example.com          # AD / FreeIPA
ss -ltn 'sport = :3389 or sport = :3390'       # both free
```

- **Names:** clients must connect to the FQDN (Kerberos asks for `TERMSRV/<fqdn>`).
  AD: the short name has at most 15 characters (the computer account is truncated).
- **DNS:** `krb5.conf` below finds the KDCs through DNS SRV records only
  (`dns_lookup_kdc = true`, no static KDC list). Use the AD/IPA DNS servers as the
  resolver, or publish the SRV records in your DNS. TCP 88 and 389 to the KDCs must be open.
- **Time:** at most 5 minutes offset to the KDCs; section 2 enables chrony.
- **Directory:** a Samba/Windows AD, FreeIPA, or an MIT KDC plus a `TERMSRV/<fqdn>`
  keytab and an `sssd.conf` that you provide. A host with only local users cannot
  run fastrdp ([quickstart.md](quickstart.md#no-directory-yet)).
- **Join account:** AD: may create computer objects in the target OU; FreeIPA: an
  enrolment user. Only needed during the join and for alias SPNs.
- **Port 3389:** nothing else may listen there (a distribution `xrdp` or a
  system-wide `gnome-remote-desktop`).

## 2. Base system and packages

Role `base`:

```sh
apt update
apt install chrony nftables openssl python3 ca-certificates dbus-user-session polkitd
systemctl enable --now chrony
chronyc tracking | grep 'Leap status'        # Normal
install -d -o root -g root -m 0755 /etc/fastrdp
```

APT repository (`roles/base/tasks/apt_repo.yml`, client setup in
[packaging.md](packaging.md#client-setup)). Suite: `resolute-stable` (Ubuntu 26.04)
or `trixie-stable` (Debian 13); `-testing` follows `main`.

```sh
apt install curl gpg                            # for the next commands
install -d -m 0755 /etc/apt/keyrings
curl -fsSLo /etc/apt/keyrings/fast-rdp-server.asc \
    https://linuxrrze.github.io/fast-rdp-server/fast-rdp-server-archive-keyring.asc
chmod 0644 /etc/apt/keyrings/fast-rdp-server.asc
gpg --show-keys /etc/apt/keyrings/fast-rdp-server.asc     # compare the fingerprint
```

`/etc/apt/sources.list.d/fast-rdp-server.sources` (`root:root 0644`):

```
Types: deb
URIs: https://linuxrrze.github.io/fast-rdp-server
Suites: resolute-stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/fast-rdp-server.asc
```

Packages (the `apt` blocks of the roles `broker`, `freerdp_proxy`, `xrdp`;
`fastrdp-webgate` only for web access):

```sh
apt update
apt install fastrdp-broker libpam-fastrdp-token fastrdp-freerdp3 fastrdp-proxy-module \
    fastrdp-session fastrdp-xrdp
systemctl is-enabled fastrdp-brokerd fastrdp-proxy xrdp xrdp-sesman    # all: disabled
```

`fastrdp-xrdp` removes a distribution `xrdp`/`xorgxrdp`. Switching a host that was
deployed with `install method: build`: also delete `/etc/systemd/system/{fastrdp-brokerd,fastrdp-proxy,xrdp,xrdp-sesman}.service`,
`/usr/local/sbin/fastrdpctl` and `/usr/local/sbin/fastrdp-termsrv-{check,keytab}`; disable
and delete `/etc/systemd/system/fastrdp-termsrv-keytab.{path,service}` (AD), then
`systemctl daemon-reload` (the roles do this).

## 3. Kerberos, SSSD, domain join

Role `identity`. The order matters: the TERMSRV keys come from the join.

### 3.1 Packages and krb5.conf

```sh
apt install sssd sssd-kcm sssd-tools libnss-sss libpam-sss krb5-user adcli realmd packagekit
```

fastrdp's own Kerberos client settings are a snippet, the same for every directory
(`krb5-fastrdp.conf.j2`). Files in `/etc/krb5.conf.d` are read first and win over
`/etc/krb5.conf`:

```sh
install -d -o root -g root -m 0755 /etc/krb5.conf.d
```

`/etc/krb5.conf.d/fastrdp` (`root:root 0644`):

```ini
# fastrdp's Kerberos client settings, for every identity provider. /etc/krb5.conf
# includes this directory before its own [libdefaults], so these values win over it
# (also over FreeIPA's default_ccache_name = KEYRING:...).
[libdefaults]
    # One credential cache per login, shared by all processes of that session.
    default_ccache_name = KCM:
    # kinit asks for renewable tickets too, so sssd-kcm can renew them ([kcm] tgt_renewal).
    renew_lifetime = 7d
```

AD and provider `none`: `/etc/krb5.conf` (`root:root 0644`, from `krb5.conf.j2`; realm
and domain are **site**). FreeIPA: skip it, `ipa-client-install` writes this file (3.6).

```ini
# Realm settings (identity provider ad or none). fastrdp's own client settings are in
# /etc/krb5.conf.d/fastrdp; files there are read first, so their values win.
includedir /etc/krb5.conf.d/

[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
    udp_preference_limit = 0

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

The directory must exist: libkrb5 refuses a configuration whose `includedir` is missing.

### 3.2 TERMSRV keytab check

FreeRDP's Kerberos acceptor needs **AES** keys; RC4 tickets fail
([windows-clients.md §3.4](windows-clients.md#34-credssp-version-nonce-pubkeyauth-token-formats-q3)).
`fastrdp-broker` installs a checker, `/usr/sbin/fastrdp-termsrv-check` (source
`broker/sbin/fastrdp-termsrv-check`, `man fastrdp-termsrv-check`), which the role and the
smoke test (section 13) call:

```sh
fastrdp-termsrv-check [-k KEYTAB] PRINCIPAL...    # default keytab: /etc/fastrdp/termsrv.keytab
```

It prints `ok`/`FAIL` per principal (an AES key at the newest kvno; without `@REALM` any
realm, case-insensitive) and a fix hint, and exits 1 if one fails. Nothing to configure:
the default keytab can be changed in `/etc/fastrdp/termsrv.conf` (3.4).

### 3.3 Join Active Directory

`roles/identity/tasks/ad.yml`. Skip the join if `realm list --name-only` already shows the domain.

```sh
realm join --membership-software=adcli --client-software=sssd \
    --user=Administrator example.com          # asks for the join password
```

TERMSRV principals with AES keys. adcli writes keytab entries and
`msDS-SupportedEncryptionTypes` for the enctypes its Kerberos configuration permits.
The role therefore puts a small file **in front of** `/etc/krb5.conf`, only for the
`adcli` runs. `/etc/fastrdp/krb5-termsrv-enctypes.conf` (`root:root 0644`):

```ini
[libdefaults]
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
```

(`fastrdp_termsrv_enctypes`; adding `arcfour-hmac` gives `0x1C` instead of `0x18`.
adcli never widens an existing value: an account set to RC4 only must be changed in AD
first.) Then check the host keytab. Register the SPNs only if a principal or its AES
key is missing (first run, or RC4-only keys). This sets a new machine password, which
re-keys the account with AES:

```sh
fastrdp-termsrv-check -k /etc/krb5.keytab TERMSRV/rdp1.example.com TERMSRV/RDP1 ||
KRB5_CONFIG=/etc/fastrdp/krb5-termsrv-enctypes.conf:/etc/krb5.conf \
    adcli update --domain=example.com --computer-password-lifetime=0 \
    --add-service-principal=TERMSRV/rdp1.example.com \
    --add-service-principal=TERMSRV/RDP1
fastrdp-termsrv-check -k /etc/krb5.keytab TERMSRV/rdp1.example.com TERMSRV/RDP1
```

The machine account may add SPNs for its own names only; other DNS names need the
join account (3.8).

`/etc/sssd/sssd.conf` (`root:root 0600`, `sssd-ad.conf.j2`; replaces the file
`realm join` wrote):

```ini
[sssd]
domains = example.com
services = nss, pam

[pam]
offline_credentials_expiration = 1

[domain/example.com]
id_provider = ad
access_provider = ad
ad_domain = example.com
krb5_realm = EXAMPLE.COM
realmd_tags = manages-system joined-with-adcli
cache_credentials = true
krb5_store_password_if_offline = true
default_shell = /bin/bash
ldap_id_mapping = true
use_fully_qualified_names = false
fallback_homedir = /home/%u
# Terminal-server sessions run for days: keep session TGTs renewed.
krb5_renewable_lifetime = 7d
krb5_renew_interval = 1h
# Treat the RDP PAM services like Windows RDS ("Allow log on through Remote Desktop Services").
ad_gpo_access_control = permissive
ad_gpo_map_remote_interactive = +fastrdp, +xrdp-sesman, +fastrdp-session
ad_maximum_machine_account_password_age = 30
```

`ad_gpo_access_control` (`fastrdp_ad_gpo_access_control`): start with `permissive`
(denials are only logged in the sssd log). Grant *Allow log on through Remote Desktop
Services* to the RDP users by GPO, check the log, then switch to `enforcing`.

### 3.4 TERMSRV keytab for the proxy (AD)

The proxy runs as `_fastrdp-proxy` and must not read `/etc/krb5.keytab`. It gets a
copy of the `TERMSRV/*` keys only, written by `/usr/sbin/fastrdp-termsrv-keytab` from
`fastrdp-broker` (`broker/sbin/fastrdp-termsrv-keytab`, `man fastrdp-termsrv-keytab`):
`root:_fastrdp-proxy 0640`, replaced atomically, and an error if the host keytab has no
TERMSRV keys.

**Machine-password rotation.** sssd changes the machine password every 30 days
(`ad_maximum_machine_account_password_age`), which writes new keys to
`/etc/krb5.keytab`. The packaged `fastrdp-termsrv-keytab.path` watches that file and
starts `fastrdp-termsrv-keytab.service`, which copies the keys again and restarts the
proxy if it runs. Both units are installed disabled.

**Configure** (only if your paths or group differ from the defaults):
`/etc/fastrdp/termsrv.conf`, a conffile of `fastrdp-broker` with every setting commented
out: `FASTRDP_HOST_KEYTAB` (`/etc/krb5.keytab`), `FASTRDP_TERMSRV_KEYTAB`
(`/etc/fastrdp/termsrv.keytab`), `FASTRDP_TERMSRV_KEYTAB_GROUP` (`_fastrdp-proxy`).
The environment and the options `-s`/`-d`/`-g` override it. Another host keytab also
needs a drop-in for the path unit (`PathChanged=`).

**Enable** the watcher and extract the keys now:

```sh
systemctl enable --now fastrdp-termsrv-keytab.path
fastrdp-termsrv-keytab
```

### 3.5 Ticket renewal, final checks, sssd

All providers. `/etc/sssd/conf.d` (`root:root 0711`), file
`/etc/sssd/conf.d/50-fastrdp.conf` (`root:root 0600`, `sssd-fastrdp.conf.j2`):

```ini
# Ticket renewal for terminal-server sessions (docs/nfs-kerberos-homes.md, Q4).

# sssd-kcm renews every renewable TGT in KCM, including those from `kinit` in a
# session, which sssd's domain renewal does not know (sssd-kcm(8), RENEWALS).
# Options here, not tgt_renewal_inherit: they work for every identity provider.
[kcm]
tgt_renewal = true
krb5_renew_interval = 1h
krb5_renewable_lifetime = 7d
```

FreeIPA only: append the domain options that `ipa-client-install` does not write (AD
has them in `sssd.conf`):

```ini
# ipa-client-install writes sssd.conf without these (AD: sssd-ad.conf.j2 has them).
[domain/example.com]
krb5_renewable_lifetime = 7d
krb5_renew_interval = 1h
```

```sh
install -d -m 0711 /etc/sssd/conf.d             # then write 50-fastrdp.conf
fastrdp-termsrv-check TERMSRV/rdp1.example.com TERMSRV/RDP1    # FreeIPA, none: the FQDN only
systemctl enable sssd
systemctl restart sssd sssd-kcm.service
id alice                                        # a directory user resolves
```

### 3.6 FreeIPA instead of AD

`roles/identity/tasks/ipa.yml`. Instead of 3.3 and 3.4 (the packages of 3.1 stay):

```sh
apt install freeipa-client
ipa-client-install --mkhomedir --domain=example.com --realm=EXAMPLE.COM --principal=admin
```

`ipa-client-install` writes its own `/etc/krb5.conf` and `/etc/sssd/sssd.conf`. Keep
both: the `krb5.conf` carries FreeIPA's PKINIT anchors and sssd's include directory, and
fastrdp only adds `/etc/krb5.conf.d/fastrdp` (3.1, written before the enrolment) and
`conf.d/50-fastrdp.conf` for sssd (3.5). `ipa-client-install` adds
`includedir /etc/krb5.conf.d/` at the top only if the directory exists when it runs; check
it afterwards (the role adds the line if it is missing):

```sh
grep -x 'includedir /etc/krb5.conf.d/' /etc/krb5.conf ||
    sed -i '1i includedir /etc/krb5.conf.d/' /etc/krb5.conf
```

FreeIPA hosts deployed with the v0.1.0 role have the AD-style file of 3.1 instead of the
enrolment's (that role wrote it again on every run), without PKINIT anchors and sssd's
include directory. The role restores an equivalent of `ipa-client-install`'s file once
(`krb5-ipa.conf.j2`); by hand, write that template's content for your realm.

TERMSRV service and keytab. FreeIPA keys are separate from the host keys, so there is
no rotation unit:

```sh
kinit admin
ipa service-show TERMSRV/rdp1.example.com >/dev/null 2>&1 || ipa service-add TERMSRV/rdp1.example.com
ipa-getkeytab -p TERMSRV/rdp1.example.com -k /etc/fastrdp/termsrv.keytab \
    -e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96
# the short name (and other DNS names, 3.8) as principal aliases; they share the keys
ipa service-add-principal TERMSRV/rdp1.example.com TERMSRV/rdp1
kdestroy
chown root:_fastrdp-proxy /etc/fastrdp/termsrv.keytab && chmod 0640 /etc/fastrdp/termsrv.keytab
fastrdp-termsrv-check TERMSRV/rdp1.example.com
```

Run `ipa-getkeytab` once only: every run creates new keys and invalidates the old
keytab (the role skips it when `/etc/fastrdp/termsrv.keytab` exists). The role also
keeps a marker `/etc/fastrdp/.termsrv-aliases` with the registered aliases; it only
matters if Ansible manages the host later.

Access control: the roles do not touch HBAC. If the `allow_all` rule is disabled, allow
the RDP users for the PAM services `fastrdp`, `xrdp-sesman` and `fastrdp-session` on this host.

### 3.7 MIT KDC or other directory (provider `none`)

`roles/identity/tasks/none.yml`: there is no join. Provide before you continue:

- `/etc/fastrdp/termsrv.keytab` with AES keys for `TERMSRV/rdp1.example.com@EXAMPLE.COM`
  (e.g. `kadmin -q "ktadd -k termsrv.keytab -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal TERMSRV/rdp1.example.com"`
  on the KDC), `root:_fastrdp-proxy 0640`;
- `/etc/sssd/sssd.conf` (`root:root 0600`) for your directory; sssd reads `conf.d/`
  only when `sssd.conf` exists.

Then 3.5 with the FQDN principal only.

### 3.8 DNS aliases (`fastrdp_termsrv_aliases`)

Only if clients type another name for this host, e.g. `rdp.example.com`. An alias
belongs to one host; a name shared by several hosts needs a service account and a
distributed keytab ([windows-clients.md §3.2](windows-clients.md#32-spn-keytab-names-q2)).

- AD (needs the join account):

  ```sh
  dir=$(mktemp -d); export KRB5CCNAME=FILE:$dir/cc
  kinit Administrator@EXAMPLE.COM
  KRB5_CONFIG=/etc/fastrdp/krb5-termsrv-enctypes.conf:/etc/krb5.conf \
      adcli update --domain=example.com --login-ccache="$KRB5CCNAME" \
      --add-service-principal=TERMSRV/rdp.example.com
  kdestroy; rm -rf "$dir"; unset KRB5CCNAME
  fastrdp-termsrv-keytab
  fastrdp-termsrv-check TERMSRV/rdp1.example.com TERMSRV/RDP1 TERMSRV/rdp.example.com
  ```

- FreeIPA: `ipa service-add-principal TERMSRV/rdp1.example.com TERMSRV/rdp.example.com`
  (no new keytab entries).
- Put the alias into the front certificate's subjectAltName as well (section 4).

## 4. Front TLS certificate

Role `base`. The proxy presents `/etc/fastrdp/front.crt` and `/etc/fastrdp/front.key`.

**CA-provided (production):** a certificate whose SAN contains the FQDN (plus short name
and aliases), full chain, PEM:

```sh
install -o root -g _fastrdp-proxy -m 0644 rdp1.example.com.fullchain.pem /etc/fastrdp/front.crt
install -o root -g _fastrdp-proxy -m 0640 rdp1.example.com.key /etc/fastrdp/front.key
```

**Self-signed (lab only):** SAN = FQDN, short name and aliases (`fastrdp_front_cert_san`).
The role does not replace an existing `front.crt`.

```sh
openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -subj "/CN=rdp1.example.com" -addext "subjectAltName=DNS:rdp1.example.com,DNS:rdp1" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout /etc/fastrdp/front.key -out /etc/fastrdp/front.crt
chown root:_fastrdp-proxy /etc/fastrdp/front.key && chmod 0640 /etc/fastrdp/front.key
```

After replacing the certificate later: `systemctl restart fastrdp-proxy` (and
section 15.2 for the web path, which pins its fingerprint).

## 5. Firewall and kernel settings

Role `base`. Back-ends listen on loopback with broker-issued credentials; only the
proxy (and root) may connect to them.

| Port | Who | Rule |
|---|---|---|
| TCP 3389 | clients → proxy | your site policy (e.g. only from the VPN) |
| TCP 443, 80 | browsers → nginx | web access only |
| TCP 3390, 33900-34899 | proxy → back-ends, loopback | nftables table `inet fastrdp` below |
| outbound | KDC (88), LDAP (389/636, AD 3268), DNS, NTP; privacyIDEA/IdP (443) | as needed |

`/etc/nftables.d/fastrdp.nft` (`root:root 0644`, `nftables-fastrdp.nft.j2`; ports from
`fastrdp_xrdp_port` and `fastrdp_backend_port_range`):

```
# Back-end RDP servers (xrdp, g-r-d, KRdp) listen on loopback with broker-issued
# credentials. Only the proxy (and root) may connect to them; nothing from outside.
table inet fastrdp
delete table inet fastrdp
table inet fastrdp {
    set backend_ports {
        type inet_service
        flags interval
        elements = { 3390, 33900-34899 }
    }

    chain input {
        type filter hook input priority filter; policy accept;
        # only new connections: replies to outgoing connections may use these ports too
        iifname != "lo" tcp dport @backend_ports ct state new drop
    }

    chain output {
        type filter hook output priority filter; policy accept;
        oifname "lo" tcp dport @backend_ports ct state new meta skuid != { "_fastrdp-proxy", "root" } reject with tcp reset
    }
}
```

`/etc/nftables.d/fastrdp-front.nft` (`root:root 0644`, role `freerdp_proxy`; written
once, then yours) is a placeholder for the inbound policy on 3389:

```
# Placeholder: add your site's inbound policy for TCP 3389 here
# (e.g. only from the VPN/NetBird range). The fastrdp table only restricts back-end ports.
```

Back-end ports must never be picked by the kernel as ephemeral ports.
`/etc/sysctl.d/60-fastrdp.conf` (`root:root 0644`):

```
# Back-end ports are allocated by fastrdp-brokerd, never by the kernel.
net.ipv4.ip_local_reserved_ports = 3390,33900-34899
```

```sh
install -d -m 0755 /etc/nftables.d                # then write the two .nft files
grep -qxF 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf ||
    echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
systemctl enable --now nftables && systemctl reload nftables
nft list table inet fastrdp
sysctl -p /etc/sysctl.d/60-fastrdp.conf
```

The distribution's `/etc/nftables.conf` starts with `flush ruleset`: if ufw or
firewalld manages the host firewall, load the fastrdp table through it instead.

Optional (`fastrdp_proc_hidepid: true`): hide other users' processes. Put
`proc /proc proc defaults,hidepid=invisible 0 0` into `/etc/fstab` (replacing an
existing `proc /proc` line), then `mount -o remount /proc`.

## 6. GPU

Role `gpu`; background in [performance.md](performance.md) and
[desktop-matrix.md](desktop-matrix.md#gpu-notes). Find the GPU stack first
(`fastrdp_gpu: auto` does the same; set `nvidia`, `mesa` or `none` to override):

```sh
apt install pciutils
lspci -nn -d ::0300; lspci -nn -d ::0302       # [10de:...] nvidia, [8086:...]/[1002:...] mesa, else none
```

Packages per stack (`fastrdp_gpu_packages` in `roles/gpu/defaults/main.yml`):

| Stack | Packages |
|---|---|
| every stack, `none` included | `libgl1-mesa-dri`: Mesa's llvmpipe, the software GL/EGL renderer that sessions without a usable GPU fall back to (GNOME Shell/KWin headless, GL apps under xorgxrdp without glamor). The desktops pull it in anyway. |
| `mesa` (Intel/AMD) | `mesa-vulkan-drivers va-driver-all vainfo vulkan-tools mesa-utils` (VA-API for xrdp's `h264_vaapi`, Vulkan, diagnostics) |
| `nvidia` | `vulkan-tools mesa-utils` (diagnostics) plus the NVIDIA driver below |

```sh
apt install libgl1-mesa-dri                                                # none
apt install libgl1-mesa-dri mesa-vulkan-drivers va-driver-all vainfo vulkan-tools mesa-utils   # mesa
apt install libgl1-mesa-dri vulkan-tools mesa-utils                        # nvidia
```

The role opens the render nodes on every stack (no render node exists without a GPU):

`/etc/udev/rules.d/70-fastrdp-render.rules` (`root:root 0644`; remote sessions have no
seat, so logind never grants render-node ACLs):

```
SUBSYSTEM=="drm", KERNEL=="renderD*", MODE="0666"
```

```sh
udevadm control --reload-rules && udevadm trigger --subsystem-match=drm
```

**NVIDIA** only:

```sh
ubuntu-drivers install                          # Ubuntu
apt install nvidia-driver nvidia-vulkan-icd     # Debian (non-free enabled)
```

`/etc/modprobe.d/fastrdp-nvidia.conf` (`root:root 0644`), then **reboot**:

```
# GNOME/KWin headless sessions need nvidia-drm KMS (GBM back-end).
options nvidia-drm modeset=1 fbdev=1
# Keep VRAM allocations across suspend of idle GPUs.
options nvidia NVreg_PreserveVideoMemoryAllocations=1
```

VirtualGL (`fastrdp_virtualgl`, default on with NVIDIA: X11 apps reach the GPU through `vglrun`):

```sh
curl -fsSLo /var/cache/fastrdp-virtualgl_3.1.5_amd64.deb \
    https://github.com/VirtualGL/virtualgl/releases/download/3.1.5/virtualgl_3.1.5_amd64.deb
echo "df3f7788ce41b182a47c0d298e5cd6d2d63579522cb41825970b7726e825485e  /var/cache/fastrdp-virtualgl_3.1.5_amd64.deb" | sha256sum -c
apt install /var/cache/fastrdp-virtualgl_3.1.5_amd64.deb
```

`/etc/profile.d/fastrdp-virtualgl.sh` (`root:root 0644`):

```sh
# vglrun renders through EGL on the GPU's DRM device, not a separate X server.
export VGL_DISPLAY=egl
```

The xrdp files that depend on the GPU stack are in section 10 (`gfx.toml`, `xorg.conf`).

## 7. Desktops

Role `desktops`. XFCE (`--no-install-recommends` like the role):

```sh
apt install --no-install-recommends dbus-x11 xauth x11-xserver-utils xdg-utils fonts-noto-core \
    xfce4 xfce4-goodies
apt remove light-locker xscreensaver            # no screen lockers: the RDP client locks
test -f /usr/share/xsessions/xfce.desktop       # the broker's xsession name
```

Other desktops (`roles/desktops/defaults/main.yml`); each needs a `[desktops.<name>]`
table in `broker.toml` (section 9):

| Desktop | Packages (`--no-install-recommends`) | broker.toml | More |
|---|---|---|---|
| `mate` | `mate-desktop-environment-core` | `backend = "xrdp"`, `xsession = "mate"` | [backends/xrdp.md](backends/xrdp.md) |
| `cinnamon` | `cinnamon-core` | `backend = "xrdp"`, `xsession = "cinnamon"` | |
| `lxqt` | `lxqt-core` | `backend = "xrdp"`, `xsession = "lxqt"` | |
| `plasma-x11` | `plasma-desktop plasma-session-x11 kwin-x11` | `backend = "xrdp"`, `xsession = "plasmax11"` | |
| `sway`, `labwc`, `wayfire` | `sway swaybg foot` / `labwc foot` / `wayfire foot`, plus `xwayland wlr-randr wl-clipboard xclip x11-utils x11-xkb-utils python3` | `backend = "xrdp"`, `xsession = "fastrdp-sway"` (`fastrdp-labwc`, `fastrdp-wayfire`) | [backends/wlroots.md](backends/wlroots.md); launcher and session files come with `fastrdp-session` |
| `gnome` | role `gnome_rd`, below | `backend = "gnome"` | [backends/gnome.md](backends/gnome.md) |
| `plasma` (Wayland) | role `plasma_krdp`, below | `backend = "plasma"` | [backends/plasma.md](backends/plasma.md) |

**GNOME** (`roles/gnome_rd`; needs GDM 50+ with `gnome-headless-session@.service`):

```sh
apt install --no-install-recommends gdm3 gnome-shell gnome-session gnome-remote-desktop \
    gnome-control-center gnome-console nautilus xwayland
test -f /usr/lib/systemd/system/gnome-headless-session@.service
systemctl enable --now gdm.service
systemctl disable --now gnome-remote-desktop.service   # the broker starts per-user headless g-r-d
```

`/etc/dconf/db/local.d/50-fastrdp` (`root:root 0644`), then `dconf update`:

```ini
[org/gnome/desktop/screensaver]
lock-enabled=false
[org/gnome/desktop/session]
idle-delay=uint32 0
[org/gnome/desktop/interface]
enable-animations=false
```

**Plasma Wayland** (`roles/plasma_krdp`; launcher, unit, PAM stack and KWin drop-in
come with `fastrdp-session`):

```sh
apt install --no-install-recommends plasma-desktop plasma-workspace kwin-wayland krdp \
    xwayland konsole dolphin
systemctl daemon-reload
```

`/etc/xdg/kscreenlockerrc` and `/etc/xdg/kdeglobals` (`root:root 0644`):

```ini
[Daemon]
Autolock=false
LockOnResume=false
```

```ini
[KDE]
AnimationDurationFactor=0
```

## 8. Tuning

Role `tuning`, defaults ([performance.md](performance.md#tuning-knobs-ansible-role-tuning)).

```sh
echo tcp_bbr > /etc/modules-load.d/fastrdp-bbr.conf
modprobe tcp_bbr
```

`/etc/sysctl.d/61-fastrdp-tcp.conf` (`root:root 0644`), then
`sysctl -p /etc/sysctl.d/61-fastrdp-tcp.conf`:

```
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

Resource limits (`limits.conf.j2`): three drop-ins named `50-fastrdp.conf`
(`root:root 0644`), then `systemctl daemon-reload`. Add `CPUQuota=` / `MemoryMax=` lines
for per-user limits (`fastrdp_user_cpu_quota`, `fastrdp_user_memory_max`) or the xrdp
daemon cap (`fastrdp_xrdp_cpu_quota`, `fastrdp_xrdp_memory_max`).

| File | Content |
|---|---|
| `/etc/systemd/system/user-.slice.d/50-fastrdp.conf` | `[Slice]`, `CPUWeight=100`, `TasksMax=4096` |
| `/etc/systemd/system/fastrdp-plasma@.service.d/50-fastrdp.conf` | `[Service]`, `CPUWeight=100`, `TasksMax=4096` |
| `/etc/systemd/system/xrdp.service.d/50-fastrdp.conf` | `[Service]`, `CPUWeight=100` |

For example the first one:

```ini
# Every user-UID.slice: all processes of a user's xrdp/X11 and GNOME sessions.
[Slice]
CPUWeight=100
TasksMax=4096
```

`/etc/fastrdp/session.env` (`root:root 0644`, read by the Plasma launcher): with the
defaults it has only comments. `fastrdp_krdp_encoder` and `fastrdp_krdp_quality` become
`KPIPEWIRE_FORCE_ENCODER=<encoder>` and `FASTRDP_KRDP_QUALITY=<0-100>`.

## 9. Broker

Role `broker`. `/etc/fastrdp/broker.toml` (`root:root 0600`, `broker.toml.j2`):

```toml
[broker]
proxy_user = "_fastrdp-proxy"
socket_group = "_fastrdp-broker"
port_range = [33900, 34899]
session_tgt = "auto"

[auth]
realms = ["EXAMPLE.COM"]
strip_realm = true
pam_service = "fastrdp"
allow_groups = []
allow_tls_password_login = true

[mfa]
mode = "none"
exempt_groups = []
otp_lengths = [6]
yubikey_otp = true
nla_kdc_enforced = false
reconnect_grace = 0
reconnect_grace_same_address = true

[mfa.privacyidea]
url = ""
realm = ""
ca_file = ""
verify_tls = true
service_user = ""
service_password_file = "/etc/fastrdp/privacyidea-service.secret"

[network]
# Connection type the proxy sends to xrdp (encoder profile) for clients that ask for
# auto-detection or send none: lan inside lan_networks, else xrdp_autodetect_profile.
lan_networks = []
xrdp_autodetect_profile = "wan"

[defaults]
desktop ="xfce"
geometry = "1920x1080"

[defaults.groups]

[desktops.xfce]
backend = "xrdp"
xsession = "xfce"

[web]
enabled = false
gateway_user = "_fastrdp-web"
# guacd runs with host networking and connects to the proxy via loopback
allowed_clients = ["127.0.0.1", "::1"]

[backends.xrdp]
port = 3390
listener_user = "root"   # xrdp binds as root, then drops to runtime_user
```

Values to change:

| Key | Role variable | Notes |
|---|---|---|
| `[auth] realms` | `fastrdp_realm` (upper case) | **site** |
| `[auth] allow_groups` | `fastrdp_allow_groups` | e.g. `["rdp-users"]`; `[]` = every user who can authenticate |
| `[auth] allow_tls_password_login` | `fastrdp_allow_tls_logins` | `false` = NLA only; keep `ServerTlsSecurity`/`AllowTls` in `proxy.ini` consistent (section 11) |
| `[broker] session_tgt` | `fastrdp_session_tgt` | `auto`, `required`, `off` ([nfs-kerberos-homes.md](nfs-kerberos-homes.md)) |
| `[network] lan_networks` | `fastrdp_lan_networks` | client CIDRs as the server sees them, e.g. `["10.0.0.0/8", "2001:db8::/32"]`: auto-detect clients from there get the uncapped `lan` profile |
| `[network] xrdp_autodetect_profile` | `fastrdp_xrdp_autodetect_profile` | `lan`, `wan`, `broadband_high`, `satellite`, `broadband_low`, `modem`, `default` ([performance.md](performance.md#bitrate-profile-of-x11-xrdp-sessions)); keep `[x264.autodetect]` in `gfx.toml` the same |
| `[defaults] desktop`, `geometry`; `[defaults.groups]` | `fastrdp_default_desktop`, `fastrdp_default_geometry`, `fastrdp_group_desktops` | `[defaults.groups]` lines look like `"rdp-kde" = "plasma"` |
| `[desktops.<name>]` | `fastrdp_desktops`, `fastrdp_desktop_labels`, `fastrdp_desktop_groups` | one table per desktop (section 7); optional `label = "..."`, `groups = [...]` |
| `[mfa]`, `[mfa.privacyidea]` | `fastrdp_mfa_*`, `fastrdp_privacyidea_*` | section 15.1 |
| `[web] enabled` | `fastrdp_web_enabled` | section 15.2 |
| `port_range`, `[backends.xrdp] port` | `fastrdp_backend_port_range`, `fastrdp_xrdp_port` | must match nftables, sysctl and `xrdp.ini` |

Other keys and their defaults: `broker/brokerd/fastrdp_broker/config.py` and the
example in `/usr/share/doc/fastrdp-broker/examples/`. Validate:

```sh
fastrdp-brokerd --check
```

## 10. xrdp

Role `xrdp`. The `postinst` of `fastrdp-xrdp` has already created the loopback
certificate; the role enforces its modes:

```sh
chown root:xrdp /etc/xrdp/key.pem /etc/xrdp/cert.pem
chmod 0640 /etc/xrdp/key.pem && chmod 0644 /etc/xrdp/cert.pem
```

The four files below are `root:root 0644`. `fastrdp-xrdp` does not ship them as
conffiles (xrdp has no drop-in directory for them): its `postinst` creates them from
upstream's defaults in `/usr/share/fastrdp-xrdp/default-config/` only where they are
missing, so package upgrades never overwrite your versions and dpkg never asks. The same
holds for `startwm.sh` and `/etc/pam.d/xrdp-sesman` further down.

`/etc/xrdp/xrdp.ini` (`xrdp.ini.j2`; `port` = `fastrdp_xrdp_port`, `h264_frame_interval` = 1000 / `fastrdp_x264_fps`):

```ini
; xrdp is an internal back-end: loopback only, reached through freerdp-proxy,
; which logs in with a one-time broker token (no login screen, no fallbacks).
[Globals]
ini_version=1
fork=true
port=tcp://127.0.0.1:3390
runtime_user=xrdp
runtime_group=xrdp
tcp_nodelay=true
tcp_keepalive=true
security_layer=tls
crypt_level=high
certificate=/etc/xrdp/cert.pem
key_file=/etc/xrdp/key.pem
ssl_protocols=TLSv1.2, TLSv1.3
autorun=Xorg
require_credentials=true
hidelogwindow=true
allow_channels=true
allow_multimon=true
bitmap_cache=true
bitmap_compression=true
bulk_compression=true
max_bpp=32
new_cursors=true
use_fastpath=both

[Logging]
LogFile=xrdp.log
LogLevel=INFO
EnableSyslog=true

[Channels]
rdpdr=true
rdpsnd=true
drdynvc=true
cliprdr=true
rail=true
xrdpvr=true

[Xorg]
name=Xorg
lib=libxup.so
username=ask
password=ask
port=-1
code=20
; Frame capture interval (ms): 16 = up to 60 fps for H.264
h264_frame_interval=16
rfx_frame_interval=32
normal_frame_interval=40
```

`/etc/xrdp/sesman.ini` (`sesman.ini.j2`; `MaxSessions` = `fastrdp_xrdp_max_sessions`,
`DisconnectedTimeLimit` = 60 × `fastrdp_xrdp_disconnected_time_limit` minutes, 0 = never):

```ini
[Globals]
; The broker decides the desktop; users cannot override it with ~/startwm.sh.
EnableUserWindowManager=false
UserWindowManager=startwm.sh
DefaultWindowManager=startwm.sh
ReconnectScript=reconnectwm.sh

[Security]
AllowRootLogin=false
MaxLoginRetry=1
; Group checks happen in the broker (fastrdp_allow_groups) and in SSSD.
AlwaysGroupCheck=false
RestrictOutboundClipboard=none
RestrictInboundClipboard=none

[Sessions]
X11DisplayOffset=10
MaxSessions=100
KillDisconnected=false
DisconnectedTimeLimit=0
IdleTimeLimit=0
; Default: one session per user and colour depth; reconnects resize it.
Policy=Default

[Logging]
LogFile=xrdp-sesman.log
LogLevel=INFO
EnableSyslog=true

[Xorg]
; The real server binary, not the setuid wrapper: no Xwrapper.config needed.
param=/usr/lib/xorg/Xorg
param=-config
param=xrdp/xorg.conf
param=-noreset
param=-nolisten
param=tcp
param=-logfile
param=.xorgxrdp.%s.log

[Chansrv]
FuseMountName=thinclient_drives
FileUmask=077

[ChansrvLogging]
LogLevel=INFO
EnableSyslog=true

[SessionVariables]
PULSE_SCRIPT=/etc/xrdp/pulse/default.pa
```

`/etc/xrdp/gfx.toml` (`gfx.toml.j2`), GPU stack `none` (encoder `x264`):

```toml
# GFX pipeline codecs for xrdp, see gfx.toml(5). H.264 first (AVC420), RFX fallback.
[codec]
order = [ "H.264", "RFX" ]
h264_encoder = "x264"

# x264: always configured, it is also the software path when H.264 is x264
[x264.default]
preset = "ultrafast"
tune = "zerolatency"
profile = "main"
vbv_max_bitrate = 0
vbv_buffer_size = 0
fps_num = 60
fps_den = 1
threads = 2

# Per connection type (client "network:" setting, or the broker's choice for auto-detect)

[x264.lan]

[x264.wan]
vbv_max_bitrate = 15_000
vbv_buffer_size = 1_500

[x264.broadband_high]
preset = "superfast"
vbv_max_bitrate = 8_000
vbv_buffer_size = 800

[x264.satellite]
preset = "superfast"
vbv_max_bitrate = 5_000
vbv_buffer_size = 500

[x264.broadband_low]
preset = "veryfast"
vbv_max_bitrate = 1_600
vbv_buffer_size = 66

[x264.modem]
preset = "fast"
vbv_max_bitrate = 1_200
vbv_buffer_size = 50

# Auto-detect (type 7, mstsc's default) = the wan profile
# (fastrdp_xrdp_autodetect_profile). xrdp 0.10.6.1 does not read this section: it
# encodes type 7 like lan. The proxy therefore sends xrdp the profile's own type instead
# (broker.toml [network]); this copy keeps an xrdp that honours it consistent.
[x264.autodetect]
vbv_max_bitrate = 15_000
vbv_buffer_size = 1_500
```

With a GPU (`fastrdp_xrdp_h264_encoder: auto`) the FFmpeg encoder comes first:
`h264_vaapi` for Intel/AMD (`mesa`), `h264_nvenc` for NVIDIA. Replace the
`h264_encoder = "x264"` line with the block below and keep the x264 sections (the
fallback). `[ffmpeg.autodetect]` repeats the profile of `xrdp_autodetect_profile`
(here `wan`):

```toml
# FFmpeg hardware encoder (fastrdp xrdp patch); falls back to libx264 at start-up
# if the GPU, driver or library is not usable.
h264_encoder = "ffmpeg"

[ffmpeg]
encoder = "h264_vaapi"
device = "/dev/dri/renderD128"
fallback = "libx264"

[ffmpeg.default]
qp = 23
gop = 300
fps_num = 60
fps_den = 1

[ffmpeg.lan]

[ffmpeg.wan]
bitrate = 12_000
max_bitrate = 15_000

[ffmpeg.broadband_high]
bitrate = 6_000
max_bitrate = 8_000

[ffmpeg.satellite]
bitrate = 4_000
max_bitrate = 5_000

[ffmpeg.broadband_low]
bitrate = 1_400
max_bitrate = 1_600

[ffmpeg.modem]
bitrate = 1_000
max_bitrate = 1_200

[ffmpeg.autodetect]
bitrate = 12_000
max_bitrate = 15_000
```

`/etc/X11/xrdp/xorg.conf` (`xorg.conf.j2`), software rendering:

```
# xorgxrdp virtual X server (software rendering)
Section "ServerLayout"
    Identifier "X11 Server"
    Screen "Screen (xrdpdev)"
    InputDevice "xrdpMouse" "CorePointer"
    InputDevice "xrdpKeyboard" "CoreKeyboard"
EndSection

Section "ServerFlags"
    Option "DefaultServerLayout" "X11 Server"
    Option "DontVTSwitch" "on"
    Option "AutoAddDevices" "off"
    Option "AutoAddGPU" "off"
EndSection

Section "Module"
    Load "dbe"
    Load "ddc"
    Load "extmod"
    Load "glx"
    Load "int10"
    Load "record"
    Load "vbe"
    Load "xorgxrdp"
    Load "fb"
EndSection

Section "InputDevice"
    Identifier "xrdpKeyboard"
    Driver "xrdpkeyb"
EndSection

Section "InputDevice"
    Identifier "xrdpMouse"
    Driver "xrdpmouse"
EndSection

Section "Monitor"
    Identifier "Monitor"
    Option "DPMS"
    HorizSync 30-80
    VertRefresh 60-75
    ModeLine "1920x1080" 138.500 1920 1968 2000 2080 1080 1083 1088 1111 +hsync -vsync
    ModeLine "1280x720" 74.25 1280 1720 1760 1980 720 725 730 750 +HSync +VSync
    Modeline "1368x768" 72.25 1368 1416 1448 1528 768 771 781 790 +hsync -vsync
    Modeline "1600x900" 119.00 1600 1696 1864 2128 900 901 904 932 -hsync +vsync
EndSection

Section "Device"
    Identifier "Video Card (xrdpdev)"
    Driver "xrdpdev"
EndSection

Section "Screen"
    Identifier "Screen (xrdpdev)"
    Device "Video Card (xrdpdev)"
    GPUDevice ""
    Monitor "Monitor"
    DefaultDepth 24
    SubSection "Display"
        Depth 24
        Modes "640x480" "800x600" "1024x768" "1280x720" "1280x1024" "1600x900" "1920x1080"
    EndSubSection
EndSection
```

Intel/AMD (`mesa`, glamor): add three options to the `Device` section. NVIDIA keeps
software rendering in Xorg (VirtualGL, section 6) unless you try the experimental
`fastrdp_xorgxrdp_nvidia_glamor`, which adds ` nvidia-drm` to the allow list:

```
Section "Device"
    Identifier "Video Card (xrdpdev)"
    Driver "xrdpdev"
    Option "DRMDevice" "/dev/dri/renderD128"
    Option "DRI3" "1"
    Option "DRMAllowList" "amdgpu i915 xe msm radeon"
EndSection
```

Session start script and token-only PAM stack, copied from `fastrdp-session`. Copy
them again after `fastrdp-session` upgrades (the role does it on every run):

```sh
install -o root -g root -m 0755 /usr/libexec/fastrdp/startwm.sh /etc/xrdp/startwm.sh
install -o root -g root -m 0644 /usr/share/fastrdp-session/pam.d/xrdp-sesman /etc/pam.d/xrdp-sesman
```

The PAM stacks of the broker (`/etc/pam.d/fastrdp`, `fastrdp-tgt`) and of Plasma
sessions (`fastrdp-session`) come with the packages and need no change; they call
`pam_sss` (section 3).

## 11. Proxy

Role `freerdp_proxy`. `/etc/fastrdp/proxy.ini` (`root:_fastrdp-proxy 0640`, `proxy.ini.j2`):

```ini
; freerdp-proxy3 front-end. Every login goes through the fastrdp module:
; NLA (Kerberos) or TLS credentials -> fastrdp-brokerd (account, groups, MFA,
; session start) -> back-end chosen by the broker.
[Server]
Host=0.0.0.0
Port=3389

[Target]
; Targets come from the broker (ServerFetchTargetAddr), never from client routing tokens.
FixedTarget=false
; Back-ends are loopback-only; the broker checks the listener's uid before routing
; and nftables lets only this service connect to them.
CertificatePolicy=allow
TlsSecLevel=1
SmartcardAuth=false

[Codecs]
RFX=true
NSC=true

[Channels]
GFX=true
DisplayControl=true
Clipboard=true
AudioInput=true
AudioOutput=true
DeviceRedirection=true
VideoRedirection=true
CameraRedirection=true
RemoteApp=false
PassthroughIsBlacklist=true
Passthrough=
Intercept=

[Input]
Keyboard=true
Mouse=true
Multitouch=true

[Security]
ServerNlaSecurity=true
ServerTlsSecurity=true
ServerRdpSecurity=false
ServerExtSecurity=false
; per-target values are set by the module (TLS for xrdp, NLA for g-r-d/KRdp)
ClientNlaSecurity=true
ClientTlsSecurity=true
ClientRdpSecurity=false
ClientExtSecurity=false
ClientAllowFallbackToTls=false

[Plugins]
Modules=fastrdp
Required=fastrdp

[Certificates]
CertificateFile=/etc/fastrdp/front.crt
PrivateKeyFile=/etc/fastrdp/front.key

[FastRDP]
BrokerSocket=/run/fastrdp/broker.sock
Timeout=120
; TLS logins are needed for password+OTP clients and for the web path (guacd has no
; Kerberos); the broker decides which credentials it accepts on them.
AllowTls=true
; TLS logins only from these peers (addresses/CIDRs, empty = any): loopback only when TLS
; is there just for guacd (web path without fastrdp_allow_tls_logins).
AllowTlsFrom=
```

`ServerTlsSecurity` and `AllowTls` are `true` if TLS logins (`allow_tls_password_login`)
**or** web access are enabled, else `false`. `AllowTlsFrom` (`fastrdp_tls_login_sources`)
limits TLS (non-NLA) logins to the listed peer addresses: comma-separated IPv4/IPv6
addresses and CIDR ranges, empty = any peer. It is `127.0.0.1,::1` when web access is on
but TLS logins are not (only guacd on loopback needs TLS then), else empty. The module
checks the TCP peer address (IPv4-mapped IPv6 counts as IPv4), not the address the
client claims, before anything reaches the broker, and refuses others with Set Error Info
`ERRINFO_SERVER_DENIED_CONNECTION` (0x7); an unparsable entry is logged and matches
nothing. NLA logins are not affected. `Timeout` (`fastrdp_proxy_broker_timeout`)
must exceed the MFA push timeout; a login whose client disconnects while the broker
still waits (MFA push) is abandoned at once, and the broker stops waiting.
`Port` = `fastrdp_listen_port`.

## 12. Start the services

Same order as `site.yml` (the broker before xrdp and the proxy; its unit also says
`Before=fastrdp-proxy.service xrdp-sesman.service`). chrony, nftables, sssd and (AD)
`fastrdp-termsrv-keytab.path` already run.

```sh
systemctl daemon-reload
systemctl enable --now fastrdp-brokerd.service
systemctl enable --now xrdp-sesman.service xrdp.service
systemctl enable --now fastrdp-proxy.service
systemctl --no-pager status fastrdp-brokerd fastrdp-proxy xrdp-sesman xrdp
```

After a configuration change restart the service that reads it: `broker.toml` →
`fastrdp-brokerd`; `proxy.ini`, `front.*`, `termsrv.keytab` → `fastrdp-proxy`;
`/etc/xrdp/*`, `xorg.conf` → `xrdp-sesman` and `xrdp`; `sssd.conf`, `conf.d` → `sssd`
and `sssd-kcm`.

## 13. Verify

`tests/smoke/check-host.sh` from the repository works on a manually set up host. It
needs root, `fastrdp-termsrv-check` (3.2) and the tools installed above
(`ss`, `nft`, `klist`, `chronyc`, `runuser`, `ldd`, `python3`). It reads the ports from
`proxy.ini` and `broker.toml`.

```sh
# the tag of your release instead of main
curl -fsSLO https://raw.githubusercontent.com/linuxrrze/fast-rdp-server/main/tests/smoke/check-host.sh
bash check-host.sh alice                         # alice: a directory user who may log in
```

Every line must say `ok`; then it prints `fastrdpctl status`. Checks: services
active, proxy on 3389, xrdp on loopback only, broker and token sockets, nftables
table, TERMSRV AES keys and keytab readable by the proxy, proxy module and FreeRDP from
`/opt/fastrdp`, PAM token module, xrdp with x264, `broker.toml` valid, time sync,
back-end port blocked for other users, and for the test user NSS and the PAM account
check. On FreeIPA hosts it checks only `TERMSRV/<fqdn>`.

## 14. First connection

Connect to the FQDN ([client-guide.md](client-guide.md)):

```sh
# FreeRDP 3, Kerberos NLA; /cert:tofu accepts the self-signed certificate once
xfreerdp3 /v:rdp1.example.com /u:alice /d:EXAMPLE.COM /sec:nla /cert:tofu \
    /gfx:avc444 /network:auto /dynamic-resolution +clipboard

# password over TLS (allow_tls_password_login = true)
xfreerdp3 /v:rdp1.example.com /u:alice /sec:tls /cert:tofu /gfx:avc444
```

```bat
mstsc /v:rdp1.example.com
```

Follow a login: `journalctl -f -u fastrdp-proxy -u fastrdp-brokerd -u xrdp-sesman`.
Common failures: [quickstart.md](quickstart.md#troubleshooting-first-runs).

## 15. Optional parts

### 15.1 MFA with privacyIDEA

Role `mfa_privacyidea`; modes and privacyIDEA settings in [auth-matrix.md](auth-matrix.md).

- private CA: `/etc/fastrdp/privacyidea-ca.pem` (`root:root 0644`) and
  `ca_file = "/etc/fastrdp/privacyidea-ca.pem"`;
- service admin for push triggers (`triggerchallenge` right): its password plus a newline
  in `/etc/fastrdp/privacyidea-service.secret` (`root:root 0600`), and `service_user`;
- `broker.toml`: `[mfa] mode` (`otp`, `push`, `otp_or_push`), `exempt_groups`,
  `otp_lengths`; `[mfa.privacyidea] url`, `realm`, `verify_tls`;
- optional: `[mfa] reconnect_grace` (seconds, e.g. `600`; `0` = off) so that reconnects
  after a network drop skip a second factor passed shortly before, bound to the same
  client address unless `reconnect_grace_same_address = false`
  ([auth-matrix.md](auth-matrix.md#reconnect-grace)); `fastrdpctl clear-grace USER`
  revokes it;
- check: `curl -fsS https://pi.example.com/healthz/` from the host; then
  `fastrdp-brokerd --check` and `systemctl restart fastrdp-brokerd`.

### 15.2 Web access (Keycloak + Guacamole)

Role `web_gateway`, design and Keycloak client in [web-access.md](web-access.md) and
[backends/web.md](backends/web.md). There are many steps; render the role's templates
for your values, or use Ansible for this part. In role order:

1. `apt install fastrdp-webgate podman nginx python3-cryptography`.
2. Secrets, generated once with `umask 077`: `openssl rand -hex 32 > /etc/fastrdp/webgate-cookie.secret`,
   `openssl rand -hex 16 > /etc/fastrdp/guacamole-json.key`; the OIDC client secret
   plus a newline in `/etc/fastrdp/webgate-oidc.secret`. All three `root:_fastrdp-web 0640`.
   IdP CA (optional): `/etc/fastrdp/webgate-idp-ca.pem` (0644).
3. `/etc/fastrdp/guacamole.env` (`root:root 0600`): `JSON_SECRET_KEY=<contents of guacamole-json.key>`.
4. `/etc/subuid` and `/etc/subgid`: line `containers:2147483647:2147483648` (podman `UserNS=auto`).
5. `/etc/fastrdp/front.fingerprint` (`root:_fastrdp-web 0640`): `sha256:` + the lower-case
   output of `openssl x509 -in /etc/fastrdp/front.crt -noout -fingerprint -sha256`
   after the `=`. Redo it whenever the front certificate changes.
6. `/etc/fastrdp/webgate.toml` (`root:_fastrdp-web 0640`) from `webgate.toml.j2`
   (example: `/usr/share/doc/fastrdp-webgate/examples/`).
7. Quadlets `/etc/containers/systemd/fastrdp-guacd.container` and
   `fastrdp-guacamole.container` from the role templates.
8. `/etc/nftables.d/fastrdp-web.nft` from `fastrdp-web.nft.j2` (ports 4822, 8080, 8090
   local only); `systemctl reload nftables`.
9. `/etc/nginx/sites-available/fastrdp-web.conf` from `nginx-fastrdp-web.conf.j2`, link
   it into `sites-enabled`, remove `sites-enabled/default`.
10. `broker.toml` `[web] enabled = true`; `proxy.ini` `ServerTlsSecurity=true`, `AllowTls=true`,
    and without TLS logins for RDP clients `AllowTlsFrom=127.0.0.1,::1` (section 11).
11. `systemctl daemon-reload`; `systemctl start fastrdp-guacd fastrdp-guacamole` (quadlets
    are started, not enabled); `systemctl enable --now fastrdp-webgate nginx`; restart
    `fastrdp-brokerd` and `fastrdp-proxy`.

Passkeys on the web path (Keycloak configuration): [passkeys.md](passkeys.md#recipe-a-acrmfa-via-a-forced-flow-recommended).

### 15.3 Kerberized NFS home directories

`roles/identity/tasks/nfs_krb5.yml`, background and the directory-side delegation in
[nfs-kerberos-homes.md](nfs-kerberos-homes.md#a-gssproxy-impersonation-s4u2self--s4u2proxy-recommended):
`apt install nfs-common gssproxy`; `/etc/gssproxy/90-fastrdp-nfs-client.conf` and
`/etc/nfs.conf.d/fastrdp-gssd.conf` (both `root:root 0644`; create `/etc/nfs.conf.d`
if missing) exactly as shown there;
`systemctl enable --now gssproxy`, then `systemctl restart gssproxy rpc-gssd`. The keytab
`/etc/krb5.keytab` must exist (join first).

### 15.4 Smartcards

Nothing to configure on the RDP host: the client gets its ticket by PKINIT and uses
ordinary Kerberos NLA. The KDC side, the MFA policy (`exempt_groups`) and the client
side are in [smartcard-nla.md](smartcard-nla.md).

### 15.5 Passkeys

Web path: 15.2. RDP path (passkey → TGT → NLA) and KDC-enforced MFA for NLA (FreeIPA:
`ipa service-mod TERMSRV/rdp1.example.com --auth-ind=passkey --auth-ind=pkinit`, then
`[mfa] nla_kdc_enforced = true`): [passkeys.md](passkeys.md#kdc-enforced-strong-authentication-for-nla).
The role refuses this on AD unless an AD policy guarantees it.

## Updates

- `apt upgrade` updates the packages. Then restart the fastrdp daemons
  (`systemctl restart fastrdp-brokerd fastrdp-proxy`, and `xrdp-sesman xrdp` in a
  maintenance window) and check them with `systemctl status`.
- The xrdp files of section 10 are yours; upgrades of `fastrdp-xrdp` only update
  upstream's defaults in `/usr/share/fastrdp-xrdp/default-config/`. Compare them after an
  xrdp version change:

  ```sh
  cd /usr/share/fastrdp-xrdp/default-config && for f in $(find . -type f); do diff -u "$f" "/$f"; done
  ```
- After a `fastrdp-session` upgrade copy `startwm.sh` and the PAM stack again (section 10).
- Before upgrading to a new fastrdp release, compare the role files listed at the top
  between the two tags (`git diff v0.1.0 <new tag> -- ansible/roles`) and apply the
  changes here and on your hosts.
