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
| [5 Firewall and kernel settings](#5-firewall-and-kernel-settings) | `roles/base/templates/nftables-fastrdp.nft.j2`, `roles/base/templates/40-fastrdp-power.rules.j2` (power actions), `roles/base/tasks/main.yml`, `roles/freerdp_proxy/tasks/main.yml` (front placeholder) |
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
| Host FQDN / short name (**site**) | `rdp1.example.com` / `rdp1` (AD account `RDP1$`) | `fastrdp_fqdn`, `fastrdp_hostname` (from the facts `fqdn`, `hostname`) |
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
| `fastrdp-proxy-module` | proxy module, `fastrdp-proxy.service` (disabled; sets `KRB5_KTNAME=FILE:/etc/fastrdp/termsrv.keytab` and `WLOG_APPENDER=JOURNALD`, [logs](#12-start-the-services)), user `_fastrdp-proxy` |
| `fastrdp-freerdp3` | FreeRDP in `/opt/fastrdp` (`freerdp-proxy`, `xfreerdp`) |
| `libpam-fastrdp-token` | `pam_fastrdp_token.so` |
| `fastrdp-session` | `/usr/libexec/fastrdp/*` (`startwm.sh`, Plasma and wlroots launchers), `fastrdp-plasma@.service`, `/etc/pam.d/fastrdp-session`, KWin user drop-in, `/usr/share/xsessions/fastrdp-{sway,labwc,wayfire}.desktop`, the token-only xrdp PAM stack as a template in `/usr/share/fastrdp-session/pam.d/xrdp-sesman`, the Kerberos login reminder `/usr/libexec/fastrdp/tgt-notify` with `/etc/xdg/autostart/fastrdp-tgt-notify.desktop` |
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
# fastrdp_sssd_fully_qualified_names: "alice@example.com" instead of "alice".
use_fully_qualified_names = false
# %u is the short name in both modes: switching keeps the home directories. Only for
# users without unixHomeDirectory in AD (that one wins).
fallback_homedir = /home/%u
# Terminal-server sessions run for days: keep session TGTs renewed.
krb5_renewable_lifetime = 7d
krb5_renew_interval = 1h
# Treat the RDP PAM services like Windows RDS ("Allow log on through Remote Desktop Services").
ad_gpo_access_control = permissive
ad_gpo_map_remote_interactive = +fastrdp, +xrdp-sesman, +fastrdp-session, +gdm-autologin
ad_maximum_machine_account_password_age = 30
```

`use_fully_qualified_names` (`fastrdp_sssd_fully_qualified_names`): `true` makes
directory users `alice@example.com`, so a local account `alice` can never stand in for
one; set `[auth] strip_realm = false` in `broker.toml` to match (section 9, and
[auth-matrix.md](auth-matrix.md#short-or-fully-qualified-account-names) for the trade-offs). `%u` in
`fallback_homedir` is the short name either way (sssd.conf(5): `%f` would be the
qualified one), so the home directories stay `/home/alice`.

`ad_gpo_access_control` (`fastrdp_ad_gpo_access_control`): start with `permissive`
(denials are only logged in the sssd log). Grant *Allow log on through Remote Desktop
Services* to the RDP users by GPO, check the log, then switch to `enforcing`.

Home directories: the users' homes are their AD `unixHomeDirectory` (else
`fallback_homedir`), and that path must exist on this host
([nfs-kerberos-homes.md](nfs-kerberos-homes.md#where-homes-are)). Two optional
additions at the end of `[domain/example.com]`:

```ini
# Local homes instead of the directory's unixHomeDirectory (fastrdp_sssd_override_homedir).
override_homedir = /home/%u
# Automount maps from AD (fastrdp_autofs: sssd; nsswitch "automount: files sss").
autofs_provider = ad
```

With `autofs_provider`, also `services = nss, pam, autofs` in `[sssd]`, and the
automounter: `apt install autofs`, the line `automount:      files sss` in
`/etc/nsswitch.conf`, `systemctl restart sssd`, then `systemctl enable --now autofs`
(details and the `files` variant in
[nfs-kerberos-homes.md](nfs-kerberos-homes.md#automounted-homes)).

### 3.4 TERMSRV keytab for the proxy (AD)

The proxy runs as `_fastrdp-proxy` and must not read `/etc/krb5.keytab`. It gets a
copy of the `TERMSRV/*` keys only, written by `/usr/sbin/fastrdp-termsrv-keytab` from
`fastrdp-broker` (`broker/sbin/fastrdp-termsrv-keytab`, `man fastrdp-termsrv-keytab`):
`root:_fastrdp-proxy 0640`, replaced atomically, and an error if the host keytab has no
TERMSRV keys.

The copy also holds the machine account's own entries (`<NAME>$@REALM`), but only those
with the same kvno, enctype and key as a TERMSRV entry: in AD these are the same keys
under the account's name, so the proxy gets no new secret. Windows clients need them:
mstsc starts NLA with Kerberos user-to-user, and the proxy (`fastrdp-freerdp3` ≥
3.32.2-3) answers with the machine account's TGT, which it gets with these entries
([windows-clients.md](windows-clients.md) §3.14). Check:

```sh
klist -k /etc/fastrdp/termsrv.keytab   # TERMSRV/<fqdn>, TERMSRV/<SHORT> and <SHORT>$ at the same kvno
```

The script prints `note: no machine account (<NAME>$) entry with the TERMSRV keys` when
the host keytab has none; then Windows clients cannot log in with Kerberos.

**Machine-password rotation.** sssd changes the machine password every 30 days
(`ad_maximum_machine_account_password_age`), which writes new keys to
`/etc/krb5.keytab`. The packaged `fastrdp-termsrv-keytab.path` watches that file and
starts `fastrdp-termsrv-keytab.service`, which copies the keys again and restarts the
proxy if it runs. Both units are installed disabled.

**Configure** (only if your paths or group differ from the defaults):
`/etc/fastrdp/termsrv.conf`, a conffile of `fastrdp-broker` with every setting commented
out: `FASTRDP_HOST_KEYTAB` (`/etc/krb5.keytab`), `FASTRDP_TERMSRV_KEYTAB`
(`/etc/fastrdp/termsrv.keytab`), `FASTRDP_TERMSRV_KEYTAB_GROUP` (`_fastrdp-proxy`),
`FASTRDP_TERMSRV_KEYTAB_MACHINE` (`yes`; `no` = TERMSRV entries only, Windows clients then
fail). The environment and the options `-s`/`-d`/`-g`/`-n` override it. Another host keytab also
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
# Snippets in conf.d override sssd.conf (sssd.conf(5)).
[domain/example.com]
krb5_renewable_lifetime = 7d
krb5_renew_interval = 1h
# fastrdp_sssd_fully_qualified_names: "alice@example.com" instead of "alice"
use_fully_qualified_names = false
```

Snippets in `conf.d` override the same keys in `sssd.conf`, later files (by name) the
earlier ones, so this one wins over what `ipa-client-install` wrote.
FreeIPA, optional, in the same section: `override_homedir = /home/%u` for local homes
instead of the directory's (`fastrdp_sssd_override_homedir`); for automount maps from
FreeIPA (`fastrdp_autofs: sssd`) `autofs_provider = ipa` and
`ipa_automount_location = default`, plus `, autofs` appended to the `services` line of
the enrolment's `sssd.conf` and the autofs steps of 3.3.

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
  only when `sssd.conf` exists. Its `use_fully_qualified_names` decides whether users
  are `alice` or `alice@example.com`; `[auth] strip_realm` in `broker.toml` must say the
  same (`false` for qualified names, section 9). The role reads your files (`sssd.conf`,
  then `conf.d/*.conf`; the last setting wins, else `default_domain_suffix` qualifies
  names) and fails if they disagree with `fastrdp_sssd_fully_qualified_names`.
  only when `sssd.conf` exists. The home paths it reports must exist on this host:
  `override_homedir = /home/%u` in its domain section for local homes, or autofs
  ([nfs-kerberos-homes.md](nfs-kerberos-homes.md#where-homes-are)).

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

No power off, reboot, suspend, hibernate or halt from RDP sessions (`fastrdp_block_power_actions:
true`, the default; [desktop-matrix.md](desktop-matrix.md#host-safety-power-actions)). Without this
rule every desktop offers these actions, and an admin's password is all it takes. Write
`/etc/polkit-1/rules.d/40-fastrdp-power.rules` (`root:root 0644`, `40-fastrdp-power.rules.j2`;
`adminGroups` from `fastrdp_power_admin_groups`, `allowLocalConsole` from
`fastrdp_power_allow_local_console`). polkitd picks it up without a restart:

```
// fastrdp: users in RDP sessions must not power off, reboot, suspend, hibernate or halt
// the shared host (fastrdp_block_power_actions; docs/desktop-matrix.md#host-safety-power-actions).
// logind's power actions are refused (polkit NO: CanPowerOff and friends answer "no",
// desktops hide or grey out the entries) except for:
//   - root: polkit authorizes uid 0 before any rule (sudo systemctl poweroff works);
//   - members of fastrdp_power_admin_groups: they authenticate as an admin, as before;
//   - with fastrdp_power_allow_local_console: active sessions on a seat (the console).
// Log out, lock, inhibitors and every other action keep their defaults.
// ES5 only: polkitd evaluates rules with duktape.
polkit.addRule(function (action, subject) {
    var actions = [
        "org.freedesktop.login1.power-off",
        "org.freedesktop.login1.power-off-multiple-sessions",
        "org.freedesktop.login1.power-off-ignore-inhibit",
        "org.freedesktop.login1.reboot",
        "org.freedesktop.login1.reboot-multiple-sessions",
        "org.freedesktop.login1.reboot-ignore-inhibit",
        "org.freedesktop.login1.halt",
        "org.freedesktop.login1.halt-multiple-sessions",
        "org.freedesktop.login1.halt-ignore-inhibit",
        "org.freedesktop.login1.suspend",
        "org.freedesktop.login1.suspend-multiple-sessions",
        "org.freedesktop.login1.suspend-ignore-inhibit",
        "org.freedesktop.login1.hibernate",
        "org.freedesktop.login1.hibernate-multiple-sessions",
        "org.freedesktop.login1.hibernate-ignore-inhibit",
        "org.freedesktop.login1.set-reboot-parameter",
        "org.freedesktop.login1.set-reboot-to-firmware-setup",
        "org.freedesktop.login1.set-reboot-to-boot-loader-menu",
        "org.freedesktop.login1.set-reboot-to-boot-loader-entry"
    ];
    var adminGroups = ["sudo"];
    var allowLocalConsole = false;
    var i;

    if (actions.indexOf(action.id) < 0 || subject.user === "root") {
        return polkit.Result.NOT_HANDLED;
    }
    if (allowLocalConsole && subject.local && subject.active) {
        return polkit.Result.NOT_HANDLED;
    }
    for (i = 0; i < adminGroups.length; i++) {
        if (subject.isInGroup(adminGroups[i])) {
            return polkit.Result.AUTH_ADMIN_KEEP;
        }
    }
    return polkit.Result.NO;
});
```

```sh
journalctl -u polkit -b | grep -i 40-fastrdp-power    # no "Error compiling script"
# log in over RDP as a normal user, then (read-only, never powers off):
sudo tests/smoke/check-power-actions.sh alice
```

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
    gnome-control-center gnome-console nautilus xwayland dconf-cli
test -f /usr/lib/systemd/system/gnome-headless-session@.service
systemctl enable --now gdm.service
systemctl disable --now gnome-remote-desktop.service   # the broker starts per-user headless g-r-d
```

The system dconf database is read only through a user profile that names it. If
`/etc/dconf/profile/user` does not exist, create it (`root:root 0644`); if it exists,
make sure it contains the `system-db:local` line:

```
user-db:user
system-db:local
```

`/etc/dconf/db/local.d/50-fastrdp` (`root:root 0644`, `mkdir -p /etc/dconf/db/local.d`
first), then `dconf update`:

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

**Kerberos login reminder** (all desktops; `roles/desktops/tasks/tgt_notify.yml`): a
desktop notification before the session's TGT can no longer be renewed
([nfs-kerberos-homes.md](nfs-kerberos-homes.md#long-running-sessions)). The program and
its autostart entry come with `fastrdp-session` (`wlroots-in-x` starts it for Sway,
labwc and Wayfire). Install the notification tool and write
`/etc/fastrdp/tgt-notify.conf` (`root:root 0644`; without the file the defaults below
apply, `enabled = false` turns it off):

```sh
apt install --no-install-recommends libnotify-bin
```

```toml
enabled = true                 # fastrdp_tgt_notify
thresholds = ["24h", "2h"]     # fastrdp_tgt_notify_thresholds: before renew-until (s m h d)
interval = "10m"               # fastrdp_tgt_notify_interval
notify_expired = true          # fastrdp_tgt_notify_expired
# summary, body, expired_summary, expired_body: own texts (fastrdp_tgt_notify_texts)
# with {left}, {deadline}, {principal}
```

Check as a user in a session: `/usr/libexec/fastrdp/tgt-notify --status`.

**Browsers for Kerberos SSO** (optional; `fastrdp_firefox_deb`, `fastrdp_browser_spnego_domains`).
Snap browsers cannot reach the session TGT in KCM. On Debian, `apt install firefox-esr`. On Ubuntu,
`apt install firefox` installs the snap, so use Mozilla's APT repository instead. Then list the
intranet domains in `/etc/firefox/policies/policies.json` (and for Chromium/Chrome
`/etc/chromium/policies/managed/fastrdp-spnego.json`, `/etc/opt/chrome/policies/managed/fastrdp-spnego.json`).
The commands and the reasons are in
[desktop-matrix.md](desktop-matrix.md#browsers-and-kerberos-sso).

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
# Missing homes are created only below these (fastrdp_home_create_roots; [] = never).
home_create_roots = ["/home"]
# Desktop picker on the proxy's waiting screen (fastrdp_desktop_picker)
desktop_picker = "never"
desktop_picker_timeout = 10
desktop_picker_when_running = "preselect"

[auth]
realms = ["EXAMPLE.COM"]
# false = SSSD names are "alice@example.com" (fastrdp_sssd_fully_qualified_names):
# that name first, so a local account "alice" never shadows the directory user.
strip_realm = true
domains = ["example.com"]
pam_service = "fastrdp"
allow_groups = []
allow_tls_password_login = true

[mfa]
mode = "none"
exempt_groups = []
otp_lengths = [6]
yubikey_otp = true
nla_kdc_enforced = false
kdc_evidence_as_mfa = []
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

# Texts of the proxy's waiting screen (fastrdp_proxy_waiting_screen)
[ui]
language = "en"
language_from_keyboard = true
approve_url = ""
qr_code = true

[backends.xrdp]
port = 3390
listener_user = "root"   # xrdp binds as root, then drops to runtime_user
```

Values to change:

| Key | Role variable | Notes |
|---|---|---|
| `[auth] realms` | `fastrdp_realm` (upper case) | **site** |
| `[auth] allow_groups` | `fastrdp_allow_groups` | e.g. `["rdp-users"]`; `[]` = every user who can authenticate |
| `[auth] strip_realm` | `fastrdp_sssd_fully_qualified_names` (inverted) | `true`: SSSD short names (`alice` is tried before `alice@example.com`); `false`: SSSD `use_fully_qualified_names = true` (the qualified name first). Must match `sssd.conf` (section 3) |
| `[auth] domains` | `fastrdp_domain` (lower case) | SSSD domain names: qualified names are tried with them as well as with the realms (FreeIPA domains may differ from the realm). Group names without `@` in this file also match `group@<domain>` |
| `[auth] allow_tls_password_login` | `fastrdp_allow_tls_logins` | `false` = NLA only; keep `ServerTlsSecurity`/`AllowTls` in `proxy.ini` consistent (section 11) |
| `[broker] session_tgt` | `fastrdp_session_tgt` | `auto`, `required`, `off` ([nfs-kerberos-homes.md](nfs-kerberos-homes.md)) |
| `[broker.session_tgt_groups]` | `fastrdp_session_tgt_groups` | `session_tgt` per group, lines like `"nfs-homes" = "required"` (table only rendered when not empty): members of listed groups get the strictest mode of their groups (`required` > `auto` > `off`), everybody else `session_tgt`; group names as in `allow_groups` ([nfs-kerberos-homes.md](nfs-kerberos-homes.md#c-require-a-typed-password-for-users-with-kerberized-homes)) |
| `[network] lan_networks` | `fastrdp_lan_networks` | client CIDRs as the server sees them, e.g. `["10.0.0.0/8", "2001:db8::/32"]`: auto-detect clients from there get the uncapped `lan` profile |
| `[network] xrdp_autodetect_profile` | `fastrdp_xrdp_autodetect_profile` | `lan`, `wan`, `broadband_high`, `satellite`, `broadband_low`, `modem`, `default` ([performance.md](performance.md#bitrate-profile-of-x11-xrdp-sessions)); keep `[x264.autodetect]` in `gfx.toml` the same |
| `[defaults] desktop`, `geometry`; `[defaults.groups]` | `fastrdp_default_desktop`, `fastrdp_default_geometry`, `fastrdp_group_desktops` | `[defaults.groups]` lines look like `"rdp-kde" = "plasma"` |
| `[desktops.<name>]` | `fastrdp_desktops`, `fastrdp_desktop_labels`, `fastrdp_desktop_groups` | one table per desktop (section 7); optional `label = "..."`, `groups = [...]` |
| `[broker] home_check` | none (not rendered) | `create` (default): refuse unusable homes, create a missing one (0700) below an existing root-owned parent; `check`; `off` ([nfs-kerberos-homes.md](nfs-kerberos-homes.md#where-homes-are)) |
| `[broker] home_create_roots` | `fastrdp_home_create_roots` | default `["/home"]`: `home_check = "create"` creates a home only when its parent is one of these or below one (also with symlinks resolved), never a root or another missing parent; `[]` = never create |
| `[broker] desktop_picker`, `desktop_picker_timeout`, `desktop_picker_when_running` | `fastrdp_desktop_picker`, `fastrdp_desktop_picker_timeout`, `fastrdp_desktop_picker_when_running` | `never` (default), `if_multiple` or `always`; 3..60 s (default 10); `preselect` (default) or `skip`. Needs proxy.ini `WaitingScreen=true` and `fastrdp-freerdp3` ≥ 3.32.2-6 ([desktop-matrix.md](desktop-matrix.md#desktop-picker-in-the-rdp-window)) |
| `[mfa]`, `[mfa.privacyidea]` | `fastrdp_mfa_*`, `fastrdp_privacyidea_*` | section 15.1 |
| `[web] enabled` | `fastrdp_web_enabled` | section 15.2 |
| `[ui] language`, `language_from_keyboard`, `approve_url`, `qr_code`; `[ui.<language>]` | `fastrdp_ui_language`, `fastrdp_ui_language_from_keyboard`, `fastrdp_ui_approve_url`, `fastrdp_ui_qr_code`, `fastrdp_ui_texts` | texts of the proxy's waiting screen; `approve_url` is `https://<fqdn>/web/approve` with the web gateway, else `""` (at most 184 characters: the QR code adds `?login=<id>`) ([auth-matrix.md](auth-matrix.md#waiting-screen)) |
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
; audio out (fastrdp_audio); the microphone is AUDIO_INPUT inside drdynvc
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
; Microphone (fastrdp_audio_input): false = /usr/libexec/fastrdp/xrdp-audio loads the
; PipeWire xrdp module sink-only (docs/audio.md). PULSE_SCRIPT of xrdp's default
; belongs to the PulseAudio module, which fastrdp does not use.
FASTRDP_AUDIO_INPUT=true
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

Audio and microphone (`fastrdp_audio`, [audio.md](audio.md)): PipeWire with its xrdp
module. `pipewire-module-xrdp` is in Debian 13 main and Ubuntu 26.04 universe.
`fastrdp-session` ships `/usr/libexec/fastrdp/xrdp-audio` and its autostart entry
(`/etc/xdg/autostart/fastrdp-xrdp-audio.desktop`), which does nothing while the
module's own entry is active; `wlroots-in-x` runs `xrdp-audio` itself. GNOME sessions need only `pipewire-pulse` (a sink for
gnome-remote-desktop on hosts without a sound card).

```sh
apt-get install --no-install-recommends pipewire pipewire-bin wireplumber pipewire-pulse \
    pipewire-module-xrdp pulseaudio-utils
# Only without the microphone (FASTRDP_AUDIO_INPUT=false in sesman.ini): hide the
# module's own entry, fastrdp's entry then loads it sink-only
sed -i '/^\[Desktop Entry\]/a Hidden=true' /etc/xdg/autostart/pipewire-xrdp.desktop
```

Without audio: `rdpsnd=false` in `xrdp.ini` and none of these packages.

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
; and nftables lets only this service connect to them. The fastrdp module pins each
; back-end's TLS certificate to the one the broker names (xrdp: /etc/xrdp/cert.pem,
; GNOME/Plasma: the user's certificate); deny refuses every other one, so a local
; user who binds a back-end port while the back-end is down cannot pose as it.
; The module refuses to route with any other policy.
CertificatePolicy=deny
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
Timeout=180
; TLS logins are needed for password+OTP clients and for the web path (guacd has no
; Kerberos); the broker decides which credentials it accepts on them.
AllowTls=true
; TLS logins only from these peers (addresses/CIDRs, empty = any): loopback only when TLS
; is there just for guacd (web path without fastrdp_allow_tls_logins).
AllowTlsFrom=
; Remote Credential Guard (mstsc /remoteGuard): false = not offered (the client gets a
; negotiation response without support and reports it); true = accepted identity only,
; the forwarded Kerberos tickets are discarded (no session TGT, like Restricted Admin).
AcceptRemoteGuard=false
; While the broker works on a login (push, web approval, session start), show what it
; waits for: a panel drawn with Bitmap Updates, texts from the broker's [ui]. StatusInfo:
; also Server Status Info PDUs, to clients that ask for them.
WaitingScreen=true
StatusInfo=false
; Lab only: log the class of each input event the waiting screen reads (code field,
; desktop picker), never a value (docs/lab-waiting-screen-input.md).
InputTrace=false
; Lab only: read the client during the whole MFA wait, answer Refresh Rect and Suppress
; Output on the waiting screen and log them (docs/backlog.md A5).
WaitingScreenObserve=false
```

`ServerTlsSecurity` and `AllowTls` are `true` if TLS logins (`allow_tls_password_login`)
**or** web access are enabled, else `false`. `AllowTlsFrom` (`fastrdp_tls_login_sources`)
limits TLS (non-NLA) logins to the listed peer addresses: comma-separated IPv4/IPv6
addresses and CIDR ranges, empty = any peer. It is `127.0.0.1,::1` when web access is on
but TLS logins are not (only guacd on loopback needs TLS then), else empty. The module
checks the TCP peer address (IPv4-mapped IPv6 counts as IPv4), not the address the
client claims, before anything reaches the broker, and refuses others with Set Error Info
`ERRINFO_SERVER_DENIED_CONNECTION` (0x7); an unparsable entry is logged and matches
nothing. NLA logins are not affected. `Timeout` (`fastrdp_proxy_broker_timeout`, 1..600, the
module's default 180) must cover the MFA push or web approval plus the session start
([auth-matrix.md](auth-matrix.md)); a login whose client disconnects while the broker
still waits (MFA push) is abandoned at once, and the broker stops waiting.
`AcceptRemoteGuard` (`fastrdp_accept_remote_guard`, default `false`): with `false`, a
client that requires Remote Credential Guard (`mstsc /remoteGuard`, GPO "Require Remote
Credential Guard") gets a negotiation response without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED
and disconnects with its own message (needs `fastrdp-freerdp3` ≥ 3.32.2-2; older builds drop
the connection). With `true` the proxy offers the mode, takes the user from the Kerberos NLA
as usual, and zeroes and discards the forwarded tickets: the broker receives
`"remote_guard": true` and no password, so the session has no TGT and
`session_tgt = required` refuses the login ([windows-clients.md](windows-clients.md) §3.12).
`WaitingScreen` (`fastrdp_proxy_waiting_screen`, default `true`; also the module's default
when the key is missing): shows a panel in the client's window while the broker works on
the login (push or web approval with countdown, approval URL, login code and a QR code of
the page for this login, session start), drawn with Bitmap Updates and painted over in the
background grey before the desktop arrives; texts from the broker's `[ui]`. `false`: the
client shows only its own "connecting" state or a black window, and no desktop picker. With the broker's `[broker] desktop_picker` the same panel also lists
the user's desktops and takes keys and clicks before the session starts (needs
`fastrdp-freerdp3` ≥ 3.32.2-6; the module offers the picker only then and adds its
countdown to `Timeout`). `StatusInfo` (`fastrdp_proxy_status_info`, default `false`) also sends
Server Status Info PDUs to clients that ask for them ([auth-matrix.md](auth-matrix.md#waiting-screen)).
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

**Logs.** The proxy unit sets `WLOG_APPENDER=JOURNALD` and `WLOG_JOURNALD_ID=fastrdp-proxy`:
FreeRDP and the fastrdp module write each message straight to the journal, at once and
with its priority. Without it, WLog's console appender buffers stdout in the pipe to
journald, and lines arrive minutes late or torn ([backlog.md](backlog.md#sessions) A4).
The appender needs `fastrdp-freerdp3` built with it (`patches/freerdp/0009`; older builds
fall back to the console without a message).

```sh
journalctl -u fastrdp-proxy.service -p warning      # warnings and errors only
journalctl -t fastrdp-proxy -o short-precise        # by the identifier
systemctl edit fastrdp-proxy.service                # debug: [Service] Environment=WLOG_LEVEL=DEBUG
```

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
ticket renewal (sssd-kcm active, effective `[kcm] tgt_renewal = true` and
`krb5_renew_interval` from `sssd.conf` and `conf.d`, `renew_lifetime` in `krb5.conf`),
back-end port blocked for other users, and for the test user NSS, the PAM account
check and a renewable TGT in the user's default cache (`fastrdpctl tickets USER`;
`skip` without a TGT: log in over RDP with a password first). On FreeIPA hosts it checks only `TERMSRV/<fqdn>`.

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
- `broker.toml`: `[mfa] mode` (`otp`, `push`, `otp_or_push`; `web`/`push_or_web` approve
  logins on the web gateway, which needs `[web] enabled`, see
  [auth-matrix.md](auth-matrix.md#web-approval); `code_or_web` adds the TOTP code on the
  waiting screen, checked by Keycloak through `[mfa.keycloak]`, see
  [auth-matrix.md](auth-matrix.md#code-on-the-waiting-screen)), `exempt_groups`, `otp_lengths`;
  `[mfa.privacyidea] url`, `realm`, `verify_tls`;
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
12. Approval notifications (optional, `[mfa] mode` web or push_or_web;
    [notifications.md](notifications.md)): `[notify]` in `webgate.toml` with
    `backends = ["ntfy", "webpush"]` (or one of them). ntfy: `ntfy_url`, and the access
    token plus a newline in `/etc/fastrdp/webgate-ntfy.token` (`ntfy_token_file`); a
    server with a private CA: its CA certificate in `/etc/fastrdp/webgate-ntfy-ca.pem`
    (`ntfy_ca_file`, also used for Web Push to `webpush_extra_hosts`). Web
    Push: `umask 077; openssl ecparam -name prime256v1 -genkey -noout -out
    /etc/fastrdp/webgate-vapid.pem` once (a new key invalidates all browser
    subscriptions), `vapid_private_key_file` and `vapid_subject = "mailto:root@<fqdn>"`.
    Both files `root:_fastrdp-web 0640`. Subscriptions go to `/var/lib/fastrdp-webgate`
    (the unit's `StateDirectory`). `fastrdp-webgate --check`, then restart it.

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

### 15.6 Kerberized SMB home directories and shares

`roles/identity/tasks/smb_krb5.yml`, background and the directory-side delegation to
`cifs/<server>` in [smb-kerberos-homes.md](smb-kerberos-homes.md):
`apt install cifs-utils keyutils gssproxy` (cifs-utils 7.0 or later);
`/etc/gssproxy/91-fastrdp-smb-client.conf` and
`/etc/request-key.d/fastrdp-cifs.spnego.conf` (both `root:root 0644`) exactly as
shown there; leave cifs-utils' own `/etc/request-key.d/cifs.spnego.conf` alone (the
fastrdp line is preferred). `systemctl enable --now gssproxy`, then
`systemctl restart gssproxy`. Mounts: `sec=krb5,multiuser` in `/etc/fstab`
(`x-systemd.automount`, then `systemctl daemon-reload` and start the `.automount`
unit) or an autofs map, by the server's FQDN. The keytab `/etc/krb5.keytab` must
exist (join first).

### 15.7 KDC proxy for off-network clients (MS-KKDCP)

`roles/web_gateway/tasks/kdcproxy.yml` (`fastrdp_web_kdcproxy`), on top of 15.2. Design,
exposure (password guessing from the internet: set an account lockout policy first)
and the client settings: [web-access.md](web-access.md#kdc-proxy).

1. `apt install python3-kdcproxy gunicorn` (Ubuntu: universe).
2. The realm's KDCs: `dig +short SRV _kerberos._tcp.example.com` (and `_kpasswd._tcp`).
3. `/etc/fastrdp/kdcproxy.conf` (`root:root 0644`), only your realm, DNS lookups off
   (without `use_dns = false` kdcproxy forwards any realm a client names to the KDCs
   DNS gives for it):
   ```ini
   [global]
   use_dns = false

   [EXAMPLE.COM]
   kerberos = kerberos+tcp://dc1.example.com:88 kerberos+tcp://dc2.example.com:88
   kpasswd = kpasswd+tcp://dc1.example.com:464 kpasswd+tcp://dc2.example.com:464

   [example.com]
   kerberos = kerberos+tcp://dc1.example.com:88 kerberos+tcp://dc2.example.com:88
   kpasswd = kpasswd+tcp://dc1.example.com:464 kpasswd+tcp://dc2.example.com:464
   ```
4. `/etc/fastrdp/kdcproxy-gunicorn.conf.py` from `kdcproxy-gunicorn.conf.py.j2` (no
   template variables), `/etc/systemd/system/fastrdp-kdcproxy.socket` and
   `fastrdp-kdcproxy.service` from the role templates (`root:root 0644`). The service
   runs gunicorn as a dynamic user on the socket systemd opens
   (`/run/fastrdp-kdcproxy.sock`, `root:www-data 0660`) and refuses to start without
   the `use_dns = false` line.
5. The nginx site (15.2, step 9) rendered with `fastrdp_web_kdcproxy: true`: a
   `limit_req_zone` line before the first `server` block and `location = /KdcProxy` in
   the HTTPS server (POST only, `client_max_body_size 128k`, `limit_req`, `proxy_pass
   http://unix:/run/fastrdp-kdcproxy.sock;`).
6. `systemctl daemon-reload`; `systemctl enable --now fastrdp-kdcproxy.socket`;
   `nginx -t && systemctl reload nginx`.
7. Check from a client with `krb5-k5tls` and `kdc = https://rdp1.example.com/KdcProxy`
   in its `krb5.conf`: `KRB5_TRACE=/dev/stderr kinit alice` shows `Sending HTTPS
   request`; `curl -s -o /dev/null -w '%{http_code}\n' https://rdp1.example.com/KdcProxy`
   gives 403 (GET is refused).

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
