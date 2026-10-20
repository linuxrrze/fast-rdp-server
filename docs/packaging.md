# Packaging and APT repository

fastrdp is packaged for **Ubuntu 26.04 (resolute)** and **Debian 13 (trixie)**.
GitHub Actions (`.github/workflows/packages.yml`) builds the packages and publishes
a signed APT repository on GitHub Pages.

## Packages

| Source package | Binary package | Contents |
|---|---|---|
| `fast-rdp-server` (`debian/`) | `fastrdp-broker` | `/usr/lib/fastrdp/python/fastrdp_broker`, `/usr/sbin/fastrdp-brokerd`, `/usr/sbin/fastrdpctl`, `fastrdp-brokerd.service`, `/etc/pam.d/fastrdp`, `/etc/pam.d/fastrdp-tgt`, `/etc/fastrdp/`, example `broker.toml`; group `_fastrdp-broker`; TERMSRV keytab helpers `/usr/sbin/fastrdp-termsrv-check` and `/usr/sbin/fastrdp-termsrv-keytab` (`broker/sbin/`), their settings `/etc/fastrdp/termsrv.conf` (conffile, all commented out), `fastrdp-termsrv-keytab.path` + `.service` (AD machine-password rotation) |
| | `fastrdp-proxy-module` | `/opt/fastrdp/lib/freerdp3/proxy/libproxy-fastrdp-plugin.so`, `fastrdp-proxy.service` (runs `/opt/fastrdp/bin/freerdp-proxy`); user `_fastrdp-proxy` |
| | `libpam-fastrdp-token` | `/usr/lib/<triplet>/security/pam_fastrdp_token.so` |
| | `fastrdp-session` | `/usr/libexec/fastrdp/*` (startwm.sh, session-plasma, kwin-wayland-launch, wlroots-in-x, clipboard-bridge), `fastrdp-plasma@.service`, `/etc/pam.d/fastrdp-session`, KWin user drop-in in `/usr/lib/systemd/user/plasma-kwin_wayland.service.d/fastrdp.conf`, `/usr/share/xsessions/fastrdp-{sway,labwc,wayfire}.desktop`, and the token-only xrdp PAM stack as a template in `/usr/share/fastrdp-session/pam.d/xrdp-sesman` |
| | `fastrdp-webgate` | `/usr/lib/fastrdp/python/fastrdp_webgate`, `fastrdp-webgate.service`, example `webgate.toml`; user `_fastrdp-web`; depends on `python3-cryptography` |
| `fastrdp-freerdp3` (`packaging/freerdp/debian/`) | `fastrdp-freerdp3` | fastrdp's FreeRDP build under `/opt/fastrdp`: libraries, `freerdp-proxy`, the `xfreerdp` client (H.264 via FFmpeg), headers and pkg-config files |
| `fastrdp-xrdp` (`packaging/xrdp/debian/`) | `fastrdp-xrdp` | patched xrdp + xorgxrdp (prefix `/usr`, config in `/etc/xrdp`); `Conflicts/Replaces/Provides: xrdp, xorgxrdp`; user `xrdp`; upstream's versions of the site configuration in `/usr/share/fastrdp-xrdp/default-config/` (below) |

The paths, users and modes are the ones the Ansible roles create; differences:

- Files a role copies to `/etc/systemd/system`, `/etc/systemd/user` or
  `/usr/local/sbin` are in `/usr/lib/systemd/...` and `/usr/sbin` in the
  packages (Debian policy). In `apt` mode the roles delete those copies from
  earlier `build` runs so they do not shadow the packaged files.
- Users and groups come from `sysusers.d` (`dh_installsysusers`), with the
  same attributes as the roles (system account, `/nonexistent`, `nologin`).
- All daemons (`fastrdp-brokerd`, `fastrdp-proxy`, `fastrdp-webgate`, `xrdp`,
  `xrdp-sesman`) are installed **disabled and stopped**: they need a site
  configuration first (`/etc/fastrdp/*.toml`, `proxy.ini`, `/etc/xrdp`; stock
  `xrdp.ini` would listen on 3389 on all addresses). The roles write the
  configuration and enable them; without Ansible, do the same by hand
  ([manual-setup.md](manual-setup.md)).
- The X session entries of all three wlroots desktops are installed (the role
  installs only the selected ones).
- `fastrdp-xrdp` creates the loopback TLS key/certificate and `rsakeys.ini` in
  its `postinst` if they are missing (the same commands as the role); they are
  never shipped in the package and are removed on purge.
- **xrdp site configuration is not a conffile.** The xrdp role (or the admin) writes
  `/etc/xrdp/{xrdp.ini,sesman.ini,gfx.toml,startwm.sh}`, `/etc/X11/xrdp/xorg.conf`
  and `/etc/pam.d/xrdp-sesman`. xrdp 0.10 has no include or drop-in directory for
  them (`gfx.toml` and the `sesman.ini` that xrdp itself reads are fixed to
  `/etc/xrdp`), so as conffiles every upstream change would make dpkg ask on
  upgrade (and `unattended-upgrades` skip the package). `third_party/build-xrdp.sh`
  therefore installs upstream's versions to
  `/usr/share/fastrdp-xrdp/default-config/<path>` and never overwrites existing
  files, in the package and in the Ansible `build` path alike; `postinst` copies a
  default only where the file is missing, and purge removes the files. Upgrading from
  `0.10.6.1+xorgxrdp0.10.5-1`, where they were conffiles: dpkg keeps them as obsolete
  conffiles, without asking. The other `/etc/xrdp` files (keymaps, `reconnectwm.sh`,
  `pulse/`, ...) stay conffiles; fastrdp does not change them.
- The TERMSRV keytab helpers of `fastrdp-broker` read `/etc/fastrdp/termsrv.conf`
  (`KEY=VALUE`), the environment and options instead of role variables, so package and
  `build` copies are the same files (`build`: `/usr/local/sbin`, units in
  `/etc/systemd/system` pointing there).

The Python code is installed into the private directory `/usr/lib/fastrdp/python`
(exactly as the roles do; the units set `PYTHONPATH`) and byte-compiled by
`dh_python3`. Both daemons are standard-library only, except the webgate's use of
`python3-cryptography`.

## Vendored dependencies (policy)

fastrdp ships its **own patched builds** of FreeRDP and of xrdp/xorgxrdp instead
of the distribution ones, because it needs fixes that are not in a release yet
(the patches are meant to go upstream; once they are in a release that the
distributions ship, the vendored package can be dropped again).
The policy itself is in [vendoring.md](vendoring.md); for packaging it means:

- **Where the inputs live.** `third_party/sources.yml` lists, per dependency,
  version, URL, sha256 and patch series; the patches are in `patches/<name>/`
  (`series` file + `*.patch`). `third_party/fetch.sh <name> <dir>` downloads,
  verifies and patches; `third_party/build-freerdp.sh` and
  `third_party/build-xrdp.sh` build. The Ansible build path, the packages and CI
  all use these same files, so the patch set cannot diverge.
  - `patches/freerdp/`: PKCS#11 slot-id fix (smartcard logon).
  - `patches/xrdp/`: FFmpeg H.264 encoder (VA-API, NVENC, QSV).
  - `patches/krb5/`: **reference only**. MIT Kerberos is *not* vendored and
    there is no krb5 package; the distribution's krb5 is used.
- **Why FreeRDP goes to `/opt/fastrdp`.** gnome-remote-desktop and KRdp (GNOME
  and Plasma back ends) link against the distribution's `freerdp3`, and they keep
  doing so. A second FreeRDP with the same sonames in `/usr/lib` would replace
  or clash with it. Under `/opt/fastrdp` (own library directory, `DT_RPATH
  $ORIGIN/../lib`, own plugin directory and own pkg-config files) both coexist:
  only `freerdp-proxy` and the fastrdp proxy module use fastrdp's build. This
  is why `fastrdp-freerdp3` and `fastrdp-proxy-module` carry a lintian override
  for `dir-or-file-in-opt`.
- **Why `fastrdp-xrdp` conflicts with `xrdp`/`xorgxrdp`.** xrdp is not a library
  that two versions of could share: same daemons, ports, `/etc/xrdp`, PAM
  service and Xorg driver. fastrdp's build replaces the distribution package
  (`Conflicts` + `Replaces`) and `Provides: xrdp (= <version>), xorgxrdp (=
  <version>)` so packages that depend on xrdp stay installable.
- **ABI coupling.** `fastrdp-proxy-module` is built against
  `/opt/fastrdp/lib/pkgconfig` and depends on exactly that FreeRDP release:
  `fastrdp-freerdp3 (>= X~), fastrdp-freerdp3 (<< X+~)`.
- **Updating.** Bump version/url/sha256 in `third_party/sources.yml`, check the
  series with `third_party/fetch.sh <name> /tmp/x`, and add an entry to
  `packaging/<freerdp|xrdp>/debian/changelog` with the new upstream version
  (`3.32.2-1`, resp. `<xrdp>+xorgxrdp<xorgxrdp>-1` for xrdp). Changing only a
  patch: bump the Debian revision (`-2`). `prepare-vendored.sh` refuses to build
  if the changelog and `sources.yml` disagree.

**Corresponding source.** The vendored binaries link the distributions' GPL FFmpeg
and x264, so they are distributed under GPL-3.0-or-later terms
([licensing.md](licensing.md)). CI archives each vendored build tree before building
it (`packaging/ci/make-source-archive.sh`: patched source, `debian/`, build scripts,
pristine upstream tarballs, patches, `SHA256SUMS`). `publish.sh` publishes the archives
under `sources/<package>_<version>/` next to the repository, for exactly the versions
in the pool, and refuses to publish a vendored package without them. Stable releases
also attach the `.source.tar.xz` files.

**Why separate source packages** for the vendored builds (instead of more binary
packages in `debian/`): they have their own upstream sources, licenses, version
numbers and release cycle, and a FreeRDP build takes far longer than the rest of
fastrdp. As separate source packages they are rebuilt only when their inputs
change (CI caches them), and fastrdp releases do not churn their versions.

## Versions

| Build | `fast-rdp-server` | vendored |
|---|---|---|
| tag `v0.2.0` (stable) | `0.2.0~deb13`, `0.2.0~ubuntu26.04` | `3.32.2-1~deb13`, ... |
| main (testing) | `0.2.0+git20261019174203.2a530f1~deb13` (changelog version + commit time + sha) | same as stable |

The `~<distro>` suffix makes the two distro builds distinct files in one pool,
and sorts below anything else, so on every distro `stable < testing of the same
base < next release`. Only release tags `v<major>.<minor>[.<patch>]` are
published; pre-release tags are rejected (they would sort above the release).
After tagging, bump `debian/changelog` to the next version so testing builds
carry it.

## Building locally

```sh
# fast-rdp-server needs fastrdp-freerdp3 installed (it provides /opt/fastrdp/lib/pkgconfig)
dir=$(packaging/ci/prepare-vendored.sh freerdp /tmp/vendored)
sudo packaging/ci/install-build-deps.sh "$dir"
(cd "$dir" && dpkg-buildpackage -us -uc -b)
sudo apt install /tmp/vendored/fastrdp-freerdp3_*.deb

sudo packaging/ci/install-build-deps.sh ./
make deb                                   # = dpkg-buildpackage -us -uc -b; .debs in ..
lintian ../fast-rdp-server_*.changes

dir=$(packaging/ci/prepare-vendored.sh xrdp /tmp/vendored)   # likewise for fastrdp-xrdp
```

`debian/rules` runs the broker and webgate unit tests and the PAM module test
(`DEB_BUILD_OPTIONS=nocheck` skips them).

## CI

`.github/workflows/packages.yml`, all builds in `ubuntu:26.04` and
`debian:trixie` containers:

1. **tests** (both distros): `make test-all` with `FASTRDP_TESTS_STRICT=1` (a
   missing tool fails instead of skipping): broker, webgate, PAM, GPU report, shell
   tests of the build/CI/publish scripts, Ansible syntax check and template rendering,
   setup assistant and preflight, ansible-lint, shellcheck; actionlint on resolute.
   Inventory and CI mapping of every test: [tests/README.md](../tests/README.md).
2. **vendored** (per distro x {freerdp, xrdp}): `prepare-vendored.sh` +
   `make-source-archive.sh` (corresponding source, before the build) +
   `dpkg-buildpackage` + lintian; for xrdp also the FFmpeg encoder test
   (`make test-xrdp-encoder`) against the built tree. Cached with `actions/cache`;
   the key is the upstream sha256 value(s) from `sources.yml` plus the hashes of
   `patches/<name>/**`, `packaging/<name>/**`, `third_party/build-<name>.sh`,
   `fetch.sh` and the CI scripts. A cache hit reuses the identical `.deb`s.
3. **build** (per distro): installs the vendored `fastrdp-freerdp3`, builds
   `fast-rdp-server`, runs lintian (`--fail-on error`), then installs **all**
   packages in the container and runs `tests/packaging/check-installed.sh` (users
   and groups, units, module RUNPATH, DT_RPATH of the vendored binaries, FreeRDP
   resolved from `/opt/fastrdp`, Python imports, broker `--check`, xrdp FFmpeg build).
4. **e2e** (per distro): installs the vendored FreeRDP and runs the proxy suites
   against it: TLS, Kerberos NLA, smartcard via p11-kit and smartcard with SoftHSM
   loaded directly (regression test of `patches/freerdp`).
5. **krb5-spnego** (per distro, informational): reports whether the distribution's
   MIT krb5 has the SPNEGO mechListMIC bug as a warning.
6. **publish** (push to `main` or tag `v*`, after tests, build and e2e): rebuilds the
   APT repository and force-pushes it as a single commit to `gh-pages`; for tags
   also attaches the `.deb`s and the source archives to a GitHub release.

## APT repository

### Layout

One repository, one suite per distro release and channel, component `main`,
architecture `amd64`:

| Suite | Contents |
|---|---|
| `resolute-stable` / `trixie-stable` | latest release tag |
| `resolute-testing` / `trixie-testing` | latest build of `main` |

Each suite contains all seven packages built for that distro release (the
vendored FreeRDP/xrdp and the proxy module are linked against that release's
libraries, so Debian and Ubuntu binaries cannot be shared). The pool is shared;
the `~<distro>` version suffix keeps file names apart.

### Why reprepro

reprepro (not aptly): the repository is rebuilt from scratch on every publish
(`packaging/apt/publish.sh`): new packages for the channel being published, the
other channel carried over from the current `gh-pages` tree. So no database
has to be persisted between runs, and reprepro's static `conf/distributions`
(`packaging/apt/distributions`) plus `includedeb`/`export` cover everything
needed. aptly's strengths (mirrors, snapshots, publishing from a persistent
database) would need that database stored somewhere. Signing is done by
`publish.sh` with `gpg` directly (`InRelease` + `Release.gpg`, SHA512), which also
handles a passphrase-protected key.

### Signing key and secrets

Create a dedicated signing key (on a trusted machine):

```sh
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key \
    'fast-rdp-server APT repository <marcel@linux-ng.de>' ed25519 sign 3y
KEYID=$(gpg --with-colons --list-secret-keys | awk -F: '/^fpr:/ {print $10; exit}')
gpg --armor --export-secret-keys "$KEYID" > apt-signing-key.asc   # -> secret
gpg --armor --export "$KEYID" > fast-rdp-server-archive-keyring.asc  # public, keep a copy
```

Repository secrets (Settings > Secrets and variables > Actions):

| Secret | Value |
|---|---|
| `APT_SIGNING_KEY` | contents of `apt-signing-key.asc` (ASCII-armored secret key, exactly one) |
| `APT_SIGNING_KEY_PASSPHRASE` | optional, if the key has a passphrase |

The workflow reads the key's fingerprint after importing it and signs with that key.
The fingerprint is printed in the job log and shown on the repository's index page.

Then delete `apt-signing-key.asc` and `$GNUPGHOME` (or keep them offline).
Settings > Pages: *Deploy from a branch*, branch `gh-pages`, folder `/`. The
first push to `main` creates the branch. Publishing is skipped in forks
(`repository_owner` check) and fails loudly if the secret is missing.

Key rotation: publish the new public key next to the old one first (both in
the clients' `Signed-By` file), then switch the secrets.

### Client setup

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/fast-rdp-server.asc \
    https://linuxrrze.github.io/fast-rdp-server/fast-rdp-server-archive-keyring.asc
gpg --show-keys /etc/apt/keyrings/fast-rdp-server.asc   # compare the fingerprint
```

`/etc/apt/sources.list.d/fast-rdp-server.sources` (suite = codename +
channel, e.g. `trixie-stable`, `resolute-testing`):

```
Types: deb
URIs: https://linuxrrze.github.io/fast-rdp-server
Suites: resolute-stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/fast-rdp-server.asc
```

```sh
sudo apt update
sudo apt install fastrdp-broker libpam-fastrdp-token fastrdp-proxy-module \
    fastrdp-session fastrdp-xrdp            # + fastrdp-webgate for browser access
```

No backports or pinning are needed on Debian 13: the proxy module uses
`fastrdp-freerdp3`, not the distribution's FreeRDP.

## Ansible: installing from the repository

`fastrdp_install_method` (role `base`, default `build`):

| Value | Behaviour |
|---|---|
| `build` | unchanged: copy from the checkout, compile on the host |
| `apt` | add the repository (`base` role) and install the packages |

```yaml
fastrdp_install_method: apt
fastrdp_apt_channel: stable          # or testing
fastrdp_apt_key_checksum: "sha256:<sha256 of the .asc file>"   # recommended
# fastrdp_apt_repo_url, fastrdp_apt_suite, fastrdp_apt_key_url, fastrdp_apt_package_state
```

In `apt` mode the roles install `fastrdp-broker` + `libpam-fastrdp-token`
(broker), `fastrdp-freerdp3` + `fastrdp-proxy-module` (freerdp_proxy),
`fastrdp-xrdp` + `fastrdp-session` (xrdp; desktops and plasma_krdp as needed) and
`fastrdp-webgate` (web_gateway). Configuration templates, certificates, keytabs,
firewall rules and service enablement are the same in both modes. xrdp's
`startwm.sh` and the token-only `/etc/pam.d/xrdp-sesman` are copied from the
installed `fastrdp-session` package. The identity role installs `fastrdp-broker`
early (before the broker role) for the TERMSRV helpers.

Switching an existing host from `build` to `apt` is supported: package files
replace the copied ones, and the roles remove unit copies in `/etc/systemd`,
`/usr/local/sbin/fastrdpctl` and `/usr/local/sbin/fastrdp-termsrv-{check,keytab}`
(the keytab watcher copy is disabled first, then the packaged one is enabled). Source-built binaries under `/usr/local`
(old xrdp builds) are left in place; remove them by hand.

## Lintian

CI runs lintian with `--fail-on error`. Overrides, all with a reason in the file:

- `fastrdp-freerdp3`, `fastrdp-proxy-module`: `dir-or-file-in-opt` (see the
  vendoring policy above).
- `fastrdp-xrdp`: `custom-library-search-path RUNPATH /usr/lib/xrdp`: xrdp's
  private libraries live in `/usr/lib/xrdp`, found through the RUNPATH libtool
  sets; same layout as upstream. And `RUNPATH /usr/lib/xorg/modules` on
  `libxorgxrdp.so`: the glamor build links `libglamoregl.so` from the Xorg module
  directory (upstream's `-R$(XORG_SERVER_MODULES)`).

Remaining informational tags come from the upstream files (`.desktop` entries
without `Icon`, units without `Documentation=`).
