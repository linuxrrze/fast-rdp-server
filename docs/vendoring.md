# Vendored dependencies

fastrdp builds its **own patched copies** of the dependencies it needs fixes in,
instead of using the distribution packages. The patches are kept local for now. They
will be offered upstream once the whole stack works (see [upstream.md](upstream.md)),
and each vendored build can be dropped when its fixes reach the distributions.

## What is vendored

| Dependency | Version | Local patches | Installed to | Used by |
|---|---|---|---|---|
| FreeRDP | 3.32.2 | `patches/freerdp/`: PKCS#11 slot id fix (smartcard logon) | `/opt/fastrdp` (private) | `freerdp-proxy` + fastrdp module, `xfreerdp` and rdpbench (H.264), e2e tests |
| xrdp | 0.10.6.1 | `patches/xrdp/`: FFmpeg H.264 encoder (VA-API, NVENC, QSV) | `/usr` (package), `/usr/local` (Ansible build) | X11 sessions |
| xorgxrdp | 0.10.5 | none (built together with xrdp, with glamor) | Xorg module directory | X11 sessions |

Not vendored:
- **MIT krb5.** `patches/krb5/` holds the upstream SPNEGO mechListMIC fix for
  reference only. Nothing in fastrdp's paths uses an MIT SPNEGO acceptor:
  freerdp-proxy, gnome-remote-desktop and KRdp all use WinPR's. Replacing the
  system's libkrb5 would affect every Kerberos user on the host.
  `tests/krb5-spnego/run.sh` shows whether a host's krb5 is affected (fixed in 1.22.2).
- **gnome-remote-desktop, KRdp, the distribution's freerdp3.** These are unchanged
  and keep linking the distribution's FreeRDP.

## One source of truth

| File | Role |
|---|---|
| `third_party/sources.yml` | version, URL, sha256 and patch series per dependency |
| `patches/<name>/series` + `*.patch` | the local patches, applied in order |
| `third_party/fetch.sh NAME DIR` | download (or `$FASTRDP_SOURCES_CACHE`), verify sha256, unpack, apply series |
| `third_party/build-freerdp.sh SRC [DESTDIR]` | build into `/opt/fastrdp`; `--deps` prints the build dependencies |
| `third_party/build-xrdp.sh XRDP XORGXRDP [DESTDIR]` | build xrdp + xorgxrdp; `--deps` likewise |
| `third_party/build-key.sh freerdp\|xrdp` | hash of all build inputs (Ansible rebuild key) |

Three consumers use exactly these files, so the patch set cannot diverge:
- the Ansible `build` path (roles `freerdp_proxy`, `xrdp`);
- the packages `fastrdp-freerdp3` and `fastrdp-xrdp` ([packaging.md](packaging.md));
- CI, whose cache keys cover the same inputs.

`packaging/ci/check-build-deps.sh` (part of `make lint`) checks that the packages'
Build-Depends cover each script's `--deps`.

## Build details that matter

- **Private prefix with `DT_RPATH`.** Every FreeRDP binary and library in
  `/opt/fastrdp` has `DT_RPATH $ORIGIN/../lib`, not `RUNPATH`. A RUNPATH would lose
  to `LD_LIBRARY_PATH`, so the unpatched distribution `libfreerdp3` could be loaded
  instead. `build-freerdp.sh` fails if the RPATH is missing. The e2e tests and
  rdpbench link their own binaries the same way.
- **H.264.** `WITH_GFX_H264` follows from `WITH_VIDEO_FFMPEG`. The script checks the
  generated `config.h`, because the Ubuntu 26.04 freerdp3 is built without it.
- **Relocatable pkg-config files.** FreeRDP's `.pc` files use
  `prefix=${pcfiledir}/../..`. The proxy module takes `proxy_plugindir` from them
  and normalises the path, so it installs into `/opt/fastrdp/lib/freerdp3/proxy`.
- **xrdp checks without running xrdp.** `build-xrdp.sh` reads
  `xrdp_configure_options.h` to confirm `--enable-x264` / `--enable-ffmpeg`. The
  binary's RUNPATH is `/usr/lib/xrdp`, so it cannot run from a DESTDIR on a builder.
- **glamor needs `xserver-xorg-core` to build:** `libglamoregl.so` comes from the
  Xorg module directory.

## Updating a dependency

1. Bump `version`, `url` and `sha256` in `third_party/sources.yml`. Use upstream's
   published checksum and compare it with `sha256sum`.
2. `third_party/fetch.sh <name> /tmp/x` shows whether every patch still applies.
   Refresh a patch that applies only with an offset, or fix it if it fails.
3. Add a changelog entry in `packaging/<freerdp|xrdp>/debian/changelog`.
4. Test against the new build:
   ```sh
   third_party/build-freerdp.sh /tmp/x/freerdp-<v> /tmp/stage
   FREERDP_PREFIX=/tmp/stage/opt/fastrdp make test-e2e test-e2e-nla test-e2e-smartcard
   SC_MODULE=softhsm FREERDP_PREFIX=/tmp/stage/opt/fastrdp tests/proxy-e2e/run_smartcard.sh
   ```
   The last command exercises the slot id fix (SoftHSM without p11-kit).
5. Once a patch is in an upstream release, delete it from the series. When a series
   is empty and the distributions ship that release, drop the vendored package.

## Tested (2026-10-19, Ubuntu 26.04 sandbox, no root; extracted build deps)

- `fetch.sh`: all three sources verify and patch cleanly; a bad name is rejected.
- `build-freerdp.sh` (3.32.2 + slot fix):
  - builds, with DT_RPATH and H.264;
  - `ldd` resolves the private libraries even with the distribution's FreeRDP 3.32.1
    on `LD_LIBRARY_PATH`;
  - `fastrdp-freerdp3_3.32.2-1` builds through `dpkg-buildpackage`; lintian is clean
    apart from the changelog distribution, which CI sets.
- `build-xrdp.sh`: builds with x264, FFmpeg, fuse, glamor and so on. The
  `fastrdp-xrdp` package builds; lintian shows only upstream man-page sections.
- All e2e suites against the vendored FreeRDP pass:
  - TLS 8/8;
  - Kerberos NLA 3/3;
  - smartcard via p11-kit 4/4;
  - smartcard via SoftHSM directly 4/4 (fails with the distribution's FreeRDP).
- The proxy module builds against `/opt/fastrdp` and resolves the plugin
  directory to `/opt/fastrdp/lib/freerdp3/proxy`.

Not tested here: installing the packages and running them on a real host, and the
Ansible build path on a real host. CI covers clean-container builds.
