# Vendored dependencies

fastrdp builds its **own patched copies** of the dependencies it needs fixes in,
instead of using the distribution packages. The patches are kept local for now. They
will be offered upstream once the whole stack works (see [upstream.md](upstream.md)),
and each vendored build can be dropped when its fixes reach the distributions.

## What is vendored

| Dependency | Version | Local patches | Installed to | Used by |
|---|---|---|---|---|
| FreeRDP | 3.32.2 | `patches/freerdp/`: PKCS#11 slot id fix (client-side smartcard logon); Remote Credential Guard: negotiation answer instead of a dropped connection, TSRemoteGuardCreds without `supplementalCreds` (server side) | `/opt/fastrdp` (private) | `freerdp-proxy` + fastrdp module, `xfreerdp` and rdpbench (H.264), e2e tests |
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

## Is each piece really required?

Checked 2026-10-19 against the distribution packages. Each patch directory has a
README with the full reasoning, evidence and the condition for dropping it.

| Item | Required? | Why | Without it | Regression test | Drop when |
|---|---|---|---|---|---|
| Vendored **FreeRDP** | **yes** | The proxy needs ≥ 3.32 (`CertificatePolicy`). Debian 13 ships 3.15.0 (3.32.1 only in backports); Ubuntu 26.04 ships 3.32.1. One tested version everywhere; H.264 in fastrdp's client builds | No supported proxy on Debian 13 without backports; version drift between distributions | e2e suites with `FREERDP_PREFIX=/opt/fastrdp` | Both distributions ship ≥ 3.32 *and* the `patches/freerdp` fixes are in their FreeRDP (the slot id fix only while fastrdp ships the client) |
| `patches/freerdp/0001` slot id | **client side only** | Fixes PKINIT smartcard logon of the `xfreerdp` that fastrdp ships, with PKCS#11 modules using slot ids ≥ 65536 (SoftHSM2, some HSMs). The server never runs this code. OpenSC/YubiKey PIV are unaffected | `fastrdp-freerdp3`'s client fails PKINIT with such tokens; the SoftHSM e2e regression test fails | `SC_MODULE=softhsm tests/proxy-e2e/run_smartcard.sh` | A FreeRDP release contains the fix |
| `patches/freerdp/0002` RCG negotiation | **yes** (server) | A client that requires Remote Credential Guard (`mstsc /remoteGuard`) gets an RDP_NEG_RSP without REDIRECTED_AUTHENTICATION_MODE_SUPPORTED ([MS-RDPBCGR] 2.2.1.2.1) and can report the refusal; FreeRDP dropped the TCP connection instead | Such clients see a bare connection close and a generic network error | `run.sh`, `run_nla.sh` (client with `E2E_REMOTE_GUARD=1`) | A FreeRDP release answers instead of dropping |
| `patches/freerdp/0003` TSRemoteGuardCreds parsing | **only with `AcceptRemoteGuard=true`** (server) | `supplementalCreds` is optional ([MS-CSSP] 2.2.1.2.3); FreeRDP's server rejected credentials without it, and FreeRDP clients never send it | Remote Credential Guard logins from FreeRDP clients fail at NLA | `run_nla.sh` ("RCG accepted" checks) | A FreeRDP release parses them |
| Vendored **xrdp/xorgxrdp** | **yes** | Debian 13 and Ubuntu 26.04 ship xrdp 0.10.1: no H.264 (0.10.2), no unprivileged daemon (0.10.2/0.10.5), none of the `gfx.toml` settings fastrdp renders; 19 later CVE fixes only as far as backported | X11 sessions without H.264, xrdp running as root, configuration partly ignored | `build-xrdp.sh` feature checks; xrdp e2e via the smoke test on a host | Both distributions ship ≥ 0.10.5 *and* the encoder patch is upstream |
| `patches/xrdp/0001` FFmpeg encoder | **yes, for GPU encoding** | The only way to use VA-API/QSV/NVENC in xrdp sessions in a released xrdp; falls back to libx264 | CPU-only H.264 (x264), about one core or more per active 1080p session | `patches/xrdp/test/run_test.sh` (libx264 path, GPU→fallback, fallback disabled) | An xrdp release offers VA-API hardware encoding |
| `patches/krb5/0001` SPNEGO MIC | **no** (reference only, not built) | No fastrdp login path uses an MIT SPNEGO acceptor (proxy, g-r-d and KRdp use WinPR; xrdp gets tokens). Kept as root-cause evidence and for distribution bug reports | nothing changes for fastrdp | `tests/krb5-spnego/run.sh` checks a host | Distributions ship krb5 ≥ 1.22.2 |

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
3. Add a changelog entry in `packaging/<freerdp|xrdp>/debian/changelog`. A change to the patches
   alone bumps the Debian revision (`3.32.2-1` → `3.32.2-2`, [packaging.md](packaging.md)).
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

2026-10-21, `3.32.2-2` (patches 0002 + 0003, Remote Credential Guard): scratch build with
MIT Kerberos (server, proxy, client libraries; no X11/FFmpeg), all four e2e suites:
TLS 30/30, Kerberos NLA 11/11, smartcard via p11-kit 4/4 and via SoftHSM 4/4. Against
the same build without 0002/0003: TLS 29/30, NLA 6/11 (the Remote Credential Guard
checks fail).

2026-10-21, `3.32.2-3` (patch 0004, Kerberos user-to-user for mstsc with AD): scratch
build with MIT Kerberos as above, all four e2e suites: TLS 30/30, Kerberos NLA 22/22 (MIT
krb5 1.22.1 KDC in AD mode), smartcard via p11-kit 4/4 and via SoftHSM 4/4. Against the
3.32.2-2 build (0001-0003): NLA 19/22, the user-to-user login fails as in the field report.

2026-10-22, `3.32.2-4` (patch 0005, KDC evidence from the accepted ticket, K11): sysroot
build of the full `build-freerdp.sh` configuration (X11, FFmpeg/H.264, MIT krb5 1.22.1),
all four e2e suites: TLS 39/39, Kerberos NLA 24/24 (AD mode), smartcard via p11-kit 6/6
and via SoftHSM 6/6 (the broker gets `ind:pkinit` from a KDC with `pkinit_indicator`). Against the same build
without 0005: smartcard 5/6, NLA 23/24, TLS 39/39 (no evidence; the module builds without
the new attributes). With a deliberately wrong verification key (user-to-user and
keytab) the indicator is dropped and the proxy logs the failed svc-verifier / PAC
signature, so the e2e checks fail.

2026-10-22, `3.32.2-5` (patch 0006, the proxy forwards Server Status Info PDUs only to
clients that announced them): sysroot build of the full `build-freerdp.sh` configuration,
TLS e2e suite 39/39. No suite exercises the drop itself (no test back-end sends the PDU);
NLA and smartcard suites not rerun (no KDC on the build host; 0006 touches only
`server/proxy/pf_update.c`).

Not tested here: installing the packages and running them on a real host, and the
Ansible build path on a real host. CI covers clean-container builds.
