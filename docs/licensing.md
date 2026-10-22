# Licensing

fast-rdp-server's own code is licensed under the **Apache License 2.0** ([LICENSE](../LICENSE),
[NOTICE](../NOTICE)). Source files carry `SPDX-License-Identifier: Apache-2.0` headers.
This document explains how that fits with the software fastrdp builds, links and
deploys, and what we must do when distributing binaries. It is a technical
assessment (2026-10-19), not legal advice.

## Components

| Component | License | How fastrdp uses it |
|---|---|---|
| fastrdp code: broker, webgate, PAM module, proxy module, Ansible, scripts | Apache-2.0 | ours |
| Roboto font 2.138, Regular and Medium (`broker/proxy-module/fastrdp_font.h`, rasterised by `gen_font.py` with freetype-py, which is needed only to regenerate it) | Apache-2.0 | antialiased glyph bitmaps built into `fastrdp-proxy-module` (waiting screen); chosen over OFL-1.1 fonts (Inter, Noto), which the FSF lists as GPL-incompatible, because the module is part of a GPL-3.0-or-later combined work; notice in the header, `NOTICE` and `debian/copyright` |
| QR code encoder (`broker/brokerd/fastrdp_broker/qrcode.py`) | Apache-2.0 | ours, written from ISO/IEC 18004; checked against Nayuki's qrcodegen (MIT) and decoded with zxing-cpp (Apache-2.0) only in tests, neither shipped |
| Patches in `patches/freerdp/`, `patches/xrdp/` | Apache-2.0, like the files they modify | built into the vendored packages |
| `patches/krb5/` | MIT Kerberos license | reference only, not built |
| FreeRDP 3.32.2 | Apache-2.0; some files public domain (MD4/MD5), BSD (cpu-features, OpenSL, CMake modules), Expat (iOS, Wayland XML), OFL-1.1 (fonts, not built) | vendored build `fastrdp-freerdp3` |
| xrdp 0.10.6.1 | Apache-2.0; `xrdp-genkeymap` and `xrdp-sesadmin` GPL-2.0-or-later; tomlc99 Expat | vendored build `fastrdp-xrdp` |
| xorgxrdp 0.10.5 | X11 | vendored build `fastrdp-xrdp` |
| FFmpeg (libavcodec, libavutil, libswscale, libswresample) | Debian/Ubuntu build it with `--enable-gpl`, `libx264`, `libx265`, so **GPL-2.0-or-later** | linked by FreeRDP and xrdp (distribution package) |
| x264 | GPL-2.0-or-later | linked by xrdp (distribution package) |
| OpenSSL 3, MIT krb5, cJSON, libpam, PC/SC, ICU, X11 libraries, opus, lame, fuse3, pixman, libjpeg | Apache-2.0, MIT-style, LGPL | linked (distribution packages) |
| Python stdlib, python3-cryptography | PSF, Apache-2.0/BSD | broker, webgate |
| privacyIDEA, Keycloak, Guacamole, gnome-remote-desktop, KRdp, VirtualGL, GPU drivers | AGPL-3.0, Apache-2.0, Apache-2.0, GPL-2.0+, LGPL, LGPL/wxWindows, various | installed from upstream or distribution sources by Ansible; never linked with or shipped by fastrdp |

## Compatibility

- **Source code.** Everything fastrdp's own code links or loads is Apache-2.0
  compatible, so the repository can be Apache-2.0.
- **Binaries with GPL libraries.** Apache-2.0 cannot be combined with GPL-2.0-*only*
  code, but it can be combined with GPL-3.0. FFmpeg and x264 are GPL-2.0-*or-later*,
  so these binaries are combined works distributed under **GPL-3.0-or-later** terms:
  - `fastrdp-freerdp3` and `fastrdp-xrdp`;
  - `fastrdp-proxy-module`, through the FreeRDP it loads into.

  Debian ships its own freerdp3 on the same basis. The source files keep their
  licenses. This affects only how the binaries may be redistributed.
- **Deployed services.** Software that fastrdp only installs or talks to over the
  network (privacyIDEA under AGPL, Keycloak, Guacamole containers) is not
  distributed by fastrdp. If fastrdp ever mirrors their packages or images,
  their own terms apply: AGPL-3.0 requires offering source for modified versions
  that are offered over a network.
- **Patents.** H.264 encoders (x264, and hardware encoders reached through FFmpeg)
  may be subject to patent licensing in some countries. This is independent of the
  copyright licenses above. The distributions ship x264 anyway; commercial
  redistributors should check their situation.

## What we do because of it

1. **Corresponding source for every published vendored binary** (GPL-3.0 §6(d):
   source available from the same place as the object code):
   - `packaging/ci/make-source-archive.sh` runs in CI right before each vendored
     build and archives exactly the tree that is built: patched upstream source,
     `debian/` and build scripts. It adds the pristine upstream tarballs, the patch
     series and `SHA256SUMS`.
   - `packaging/apt/publish.sh` publishes them at
     <https://linuxrrze.github.io/fast-rdp-server/sources/> for every version in
     the APT pool. It refuses to publish a vendored package without its source.
   - Stable releases also attach the `.source.tar.xz` files to the GitHub release.
2. **Copyright files** in the packages (`packaging/*/debian/copyright`,
   `debian/copyright`) list every license in the sources. They state the
   combined-work terms and where the source is.
3. **No GPL-incompatible additions.** Before adding a dependency to fastrdp or to a
   vendored build, check its license against this table. Apache-2.0, MIT, BSD,
   LGPL, GPL-2.0-or-later and GPL-3.0 are fine. GPL-2.0-only must not be linked
   with the Apache-2.0 code. Non-free licenses (for example FFmpeg built with
   `--enable-nonfree`) are excluded.

## Alternative if GPL obligations must be avoided

The binaries could be kept free of GPL code:
- build an LGPL-only FFmpeg (no `--enable-gpl`, no x264/x265) as a third
  vendored dependency;
- build xrdp without x264, falling back to OpenH264 (BSD; Cisco's binary
  includes the patent licence), with VA-API, NVENC and QSV still available
  through the LGPL FFmpeg.

The costs are another large vendored build and lower software-encoder quality.
This is only worth it if third parties want to redistribute fastrdp without
GPL obligations.
