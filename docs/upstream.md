# Upstream reports and fixes

Problems found while building fastrdp that belong to other projects.

**Policy (2026-10-19):** nothing is submitted upstream yet. The fixes are kept as local
patches and built into fastrdp's own dependency builds ([vendoring.md](vendoring.md)).
The texts below are ready for when the stack works end to end. All were
reproduced on 2026-10-19 on Ubuntu 26.04 with FreeRDP 3.32.1 and MIT krb5 1.22.1, plus
self-built FreeRDP 3.32.1 (with the fix below) and MIT krb5 1.22.2.

| # | Project | Problem | Status |
|---|---|---|---|
| 1 | FreeRDP | Smartcard logon (client side): PKCS#11 slot id truncated to 16 bits | fix in `patches/freerdp/`, shipped in `fastrdp-freerdp3`; not submitted. Necessity: [patches/freerdp/README.md](../patches/freerdp/README.md) |
| 2 | MIT krb5 (Debian, Ubuntu) | SPNEGO acceptor ignores the initiator's mechListMIC; breaks FreeRDP Kerberos NLA against xrdp PR #3868 | fixed upstream in 1.22.2; fix kept in `patches/krb5/` (reference, not built); distro requests not filed |
| 3 | xrdp PR #3868 | Not an xrdp bug (see 2); comment with the root cause drafted | not posted |
| 4 | xrdp | FFmpeg H.264 encoder (VA-API, NVENC, QSV) | `patches/xrdp/`, shipped in `fastrdp-xrdp`; draft PR text in §4 (rebase onto devel, GPU results to do); not submitted |

Nothing here is needed for fastrdp itself:
- (1) is a client-side bug, and p11-kit-proxy (small slot ids) avoids it.
- (2) does not affect freerdp-proxy, whose WinPR acceptor parses the MIC correctly.

## 1. FreeRDP: PKCS#11 slot id truncated to 16 bits

**Bug.** `build_pkinit_args()` in `libfreerdp/core/smartcardlogon.c` formats the slot
id with `PRIu16` after casting it to `UINT16`. The value comes from WinPR's
`NCRYPT_WINPR_SLOTID` property as a `UINT32`. Some PKCS#11 modules use 32-bit slot
ids; SoftHSM2's are random, e.g. `0x47c3da5d`. The truncated value matches no slot, so:
- MIT PKINIT logs "PKCS#11 module has no matching tokens";
- the client falls back to encrypted timestamp;
- the logon fails.

Still present on FreeRDP master `bf05ae7` (2026-10-19).

**Fix.** Print the full value with `PRIu32` (4 lines). MIT accepts slot ids up to
`INT_MAX` (`pkinit_identity.c` rejects larger ones), which covers the module seen
here.

**Verified** with `SC_MODULE=softhsm tests/proxy-e2e/run_smartcard.sh`, which loads
SoftHSM directly instead of through p11-kit:

| Client library | Client asks PKINIT for | Result |
|---|---|---|
| FreeRDP 3.32.1 (Ubuntu) | `slotid=33479` (truncated) | no PKINIT, logon fails |
| 3.32.1 + fix (`CLIENT_LIBDIR=<build>`) | full slot id | 4/4 checks pass |
| 3.32.1 via p11-kit-proxy (default test) | small slot id | 4/4 checks pass |
| 3.32.2 + fix (fastrdp's vendored build, `FREERDP_PREFIX=`) | full slot id | 4/4 pass; with p11-kit 4/4 too |

The patch was refreshed against 3.32.2, where it applies without offset, and was
written on master `bf05ae7` (branch `fix-pkinit-slotid`). Before submitting, rebase
onto current master and recheck that `build_pkinit_args()` is unchanged.

**Pull request text** (branch `fix-pkinit-slotid` on master):

> **[core,scard] do not truncate PKCS#11 slot id in pkinit args**
>
> `build_pkinit_args()` formats the slot id with `PRIu16` after a cast to `UINT16`,
> but `SmartcardCertInfo::slotId` is a `UINT32` (from `NCRYPT_WINPR_SLOTID`).
> PKCS#11 modules with 32-bit slot ids, such as SoftHSM2 (slot `0x47c3da5d` →
> `slotid=55901`), therefore fail smartcard logon: MIT PKINIT reports "PKCS#11
> module has no matching tokens" and falls back to encrypted timestamp.
>
> Reproducer: a SoftHSM2 token with certificate and key, a KDC with PKINIT,
> `/smartcard-logon /p11-module:libsofthsm2.so`, and `KRB5_TRACE=/dev/stderr` on the
> client shows the truncated `slotid=`.
>
> With this change the logon succeeds. Tested with FreeRDP 3.32.1 and 3.32.2 clients
> against MIT krb5 1.22.1 (PKINIT), through freerdp-proxy with Kerberos NLA:
> - SoftHSM2 loaded directly (32-bit slot ids): before the fix PKINIT finds no token
>   and the logon fails; after it, the logon succeeds, a wrong PIN stops at PKINIT,
>   and the principal comes from the certificate.
> - The same token through p11-kit-proxy (small slot ids) works before and after.
>
> Tokens behind OpenSC and p11-kit-proxy use small slot ids and were not affected.
> MIT's PKINIT accepts slot ids up to `INT_MAX` (`pkinit_identity.c`), so larger ids
> would still be rejected there, but that is independent of this change.

## 2. MIT krb5 1.21.0–1.22.1: SPNEGO acceptor ignores the initiator's mechListMIC

**Symptom.** Kerberos NLA from FreeRDP 3 clients to xrdp with PR #3868 fails with
default settings:
- The client log shows "Invalid token was supplied" after the Kerberos exchange
  itself succeeded.
- With `/auth-pkg-list:'kerberos,!u2u,!ntlm'` the login works.

**Root cause.** The exchange goes like this:
1. WinPR's SPNEGO offers *Kerberos user-to-user* first, then Kerberos.
2. MIT selects Kerberos. Because that is not the initiator's first mechanism,
   RFC 4178 requires a mechListMIC from both sides.
3. MIT sends the AP-REP with its MIC.
4. WinPR verifies it and answers with `negTokenResp { negState accept-completed,
   mechListMIC [3] }`.

MIT commit fdceb225 (1.21, "Use k5-der.h in GSS library") changed `get_negTokenResp()`
to look for mechListMIC under tag `0xA4` instead of `0xA3`. MIT therefore sees a token
with neither responseToken nor MIC and returns `GSS_S_DEFECTIVE_TOKEN`.

MIT fixed this in commit
[942c5036](https://github.com/krb5/krb5/commit/942c5036e14066a1f4badfdf67716c47f2e33a39)
("Fix SPNEGO mechListMIC parsing", ticket 9183, tagged `pullup` for 1.21 and 1.22). The
fix is in **krb5 1.22.2**.

Affected distribution packages (source checked for `CONTEXT | 0x04`):

| Distribution | krb5 package | Affected |
|---|---|---|
| Debian 13 trixie | 1.21.3-5+deb13u1 | yes |
| Debian sid / forky | 1.22.1-3 | yes |
| Ubuntu 26.04 | 1.22.1-2ubuntu4.1 | yes (reproduced) |

Any MIT acceptor is affected whenever a SPNEGO initiator's first mechanism is not the
one MIT selects, not only xrdp:
- the initiator offers a mechanism MIT doesn't support first (as WinPR does with U2U);
- Windows clients that put NTLM or NegoEx first.

**Reproducer:** `tests/krb5-spnego/run.sh`. It runs a WinPR initiator and an MIT
`gss_accept_sec_context` in one process against a throwaway KDC, with no RDP involved.

| MIT library | FreeRDP defaults | `kerberos,!u2u,!ntlm` | run.sh |
|---|---|---|---|
| 1.22.1 (Ubuntu 26.04) | rejected, `GSS_S_DEFECTIVE_TOKEN` | ok | exit 1 "AFFECTED" |
| 1.22.2 (self-built, `MIT_LIBDIR=`) | ok | ok | exit 0 |

The client in both runs is the stock Ubuntu FreeRDP 3.32.1, so FreeRDP needs no
change.

A side observation, not reported: WinPR records Kerberos sequence numbers only when
`ISC_REQ_SEQUENCE_DETECT` is requested, so its MIC tokens carry `SND_SEQ = 0`. MIT
accepts this because the context has no sequence/replay flags. Correcting it does not
change the result above.

**Debian bug report** (`reportbug krb5`, severity important, tags patch, upstream,
fixed-upstream; one for trixie via stable-proposed-updates, and sid):

> Subject: krb5: SPNEGO acceptor ignores initiator mechListMIC (upstream #9183), please backport 942c5036
>
> Since 1.21, `get_negTokenResp()` looks for mechListMIC with tag 0xA4 instead of 0xA3
> (regression from upstream commit fdceb225). Any SPNEGO exchange where the acceptor
> selects a mechanism other than the initiator's first one needs a MIC from the
> initiator, and MIT rejects that final token with GSS_S_DEFECTIVE_TOKEN.
>
> Practical impact: FreeRDP 3 clients (default settings: Kerberos U2U offered first)
> cannot complete Kerberos NLA against MIT-based RDP servers (xrdp NLA, PR #3868).
>
> Upstream fix: https://github.com/krb5/krb5/commit/942c5036e14066a1f4badfdf67716c47f2e33a39
> (one-line change in src/lib/gssapi/spnego/spnego_mech.c, released in 1.22.2).
> Verified with an in-process WinPR initiator → MIT acceptor test: 1.22.1 fails,
> 1.22.2 succeeds. Affects trixie (1.21.3-5+deb13u1) and sid (1.22.1-3).

**Ubuntu (Launchpad, package krb5)**: same text, with "Ubuntu 26.04,
1.22.1-2ubuntu4.1", asking for an SRU of the one-line fix.

## 3. xrdp PR #3868: comment

> Tested 0f9be1d against FreeRDP 3.32.1 clients on Ubuntu 26.04. Kerberos NLA fails
> with default client settings ("Invalid token was supplied") and works with
> `/auth-pkg-list:'kerberos,!u2u,!ntlm'`. This is not a bug in this PR. FreeRDP offers
> Kerberos U2U first; MIT selects Kerberos, which requires a mechListMIC from the
> client; MIT krb5 1.21.0–1.22.1 parses the MIC under the wrong tag and rejects it
> (krb5 ticket 9183, fixed in 1.22.2 by commit 942c5036). The same client succeeds
> against MIT 1.22.2. Debian 13 and Ubuntu 26.04 ship affected versions, so it may be
> worth mentioning in the docs.
>
> Two small notes: GSSAPI detection only uses `krb5-config` (a
> `pkg-config krb5-gssapi` fallback would help sysroot builds), and smartcard
> TSCredentials are rejected as documented.

## 4. xrdp: FFmpeg H.264 encoder (VA-API, NVENC, QSV)

Patch: `patches/xrdp/0001-Add-FFmpeg-H.264-encoder-VA-API-NVENC-QSV.patch`
(against v0.10.6.1). Design, configuration and local test harness:
[patches/xrdp/README.md](../patches/xrdp/README.md). This section is the **draft
pull request**. Items marked *to do* must be done before submitting.

### Before submitting

- **Rebase onto `devel`** (*to do*). On devel `5943357a54` (2026-10-14), all hunks
  in `xrdp/` apply, some with offsets. Only `configure.ac` conflicts: 2 of 3 hunks,
  the `--enable-ffmpeg` option and the summary line.
- **Relation to `xrdp_accel_assist`** (devel, unreleased). That helper encodes with
  NVENC only and takes frames zero-copy from GLX/EGL. This patch encodes inside the
  xrdp process from the NV12 frames xorgxrdp already sends for x264, and covers
  VA-API (Intel/AMD), QSV and NVENC through FFmpeg. The two are complementary:
  `accel_assist` is the faster NVIDIA path, and this patch brings hardware encoding
  to Intel/AMD and to setups without `accel_assist`. Ask the maintainers whether
  they prefer this as a separate `h264_encoder` or as a VA-API backend for
  `accel_assist` (EGL → dma-buf → VA surface, no CPU copy). The latter is more
  work, but would be the natural long-term design.
- **Tests in xrdp's own suite** (*to do*): `tests/xrdp/gfx/gfx_h264_encoder_ffmpeg.toml`
  plus `test_tconfig.c` cases for the `[ffmpeg]` sections (defaults, per connection
  type, invalid values), alongside the existing x264/openh264 fixtures.
- **Real GPU results** (*to do*). Run `patches/xrdp/test/run_test.sh <src>
  h264_vaapi` on Intel and AMD and `h264_nvenc` on NVIDIA. Record fps, encode
  latency and CPU per session (fastrdp's `tests/perf` rdpbench), then fill in the
  table below.
- **CI** (*to do*): xrdp's GitHub CI builds with `--enable-ffmpeg`; add
  `libavcodec-dev` to the build matrix.
- **Commit trailer.** The commit carries `Co-Authored-By: Claude Opus 5.5`. Keep or
  drop it according to your preference and xrdp's contribution rules.

### Pull request text

> **Add FFmpeg H.264 encoder backend (VA-API, NVENC, QSV)**
>
> **Motivation.** xrdp encodes H.264 in software only (x264 or OpenH264). On
> multi-user servers this costs one or more CPU cores per active session at 1080p.
> Most server and workstation GPUs have fixed-function H.264 encoders that are idle
> in these setups: Intel Quick Sync, AMD VCN and NVIDIA NVENC. FFmpeg's libavcodec
> exposes all of them through one API, `h264_vaapi`, `h264_qsv` and `h264_nvenc`,
> so one backend covers every vendor.
>
> **What it does**
> - Adds `h264_encoder = "ffmpeg"` as a third encoder next to `x264` and `openh264`
>   (`xrdp/xrdp_encoder_ffmpeg.c`, selected in `set_h264_encoder_methods()`).
> - Input is the NV12 frame xorgxrdp already produces for the x264 backend, so
>   xorgxrdp is unchanged. Each session keeps one full frame and copies only the
>   damaged rectangles into it. VA-API uploads with `av_hwframe_transfer_data`;
>   NVENC and QSV take NV12 from system memory.
> - Low latency. Every input frame produces exactly one access unit
>   immediately: no B-frames, `AV_CODEC_FLAG_LOW_DELAY`, `async_depth=1` (VA-API,
>   QSV), and `preset=p1 tune=ull zerolatency=1 delay=0` (NVENC). SPS/PPS are
>   repeated with every IDR, and the output is Annex B as the GFX channel expects.
> - Rate control per connection type, in the same structure as `[x264.*]`:
>   `bitrate`/`max_bitrate` (kbit/s) or constant quality `qp`, plus `gop`,
>   `fps_num` and `fps_den`.
> - Start-up probe and fallback. When an encoder is created, it encodes one
>   256×256 frame. If the GPU, driver or library is unusable, xrdp logs one warning
>   and uses `fallback` (default `libx264`, also through FFmpeg) instead of failing
>   on every frame. `fallback = ""` turns this off, and the encoder is then refused.
> - Opt-in at build time: `./configure --enable-ffmpeg` (libavcodec ≥ 60,
>   libavutil ≥ 58). Nothing changes for builds without it.
>
> **Configuration (gfx.toml)**
> ```toml
> [codec]
> h264_encoder = "ffmpeg"
>
> [ffmpeg]
> encoder = "h264_vaapi"          # h264_vaapi | h264_nvenc | h264_qsv | libx264
> device = "/dev/dri/renderD128"  # VA-API render node
> fallback = "libx264"            # if `encoder` fails its start-up probe; "" = none
> options = ""                    # extra AVOptions, "key=value:key=value"
>
> [ffmpeg.default]
> qp = 23
> gop = 300
> fps_num = 60
> fps_den = 1
>
> [ffmpeg.lan]
> bitrate = 0                     # 0 = constant quality (qp)
>
> [ffmpeg.wan]
> bitrate = 12000
> max_bitrate = 15000
> ```
>
> **Testing**
> - Builds with `--enable-ffmpeg` on Ubuntu 26.04 (libavcodec 62, also with
>   `-Werror`) and Debian 13 (FFmpeg 7.1, libavcodec 61). *To do: confirm that
>   builds without `--enable-ffmpeg` are unchanged, on devel.*
> - A functional test drives `xrdp_encoder_ffmpeg` through the real `gfx.toml` loader
>   and decodes the output with libavcodec. Using `libx264` through the same code
>   path:
>   - 30 of 30 inputs decode immediately, one access unit each;
>   - SPS and IDR at start and after a resize;
>   - luma PSNR 56 dB at QP 20;
>   - coded size 1376×768 for 1366×768 (16-pixel alignment);
>   - partial-update frames are correct;
>   - an output buffer that is too small is refused.
> - Without a GPU, `h264_vaapi` and `h264_nvenc` fail the probe, fall back to
>   `libx264` and pass the same checks; with `fallback = ""` they are refused.
> - Hardware results:
>
>   | GPU | Encoder | 1080p fps | encode ms/frame | CPU per session (xrdp) |
>   |---|---|---|---|---|
>   | Intel (iGPU) | h264_vaapi | *to measure* | | |
>   | AMD | h264_vaapi | *to measure* | | |
>   | NVIDIA | h264_nvenc | *to measure* | | |
>   | none | libx264 (fallback) | *to measure* | | |
>
> **Notes**
> - The encoder runs in the unprivileged xrdp daemon, which needs read/write
>   access to the render node for VA-API and QSV (for example through the
>   distribution's `render` group or a udev rule).
> - This complements `xrdp_accel_assist` on devel: that helper is a zero-copy
>   NVENC path, while this backend adds VA-API and QSV, works with any xorgxrdp
>   setup, and is optional at build time.
