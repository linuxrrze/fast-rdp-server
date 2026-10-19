# Patches for FreeRDP 3.32.2

Applied by `third_party/fetch.sh freerdp` (series: `series`) to the release tarball
listed in `third_party/sources.yml`. Built by `third_party/build-freerdp.sh` into
`/opt/fastrdp` and shipped as `fastrdp-freerdp3`. Policy: [docs/vendoring.md](../../docs/vendoring.md).

## Why fastrdp builds FreeRDP at all

The vendored build is required even without any patch:

| Reason | Evidence |
|---|---|
| The proxy configuration needs FreeRDP **≥ 3.32**: `[Target] CertificatePolicy` in `proxy.ini` (role `freerdp_proxy`, `fastrdp_proxy_min_version`) | `server/proxy/pf_config.c` has no `CertificatePolicy` in 3.15.0 and 3.31.0; it appears in 3.32.0 |
| **Debian 13 ships 3.15.0** (`3.15.0+dfsg-2.1+deb13u3`); 3.32.1 is only in trixie-backports. Ubuntu 26.04 ships 3.32.1 | sources.debian.org, Launchpad (checked 2026-10-19) |
| One identical, tested FreeRDP on both distributions: proxy, module ABI and e2e tests | `fastrdp-proxy-module` depends on exactly the vendored version |
| H.264 decoding in fastrdp's own client builds (`xfreerdp`, rdpbench). The Ubuntu 26.04 freerdp3 is built without `WITH_GFX_H264`, so benchmarks could not measure H.264. The proxy itself forwards GFX without decoding | `build-freerdp.sh` checks `WITH_GFX_H264` in the generated `config.h` |

## 0001 – [core,scard] do not truncate PKCS#11 slot id in pkinit args

**Problem.** For smartcard logon (`/smartcard-logon`), the FreeRDP **client** passes
the token's PKCS#11 slot to MIT PKINIT as `PKCS11:...:slotid=<n>`.
`build_pkinit_args()` in `libfreerdp/core/smartcardlogon.c` prints that id with
`PRIu16` after casting it to `UINT16`. The value is a `UINT32`
(`SmartcardCertInfo::slotId`, from WinPR's `NCRYPT_WINPR_SLOTID`).

**Who is affected.** Clients using a PKCS#11 module with slot ids ≥ 65536:
- SoftHSM2 (random 32-bit ids such as `0x47c3da5d` → `slotid=55901`);
- HSM- or cloud-backed modules that number slots the same way.

PKINIT then reports "PKCS#11 module has no matching tokens", falls back to encrypted
timestamp, and the logon fails.

Not affected:
- OpenSC (PIV cards, YubiKey PIV), `libykcs11` and `p11-kit-proxy.so`, which use
  small slot numbers;
- the **server side**: freerdp-proxy and the fastrdp module never call
  `build_pkinit_args()`.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp server (proxy + module) | **no**: the code path is client-only |
| `xfreerdp` from `fastrdp-freerdp3` (admin and test client) with such a token | **yes** |
| fastrdp's regression suite: `SC_MODULE=softhsm tests/proxy-e2e/run_smartcard.sh` exercises a 32-bit slot id end to end | **yes**; this test fails without the patch |

It is kept because the vendored client is part of what fastrdp ships and tests, the
change is four lines with no side effects, and upstream still has the bug.

**Fix.** Print the full `UINT32` with `PRIu32`. MIT PKINIT itself accepts slot ids up
to `INT_MAX` (`src/plugins/preauth/pkinit/pkinit_identity.c`), so larger ids would
still be rejected there, independently of this patch.

**Regression test.** `SC_MODULE=softhsm FREERDP_PREFIX=/opt/fastrdp
tests/proxy-e2e/run_smartcard.sh` (4 checks). With the unpatched client PKINIT asks
for the truncated `slotid=` and the logon check fails. The default variant through
p11-kit must pass both with and without the patch.

**Status upstream.** Present on FreeRDP master (`bf05ae7`, 2026-10-19). The
pull request text is in [docs/upstream.md §1](../../docs/upstream.md); it has not
been submitted.

**Drop it when** a FreeRDP release with the fix is the vendored version, or when
fastrdp stops shipping its own client binaries.
