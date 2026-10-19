# Upstream reports and fixes

Problems found while building fastrdp that belong to other projects.

**Policy (2026-10-19):** nothing is submitted upstream yet. The fixes are kept as local
patches and built into fastrdp's own dependency builds ([vendoring.md](vendoring.md)).
The texts below are ready for when the stack works end to end. All were
reproduced on 2026-10-19 on Ubuntu 26.04 with FreeRDP 3.32.1 and MIT krb5 1.22.1, plus
self-built FreeRDP 3.32.1 (with the fix below) and MIT krb5 1.22.2.

| # | Project | Problem | Status |
|---|---|---|---|
| 1 | FreeRDP | Smartcard logon: PKCS#11 slot id truncated to 16 bits | fix in `patches/freerdp/`, shipped in `fastrdp-freerdp3`; not submitted |
| 2 | MIT krb5 (Debian, Ubuntu) | SPNEGO acceptor ignores the initiator's mechListMIC; breaks FreeRDP Kerberos NLA against xrdp PR #3868 | fixed upstream in 1.22.2; fix kept in `patches/krb5/` (reference, not built); distro requests not filed |
| 3 | xrdp PR #3868 | Not an xrdp bug (see 2); comment with the root cause drafted | not posted |
| 4 | xrdp | FFmpeg H.264 encoder (VA-API, NVENC, QSV) | `patches/xrdp/`, shipped in `fastrdp-xrdp`; not submitted |

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
> client shows the truncated `slotid=`. With this change the logon succeeds (tested
> on 3.32.1 against MIT krb5 1.22.1). Tokens behind OpenSC or p11-kit-proxy have
> small slot ids and were not affected.

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
