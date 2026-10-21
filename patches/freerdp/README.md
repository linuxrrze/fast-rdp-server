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

## 0002 – [core,nego] answer an unsupported Remote Credential Guard request

**Problem.** A client that *requires* Remote Credential Guard sets
REDIRECTED_AUTHENTICATION_MODE_REQUIRED in its RDP_NEG_REQ ([MS-RDPBCGR] 2.2.1.1.1):
`mstsc /remoteGuard`, or any mstsc under the policy "Restrict delegation of credentials
to remote servers: Require Remote Credential Guard". When the server does not support the
mode, `nego_process_negotiation_request()` in `libfreerdp/core/nego.c` failed, and the
server closed the TCP connection without an X.224 Connection Confirm. The client could only
report a generic network error.

**Who is affected.** Every FreeRDP server with `FreeRDP_RemoteCredentialGuard` off, so
freerdp-proxy with the fastrdp module unless `[FastRDP] AcceptRemoteGuard=true`. The case
where the client sets both RESTRICTED_ADMIN_MODE_REQUIRED and the Remote Credential Guard
flag ("either mode") already fell back to Restricted Admin and is unchanged.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp server, default (`AcceptRemoteGuard=false`) | **yes**, for a clear refusal of `/remoteGuard` clients instead of a dropped connection ([rdp-spec-conformance.md](../../docs/rdp-spec-conformance.md) R4) |
| `AcceptRemoteGuard=true` | no: the server then supports the mode |
| fastrdp's regression suite | **yes**: `run.sh` and `run_nla.sh` check that a `/remoteGuard` client gets a negotiation response |

**Fix.** Choice per [MS-RDPBCGR]:
- 2.2.1.2.1: the server states support with REDIRECTED_AUTHENTICATION_MODE_SUPPORTED in
  the RDP_NEG_RSP. Leaving the flag out *is* the answer "not supported".
- 2.2.1.2.2: none of the RDP_NEG_FAILURE codes (SSL/HYBRID required, certificate missing,
  inconsistent flags, Entra ID) describes the case; a failure code would give the client a
  wrong message.
- 3.3.5.3.2: the server sends an RDP_NEG_RSP when it supports one of the requested
  security protocols, which it does.

So the server goes on and answers with an RDP_NEG_RSP without the flag. A client that
requires the mode disconnects on its own and can say why. The FreeRDP client logs
`remote credential guard requested but not supported, terminating`
(`nego_process_negotiation_response()`). mstsc's dialog is still to be recorded
([rdp-spec-conformance.md](../../docs/rdp-spec-conformance.md) lab S2). The server-side
state (`RemoteCredsGuardActive`) stays off. TSRemoteGuardCreds a client might send anyway
reach `peer->RemoteCredentials`; the fastrdp module refuses them unless
`AcceptRemoteGuard=true`.

**Regression test.** `tests/proxy-e2e/run.sh` (TLS proxy, client with
`E2E_REMOTE_GUARD=1`) and `run_nla.sh` (NLA proxy without `AcceptRemoteGuard`). Both check
the client's message. Without the patch the client sees the connection close and the
checks fail (checked against an unpatched 3.32.2 build: `run.sh` 29/30, `run_nla.sh` 6/11).

**Status upstream.** Still present in 3.32.2. Not submitted ([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** a FreeRDP release answers the request without dropping the connection.

## 0003 – [core,nla] accept TSRemoteGuardCreds without supplementalCreds

**Problem.** `supplementalCreds` in TSRemoteGuardCreds is OPTIONAL ([MS-CSSP] 2.2.1.2.3).
When it is absent it is also the last element. `nla_read_ts_credentials()` in
`libfreerdp/core/nla.c` then called `WinPrAsn1DecReadContextualSequence()` on an empty
decoder, which reports an error, and rejected the credentials ("invalid
supplementalCreds"). FreeRDP's own client never sends `supplementalCreds`
(`nla_encode_ts_remoteguard_credentials()`: "TODO: compute the NTLM supplemental creds").
So a FreeRDP server with Remote Credential Guard enabled refused every FreeRDP client
using `/remoteGuard`.

**Who is affected.** fastrdp with `[FastRDP] AcceptRemoteGuard=true` and FreeRDP clients
(xfreerdp built with the rdpear channel, the e2e client). Whether mstsc sends
`supplementalCreds` is not recorded yet (lab S2). It parses either way.

**Is it required?**

| Use | Required |
|---|---|
| `AcceptRemoteGuard=false` (default) | no |
| `AcceptRemoteGuard=true` with FreeRDP clients | **yes** |
| fastrdp's regression suite (`run_nla.sh`, Remote Credential Guard accepted) | **yes**; the login fails at NLA without it |

**Fix.** Peek at the next tag first, as `set_creds_octetstring_to_settings()` does for the
optional TSSmartCardCreds fields, and read `supplementalCreds` only when it is there.
Malformed `supplementalCreds` are still refused.

**Regression test.** `tests/proxy-e2e/run_nla.sh` (local MIT KDC): the "RCG accepted"
checks.

**Status upstream.** Still present in 3.32.2. Not submitted.

**Drop it when** a FreeRDP release parses TSRemoteGuardCreds without `supplementalCreds`.

## 0004 – [winpr,kerberos] U2U acceptor: answer with the TGT of the machine account

**Problem.** Windows does Kerberos user-to-user under CredSSP on purpose: CredSSP calls
`InitializeSecurityContext` with `ISC_REQ_USE_SESSION_KEY`, so mstsc's first token is a
KERB-TGT-REQUEST for `TERMSRV/<host>` (GSS OID 1.2.840.113554.1.2.2.3, TOK_ID `04 00`),
listed under the MS-KRB5 mechType. The acceptor must answer with a TGT; the KDC then
issues the user-to-user ticket only if that TGT's client is the account that owns the
requested name (MIT `check_tgs_u2u()`; AD maps the SPN to its account).
`retrieveSomeTgt()` in `winpr/libwinpr/sspi/Kerberos/kerberos.c` asked for a TGT of
`TERMSRV/<host>` with the keytab key and, with MIT krb5, of `<second name component>$`,
i.e. `<fqdn>$`. In Active Directory `TERMSRV/<host>` is an SPN of the computer account
`<NAME>$`: the KDC refuses it as an AS client ("Client 'TERMSRV/…' not found in Kerberos
database") and no account is called `<fqdn>$`. Kerberos was dropped; before R5 the client
ended in NTLM, now the login simply fails. Field report and analysis:
[docs/windows-clients.md](../../docs/windows-clients.md) §3.14.

**Who is affected.** Every mstsc (domain-joined or not) against a FreeRDP server whose
Kerberos acceptor uses an AD computer account's keys: freerdp-proxy with fastrdp,
gnome-remote-desktop, the shadow server. FreeRDP clients log in anyway: they offer U2U
as a mechanism of its own before plain Kerberos and fall back to an AP-REQ. With FreeIPA
or a plain MIT KDC `TERMSRV/<host>` is a principal of its own, may get a TGT, and U2U
already worked.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp with AD, Windows clients | **yes**, together with the machine account entries in `/etc/fastrdp/termsrv.keytab` (`fastrdp-termsrv-keytab` copies them: same keys as the TERMSRV entries) |
| FreeIPA, MIT, FreeRDP clients only | no (behaviour unchanged) |
| fastrdp's regression suite (`run_nla.sh`, AD-like KDC) | **yes**: the user-to-user login fails without it |

**Fix.** Look in the acceptor's keytab for a machine account entry (one name component
ending in `$`, realm of the service) and get its TGT first; then the service principal
itself as before; otherwise log a warning that names the missing keys. The `<fqdn>$`
guess is dropped (an entry of that name would still be found by the keytab search). No
new configuration: the keytab content decides. One AS exchange per user-to-user login,
as before.

**Regression test.** `tests/proxy-e2e/run_nla.sh` with MIT krb5 ≥ 1.22 (kadmin
`add_alias`): `TERMSRV/localhost` is an alias of `FASTRDP$`, the kdcpolicy module
`tests/proxy-e2e/kdc_adlike.c` refuses SPNs as AS clients. A client limited to U2U logs in
through a proxy with the `FASTRDP$` entries; unpatched, the same login fails with the
field report's error (19/22 instead of 22/22).

**Status upstream.** Still present on FreeRDP master (2026-10-21). Not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** a FreeRDP release gets the U2U TGT from the account that owns the
service name.
