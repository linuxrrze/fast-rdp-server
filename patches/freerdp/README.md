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

## 0005 – [winpr,kerberos] acceptor: keep the KDC's evidence from the accepted ticket

**Problem.** The WinPR Kerberos acceptor decrypted the service ticket in `krb5_rd_req()`
and threw it away. A server could not tell how the client had authenticated to the KDC,
although the KDC says so in the ticket's authorization data: MIT krb5 and FreeIPA as
authentication indicators (`pkinit`, `passkey`, `otp`, …) in a CAMMAC (RFC 7751),
Active Directory as group SIDs in the PAC (S-1-18-3 PKINIT with freshness, S-1-18-4 key
trust / Windows Hello for Business, Authentication Mechanism Assurance groups). fastrdp
could therefore count smart card or WHfB logons as MFA only through exempt groups or the
global `[mfa] nla_kdc_enforced` (backlog K11).

**Who is affected.** Servers that want to grant something per login from the KDC's
statement. Nothing changes for anybody else: two new context attributes, no change to
what the acceptor accepts.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp without `fastrdp_mfa_kdc_evidence_as_mfa` | no |
| `fastrdp_mfa_kdc_evidence_as_mfa` (broker `[mfa] kdc_evidence_as_mfa`) | **yes**: without it the module reports no `kdc_evidence` and every login keeps its second factor |
| fastrdp's regression suite | **yes**: `run_smartcard.sh` (6) expects `["ind:pkinit"]`, `run_nla.sh` (24) `[]` for password logins |

**Fix.** After `krb5_rd_req()` (now with the ticket as out-parameter), and only with MIT
krb5:
- *Which key.* The key that decrypted the ticket: for user-to-user the session key of
  the acceptor's TGT (`krb5_auth_con_getkey()` before `krb5_rd_req()` replaces it),
  otherwise the keytab entries of the ticket's encryption type (any of them; all are
  shared with the KDC only).
- *Indicators.* `krb5_find_authdata(KRB5_AUTHDATA_CAMMAC)` (also inside AD-IF-RELEVANT);
  the CAMMAC is decoded with WinPR's DER decoder; only one whose svc-verifier
  (`krb5_c_verify_checksum()`, key usage 64, over the DER `elements`) verifies counts;
  AD-AUTHENTICATION-INDICATOR UTF8Strings of 1-64 printable ASCII characters, at most 16.
- *PAC.* Exactly one `AD-WIN2K-PAC`, `krb5_pac_parse()`, `krb5_pac_verify()` with the
  server key (the KDC signature needs the krbtgt key and is not checked), then the raw
  `PAC_LOGON_INFO` buffer (at most 64 KiB). The NDR is parsed by the caller (fastrdp:
  `broker/proxy-module/fastrdp_pac.h`, unit-tested without FreeRDP).
- Never fails the authentication: without verified evidence the attributes are empty.
  A CAMMAC or PAC that does not verify is logged at WARN.

Attributes (`winpr/sspi.h`, ids 1900-1999 left to fastrdp), `pBuffer` is a
caller-allocated `SecBuffer`, so no `FreeContextBuffer`:
- `SECPKG_ATTR_KERBEROS_AUTH_INDICATORS` (1900): NUL-terminated strings;
- `SECPKG_ATTR_KERBEROS_PAC_LOGON_INFO` (1901): the `PAC_LOGON_INFO` buffer.
Both answer `SEC_E_INVALID_HANDLE` before the AP-REQ was accepted and
`SEC_E_BUFFER_TOO_SMALL` (with the length needed) for a short buffer. Heimdal builds
compile but report nothing.

**Regression test.** `tests/proxy-e2e/run_smartcard.sh` (MIT KDC with
`pkinit_indicator = pkinit`): the broker receives `"kdc_evidence": ["ind:pkinit"]`
(6/6; without the patch 5/6). `run_nla.sh`: password logins report `[]` and no CAMMAC or
PAC fails verification (24/24; without the patch 23/24). Checked by hand: with a wrong
verification key (user-to-user and keytab path) the indicator disappears and the
warnings appear. Not testable with MIT: PAC group SIDs (an MIT KDC issues only a minimal
PAC); `tests/proxy-module/test_pac.c` covers the parser with Windows PACs.

**Status upstream.** fastrdp-specific (vendor attribute ids); not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** FreeRDP offers the ticket's verified authorization data itself.

## 0006 – [server,proxy] drop Server Status Info PDUs the front client did not announce

**Problem.** `pf_client_server_status_info()` in `server/proxy/pf_update.c` forwarded
every Server Status Info PDU ([MS-RDPBCGR] 2.2.5.2) of the back-end to the front client.
A client announces support with RNS_UD_CS_SUPPORT_STATUSINFO_PDU in the
`earlyCapabilityFlags` of its Client Core Data (2.2.1.3.2); 3.3.5.7.2: the server MUST NOT
send the PDU unless the client did.

**Who is affected.** freerdp-proxy in front of a back-end that sends the PDU although the
proxy's back-end hop did not announce it, or of a back-end hop whose settings a module
changed. The hop starts from a copy of the front settings
(`pf_context_create_client_context()`), so it announces exactly what the front client
announced, and a conforming back-end stays quiet. Clients that announce
support (mstsc, FreeRDP) see no difference.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp server with conforming back-ends | no: defence in depth, the proxy no longer depends on the back-end for this rule |
| fastrdp's regression suite | no: no test back-end sends the PDU |

**Fix.** Check `FreeRDP_SupportStatusInfoPdu` in the front peer's settings
(`ps->context.settings`: TRUE by default in server mode, cleared by
`updateEarlyClientCaps()` when the client did not set the flag) and drop the PDU with a
DEBUG message (`dropping server status info 0x…`) when it is off. Forwarding is unchanged
otherwise. Settings copied from the back-end on a reactivation
(`proxy_server_reactivate()`) carry the same value, because the hop's value came from the
front.

**Regression test.** None dedicated: no test back-end sends a Server Status Info PDU, and
faking one needs a back-end that breaks the rule. `tests/proxy-e2e/run.sh` (39/39 against
3.32.2-5) shows that forwarding is otherwise unchanged.

**Status upstream.** Still present in 3.32.2. Not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** a FreeRDP release checks the front client's capability before forwarding.

## 0007 – [core,peer] input during PostConnect: no second PostConnect

**Problem.** The server calls the peer's `PostConnect` once the connection is active
([MS-RDPBCGR] 1.3.1.1): after the client's Font List PDU, in
`rdp_peer_handle_state_active()` (`libfreerdp/core/peer.c`), with `client->connected`
still FALSE until the callback returns. The client may send input from then on (1.3).
A callback that reads that input itself, with `GetEventHandles()` and
`CheckFileDescriptor()` from inside `PostConnect`, gets every PDU into
`rdp_peer_handle_state_active()` again: `connected` is still FALSE, so `PostConnect`
runs a second time, nested in the first.

**Who is affected.** Servers whose `PostConnect` waits for the user and reads the
connection meanwhile. freerdp-proxy runs its modules' `ServerFetchTargetAddr` hook there
(`pf_server_post_connect()` → `pf_server_get_target_info()`): fastrdp's broker call (MFA
push, web approval) and its desktop picker ([docs/desktop-matrix.md](../../docs/desktop-matrix.md#choosing-a-desktop)),
which takes keys and clicks on the waiting screen before the back-end starts. The proxy's
own input handlers drop input until its back-end is connected, and module input filters
run only after that, so the module must read the input itself.

**Is it required?**

| Use | Required |
|---|---|
| fastrdp's desktop picker (`[broker] desktop_picker`) | yes: without it the module does not offer the picker (`ws_picker_possible()`) and logins get the desktop as before |
| everything else in fastrdp, other FreeRDP servers | no: nothing changes for a `PostConnect` that does not read the connection |

**Fix.** `rdpRdp` remembers that `PostConnect` runs (`in_post_connect`); a PDU that
arrives meanwhile is handled as in the active state (`STATE_RUN_ACTIVE`: input callbacks,
channel data, Refresh Rect, ...), not with a second `PostConnect`. `Activate` still runs
once, after `PostConnect` returned; `client->connected` and `client->activated` are
untouched. `freerdp_peer_in_post_connect()` (new, `include/freerdp/peer.h`, marked by
`FREERDP_PEER_IN_POST_CONNECT`) returns TRUE while `PostConnect` runs. The fastrdp module
compiles the picker in only with the macro and calls the function through a weak
reference, so a module built against these headers but loaded with an unpatched
`libfreerdp3` offers no picker instead of running into the nested `PostConnect`.

Without a patch, a module could set `peer->connected` itself before reading and reset
it afterwards. That depends on FreeRDP's internals in the same way, leaves the peer in
an inconsistent state if the module fails in between, and cannot be detected; the patch
is ten lines and testable.

**Regression test.** `tests/proxy-e2e/run.sh` (desktop picker, 3.32.2-6): keys (top row,
keypad with NumLock, arrows, Enter, Esc, Unicode), a click, keys typed before the
picker showed (ignored), the countdown, and a client closed during the picker; every
choice reaches the broker and the login reaches the back-end afterwards. Without the
patch the module does not announce the picker and these checks fail; the rest of the
suite passes either way.

**Status upstream.** Still present in 3.32.2. Not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** FreeRDP processes PDUs read during `PostConnect` as input (or offers
another way to read input before `Activate`), and the module checks for that instead.

## 0008 – [core,peer] deny a client's Shutdown Request once the session runs

**Problem.** A client that wants to close the connection may first send a Shutdown
Request PDU ([MS-RDPBCGR] 2.2.2.2); mstsc does so when the user clicks the X in its
connection bar. [MS-RDPBCGR] 1.3.1.4.1: "If a logged-on user account is associated with
the session, the server always denies the shutdown request and sends the client a
Shutdown Request Denied PDU"; the client then sends a Disconnect Provider Ultimatum with
reason "user requested" and closes the connection. Only "if a logged-on user account is
not associated with the session, the server closes the connection immediately"
[verified: Microsoft Learn, MS-RDPBCGR "User-Initiated on Client"]. FreeRDP's
`peer_recv_data_pdu()` (`libfreerdp/core/peer.c`) always takes the second way: it sends a
Disconnect Provider Ultimatum with reason "provider initiated" and quits. FreeRDP's server
side cannot send the Denied PDU at all; only its client parses it
(`rdp_recv_server_shutdown_denied_pdu()`, which does nothing).

**Who is affected.** Every FreeRDP server whose clients send the Shutdown Request:
mstsc, not FreeRDP's own client (it never sends one [verified: source]). In fastrdp the
front connection of freerdp-proxy. Field report 2026-10-23 (mstsc, Kerberos NLA, web
approval): after a disconnect with the X, the next *Connect* in the same mstsc process
showed a black window instead of the waiting screen, although the proxy sent it (97
Bitmap Updates logged), until the login timed out; a restarted mstsc worked. The proxy log
shows `disconnect provider ultimatum sent to peer, closing connection` at the X. That
the Denied answer also fixes the next *Connect* in mstsc is [inferred, not tested].

**Is it required?**

| Use | Required |
|---|---|
| mstsc (and other clients that send the Shutdown Request) closing a fastrdp session | yes: without it the proxy ends the connection itself, as a server-side disconnect |
| everything else | no: FreeRDP clients never send the request |

**Fix.** Once `PostConnect` has accepted the client (`client->connected`), answer with a
Shutdown Request Denied PDU (a Share Data Header with `pduType2` 0x25) and keep the
connection; the client's Disconnect Provider Ultimatum ends it as any client
disconnect does (the proxy closes the back-end connection, the session keeps running,
the module reports the session end). Before that, while `PostConnect` runs (fastrdp: the
broker call with MFA, the desktop picker) or before it, there is no session yet, and the
connection is closed at once as before. No setting: the old behaviour contradicts the
specification for a running session.

**Regression test.** `tests/proxy-e2e/run.sh` (3.32.2-7): the e2e client sends the
Shutdown Request PDU itself (FreeRDP's client has no function for it) through the
transport and watches the server's PDUs. During a session (proxy A has accepted the
client, its back-end proxy B still holds the login): Denied within milliseconds, no
disconnect by the proxy, the client's own disconnect ends the session (session end at
broker A, back-end connection closed); without the patch the proxy disconnects and these
two checks fail. During the desktop picker: closed at once, not denied, login abandoned
(same with and without the patch).

**Status upstream.** Still present in 3.32.2. Not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** FreeRDP's server answers the Shutdown Request with Shutdown Request
Denied for a running session.

## 0009 – [winpr,wlog] make WITH_SYSTEMD reach config.h (journald appender)

**Problem.** With the CMake option `WITH_SYSTEMD`, `winpr/libwinpr/utils/CMakeLists.txt`
compiles `wlog/JournaldAppender.c`, links libsystemd and sets `WINPR_HAVE_JOURNALD_H`
for `winpr/config.h`. That header is configured in `winpr/include`, which
`winpr/CMakeLists.txt` adds after `libwinpr`, so in a sibling directory scope: a plain
`set()` in `libwinpr/utils` never reaches it, and `config.h` always has
`/* #undef WINPR_HAVE_JOURNALD_H */` [verified: 3.32.2 source; a minimal CMake model with
the same directory layout gives the same result]. `wlog.c` and `Appender.c` test that
macro, so `WLOG_APPENDER=JOURNALD` is ignored without a message and WLog keeps the
console appender, although the appender is compiled in.

**Who is affected.** Every 3.32.2 build that wants WLog in the journal. fastrdp's
`fastrdp-proxy.service` sets `WLOG_APPENDER=JOURNALD`: with the console appender,
stdout in the pipe to journald is block-buffered, and the proxy's log lines arrive
minutes late or torn ([docs/backlog.md](../../docs/backlog.md#sessions) A4).

**Is it required?**

| Use | Required |
|---|---|
| fastrdp-proxy logging to the journal (unit file, `WLOG_APPENDER=JOURNALD`) | yes: without it the proxy logs through the console appender as before |
| everything else | no |

**Fix.** Set `WINPR_HAVE_JOURNALD_H` as an internal cache entry, which every later
scope reads, and remove the entry when `WITH_SYSTEMD` is off, so a reconfigure without
systemd keeps no stale define. `third_party/build-freerdp.sh` passes `-DWITH_SYSTEMD=ON`
(it used to pass `-DWITH_LIBSYSTEMD=ON`, which is no FreeRDP option) and fails the
build if `winpr/config.h` lacks `WINPR_HAVE_JOURNALD_H` or `libwinpr3` is not linked
against libsystemd.

**Regression test.** The build check above. Not yet run through a full vendored build
and a proxy under systemd ([docs/backlog.md](../../docs/backlog.md#sessions) A4).

**Status upstream.** Still present in 3.32.2. Not submitted
([docs/upstream.md](../../docs/upstream.md)).

**Drop it when** upstream's `config.h` gets `WINPR_HAVE_JOURNALD_H` with `WITH_SYSTEMD`.
