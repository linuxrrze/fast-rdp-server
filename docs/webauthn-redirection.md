# WebAuthn redirection into Linux sessions (MS-RDPEWA) – feasibility

**Status: research (stage 3 of [passkeys.md](passkeys.md)). Not implemented in fastrdp.**
A prototype of the protocol-independent core is in `prototypes/webauthn-redirection/`
(`make test-prototypes`); nothing in xrdp, the proxy or the packages uses it.

Goal: a browser **inside** a Linux session (Chromium, Firefox) uses the passkeys and
security keys of the user's **local** machine: a YubiKey through FreeRDP, Windows
Hello or a phone through mstsc. That is what Windows RDP hosts offer with
[MS-RDPEWA] ("WebAuthn redirection").

Sources: [MS-RDPEWA] revision 3.0 (2026-03-30); FreeRDP 3.32.2 `channels/rdpewa`
(client side); xrdp 0.10.6.1 `xrdpapi/`, `sesman/chansrv/chansrv.c`; FIDO CTAP 2.1
(§8 canonical CBOR, §11.2 CTAPHID). Marks as in passkeys.md: [verified] (source or
specification), [inferred], [tested] (prototype tests).

## 1. Protocol (MS-RDPEWA)

**Transport** (§2.1): dynamic virtual channel `WebAuthN_Channel`, reliable and in
order; one request or response per message. FreeRDP names the client plugin `rdpewa`.

**Roles.** The **server** (the remote session) sends requests; the **client** runs
them against its local authenticators (§3.1: it picks the authenticator per CTAP
§4/§5.4) and answers. There are no unsolicited client messages.

**Request** (§2.2.1): a CBOR map with **text** keys:

| Key | Type | Meaning |
|---|---|---|
| `command` | uint | 5 `WEB_AUTHN`, 6 `IUVPAA` (is a user-verifying platform authenticator available), 7 `CANCEL_CUR_OP`, 8 `API_VERSION`, 9 `GET_CREDENTIALS`, 12 `GET_AUTHENTICATOR_LIST` |
| `request` | bytes | `WEB_AUTHN`: one byte CTAP command (0x01 MakeCredential, 0x02 GetAssertion) + the **CTAP2 request map** (§2.2.1.2/§2.2.1.3, i.e. CTAP §5.1/§5.2 with `clientDataHash`, `rp`/`rpId`, allow/exclude lists, extensions, options); `CANCEL_CUR_OP`: the operation's GUID |
| `flags` | uint | `CTAPCLT_*` bits: UV required/preferred/not required, client PIN required, hmac-secret, U2F |
| `timeout` | uint | milliseconds |
| `transactionId` | bytes(16) | GUID |
| `webAuthNPara` | map (§2.2.1.1) | `attachment` (any/platform/cross-platform), `requireResident`, `preferResident`, `userVerification`, `attestationPreference`, `enterpriseAttestation`, `cancellationId`, large blob, `transportHint` |
| `clientDataJSON` | bytes | optional: the client data the **server** built (type, challenge, **origin**) |
| `rpId` | text | `GET_CREDENTIALS` |
| `filterHybridTransport`, `thirdPartyPayment`, `hmacSecretSaltValues`, … | | optional |

**Response** (§2.2.2): a 32-bit HRESULT, then the payload:
- `WEB_AUTHN` (§2.2.2.1): CBOR map `deviceInfo` (provider, manufacturer, product,
  AAGUID, `uvStatus`, `uvRetries`, …), `status`, `response` = **CTAP status byte + CTAP
  response map** (§2.2.2.1.1 MakeCredential: `fmt`, `authData`, `attStmt`;
  §2.2.2.1.2 GetAssertion: credential, `authData`, signature, user);
- `IUVPAA`, `API_VERSION`: 4-byte little-endian integer;
- `CANCEL_CUR_OP`: nothing;
- `GET_CREDENTIALS` (§2.2.2.2), `GET_AUTHENTICATOR_LIST` (§2.2.2.3): CBOR arrays
  (credential metadata for autofill; authenticators with name/logo).

**Flow of one browser login through a Linux session:**

```
browser (session)   bridge (session)                 RDP client (user's PC)
  │ CTAPHID_INIT ─────▶ allocate channel
  │ CTAP2 GetInfo ────▶ answered locally
  │ CTAP2 GetAssertion ▶ policy (RP ID, rate, consent)
  │                     WEB_AUTHN {request: 0x02|map, flags, timeout,
  │ ◀─ KEEPALIVE ─────   transactionId, webAuthNPara} ─────▶ local key / Hello:
  │    (UPNEEDED)                                            PIN/UV + touch
  │                     ◀──── HRESULT | {deviceInfo, status, response: 00|map}
  │ ◀─ CTAP2 response ─ status byte + map, unchanged
```

The CTAP2 map inside `request` is exactly what a browser sends to a USB key, and the
`response` bytes are exactly what a key answers. A bridge is therefore mostly
framing; the security decisions are about **which** requests it forwards.

**What the specification gets wrong or leaves open** [verified, found while building
test vectors from §4]:
- example 4.1.1 is titled API_VERSION but encodes `command: 5`;
- the response examples print the HRESULT as two bytes (`0x0000`), §2.2.2 says 32 bits
  (FreeRDP sends 4 bytes little endian; the prototype follows FreeRDP);
- key spellings differ between field lists and examples (`transactionid` /
  `transactionId`, `Manufacturer` / `manufacturer`); the examples use keys that the
  field lists do not define (`credentialListIndexPlusOne`,
  `pluginAutofillScenarioSupported`, `uvTransactionId`) and flag `0x10000000`;
- the GetAssertion response example is not for the RP of its request (its rpIdHash
  differs from SHA-256("ctap.dev")).

## 2. Where the server side would live

| Option | How | Verdict |
|---|---|---|
| **A. Per-session daemon on xrdp's channel API** | xrdp's `xrdpapi` (`WTSVirtualChannelOpenEx` with `WTS_CHANNEL_OPTION_DYNAMIC`) lets a process in the session open a **dynamic** channel by name through chansrv's per-display socket (`xrdpapi_<display>` in the user's xrdp socket directory; `handle_xrdpapi_connection_request` → DVC branch) [verified]. A user daemon opens `WebAuthN_Channel`; no xrdp patch | **Preferred for xrdp.** Runs as the user, needs no change to xrdp. To check: chansrv's DVC open when the client lacks the channel (FreeRDP without `rdpewa`), reconnects (the channel is per connection) |
| B. chansrv plugin | new channel module inside chansrv (like `smartcard*.c`) | more code in xrdp's C, a patch to maintain; no gain over A |
| C. freerdp-proxy module | the proxy sits on every connection, independent of the back-end | the module API can intercept channels but not create its own server DVC on the front connection [verified in passkeys.md]; and the proxy does not know which session process should get the data |
| D. GNOME (gnome-remote-desktop), Plasma (KRdp) | no third-party DVC API | needs upstream work in each; out of reach for now |

fastrdp's proxy already passes unknown DVCs through (`PassthroughIsBlacklist=true`),
so option A needs no proxy change [inferred, to test].

## 3. How the browser in the session reaches it

| Option | How | Verdict |
|---|---|---|
| **1. Virtual FIDO HID device per session (uhid)** | a privileged helper creates `/dev/uhid` device "fastrdp FIDO (session N)" with the FIDO report descriptor (usage page 0xF1D0); the kernel creates `/dev/hidrawN`; a udev rule gives that node to the session user, mode 0600; the bridge speaks CTAPHID on it | **Preferred.** Works with every browser that supports USB security keys, without browser changes. `/dev/uhid` is root-only, so the helper is privileged (below) |
| 2. libfido2 / PC/SC bridge | sessions' applications use libfido2 or PC/SC | browsers do not use libfido2 or PC/SC for WebAuthn; only useful for `ssh -o SecurityKeyProvider`, sssd, … |
| 3. Browser extension (WebAuthn API override) | an extension replaces `navigator.credentials` and talks to a native messaging host | sees the **origin** and could fill `clientDataJSON`, but must be installed per browser and profile, is fragile, and an extension able to sign for any site is a target itself |

**Privileged helper for option 1** (small, root): on request of the broker or a
systemd unit at session start, it opens `/dev/uhid`, sends `UHID_CREATE2` with a fixed
name containing the session id, a fixed report descriptor and a fixed VID/PID, and
hands the uhid file descriptor to the user's bridge (`SCM_RIGHTS`). With that fd the
bridge can only feed and read **its** device. A udev rule matches the device by name
/`HID_PHYS` and sets owner = session user, mode 0600. At session end the helper
destroys the device.

**Browser caveats** [inferred]: Chromium and Firefox find FIDO HID devices by usage
page. Snap-packaged browsers (Firefox on Ubuntu) get hidraw access only through the
`u2f-devices` interface, which allows a **list of vendor/product ids**: a virtual
device with its own ids would be invisible there unless it borrows a listed id.
Flatpak browsers need `--device=all`. To test per distribution.

**PIN and user verification.** The bridge answers `authenticatorGetInfo` itself and
advertises `uv: true` without `clientPin`, so the browser sends `uv` instead of
running the PIN protocol (which a bridge cannot pass through: the PIN token is bound
to the device that issued it). The client performs PIN/UV locally (FreeRDP:
`FIDO2 PIN:` prompt, libfido2; mstsc: Windows Hello UI) [verified for FreeRDP].

## 4. Security model

**The relay risk** (passkeys.md, RDPEWA): the client signs whatever RP ID the remote
side asks for. Two points decide what that means here:
- **Origin binding stays with the browser.** At the CTAP level the bridge gets only
  `clientDataHash`; the origin was checked by the browser in the session. A compromised
  *browser* or anything else running as the user in the session can open the hidraw
  node and ask for assertions for **any** RP ID. The client cannot tell: FreeRDP
  prints only "Touch the security key", without the RP ID [verified]; mstsc shows
  Windows' WebAuthn dialog, which names the RP ID [docs, to test].
- `clientDataJSON` (with the origin) can be sent in the request, but a CTAPHID bridge
  does not have it; whether mstsc accepts requests without it is open [inferred].

Controls, all in the prototype (`fastrdp_ewa/bridge.py`) and tested [tested]:

| Control | What it does |
|---|---|
| **RP ID allow-list** per site (or per user) | only listed RP IDs (`example.com` or `.corp.example` for the domain and subdomains) are forwarded; everything else gets `CTAP2_ERR_OPERATION_DENIED` and is logged. Empty list = nothing forwarded. This is the main limit on what a compromised session can do with the user's keys |
| **One operation at a time**, timeouts | a second request gets `CHANNEL_BUSY`; stale requests time out; late client answers are dropped |
| **Rate limit** | default 10 operations per minute per session |
| **Local consent hook** | optional prompt in the session before forwarding; weak against malware in the same session (it can click it), useful against surprises |
| **Client-side consent** | every operation still needs touch/UV on the client; that is the user's real decision. With FreeRDP the user does not see *which* RP asks |
| **Per-session isolation** | one bridge, one uhid device and one DVC per session; hidraw node owned by the session user, mode 0600; a channel id from one session is unknown to another bridge, and answers go only to the channel that asked |

What isolation does **not** cover: root on the terminal server, and the user's own
processes in the session (same uid). Hence: per-user opt-in, an RP allow-list that
names the sites the session really needs, and never for administrators' keys that
protect high-value RPs. The `.rdp` setting is client-side; users who do not enable it
are unaffected.

Also: do not forward `CTAPHID_MSG` (U2F) and do not support `GetNextAssertion`
(both refused in the prototype); synthesize `GetInfo` locally; validate CBOR with
limits before forwarding (the prototype's decoder refuses indefinite lengths, deep
nesting and duplicate keys).

## 5. Prototype (protocol-independent core)

`prototypes/webauthn-redirection/` (Python 3.11+, standard library only):

| Module | Content | Tests |
|---|---|---|
| `fastrdp_ewa/cbor.py` | CBOR encode/decode (RFC 8949), insertion order kept, CTAP2 canonical encoding, limits | RFC 8949 Appendix A vectors, canonical order, hostile input |
| `fastrdp_ewa/rdpewa.py` | request/response codec, constants, CTAP payload helpers, `WebAuthnResult` | all request examples of [MS-RDPEWA] §4 decode and **re-encode byte for byte**; MakeCredential/GetAssertion/authenticator-list response examples decode (rpIdHash, flags, attestation) |
| `fastrdp_ewa/ctaphid.py` | 64-byte report framing, reassembly per channel (sequence, length, busy, broadcast rules), INIT/ERROR/KEEPALIVE builders, FIDO HID report descriptor | layout, sizes up to 7609 bytes, errors |
| `fastrdp_ewa/bridge.py` | CTAPHID ↔ RDPEWA mapping with the policy above | a browser-side simulation: INIT, GetInfo, GetAssertion forwarded and the specification's response delivered back, MakeCredential, denied RP IDs, rate limit, consent, cancel, timeouts, client errors, unsupported commands, two sessions |

`make test-prototypes`: 54 tests [tested]. Not done: uhid, xrdpapi, a real browser,
a real client.

## 6. Effort and decision

Rough estimate for **xrdp sessions only**, one experienced developer:

| Work | Effort |
|---|---|
| Bridge daemon (from the prototype): xrdpapi DVC client, uhid fd loop, reconnect handling, logging | 2–3 weeks |
| Privileged helper (uhid create/destroy, fd passing), udev rule, systemd/broker integration, packaging | 1–2 weeks |
| Interop: FreeRDP + mstsc clients; Chromium/Firefox as deb, snap, flatpak; YubiKey, Windows Hello, phone via mstsc | 2 weeks |
| Security review, per-user opt-in and RP allow-list configuration (Ansible), docs | 1–2 weeks |
| **Total** | **≈ 6–9 person-weeks** to a supportable feature; ≈ 2–3 weeks for a lab demo |
| GNOME / Plasma back-ends | upstream DVC API work in each project; not estimable now |

Risks: snap browsers and the VID/PID allow-list; mstsc behaviour without
`clientDataJSON`; chansrv DVC handling when the client has no `rdpewa`; maintaining a
root helper; the relay risk, which the allow-list limits but cannot remove.

**Recommendation:** do not build it now. Revisit if users need local passkeys inside
sessions for a small, fixed set of RPs (internal SSO, VPN portal). The web path
(Keycloak passkeys) and KeePassXC/Bitwarden inside the session cover today's needs
([passkeys.md](passkeys.md)). If it is built: xrdp first (option A + device option 1),
allow-list mandatory, off by default.
