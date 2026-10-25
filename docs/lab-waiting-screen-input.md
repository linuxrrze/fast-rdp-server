# Lab test plan: code entry on the waiting screen

**Status: plan, not run.** It covers `fastrdp_mfa_mode: code_or_web`
([auth-matrix.md](auth-matrix.md#code-on-the-waiting-screen)), which offers two ways on
one waiting screen: type the TOTP code in the RDP window (the broker has Keycloak check
it through a direct grant of the client `fastrdp-otp-check`), or scan the QR code and
approve with a passkey on `/web/approve`. The first success wins. Names and defaults
below are those of the implementation (broker `mfa.py` `code_or_web`, `keycloak_otp.py`;
module `fastrdp_code.h`, `fastrdp_inputtrace.h`); none of it has run with a real client
yet [not tested].

**The question this lab answers:** does the waiting screen render on each client, and
do the keys the user types for a code reach the proxy module, so that code entry is
usable there? The answer decides, per client, whether code entry ships or that client
gets QR approval only ([go/no-go](#go--no-go-per-client)).

It extends lab S3 ([rdp-spec-conformance.md](rdp-spec-conformance.md), table of lab
tests), item 9 of [windows-clients.md](windows-clients.md#6-what-only-a-windows-lab-can-settle)
and backlog A3 (desktop picker, client validation pending). The picker and code entry
read input the same way, so one lab run can settle both: run the S3 picker steps on
each client in the same session.

Marks as elsewhere: [verified] (source), [inferred], [tested].

## 1. What the module sees, and what can go wrong

The module reads the client's input itself while it waits in PostConnect: the proxy's
own input handlers drop everything until the back-end is active, so nothing typed on
the waiting screen can reach the session [verified: FreeRDP 3.32.2 `pf_input.c`; module
`ws_picker_start()`]. The picker's handlers are the template for code entry
[verified: `broker/proxy-module/fastrdp_plugin.c`]:

| Event (MS-RDPBCGR) | Handler today | What it carries | What code entry needs |
|---|---|---|---|
| Keyboard (scancode) | `ws_picker_keyboard` → `ws_code_key` → `fastrdp_code_key()`: acts on **release** of a key that went down while the field showed | key position, `KBD_FLAGS_EXTENDED` | top row 0x02–0x0b = digits 1–9, 0 on every layout, Shift or not [inferred]; keypad 0x47–0x52 only with NumLock; Backspace 0x0e deletes; Enter 0x1c / 0x11c submits; Esc 0x01 clears the field [verified: code, `tests/proxy-module/test_code.c`] |
| Unicode keyboard | `ws_picker_unicode` → `ws_code_unicode` → `fastrdp_code_char()` | the typed character | '0'–'9', Backspace (0x08), CR submits; everything else ignored without a hint (AZERTY without Shift sends `&é"'(` …; LF and full-width digits are ignored too) [verified: code] |
| Synchronize | `ws_picker_sync`: NumLock state, passed on to the proxy | toggle states | keypad digits count only when the client reported NumLock on |
| Mouse | `ws_picker_mouse`: clicks on picker rows only | position | ignored while the code field shows |
| Channel data (clipboard, drdynvc, …) | counted, abandoned above 4 MiB | – | a paste must never become input: clipboard is a channel, not keystrokes |

Keys typed **before** the panel shows are drained for up to 500 ms
(`ws_picker_drain`, `WS_PICKER_DRAIN_MS`), and a release only counts if the press came
while the panel showed [verified]. A user who starts typing the code too early loses
those digits; the lab records whether that is noticeable.

Risks per client that only a lab shows:
- the client renders nothing before the session (empty window, own progress dialog on top);
- the client sends Unicode events only (Windows App on macOS/iOS/Android is expected to,
  at least from soft keyboards [inferred]), or scancodes without a usable NumLock sync;
- an IME composes characters and sends them only on commit, or not at all;
- the client swallows keys while "connecting" and sends them later in a burst;
- touch-only clients without a way to bring up the keyboard on a bitmap-only screen.

## 2. Setup

**Server:** one fastrdp host `rdp1.lab.example.com` (realm `LAB.EXAMPLE.COM`) with:
- `fastrdp_mfa_mode: code_or_web`, `fastrdp_web_enabled: true`,
  `fastrdp_proxy_waiting_screen: true` (default; Ansible refuses `code_or_web` without
  it), QR code on (default), `fastrdp_otp_lengths: [6]` (default: the field submits at
  the sixth digit);
- Keycloak 26.8.1 with the `fastrdp-mfa` flow (recipe A), the client
  `fastrdp-otp-check` (from `docs/examples/keycloak-fastrdp-otp-check-client.json`,
  secret in `vault_fastrdp_mfa_keycloak_client_secret`) and its direct grant flow
  `fastrdp-otp-check` (Username Validation, then OTP for users with one and *Deny access*
  for users without; the client's amr mapper; set up by `fastrdp_web_passkeys: true`,
  whose check mode reports no changes before the lab); realm brute-force detection on, OTP
  reuse off (`otpPolicyCodeReusable: false`); the role warns otherwise;
- the limits at their defaults: `fastrdp_mfa_code_attempts: 3` per login,
  `fastrdp_mfa_code_user_failures: 10` within `fastrdp_mfa_code_failure_window: 900` s;
- `fastrdp_proxy_input_trace: true` (proxy.ini `[FastRDP] InputTrace`, [§3](#3-capturing-input-without-leaking-codes));
- `fastrdp_mfa_web_approval_timeout: 90`, `fastrdp_mfa_reconnect_grace: 300` for F8;
- the proxy's journal at INFO; DEBUG only where a test says so.

**Test users** (local accounts and Keycloak users with the same name):

| User | Credentials in Keycloak | Used for |
|---|---|---|
| `alice` | password, TOTP (default OTP device), passkey | most tests |
| `bob` | password, TOTP only | code entry without passkey |
| `dave` | password, passkey only | QR only, code refused |
| `carol` | password only | neither |
| `erin` | password, two TOTP devices, the second one default | only the default device counts |

The TOTP secrets of these users are **lab secrets**, created for this lab and deleted
afterwards. Never use real users' codes in the lab: some steps capture input.

**Phone:** one with an authenticator app (TOTP for alice, bob, erin) and a passkey for
alice and dave (platform passkey or a security key over NFC).

**Clients:**

| ID | Client | Platform | Notes |
|---|---|---|---|
| C1 | mstsc | Windows 10 22H2, domain-joined | NLA Kerberos (SSO) and typed password |
| C2 | mstsc | Windows 11 24H2 Enterprise, domain-joined, Credential Guard on | |
| C3 | mstsc | Windows 11 25H2, workgroup | typed UPN, NLA |
| C4 | Windows App | Windows 11 (Store) | if installed in the lab |
| C5 | Windows App | macOS (current), Apple keyboard and a PC keyboard | |
| C6 | Windows App | iPadOS with and without a hardware keyboard; iPhone | soft keyboard, touch |
| C7 | Windows App | Android phone and tablet | soft keyboard, Gboard and the vendor keyboard |
| C8 | xfreerdp3, distribution package | Debian 13 (FreeRDP 3.15.0) | X11 and Wayland session on the client |
| C9 | xfreerdp3, `/opt/fastrdp` | Debian 13 / Ubuntu 24.04 (FreeRDP 3.32.2) | reference: `tests/proxy-e2e/run.sh` covers it |
| C10 | Remmina (FreeRDP 3) | Debian 13, Ubuntu 24.04 | |

Other clients (Thincast, web clients through Guacamole) are not in fastrdp's docs; add
them as extra rows if the site uses them. Guacamole logins never see this screen (web
logins get their MFA at Keycloak).

**Keyboard layouts** (set on the client OS; the RDP client sends the layout id):

| ID | Layout | Digits on the top row |
|---|---|---|
| K1 | US QWERTY | unshifted |
| K2 | German QWERTZ | unshifted |
| K3 | French AZERTY | **shifted** (unshifted: `& é " ' ( - è _ ç à`) |
| K4 | French Bépo | shifted (`" « » ( ) @ + - / *` unshifted) |
| K5 | Japanese 106/109, IME off and on (romaji and kana input) | unshifted |

Run all layouts on C1/C2, C5, C8 or C10; K1 and K3 on the others.

**Connection variants:** NLA with Kerberos (C1, C2), NLA with typed password (all),
TLS password login where `fastrdp_allow_tls_logins` is on (C8/C9 only; mstsc TLS is not
practical, lab S1); RD Gateway or rdpgw in front (if the lab has one, L20/L21); window
and full screen; two monitors (C1, C5, C8: `/multimon`); high DPI (a 4K monitor at
200 %, macOS Retina).

## 3. Capturing input without leaking codes

What reaches the module has to be recorded for every client and layout, but the module
must never log digits. Three levels:

1. **Production logging (all tests):** the module logs `code field shown (6 digits)`
   and, on errors, `code not sent to the broker`; the broker logs the outcome per code:
   `alice: code from the waiting screen accepted by Keycloak`, `alice: wrong code on the
   waiting screen (nla login from 192.0.2.10); 2 attempt(s) left`, `code of alice not
   checked: …` (Keycloak unreachable), `Keycloak refused the code of alice: HTTP …`.
   None of them contains the digits [verified: code; checked again in S1].
2. **Input trace (lab only):** `fastrdp_proxy_input_trace: true` (proxy.ini
   `[FastRDP] InputTrace = true`, then restart the proxy). Every connection then logs a
   warning (`InputTrace is on: … lab only …`), and the proxy logs one line per input
   event the waiting screen reads, with its **class** only:

   ```
   [<session>] input trace: scancode top-row digit up (code field), code field 3 of 6 digits
   [<session>] input trace: unicode other down (code field), before the prompt
   [<session>] input trace: sync NumLock on CapsLock off (code field), code field 0 of 6 digits
   ```

   Classes: scancode `top-row digit`, `keypad digit`, `keypad digit key (NumLock off)`,
   `backspace`, `esc`, `enter`, `keypad enter`, `modifier`, `caps lock`, `num lock`,
   `other`, `other (extended)`; Unicode `digit`, `full-width digit`, `backspace`,
   `enter`, `esc`, `other`; `sync` with the NumLock and CapsLock state; `mouse button
   1–3` down/up (no position, no moves). `down`/`up` shows key repeat (several downs, one
   up); `before the prompt` marks input read and dropped before the field took keys
   (drain); the field length shows whether a key counted. No digit value, key code or
   character is ever logged: all digit keys of one source share one class, and every
   non-digit character is `other` (AZERTY's unshifted digit row is made of them)
   [verified: `fastrdp_inputtrace.h`, `tests/proxy-module/test_inputtrace.c`]. Channel
   data (clipboard) is not traced. Switch it off after the lab: the trace still shows
   *that* and *when* digits were typed.
3. **No raw trace.** There is no build that logs key codes or characters, and none is
   needed: the classes answer every question of this plan. If a client sends something
   the classes cannot explain (`other` where digits were typed), use the client-side
   trace below with the fixed test sequence, never with a real code.

**Fixed test sequence** (with the input trace on): type `1234567890`, then Backspace,
Enter, Esc, on the top row, then on the keypad with NumLock on, then with NumLock off.
With the default 6-digit field the sixth digit already submits: the expected result is
a wrong code (`Wrong code. Attempts left: 2`), the trace shows the classes of all keys,
and the keys typed during "Checking the code…" are not counted.

Client-side traces where available: xfreerdp3/Remmina `/log-level:DEBUG` with
`WLOG_FILTER=com.freerdp.core.input:TRACE` (shows what the client sends); nothing
comparable for mstsc or the Windows App. Wireshark sees only TLS.

## 4. Tests

Each test: run it on every client of the [matrix](#5-results-matrix) unless the
preconditions say otherwise. **Record** for every run: client and version, OS and
layout, connection variant, a photo or screenshot of the panel, the input trace
(level 2), the broker journal of the login, pass/fail and notes.

### 4.1 Rendering (R)

| ID | Preconditions | Steps | Expected | Pass/fail |
|---|---|---|---|---|
| R1 | alice, NLA | Connect; stop at the waiting screen | Panel within 1 s of the credentials being accepted: title "Approve the sign-in", the `mfa_code_or_web` text ("Type the code from your authenticator app below, or sign in on the approval page (passkey) and approve this login"), approval URL, login code, QR code, countdown and the field `Authenticator code: ______` (`code_label`; German texts with a German keyboard layout) | fail if the client shows only its own dialog, a black window, or the panel later than 3 s |
| R2 | R1 | Watch 10 s | Countdown updates every second; the code field does not flicker | fail if the countdown stops or the field is redrawn with artefacts |
| R3 | R1 | Scan the QR code from the monitor with the phone camera, in window and full screen, at 100 % and 200 % DPI | Opens `https://rdp1.lab.example.com/web/approve?login=<id>` | fail if not scannable at any one supported size |
| R4 | R1, window mode | Resize the window, minimise and restore, move it to the second monitor | Panel repainted completely after each action (or the client scales the bitmap); typed digits kept | fail if the panel stays black or half drawn after restore; note client scaling |
| R5 | two monitors (`/multimon`, mstsc "use all monitors") | Connect | Panel visible (known: centred on the whole virtual desktop, A3) | record where it appears; fail only if not visible at all |
| R6 | 15/16/24/32 bpp where the client lets you choose (C8, C9, mstsc `.rdp` `session bpp`) | Connect | Same panel at each depth | fail on garbled colours |
| R7 | R1 | Approve (by code or QR) | No part of the panel remains once the desktop appears, also when the back-end changes the resolution | fail on leftovers |

### 4.2 Input (I)

All with alice and the input trace on. "Type the code" means the current TOTP code from
the authenticator app; wait for a fresh code if fewer than 10 s are left. With the
default field of 6 digits the sixth digit submits; Enter is only needed with several
`fastrdp_otp_lengths` (field of open length: Enter submits 4–10 digits).

| ID | Preconditions | Steps | Expected | Pass/fail |
|---|---|---|---|---|
| I1 | each layout K1–K5 | Type the code on the top row the way users of that layout type digits (K3/K4: with Shift, also with Caps Lock for AZERTY) | Field fills with masked digits (`••••__`), "Checking the code…" after the sixth, login proceeds. Trace: `scancode top-row digit` (or `unicode digit`) per digit, field length counting up | fail if digits are lost, doubled, or a correct code is refused |
| I2 | K3, K4 | Type the digits **without** Shift (`&é"'(`…) | Scancode clients: accepted as digits (position counts) [inferred]. Unicode clients: ignored without a hint, field stays empty; trace `unicode other` | record which; fail only if a wrong digit is entered |
| I3 | keyboard with numpad | NumLock on at the client, type the code on the keypad | Accepted. Trace: `sync NumLock on` before the keys, then `scancode keypad digit` (or `unicode digit`) | fail if keypad digits do not count while NumLock is on |
| I4 | I3 | NumLock off, type on the keypad | Not taken as digits; nothing entered. Trace: `scancode keypad digit key (NumLock off)` | fail if digits appear |
| I5 | I3 | Toggle NumLock **while** the panel shows, then type on the keypad | Follows the new state (the client sends a Synchronize) | record whether the client sends the sync; fail if keypad state and entry disagree |
| I6 | – | Type 3 digits, Backspace twice, finish the code | Correct code accepted (submitted at the sixth digit) | fail if Backspace does nothing or deletes everything |
| I7 | – | Type 4 digits, press Esc; then Esc on the empty field | Field cleared (`______`), no attempt used; Esc on an empty field does nothing; login still waits for code or QR | fail if Esc ends the login or sends the code |
| I8 | – | Hold a digit key for 2 s (key repeat) | **One** digit: a key counts on its release, repeated presses without release add nothing (scancode and Unicode alike). Trace: several `down`, one `up` | fail on more than one digit, overflow or a crash |
| I9 | – | Type the code while the panel is not shown yet (during NLA "connecting"), then again on the panel | Early digits dropped (drain, up to 500 ms; trace `before the prompt`); digits typed on the panel count. The same after a wrong code: keys typed during "Checking the code…" are dropped | record how users notice; fail if early digits are taken |
| I10 | clipboard redirection on | Copy the code on the client, paste with Ctrl+V and with the client's paste menu | Nothing entered (clipboard is channel data, not keys). Ctrl+V gives at most a `v` key, which is ignored | fail if a paste fills the field |
| I11 | K5 with IME on (romaji, then kana) | Type the code | Record what arrives: scancodes (`top-row digit`), Unicode on commit (`digit` or `full-width digit`), or nothing. Full-width digits are **not** entered (the field takes ASCII digits only) | fail if anything is entered as a wrong digit; if only `full-width digit` arrives, document "switch the IME off" |
| I12 | C6, C7 soft keyboard | Tap into the panel, bring up the keyboard (client's keyboard button), type the code with the numeric keyboard | Accepted. Trace: `unicode digit` (record whether the soft keyboard's Enter arrives as `unicode enter` or not at all; with a 6-digit field it is not needed) | fail if the keyboard cannot be brought up or digits do not arrive |
| I13 | C6 with a hardware keyboard (Magic Keyboard / USB) | Type the code | Accepted; record scancode or Unicode | as I1 |
| I14 | C5 with an Apple keyboard (no NumLock), then a PC keyboard | Type on the top row; on the Apple keypad (if any) | Top row accepted; record the keypad behaviour | fail on top-row loss |
| I15 | any | Click into the panel, on the QR code and outside the card while typing | Clicks are ignored while the code field shows (trace `mouse button 1 down/up`) | fail if a click changes the entry |
| I16 | any | Type 10 digits in one go | The field submits at the sixth digit; digits 7–10 come during "Checking the code…" and are ignored. With an open-length field (several `fastrdp_otp_lengths`): at most 10 digits, Enter submits | fail on overflow or if extra digits are taken into the next try |

### 4.3 Flow (F)

| ID | Preconditions | Steps | Expected | Pass/fail |
|---|---|---|---|---|
| F1 | alice | Type the correct code | Desktop starts. Broker journal: `alice: code from the waiting screen accepted by Keycloak`; Keycloak events: a login and a logout of `fastrdp-otp-check`, no session left (admin console *Sessions*); webgate untouched | fail otherwise |
| F2 | alice | Wrong code | "Checking the code…", then `Wrong code. Attempts left: 2` (`code_wrong`) above an empty field; QR still valid; countdown keeps running. Broker: `alice: wrong code on the waiting screen (nla login from …); 2 attempt(s) left` | fail if the login ends at once or the attempts text is missing |
| F3 | F2 | Wrong codes up to `fastrdp_mfa_code_attempts` (3) | The third wrong code ends the login with `mfa_failed` (Set Error Info 0x7); the broker logs each attempt without the code | fail if a fourth attempt is allowed |
| F4 | alice | Repeat F3 with new logins until `fastrdp_mfa_code_user_failures` (10 within 900 s); separately until Keycloak's brute-force limit | Broker: `alice: 10 wrong codes within 900s: code entry closed, approval page only`; the next logins show `Too many wrong codes. Please use the approval page.` (`code_blocked`) and no field; QR approval with a passkey still works. Keycloak's lockout refuses a correct code too (record whether it also blocks the passkey sign-in on the approval page) | record the limits reached; fail if no limit applies |
| F5 | alice | Do nothing | Login fails with `mfa_timeout` (0x409) after `fastrdp_mfa_web_approval_timeout` | fail on another code or no timeout |
| F6 | alice, phone | Scan the QR code, approve with the passkey, then type a code in the RDP window | QR wins; the field closes; a late code is ignored and not sent to Keycloak (broker journal) | fail if both are used |
| F7 | alice, phone | Type the correct code; then open the QR link on the phone and sign in | Code wins; the approval page shows no waiting login ("no longer waiting") | fail if the page still offers Approve |
| F8 | after F1 | Disconnect, reconnect within `fastrdp_mfa_reconnect_grace` from the same address | No second factor asked (grace from factor `keycloak_otp`) | fail if asked again, or if grace applies from another address with `..._same_address` on |
| F9 | alice | Close the client window while the panel shows (and once while typing) | Broker log: login abandoned at once; no Keycloak call after the close | fail if the broker waits for the timeout |
| F10 | bob (TOTP only) | Code | Works like F1 | as F1 |
| F11 | dave (passkey only) | Type any 6 digits | **Not counted**: the field closes and the panel says `No authenticator app is set up for your account. Approve with your passkey: scan the QR code.` (`code_no_otp`); QR code and countdown stay; broker `Keycloak: dave has no OTP credential …` and `dave: code entry closed for this login (no OTP credential), approval page only` at INFO; QR approval with the passkey works | fail if dave passes with a code, if an attempt is counted, if the field stays, or if the screen shows an internal error |
| F12 | carol (password only) | Connect, type a code | The field closes as in F11 (no attempt); the approval page shows *Second factor required*; the login times out (`mfa_timeout`) | fail if carol passes |
| F13 | erin | Code from the non-default device, then from the default device | Only the default device's code works (Keycloak checks the default OTP credential only) | record; this is documentation, not a bug |
| F14 | alice | Use the same correct code twice: once accepted (F1), then a new login within the same 30 s step | Second use refused (OTP reuse off) | fail if accepted |
| F15 | old proxy module (one that does not announce `"code_entry": 1`) against the new broker | Connect | Waiting screen with QR approval only, no code field; QR approval works | fail if the login breaks |
| F16 | `[FastRDP] WaitingScreen = false` set by hand in proxy.ini (Ansible refuses `code_or_web` without the waiting screen), or a client at 8 bpp | Connect | No panel and no field; approval on `/web/approve` (URL from the documentation) works | fail if the login breaks |
| F17a | Keycloak stopped (or unreachable: firewall rule) | Type a code | `The code could not be checked. Try again or use the approval page.` (`code_unavailable`); **no attempt used**; broker `code of alice not checked: …` at ERROR; QR approval fails too (Keycloak is down) and the login times out | fail if the outage counts as a wrong code, or if the check hangs past `fastrdp_mfa_keycloak_timeout` (10 s) |
| F17b | the OTP client's secret wrong in the vault | Type a correct code | **Not counted**: Keycloak answers HTTP 401 `unauthorized_client`; the field closes with `Codes cannot be checked at the moment. Please use the approval page.` (`code_off`); broker `Keycloak cannot check codes of alice: HTTP 401, … (wrong [mfa.keycloak] client secret or client_id?) …` at ERROR; QR approval works | fail if an attempt is counted or the field stays open |
| F17c | in Keycloak, the flow `fastrdp-otp-check`: set the sub-flow `fastrdp-otp-check - no otp` to *Disabled* (a hand-made mistake); afterwards run the role again | dave types any 6 digits; then run the role in check mode, then normally | Keycloak issues dave a token on his name alone, without `otp` in `amr`; the broker refuses it: the field closes with `code_off`, no attempt, broker `Keycloak flow issued a token without 'otp' in amr …` at ERROR. Check mode lists `rebuild direct grant flow fastrdp-otp-check` and a warning naming the disabled step; the normal run rebuilds the flow, after which dave gets F11 again | fail if dave passes, or if check mode reports nothing (safeguards 2 and 1, [auth-matrix.md](auth-matrix.md#code-on-the-waiting-screen)) |
| F18 | combinations with privacyIDEA push | – | Not offered: `code_or_web` uses Keycloak only | – |
| F19 | C1–C3 (mstsc), `fastrdp-freerdp3` ≥ 3.32.2-7 (`patches/freerdp/0008`); unattended: `tests/lab/a5_f19.py` ([lab-windows-mcp.md](lab-windows-mcp.md) §5) | After F1: click the X in mstsc's connection bar, confirm mstsc's dialog; then *Connect* again in the **same** mstsc (no restart). Once more with the X while the panel waits for the code | X during the session: mstsc's own disconnect dialog, then a clean close; proxy journal without `disconnect provider ultimatum sent to peer` for that session; broker `session end`. The next *Connect*: the panel with code field and QR code within 1 s, F1 and the QR approval both work (field report 2026-10-23 before the patch: black window until `mfa_timeout`). X while the panel waits: the login is abandoned at once (broker log), no Keycloak call; record what mstsc shows | fail if the next *Connect* in the same mstsc shows no panel, or if the proxy still logs the provider-initiated disconnect for a running session. Field report with v0.7.4: mstsc's dialog appears (0008 works), the next *Connect* still shows no panel: run F19c |
| F19c | C1–C3 (mstsc), fast-rdp-server with the A5 diagnostics | Backlog A5, decides the cause. Proxy journal with `-o short-precise`. Run 1, `fastrdp_proxy_waiting_screen_observe: false` (default): restart mstsc, log in and approve (connection 1), X, *Connect* in the same mstsc (connection 2), wait for the countdown to end; then GNOME logout instead of the X (connections 3 and 4). Run 2: the same with `fastrdp_proxy_waiting_screen_observe: true` (role run, proxy restart). Note per connection which button started it (*Connect* in the main window or *Reconnect* in mstsc's dialog) and what mstsc showed | Per connection one `front: client "…"` line: compare connection 2 with 1 (desktop size, monitors, scale, gfx, bitmap cache/persist, auto-reconnect cookie, performance flags, connection type). `back-end Save Session Info to the client: …` lines show what mstsc got from the back-end. Run 1: `the client sent at least N bytes during the wait that were not read` for connection 2 means mstsc sent something during the wait. Run 2: `client Refresh Rect #…` / `client Suppress Output #…: allowDisplayUpdates 0|1` lines and the counts at the end of the wait | pass when run 2 shows the panel on connection 2 (then the cause is a Refresh Rect or Suppress Output nobody answered, and the switch becomes the default); otherwise the lines locate the difference; attach both journals and mstsc's event log |
| F19b | C1–C3 (mstsc) | After F1: log out inside the session (GNOME *Log Out*; on an xrdp desktop its logout), no X; then *Connect* again in the same mstsc; once more with a restarted mstsc for comparison. Note the times | Proxy journal: `received ErrorInfo PDU. code=0x…` (gnome-remote-desktop sends 0x1) and the session end; mstsc's message after the logout; the next *Connect*: the panel within 1 s and F1 works. On Windows, export Event Viewer → *Microsoft-Windows-TerminalServices-ClientActiveXCore/Operational* for both connections (disconnect reasons). Field report 2026-10-23: mstsc closed the next connection itself after 7.5 s while the login waited (`front connection closed while waiting for the broker`); record whether anybody cancelled | fail if the next *Connect* in the same mstsc shows no panel or ends by itself; attach the event log either way |

### 4.4 Security observations (S)

| ID | Preconditions | Steps | Expected | Pass/fail |
|---|---|---|---|---|
| S1 | after F1–F17 | `journalctl` of proxy, broker and webgate for the whole lab; Keycloak server log and its user/admin events; nginx access and error logs | The codes typed in the lab (note them during the run) appear nowhere; Keycloak events show the OTP-check client's login and logout, no code | fail on any hit (grep for each noted code) |
| S2 | X11 desktop (xrdp) and GNOME/Plasma (if offered); in the user's autostart a key logger that starts first: X11 `xinput test-xi2 --root > ~/keys.log`, Wayland a focused text editor | Type the code, then 5 extra digits right after Enter and during the "connecting to your desktop" step | No key event in the session from the code; extra keys typed after the panel closed may arrive, and are recorded with their timing | fail if any digit of the code reaches the session |
| S3 | S2, lab build and lab user only: proxy with `WLOG_FILTER=com.freerdp.core:DEBUG` for the back-end hop | Same as S2 | No input sent to the back-end before it is active | fail on forwarded key events before activation |
| S4 | R1 | Photograph the panel while typing; screen-record on the client (macOS screen recording, Windows Game Bar) | Field shows masks (e.g. ●●●○○○), never the digits, also not briefly on key-down | fail if a digit is visible |
| S5 | two logins of alice at once (second client with alice's password) | Type the code in the first window | Only the first login proceeds; the second still waits and can be denied on `/web/approve` | fail if one code approves both |
| S6 | an RDP client that accepts any certificate, a man-in-the-middle RDP proxy in the lab (e.g. a second fastrdp proxy or `freerdp-proxy` forwarding to rdp1) | Connect through it with a TLS/password login; type the code | Expected to **succeed** (a real-time relay passes password and code on, as with push and web approval). With Kerberos NLA through the relay: refused (mutual authentication) | documentation result, not a fail: records the residual risk for users who click through certificate warnings |
| S7 | after S2 | Check the session for clipboard contents and the client's "recent" lists | The code is not in the session's clipboard | fail if it is |

## 5. Results matrix

One sheet per client (C1–C10). Mark each cell **P** (pass), **F** (fail), **W** (works
with a workaround: note it), **–** (not applicable), **?** (not run).

| Test | K1 | K2 | K3 | K4 | K5 IME off | K5 IME on | Notes (event classes seen) |
|---|---|---|---|---|---|---|---|
| R1 panel shown | | | | | | | |
| R3 QR scannable | | | | | | | |
| R4 repaint | | | | | | | |
| I1 top-row digits | | | | | | | |
| I2 unshifted (K3/K4) | – | – | | | – | – | |
| I3 keypad NumLock on | | | | | | | |
| I4 keypad NumLock off | | | | | | | |
| I6 Backspace | | | | | | | |
| I9 drain | | | | | | | |
| I10 paste refused | | | | | | | |
| I11 IME | – | – | – | – | – | | |
| I12/I13 soft / hardware keyboard (C6, C7) | | | | | | | |
| F1 code accepted | | | | | | | |
| F2/F3 wrong code, limit | | | | | | | |
| F6/F7 race | | | | | | | |
| F19 X, then *Connect* in the same mstsc | | – | – | – | – | – | |
| F19b logout, then *Connect* in the same mstsc | | – | – | – | – | – | |
| S2 nothing in the session | | | | | | | |
| S4 masking | | | | | | | |

Summary sheet:

| Client | Version | Panel (R1–R4) | Digits (I1, I3, I12/13) | Flow (F1–F9) | Security (S1–S4) | Verdict |
|---|---|---|---|---|---|---|
| C1 mstsc W10 22H2 | | | | | | |
| C2 mstsc W11 24H2 | | | | | | |
| … | | | | | | |

## Go / no-go per client

- **Go (code entry on):** R1, R3 and I1 pass on K1 and on the site's own layouts; F1–F3,
  F6, F7 and F9 pass (mstsc also F19 and F19b); S1, S2 and S4 pass.
- **QR only:** the panel renders (R1, R3) but digits are unreliable (I1 fails on a
  layout the site uses, I12 fails on the platform's soft keyboard). The client keeps the
  waiting screen and QR approval; the docs say "type the code" does not work on it.
  The module has no per-client switch for the code field today; record `clientBuild`
  and `clientName` of each client (Client Core Data, in the proxy's journal at DEBUG) so
  that one can be added (backlog W5).
- **No-go for the mode:** any S1–S4 failure on any client (a code in a log, in the
  session, or visible on screen), or a correct code accepted after the per-login limit.
  Fix before shipping, on all clients.
- **Not blocking:** R5 (multi-monitor placement), I11 (IME; document "switch the IME
  off"), I8 (key repeat), F13 (default OTP device), S6 (relay; documented residual risk).

Before shipping, also re-run the S3 picker steps on every client that gets code entry:
both features share the input path.

## 6. After the lab

- Enter the results in the [S3](rdp-spec-conformance.md) row and in
  [windows-clients.md](windows-clients.md) §6 item 9; close or update backlog A3.
- Add client-specific notes to [client-guide.md](client-guide.md) (how to bring up the
  soft keyboard on iPad/Android, NumLock, IME).
- Delete the lab users' OTP and passkey credentials, and set
  `fastrdp_proxy_input_trace: false` again (the proxy warns on every connection while it
  is on).
