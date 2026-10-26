# Lab checklist: v0.7.6

One lab round that closes the open host and client checks of the
[backlog](backlog.md). Every item gives the setup, the steps or script, and what to
bring back. The detailed test plans stay in the linked docs; this page only orders them.
Tick an item when its results are attached; update the backlog row afterwards.

## 0. Before the round

- [ ] Host on **fast-rdp-server 0.7.9** (0.7.8 lacks the lab keypress accounts and the
      lab xorgxrdp variant, 0.7.7 the reactivation switch of A5, 0.7.6 also the TLS key
      log),
      `fastrdp-freerdp3 3.32.2-8`, `fastrdp-xrdp 0.10.6.1+xorgxrdp0.10.5-2` (`dpkg -l 'fast*'`), deployed with
      `make deploy INVENTORY=…`.
- [ ] Inventory for the round: `fastrdp_desktop_picker: true`,
      `fastrdp_mfa_mode: code_or_web` with the Keycloak setup of
      [lab-waiting-screen-input.md §2](lab-waiting-screen-input.md#2-setup),
      `fastrdp_proxy_input_trace: true`, `fastrdp_proxy_waiting_screen_observe: false`,
      `fastrdp_proxy_waiting_screen_reactivate: false` (run 2 of A5 turns it on).
- [ ] Desktops installed: xfce (xrdp), one wlroots desktop, gnome, plasma.
- [ ] Clients: mstsc on Windows 10 and Windows 11, the Windows App (macOS, iOS),
      xfreerdp3, Remmina.
- [ ] Automated Windows client (optional): set up as in
      [lab-windows-mcp.md](lab-windows-mcp.md).
- [ ] Logs: `journalctl -o short-precise -u fastrdp-proxy -u fastrdp-brokerd
      -u xrdp -u xrdp-sesman` per test, `/var/log/xrdp.log`; on Windows the event log
      *Microsoft-Windows-TerminalServices-ClientActiveXCore/Operational*.
- [ ] `sudo tests/smoke/check-host.sh TESTUSER`: all `ok` (includes the A7 template
      check and the Kerberos settings of K2).

## 1. A5: mstsc reconnect in the same process (priority)

Test plan: [lab-waiting-screen-input.md](lab-waiting-screen-input.md) F19, F19b, F19c.
Findings so far: [a5-capture-2026-10-26.md](a5-capture-2026-10-26.md).

Done on 2026-10-26 (0.7.7/0.7.8, mstsc build 26100, Windows 11):

- [x] **Run 1** (switches off): connection 2 black after a session, every time; the
      next connection after a black one worked, but the event log shows it in a new mstsc
      process ([a5-capture](a5-capture-2026-10-26.md#process-ids-in-the-event-log)): to
      check again in the same window.
- [x] **Run 2** (`fastrdp_proxy_waiting_screen_reactivate: true`): the reactivation
      completes, connection 2 still black. The switch stays off.
- [x] **GFX off, first try** (`[Channels] GFX=false`, xfce): connection 2 still black.
      Not conclusive yet: the xfce desktop of connection 1 was black itself (backlog A10)
      and nothing shows whether mstsc started GFX in connection 1.

Next session (in this order; the first two decide whether backlog A8 is needed):

- [ ] **Before every run:** restart mstsc; `fastrdp_proxy_tls_keylog: true`; on the proxy
      host `sudo tests/lab/a5-collect.sh start <run>` before connection 1 (tcpdump and the
      `ss` loop) and `sudo tests/lab/a5-collect.sh stop <run>` after the last connection
      (key log, journals, xrdp.log, a summary; everything in `/root/fastrdp-lab/<run>`;
      [lab-waiting-screen-input.md §3](lab-waiting-screen-input.md#3-capturing-input-without-leaking-codes),
      *Packet capture*). On the Windows client afterwards
      `tests/lab/windows/rdp-eventlog.ps1 -Clear` (exports mstsc's event log
      *TerminalServices-ClientActiveXCore* → *RDPClient/Operational* to an .evtx, prints it
      per connection, then empties the log for the next run; elevated PowerShell for
      `-Clear`; untested on Windows so far). Analysis:
      `tests/lab/rdpcapture/decode.py … --summary` and `evtx_summary.py <file>.evtx`. Note
      per connection the button (*Connect* / *Reconnect*), whether mstsc was restarted,
      what mstsc showed, the times.
      For A, C and D the second factor is in the way: a lab account in
      `fastrdp_mfa_lab_keypress_users` (with `fastrdp_mfa_lab_keypress_ack`,
      [auth-matrix.md](auth-matrix.md#lab-keypress)) logs in with any 4 digits and Enter
      on the waiting screen instead (the waiting screen is still shown, which A5 is about).
      Not for B: reconnect grace needs a real second factor (lab logins never earn it).
- [ ] **A. GFX off, repeated with evidence:** `[Channels] GFX=false` in
      `/etc/fastrdp/proxy.ini`, proxy restart (the next role run puts it back), xfce
      desktop: connection 1 into the session (a black desktop is fine), X, connection 2.
      Check mstsc's event log for **1401/1402 during connection 1**:
      - none, and connection 2 black: GFX is **not** the trigger, a session as such is;
        continue with C.
      - none, and the panel on connection 2: GFX is the trigger; backlog A8 is the fix.
      - 1401 present: mstsc used GFX anyway, the test does not count (and A10 likely has
        the same cause); bring the capture.
- [ ] **B. Reconnect grace (mitigation, any cause):** `fastrdp_mfa_reconnect_grace: 900`
      in `lab.yml`, deploy, GNOME: connection 1 approve, X, connection 2 within 15 min
      from the same client. Expected: no waiting for the second factor, the desktop
      directly (broker log `second factor skipped: reconnect grace`). Note whether the
      short session-start screen is black and whether the desktop then appears.
- [ ] **C. Which part of the session leaves mstsc broken** (only if A rules GFX out):
      repeat connection 1 → X → connection 2 with mstsc's *Local Resources* reduced step by
      step, mstsc restarted each time: (1) clipboard, printers, drives and devices off;
      (2) also *Remote audio: Do not play* and recording off; (3) connection 1 X'ed right
      after the desktop appears versus after a minute. The step at which connection 2
      shows the panel names the channel; the decoded captures
      (`tests/lab/rdpcapture/decode.py`) of connection 1 show what it opened.
- [ ] **D. A9 reach (xfce glitches):** mstsc from a physical Windows PC with a GPU to the
      xfce desktop: event 1401 `AvcEnabled=1` means xrdp uses H.264 there and the
      RemoteFX Progressive glitches do not occur (check `Matched H264 mode` in
      `/var/log/xrdp.log`); note whether windows leave stale rectangles.
- [ ] **E. A9: capture or encoder?** Lab host with `fastrdp_install_method: build` only:
      `fastrdp_xorgxrdp_lab_gfxpro_no_tile_skip: true` in `lab.yml`, deploy (rebuilds
      xrdp and xorgxrdp with `patches/xorgxrdp-lab/0001`: the progressive capture sends
      every damaged tile instead of skipping tiles whose hash matches the last capture),
      new session (log out first). Then the A9 repro with the client that glitched (mstsc
      with `AvcEnabled=0` or `xfreerdp3 /gfx:progressive`; `xrdp.log`: `gfx rfx pro`),
      moving windows over each other for a minute:
      - clean: the tile skip (or a stored hash that goes stale) is the cause; report it
        to xorgxrdp with this result ([upstream.md §12](upstream.md#12-xrdp--xorgxrdp-stale-tiles-with-gfx-remotefx-progressive-backlog-a9)).
      - the same glitches: the capture's skip is not it; the encoder (xrdp/librfxcodec)
        or the client's progressive decoding; report to xrdp.
      Note the CPU load of xrdp and Xorg compared with the normal build. Set the variable
      back to `false` and deploy afterwards (rebuilds the normal variant).
- [ ] Bring back: proxy and broker journals, captures, `ss` logs, key logs, mstsc's event
      logs, the notes.

## 2. Fixes of 0.7.5 / 0.7.6

- [ ] **A7** (X11 via xrdp): log in to xfce and to the wlroots desktop end to end. `ls -ld
      /run/xrdp/<uid>` shows group `xrdp`; no `Permission denied` in `/var/log/xrdp.log`.
- [ ] **A6** (GNOME beside X11): with an xfce session running, the picker marks xfce
      `(running)`; choosing GNOME is refused within seconds with a message naming the
      X11 session (no 90 s wait). Log out of xfce, then GNOME starts. The reverse: xfce
      while a GNOME session runs (record the result). Look for
      `xrdp session state unknown:` lines in the broker journal.
- [ ] **A4** (journal): within one login, INFO and WARN lines arrive in order, the journal
      time matches the FreeRDP time stamp, no torn lines; `journalctl -u fastrdp-proxy
      -p warning` lists only warnings.

## 3. Sessions and host safety (per desktop: xfce, wlroots, gnome, plasma)

- [ ] **K1** TGT in the session, after a password login:
      `sudo tests/smoke/check-session-tgt.sh -s HTTP/<intranet> -s cifs/<fileserver> USER`
      as root, and the same script without `USER` in a session terminal.
- [ ] **K9** browsers: the K1 script's browser lines; on Ubuntu 26.04 and Debian 13
      Firefox SPNEGO against the intranet.
- [ ] **K2** `sudo fastrdpctl status` and `fastrdpctl tickets USER`: real `klist` output
      parsed, state `ok`; after a renewal the expiry has moved forward.
- [ ] **K4** reconnect with the password renews the TGT (expiry before/after in
      `fastrdpctl tickets`); with short test thresholds in
      `/etc/fastrdp/tgt-notify.conf`, the reminder appears once per threshold.
- [ ] **H1** `sudo tests/smoke/check-power-actions.sh USER ADMIN`; look at each desktop's
      menu (power entries hidden or greyed out); `systemctl poweroff` as the user is
      refused.
- [ ] **A1** audio: "play on this computer" and "record from this computer" in the
      client; `sudo tests/smoke/check-audio.sh USER`; play a sound and record a few
      seconds (mstsc, Windows App, xfreerdp3, browser). Plasma has no audio (expected).

## 4. Clients: picker and code field

Test plan: [lab-waiting-screen-input.md](lab-waiting-screen-input.md) §4 and the results
matrix in §5, for every client of §0.

- [ ] **A3** picker: keys, arrows + Enter, clicks, Esc, countdown; multi-monitor
      placement on one client.
- [ ] **W5** code field: R1, R3, I1, F1–F3, F6, F7, F9 and S1–S4; go / no-go per client
      as in that doc.
- [ ] Afterwards: §6 *After the lab* of that doc (credentials, `input_trace` off).

## 5. If the Windows lab is set up (otherwise next round)

- [ ] **K11** AD + mstsc smart card or WHfB: `kdc_evidence` in the broker journal, which
      SIDs and indicators arrive; the push is skipped only with a matching
      `kdc_evidence_as_mfa`.
- [ ] **K6** KDC proxy: mstsc via GPO (lab L12), AD as KDC, kpasswd through the proxy.
- [ ] **K8** `/remoteGuard` and `/restrictedAdmin` per [windows-clients.md](windows-clients.md) §7.
- [ ] **K3** SMB homes with a Windows and a Samba file server
      ([smb-kerberos-homes.md](smb-kerberos-homes.md)); reconnect identity on Debian's
      cifs-utils.
- [ ] **W1** approval notifications on iOS, Android and Windows devices.

## What to bring back

Per item: pass/fail, the journals named above (with `-o short-precise`), the client and
OS build, and a note of anything shown on screen that the logs do not record. Codes and
passwords stay out of the notes (input trace logs classes only).
