# Lab checklist: v0.7.6

One lab round that closes the open host and client checks of the
[backlog](backlog.md). Every item gives the setup, the steps or script, and what to
bring back. The detailed test plans stay in the linked docs; this page only orders them.
Tick an item when its results are attached; update the backlog row afterwards.

## 0. Before the round

- [ ] Host on **fast-rdp-server 0.7.7** (0.7.6 lacks only the TLS key log of A5),
      `fastrdp-freerdp3 3.32.2-7`, `fastrdp-xrdp 0.10.6.1+xorgxrdp0.10.5-2` (`dpkg -l 'fast*'`), deployed with
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
Windows 10 and Windows 11 each.

Run 1 was done on 2026-10-26 with 0.7.7 and mstsc build 26100 (Windows 11 24H2, inferred
from the build; findings:
[a5-capture-2026-10-26.md](a5-capture-2026-10-26.md)): the window is black only after a
connection that used GFX, and mstsc sends no Refresh Rect or Suppress Output during the
wait, so `WaitingScreenObserve` has nothing to answer and stays off.

- [ ] **Run 1** (both switches off; still open on Windows 10): restart mstsc;
      log in and approve (connection 1); X; *Connect* in the same mstsc (connection 2),
      wait for the end of the countdown; then GNOME *Log Out* instead of the X
      (connections 3, 4).
- [ ] **Run 2:** `fastrdp_proxy_waiting_screen_reactivate: true`, role run, proxy
      restart; the same steps. The journal shows `WaitingScreenReactivate: reactivation
      completed in N ms` per connection (F19c run 3).
- [ ] **GFX off (confirms the cause):** `[Channels] GFX=false` temporarily in
      `/etc/fastrdp/proxy.ini` (proxy restart; the next role run puts it back), with the
      xfce/xrdp desktop (gnome-remote-desktop probably needs GFX, unverified) and both
      switches off: restart mstsc, connection 1 into the session, X, connection 2. The
      panel on connection 2 is expected if GFX is the cause.
- [ ] Per connection note: which button started it (*Connect* or *Reconnect* in mstsc's
      dialog), what mstsc showed, the times.
- [ ] Both runs: `tcpdump` and the `ss` loop on the proxy host from before connection 1
      ([lab-waiting-screen-input.md §3](lab-waiting-screen-input.md#3-capturing-input-without-leaking-codes),
      *Packet capture*). Also `fastrdp_proxy_tls_keylog: true`
      (lab users only), and copy the key log after each run.
- [ ] Bring back: both proxy journals, mstsc's event log, the notes, the captures and
      `ss` logs (and key logs).

Decision: the panel on connection 2 in run 2 means the reactivation clears what mstsc
carries over from the GFX connection; the switch then becomes the default for the
waiting screen. The panel with GFX off but not in run 2 points at the waiting screen over
GFX ([backlog A8](backlog.md#maybe-later)). Otherwise compare the decoded captures
(`tests/lab/rdpcapture/decode.py`) of connections 1 and 2.

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
