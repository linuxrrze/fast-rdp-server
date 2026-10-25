# Lab: a Windows client driven over MCP

Set-up note for the Windows client of the lab ([lab-checklist-0.7.6.md](lab-checklist-0.7.6.md))
when an orchestrator drives it instead of a person. The orchestrator runs on Linux. It
talks to [Windows-MCP](https://github.com/CursorTouch/Windows-MCP) on the Windows box
(screenshots, UI Automation text, mouse, PowerShell) and reads the fastrdp host's journal
over ssh. Keys under test go through `tests/lab/windows/send-keys.ps1`, never through
Windows-MCP's `Type` tool.

```
orchestrator (Linux) ──HTTPS + bearer──▶ Windows-MCP ── SendInput ──▶ mstsc ──RDP──▶ fastrdp host
        └──────────────────────────────── ssh: journalctl, smoke scripts ─────────────────┘
```

Facts about Windows-MCP were checked against its source as of 2026-10-24 (v0.8.8);
Windows behaviour marked *(inferred)* has not been tested in this lab yet.

## 1. The box

- **A VM** (KVM/libvirt or Hyper-V) with Windows 11 24H2 or later, and a second one with
  Windows 10 22H2 for A5. Watch it through the VM console, not through RDP (§5).
- A local **lab user without admin rights** who runs mstsc, Windows-MCP and the tests.
  Its password and the fastrdp lab users exist only in the lab.
- The keyboard layouts the tests need (W5 I-tests: German, French AZERTY), added for the
  lab user: `Set-WinUserLanguageList` or Settings.
- Optional: the OpenSSH server for `Get-WinEvent` and file copies from the orchestrator.
  An ssh session has no input desktop, so screenshots and `send-keys.ps1` fail there.

## 2. Keep the session logged in and unlocked

SendInput on a locked desktop goes nowhere and screenshots come back black. Windows-MCP
accepts black frames without an error, so the orchestrator must check for them.
As an admin:

```powershell
# autologon for the lab user (Sysinternals Autologon stores the password LSA-encrypted)
autologon64.exe labuser $env:COMPUTERNAME '<password>' /accepteula
# no idle lock, no sleep, no sign-in after wake
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 0 /f
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
powercfg /setactive SCHEME_CURRENT
```

As the lab user, switch the screen saver off: `reg add "HKCU\Control Panel\Desktop" /v
ScreenSaveActive /t REG_SZ /d 0 /f`. Also turn off Dynamic Lock, and set Windows Update's active hours to cover the test
window. Updates that restart the box end the autologon session until the next logon.

## 3. Windows-MCP

As the lab user: Python 3.14+ and uv (`winget install astral-sh.uv`), then
`uv tool install windows-mcp`. Configuration in `%USERPROFILE%\.windows-mcp\config.toml`:

```toml
[server]
transport    = "streamable-http"
host         = "0.0.0.0"
port         = 8000
auth_key     = "<random, 32+ bytes; only in the orchestrator's vault>"
ssl_certfile = "cert.pem"          # relative to ~/.windows-mcp/
ssl_keyfile  = "key.pem"

[security]
ip_allowlist = ["<orchestrator>/32"]

[tools]
exclude = ["Type"]                 # input under test goes through send-keys.ps1

[control]
enabled = false                    # no ownership gate, no takeover hooks beside mstsc's
```

- **Auth:** without `auth_key` (or OAuth), the server refuses to bind to a non-loopback
  address. Clients send `Authorization: Bearer <auth_key>`; the endpoint is
  `https://<box>:8000/mcp/`. Self-signed certificate: `openssl req -x509 -newkey rsa:4096
  -nodes -days 365 -keyout key.pem -out cert.pem` in that directory, and pin it in the
  orchestrator.
- **Telemetry:** on by default (PostHog). Run `setx ANONYMIZED_TELEMETRY false` before the
  install, so the logon task inherits it.
- **Start at logon:** `windows-mcp install --transport streamable-http --host 0.0.0.0
  --port 8000`. This creates the per-user task `windows-mcp-server` (at logon, RunLevel
  Limited) that runs `serve`, which reads `config.toml`. Logs are in
  `~\.windows-mcp\server.log`; check whether they record tool arguments before typing
  codes (§6).
- **Task time limit:** the task's settings set no execution limit, and Task Scheduler's
  default is 72 h *(inferred)*. Lift it: `$s = New-ScheduledTaskSettingsSet
  -ExecutionTimeLimit 0 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;
  Set-ScheduledTask -TaskName windows-mcp-server -Settings $s`.
- **Firewall** (as admin): `New-NetFirewallRule -DisplayName windows-mcp -Direction
  Inbound -Protocol TCP -LocalPort 8000 -RemoteAddress <orchestrator> -Action Allow`.
- **Rights:** PowerShell runs as the lab user, not elevated. mstsc does not need more.
  Whether that user can read the RDP client's event log is to be checked (§4). Admin
  rights for the task are not needed for the checklist.

## 4. mstsc and the key helper

Copy `tests/lab/windows/send-keys.ps1` and an `.rdp` file to `C:\fastrdp-lab\`
(scp, or Windows-MCP's FileSystem tool). The `.rdp` file pins what the tests compare:

```
full address:s:rdp1.lab.example.com
username:s:LAB\labuser1
prompt for credentials:i:0
authentication level:i:2
screen mode id:i:1
desktopwidth:i:1280
desktopheight:i:800
keyboardhook:i:1
redirectclipboard:i:0
```

- `keyboardhook:i:1` ("Apply Windows key combinations: on the remote computer") keeps
  mstsc's low-level keyboard hook active in a window too. Record the setting with every
  input result: what mstsc forwards may depend on it *(inferred)*.
- `redirectclipboard:i:0` keeps an accidental paste from reaching the session.
- Credentials for NLA: `cmdkey /generic:TERMSRV/rdp1.lab.example.com /user:LAB\labuser1
  /pass:<password>`; start with `mstsc C:\fastrdp-lab\fastrdp.rdp`.

`send-keys.ps1` sends keys in one explicit event type (header of the script for the
details):

```powershell
$k = 'C:\fastrdp-lab\send-keys.ps1'
powershell -NoProfile -ExecutionPolicy Bypass -File $k -Mode Scancode -Text 123456
powershell -NoProfile -ExecutionPolicy Bypass -File $k -Mode Unicode -Text 123456
powershell -NoProfile -ExecutionPolicy Bypass -File $k -Mode VirtualKey -Keys Num1,Num2,NumEnter
powershell -NoProfile -ExecutionPolicy Bypass -File $k -Mode Scancode -Keys Down,Enter
```

It targets the newest mstsc window (`-Process`, `-Title`), brings it to the foreground,
refuses to type if the window loses the foreground, and prints one summary line without
the characters. Exit status 3 means a locked desktop or a refused SendInput. The
proxy's input trace (`fastrdp_proxy_input_trace`) shows which event class arrived.

**Self-test before the round:** with Notepad open, run each mode with
`-Process notepad -Text "aZ1ä"` and `-Keys Shift+Tab,Enter`. Notepad must show the same
text for all three modes. The RDP client's event log (for A5):
`Get-WinEvent -ListLog *RDPClient*`, then `Get-WinEvent -LogName '<that name>'
-MaxEvents 50`. Note whether this works without admin rights.

## 5. Watching the box

Use the VM console. If you RDP into the box yourself, Windows stops rendering the
session when your client is minimized, and locks the desktop when you disconnect
*(inferred)*:

- On your own client, set `HKCU\Software\Microsoft\Terminal Server Client` →
  `RemoteDesktop_SuppressWhenMinimized` (DWORD) = 2.
- Before leaving, hand the session back to the console instead of disconnecting: look up
  its id with `quser`, then `tscon <id> /dest:console` as admin.

That outer RDP session goes to the Windows box, not to fastrdp. Do not point it at the
fastrdp host. The orchestrator filters the proxy journal by
`front: client "<the box's name>"` anyway.

## 6. The second factor

The orchestrator computes the code for the waiting screen's code field
(`code_or_web`) with `tests/lab/totp.py` (RFC 6238, stdlib only; header for all options)
from the lab user's seed, and types it with `send-keys.ps1`:

```sh
code=$(tests/lab/totp.py --secret-file ~/lab-secrets/labuser1.totp \
       --state ~/lab-secrets/labuser1.step --min-left 8)
```

- The seed comes from a file, stdin or an environment variable, never from argv. Base32
  as Keycloak shows it, an `otpauth://` URI, or `--raw` for the key text of a realm
  export. Defaults: HmacSHA1, 6 digits, 30 s (Keycloak's); other policies via options or
  the URI.
- `--state` hands out each time step once per user: the lab realm refuses a reused code
  (`otpPolicyCodeReusable: false`), so a second login in the same step waits for the
  next one. `--min-left 8` waits when the code would expire while being typed.
  `--no-wait` exits 75 instead of waiting.
- Tests that are about the approval page (F-tests with QR or link) still approve there,
  e.g. with the CDP driver of `tests/keycloak/`; a code typed here covers W5 only.

## 7. Secrets

- The code typed by `send-keys.ps1` appears in the PowerShell tool's arguments, possibly
  in Windows-MCP's log, and on screenshots while the panel shows it. Use lab-only users
  and TOTP seeds, keep screenshots and MCP logs in the lab, and delete them after the
  round. Lab tests S1–S4 concern fastrdp's own logs and stay strict.
- The auth key and the TOTP seeds live in the orchestrator's vault. Rotate the auth key
  after the round, or remove the task: `windows-mcp uninstall`.
