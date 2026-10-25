# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (Windows client of the lab; docs/lab-windows-mcp.md). Types into a window with
# SendInput in ONE explicit event type, so a test decides what mstsc forwards to fastrdp:
#   -Mode Scancode    KEYEVENTF_SCANCODE (+ EXTENDEDKEY), wVk 0: mstsc sends RDP scancode
#                     events (TS_KEYBOARD_EVENT)
#   -Mode VirtualKey  wVk only, wScan 0: what mstsc makes of a key without a scancode is
#                     the point of the test (inferred: it maps the VK itself)
#   -Mode Unicode     KEYEVENTF_UNICODE (VK_PACKET): mstsc sends RDP Unicode events
#                     (TS_UNICODE_KEYBOARD_EVENT)
# Windows-MCP's Type tool mixes Unicode events with VK shortcuts and pastes text of 20 or
# more characters through the clipboard, which mstsc would redirect: never use it for
# input under test.
#
# Usage (Windows PowerShell 5.1 or pwsh 7, in the user's interactive session, e.g. from
# Windows-MCP's PowerShell tool; not over ssh, which has no input desktop):
#   send-keys.ps1 -Mode Scancode   -Text 123456 [-Process mstsc]
#   send-keys.ps1 -Mode Unicode    -Text 123456
#   send-keys.ps1 -Mode VirtualKey -Keys Num1,Num2,NumEnter
#   send-keys.ps1 -Mode Scancode   -Keys Down,Down,Enter
#   send-keys.ps1 -Mode Scancode   -Keys Shift+Tab,sc:0x1C,sc:0xE01C,vk:0x0D
#   send-keys.ps1 -List            print the named keys
# -Text   characters; Scancode and VirtualKey map them through the TARGET window's
#         keyboard layout (VkKeyScanEx, MapVirtualKeyEx) and press Shift/Ctrl/Alt as the
#         layout needs (AltGr as LCtrl+LAlt); a character the layout cannot type fails.
#         Unicode sends each UTF-16 unit as is.
# -Keys   named keys (see -List), combinations with + (Ctrl+Alt+End), or raw tokens:
#         sc:0x1C, sc:0xE01C (E0 prefix = extended), vk:0x0D. Named keys and
#         combinations use -Mode (not Unicode); raw tokens keep their own type.
# -Process / -Title   the target: the main window of the newest process with that name
#         (default mstsc), or the first visible window whose title matches the regex.
#         It is brought to the foreground and checked before any key is sent.
# -DelayMs (between keys, default 40) / -HoldMs (down to up, default 15).
# Output: one summary line WITHOUT the characters (codes typed here must not reach the
# MCP's logs, lab S1-S4); -Trace adds one line per event, which reveals them.
# Exit status: 0 sent, 1 bad arguments or untypable character, 2 no target window,
# 3 SendInput refused (locked desktop, UIPI against an elevated window).

[CmdletBinding(DefaultParameterSetName = 'Text')]
param(
    [Parameter(ParameterSetName = 'Text', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Keys', Mandatory = $true)]
    [ValidateSet('Scancode', 'VirtualKey', 'Unicode')]
    [string]$Mode,
    [Parameter(ParameterSetName = 'Text', Mandatory = $true)]
    [string]$Text,
    [Parameter(ParameterSetName = 'Keys', Mandatory = $true)]
    [string[]]$Keys,
    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'Keys')]
    [string]$Process = 'mstsc',
    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'Keys')]
    [string]$Title,
    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'Keys')]
    [int]$DelayMs = 40,
    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'Keys')]
    [int]$HoldMs = 15,
    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'Keys')]
    [switch]$Trace,
    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [switch]$List
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# Named keys: scancode (0xE0xx = extended) and virtual key. Keypad digits give digits only
# with NumLock on (scancode mode: on the server's NumLock state).
$NamedKeys = [ordered]@{
    'Enter' = @(0x1C, 0x0D); 'NumEnter' = @(0xE01C, 0x0D); 'Esc' = @(0x01, 0x1B)
    'Backspace' = @(0x0E, 0x08); 'Tab' = @(0x0F, 0x09); 'Space' = @(0x39, 0x20)
    'Up' = @(0xE048, 0x26); 'Down' = @(0xE050, 0x28); 'Left' = @(0xE04B, 0x25)
    'Right' = @(0xE04D, 0x27); 'Home' = @(0xE047, 0x24); 'End' = @(0xE04F, 0x23)
    'PageUp' = @(0xE049, 0x21); 'PageDown' = @(0xE051, 0x22); 'Insert' = @(0xE052, 0x2D)
    'Delete' = @(0xE053, 0x2E); 'NumLock' = @(0xE045, 0x90)
    'Num0' = @(0x52, 0x60); 'Num1' = @(0x4F, 0x61); 'Num2' = @(0x50, 0x62)
    'Num3' = @(0x51, 0x63); 'Num4' = @(0x4B, 0x64); 'Num5' = @(0x4C, 0x65)
    'Num6' = @(0x4D, 0x66); 'Num7' = @(0x47, 0x67); 'Num8' = @(0x48, 0x68)
    'Num9' = @(0x49, 0x69); 'NumDecimal' = @(0x53, 0x6E)
    'Shift' = @(0x2A, 0xA0); 'RShift' = @(0x36, 0xA1); 'Ctrl' = @(0x1D, 0xA2)
    'RCtrl' = @(0xE01D, 0xA3); 'Alt' = @(0x38, 0xA4); 'AltGr' = @(0xE038, 0xA5)
    'Win' = @(0xE05B, 0x5B)
}
for ($i = 1; $i -le 12; $i++) {
    $sc = if ($i -le 10) { 0x3A + $i } else { 0x57 + $i - 11 }
    $NamedKeys["F$i"] = @($sc, 0x6F + $i)
}

if ($List) {
    foreach ($k in $NamedKeys.Keys) {
        '{0,-11} sc 0x{1:X4}  vk 0x{2:X2}' -f $k, $NamedKeys[$k][0], $NamedKeys[$k][1]
    }
    exit 0
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FastrdpLabInput {
    [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT {
        public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
        public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)] public struct InputUnion {
        [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public InputUnion u; }
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern IntPtr GetKeyboardLayout(uint thread);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern short VkKeyScanEx(char c, IntPtr hkl);
    [DllImport("user32.dll")] public static extern uint MapVirtualKeyEx(uint code, uint mapType, IntPtr hkl);
    public static INPUT Key(ushort vk, ushort scan, uint flags) {
        INPUT i = new INPUT(); i.type = 1; i.u.ki.wVk = vk; i.u.ki.wScan = scan; i.u.ki.dwFlags = flags; return i; }
    public static uint Send(INPUT i) { return SendInput(1, new INPUT[] { i }, Marshal.SizeOf(typeof(INPUT))); }
}
'@

$KEYEVENTF_EXTENDEDKEY = 0x1; $KEYEVENTF_KEYUP = 0x2; $KEYEVENTF_UNICODE = 0x4
$KEYEVENTF_SCANCODE = 0x8; $MAPVK_VK_TO_VSC_EX = 4
# Virtual keys that are extended keys on a PC keyboard: PageUp..Down, Insert, Delete,
# LWin, NumLock, RCtrl, AltGr
$ExtendedVks = @(0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x90, 0xA3, 0xA5)

function Fail([int]$code, [string]$msg) { Write-Error -ErrorAction Continue "send-keys: $msg"; exit $code }

# --- target window ---------------------------------------------------------------------
$hwnd = [IntPtr]::Zero
if ($Title) {
    $p = Get-Process | Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero -and $_.MainWindowTitle -match $Title } |
        Select-Object -First 1
} else {
    $p = Get-Process -Name $Process -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero } | Sort-Object StartTime -Descending |
        Select-Object -First 1
}
if ($p) { $hwnd = $p.MainWindowHandle }
if ($hwnd -eq [IntPtr]::Zero) { Fail 2 "no window for $(if ($Title) { "title /$Title/" } else { "process $Process" })" }
if ([FastrdpLabInput]::GetForegroundWindow() -eq [IntPtr]::Zero) {
    Fail 3 'no foreground window: desktop locked or no input desktop (ssh session?)'
}

if ([FastrdpLabInput]::IsIconic($hwnd)) { [void][FastrdpLabInput]::ShowWindow($hwnd, 9) }  # SW_RESTORE
if (-not [FastrdpLabInput]::SetForegroundWindow($hwnd)) {
    # The foreground lock refuses processes that did not get the last input: borrow the
    # foreground thread's input state for the switch.
    $fgPid = 0
    $fgThread = [FastrdpLabInput]::GetWindowThreadProcessId([FastrdpLabInput]::GetForegroundWindow(), [ref]$fgPid)
    $me = [FastrdpLabInput]::GetCurrentThreadId()
    [void][FastrdpLabInput]::AttachThreadInput($me, $fgThread, $true)
    [void][FastrdpLabInput]::BringWindowToTop($hwnd)
    [void][FastrdpLabInput]::SetForegroundWindow($hwnd)
    [void][FastrdpLabInput]::AttachThreadInput($me, $fgThread, $false)
}
Start-Sleep -Milliseconds 150
if ([FastrdpLabInput]::GetForegroundWindow() -ne $hwnd) { Fail 2 "could not bring $($p.ProcessName) ($($p.Id)) to the foreground" }

$targetPid = 0
$hkl = [FastrdpLabInput]::GetKeyboardLayout([FastrdpLabInput]::GetWindowThreadProcessId($hwnd, [ref]$targetPid))

# --- events ------------------------------------------------------------------------------
# A stroke is @{ Type = 'sc'|'vk'|'uni'; Code = int }; a chord is a list of strokes
# pressed in order and released in reverse.
function Stroke-Named([string]$name) {
    $k = $NamedKeys.Keys | Where-Object { $_ -ieq $name } | Select-Object -First 1
    if (-not $k) { Fail 1 "unknown key '$name' (send-keys.ps1 -List)" }
    if ($Mode -eq 'Unicode') { Fail 1 "named key '$name' in Unicode mode: use -Mode Scancode/VirtualKey or a raw sc:/vk: token" }
    if ($Mode -eq 'Scancode') { @{ Type = 'sc'; Code = $NamedKeys[$k][0] } } else { @{ Type = 'vk'; Code = $NamedKeys[$k][1] } }
}
function Stroke-Token([string]$tok) {
    if ($tok -match '^(sc|vk):(0x[0-9a-fA-F]+|\d+)$') {
        $code = [Convert]::ToInt32($Matches[2], $(if ($Matches[2] -like '0x*') { 16 } else { 10 }))
        return @{ Type = $Matches[1]; Code = $code }
    }
    Stroke-Named $tok
}
function Chord-Char([char]$c) {
    if ($Mode -eq 'Unicode') { return , @(@{ Type = 'uni'; Code = [int]$c }) }
    $r = [FastrdpLabInput]::VkKeyScanEx($c, $hkl)
    if ($r -eq -1) { Fail 1 ('character U+{0:X4} cannot be typed on the target layout' -f [int]$c) }
    $vk = $r -band 0xFF; $shift = ($r -shr 8) -band 0xFF
    $mods = @()
    if ($shift -band 2) { $mods += 'Ctrl' }
    if ($shift -band 4) { $mods += 'Alt' }
    if ($shift -band 1) { $mods += 'Shift' }
    $chord = @($mods | ForEach-Object { Stroke-Named $_ })
    if ($Mode -eq 'Scancode') {
        $sc = [FastrdpLabInput]::MapVirtualKeyEx($vk, $MAPVK_VK_TO_VSC_EX, $hkl)
        if ($sc -eq 0) { Fail 1 ('no scancode for VK 0x{0:X2} on the target layout' -f $vk) }
        $chord += @{ Type = 'sc'; Code = [int]$sc }
    } else {
        $chord += @{ Type = 'vk'; Code = $vk }
    }
    , $chord
}

function Send-Stroke($s, [bool]$up) {
    $flags = if ($up) { $KEYEVENTF_KEYUP } else { 0 }
    switch ($s.Type) {
        'sc' {
            $flags = $flags -bor $KEYEVENTF_SCANCODE
            if (($s.Code -band 0xFF00) -eq 0xE000) { $flags = $flags -bor $KEYEVENTF_EXTENDEDKEY }
            $ev = [FastrdpLabInput]::Key(0, [uint16]($s.Code -band 0xFF), [uint32]$flags)
        }
        'vk' {
            # Keys that are extended on a PC keyboard carry the flag in VK mode too.
            if ($ExtendedVks -contains $s.Code) { $flags = $flags -bor $KEYEVENTF_EXTENDEDKEY }
            $ev = [FastrdpLabInput]::Key([uint16]$s.Code, 0, [uint32]$flags)
        }
        'uni' { $ev = [FastrdpLabInput]::Key(0, [uint16]$s.Code, [uint32]($flags -bor $KEYEVENTF_UNICODE)) }
    }
    if ([FastrdpLabInput]::Send($ev) -ne 1) {
        Fail 3 ('SendInput refused the event (error {0}): locked desktop or an elevated target window' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($Trace) { '{0,-4} {1,-3} 0x{2:X4} flags 0x{3:X}' -f $(if ($up) { 'up' } else { 'down' }), $s.Type, $s.Code, $flags }
}

$chords = @()
if ($PSCmdlet.ParameterSetName -eq 'Text') {
    foreach ($c in $Text.ToCharArray()) { $chords += , (Chord-Char $c) }
} else {
    foreach ($k in $Keys) { $chords += , @($k -split '\+' | ForEach-Object { Stroke-Token $_ }) }
}

$events = 0
foreach ($chord in $chords) {
    if ([FastrdpLabInput]::GetForegroundWindow() -ne $hwnd) { Fail 2 "the target lost the foreground after $events events" }
    foreach ($s in $chord) { Send-Stroke $s $false; $events++; Start-Sleep -Milliseconds $HoldMs }
    for ($i = $chord.Count - 1; $i -ge 0; $i--) { Send-Stroke $chord[$i] $true; $events++ }
    Start-Sleep -Milliseconds $DelayMs
}
'send-keys: {0} {1} as {2} ({3} events) to {4} ({5}), layout 0x{6:X8}' -f $chords.Count,
    $(if ($PSCmdlet.ParameterSetName -eq 'Text') { 'characters' } else { 'keys' }), $Mode, $events,
    $p.ProcessName, $p.Id, ($hkl.ToInt64() -band 0xFFFFFFFFL)
