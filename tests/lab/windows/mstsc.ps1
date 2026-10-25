# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (Windows client of the lab; docs/lab-windows-mcp.md). Drives and observes mstsc
# for the orchestrator (tests/lab/a5_f19.py) without pixel clicks: window lists and buttons
# through UI Automation, the X as WM_CLOSE, the session window's content as colour
# fractions. Windows PowerShell 5.1 or pwsh 7, in the user's interactive session.
#
#   mstsc.ps1 -Action start -RdpFile F      mstsc /edit F: the connection dialog with F
#   mstsc.ps1 -Action stop                  end every mstsc process
#   mstsc.ps1 -Action windows               visible windows of mstsc: class, title; for
#                                           dialogs (#32770) also texts and buttons
#   mstsc.ps1 -Action invoke -Button RE     press the first enabled dialog button whose
#                                           name matches RE (or "id:<AutomationId>")
#   mstsc.ps1 -Action close                 WM_CLOSE to the session window (the X)
#   mstsc.ps1 -Action watch [-Button RE] [-Timeout S] [-Until panel|desktop|gone] [-Save F]
#        with -Button, press it first (Connect); then sample the session window every
#        100 ms and report when it appeared and each change of its state:
#          none     no session window (TscShellContainerClass)
#          black    >= 95 % of the samples black: the symptom of backlog A5
#          panel    the waiting screen: its screen colour 0x1e1f24 around a white card
#          other    anything else (a desktop, mstsc's own drawing)
#        until the state given by -Until (default panel) or the timeout; -Save writes a
#        PNG of the session window at the end (it may show the panel's code field)
#   mstsc.ps1 -Action events -Since ISO     the RDP client's event log (Operational)
# -ProcessId limits everything to one mstsc process (default: all of them).
# Output: one line "@@JSON {...}"; exit 0, 1 bad arguments, 2 window or button not found.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'windows', 'invoke', 'close', 'watch', 'events')]
    [string]$Action,
    [string]$RdpFile,
    [int]$ProcessId = 0,
    [string]$Button,
    [double]$Timeout = 20,
    [ValidateSet('panel', 'desktop', 'gone')]
    [string]$Until = 'panel',
    [string]$Save,
    [string]$Since
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class FastrdpLabWin {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
    public static string ClassOf(IntPtr h) { var s = new StringBuilder(256); GetClassName(h, s, 256); return s.ToString(); }
    public static string TitleOf(IntPtr h) { var s = new StringBuilder(512); GetWindowText(h, s, 512); return s.ToString(); }
    public static List<IntPtr> Top() {
        var l = new List<IntPtr>();
        EnumWindows(delegate (IntPtr h, IntPtr p) { l.Add(h); return true; }, IntPtr.Zero);
        return l;
    }
    // Fractions of sampled pixels: black (all channels < 16), white (all > 240), and the
    // waiting screen's colour 0x1e1f24 (each channel within 6).
    public static double[] Sample(byte[] px, int stride, int w, int h) {
        int n = 0, black = 0, white = 0, screen = 0;
        int sx = Math.Max(1, w / 96), sy = Math.Max(1, h / 64);
        for (int y = sy / 2; y < h; y += sy)
            for (int x = sx / 2; x < w; x += sx) {
                int i = y * stride + x * 4; int b = px[i], g = px[i + 1], r = px[i + 2]; n++;
                if (r < 16 && g < 16 && b < 16) black++;
                else if (r > 240 && g > 240 && b > 240) white++;
                else if (Math.Abs(r - 0x1e) <= 6 && Math.Abs(g - 0x1f) <= 6 && Math.Abs(b - 0x24) <= 6) screen++;
            }
        if (n == 0) return new double[] { 0, 0, 0 };
        return new double[] { (double)black / n, (double)white / n, (double)screen / n };
    }
}
'@

$WM_CLOSE = 0x0010
$SessionClass = 'TscShellContainerClass'

function Emit($obj) { '@@JSON ' + (ConvertTo-Json -InputObject $obj -Compress -Depth 8); }
function Fail([int]$code, [string]$msg) { Emit @{ ok = $false; error = $msg }; exit $code }

function Mstsc-Pids {
    if ($ProcessId -gt 0) { return @($ProcessId) }
    @(Get-Process -Name mstsc -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
}

function Mstsc-Windows([bool]$details) {
    $pids = Mstsc-Pids
    $out = @()
    foreach ($h in [FastrdpLabWin]::Top()) {
        if (-not [FastrdpLabWin]::IsWindowVisible($h)) { continue }
        $wpid = 0
        [void][FastrdpLabWin]::GetWindowThreadProcessId($h, [ref]$wpid)
        if ($pids -notcontains [int]$wpid) { continue }
        $w = [ordered]@{ pid = [int]$wpid; hwnd = $h.ToInt64(); class = [FastrdpLabWin]::ClassOf($h)
            title = [FastrdpLabWin]::TitleOf($h); iconic = [FastrdpLabWin]::IsIconic($h)
            foreground = ([FastrdpLabWin]::GetForegroundWindow() -eq $h) }
        if ($details -and $w.class -eq '#32770') {
            $texts = @(); $buttons = @()
            $el = [System.Windows.Automation.AutomationElement]::FromHandle($h)
            $all = $el.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                [System.Windows.Automation.Condition]::TrueCondition)
            foreach ($e in $all) {
                $ct = $e.Current.ControlType.ProgrammaticName
                if ($ct -eq 'ControlType.Button') {
                    $buttons += [ordered]@{ name = $e.Current.Name; id = $e.Current.AutomationId; enabled = $e.Current.IsEnabled }
                } elseif ($ct -eq 'ControlType.Text' -and $e.Current.Name) {
                    $texts += $e.Current.Name
                }
            }
            $w.texts = $texts; $w.buttons = $buttons
        }
        $out += $w
    }
    , $out
}

function Session-Window {
    foreach ($w in (Mstsc-Windows $false)) { if ($w.class -eq $SessionClass) { return $w } }
    $null
}

function Invoke-Button([string]$re) {
    $pids = Mstsc-Pids
    foreach ($h in [FastrdpLabWin]::Top()) {
        if (-not [FastrdpLabWin]::IsWindowVisible($h) -or [FastrdpLabWin]::ClassOf($h) -ne '#32770') { continue }
        $wpid = 0
        [void][FastrdpLabWin]::GetWindowThreadProcessId($h, [ref]$wpid)
        if ($pids -notcontains [int]$wpid) { continue }
        $el = [System.Windows.Automation.AutomationElement]::FromHandle($h)
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button)
        foreach ($b in $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)) {
            $hit = if ($re -like 'id:*') { $b.Current.AutomationId -eq $re.Substring(3) } else { $b.Current.Name -match $re }
            if (-not $hit -or -not $b.Current.IsEnabled) { continue }
            $b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            return [ordered]@{ pid = [int]$wpid; dialog = [FastrdpLabWin]::TitleOf($h); button = $b.Current.Name; id = $b.Current.AutomationId }
        }
    }
    $null
}

function Capture($w) {
    $r = New-Object FastrdpLabWin+RECT
    [void][FastrdpLabWin]::GetClientRect([IntPtr]$w.hwnd, [ref]$r)
    $p = New-Object FastrdpLabWin+POINT
    [void][FastrdpLabWin]::ClientToScreen([IntPtr]$w.hwnd, [ref]$p)
    $width = $r.Right - $r.Left; $height = $r.Bottom - $r.Top
    if ($width -le 0 -or $height -le 0) { return $null }
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($p.X, $p.Y, 0, 0, $bmp.Size)
    $g.Dispose()
    @{ bitmap = $bmp; rect = @($p.X, $p.Y, $p.X + $width, $p.Y + $height) }
}

function Sample-Bitmap($bmp) {
    $rect = New-Object System.Drawing.Rectangle(0, 0, $bmp.Width, $bmp.Height)
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $bytes = New-Object byte[] ($data.Stride * $bmp.Height)
        [Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
        [FastrdpLabWin]::Sample($bytes, $data.Stride, $bmp.Width, $bmp.Height)
    } finally { $bmp.UnlockBits($data) }
}

function State-Of($f) {
    if ($f[0] -ge 0.95) { return 'black' }
    if ($f[2] -ge 0.20 -and $f[1] -ge 0.03) { return 'panel' }
    'other'
}

switch ($Action) {
    'start' {
        if (-not $RdpFile) { Fail 1 '-RdpFile needed' }
        if (-not (Test-Path -LiteralPath $RdpFile)) { Fail 1 "no file $RdpFile" }
        $p = Start-Process -FilePath mstsc.exe -ArgumentList @('/edit', "`"$RdpFile`"") -PassThru
        $ProcessId = $p.Id
        $deadline = (Get-Date).AddSeconds($Timeout)
        do {
            Start-Sleep -Milliseconds 200
            $ws = Mstsc-Windows $true
        } until (@($ws | Where-Object { $_.class -eq '#32770' }).Count -gt 0 -or (Get-Date) -gt $deadline)
        if (@($ws | Where-Object { $_.class -eq '#32770' }).Count -eq 0) { Fail 2 "mstsc $ProcessId shows no dialog" }
        Emit @{ ok = $true; pid = $ProcessId; windows = $ws }
    }
    'stop' {
        $ps = @(Get-Process -Name mstsc -ErrorAction SilentlyContinue)
        $ps | Stop-Process -Force
        Emit @{ ok = $true; stopped = $ps.Count }
    }
    'windows' { Emit @{ ok = $true; windows = (Mstsc-Windows $true) } }
    'invoke' {
        if (-not $Button) { Fail 1 '-Button needed' }
        $hit = Invoke-Button $Button
        if (-not $hit) { Fail 2 "no enabled button /$Button/ in an mstsc dialog" }
        Emit @{ ok = $true; invoked = $hit }
    }
    'close' {
        $w = Session-Window
        if (-not $w) { Fail 2 'no session window' }
        [void][FastrdpLabWin]::PostMessage([IntPtr]$w.hwnd, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
        Emit @{ ok = $true; closed = $w }
    }
    'watch' {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $invoked = $null
        if ($Button) {
            $invoked = Invoke-Button $Button
            if (-not $invoked) { Fail 2 "no enabled button /$Button/ in an mstsc dialog" }
        }
        $states = @(); $state = ''; $windowMs = $null; $last = $null; $w = $null; $samples = 0
        $want = @{ panel = 'panel'; desktop = 'other'; gone = 'none' }[$Until]
        while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
            $w = Session-Window
            $now = 'none'
            if ($w) {
                if ($null -eq $windowMs) { $windowMs = [int]$sw.ElapsedMilliseconds }
                $cap = Capture $w
                if ($cap) {
                    $last = Sample-Bitmap $cap.bitmap; $samples++
                    $cap.bitmap.Dispose()
                    $now = State-Of $last
                }
            }
            if ($now -ne $state) { $states += , @($now, [int]$sw.ElapsedMilliseconds); $state = $now }
            if ($now -eq $want) { break }
            Start-Sleep -Milliseconds 100
        }
        $saved = $null
        if ($Save -and $w) {
            $cap = Capture $w
            if ($cap) { $cap.bitmap.Save($Save, [System.Drawing.Imaging.ImageFormat]::Png); $cap.bitmap.Dispose(); $saved = $Save }
        }
        Emit ([ordered]@{ ok = $true; invoked = $invoked; reached = ($state -eq $want); state = $state
            window_ms = $windowMs; states = $states; samples = $samples
            fractions = $(if ($last) { [ordered]@{ black = $last[0]; white = $last[1]; screen = $last[2] } } else { $null })
            rect = $(if ($w) { $c = Capture $w; if ($c) { $c.bitmap.Dispose(); $c.rect } }); saved = $saved
            windows = (Mstsc-Windows $true) })
    }
    'events' {
        $log = Get-WinEvent -ListLog '*RDPClient/Operational' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $log) { Fail 2 'no RDPClient Operational log' }
        $start = if ($Since) { [datetime]::Parse($Since, $null, [Globalization.DateTimeStyles]::RoundtripKind) } else { (Get-Date).AddHours(-1) }
        $ev = @()
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $log.LogName; StartTime = $start } |
                Sort-Object TimeCreated | ForEach-Object {
                    [ordered]@{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id
                        level = $_.LevelDisplayName; message = $_.Message } })
        } catch [Exception] {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Fail 2 "Get-WinEvent: $($_.Exception.Message)" }
        }
        Emit @{ ok = $true; log = $log.LogName; events = $ev }
    }
}
exit 0
