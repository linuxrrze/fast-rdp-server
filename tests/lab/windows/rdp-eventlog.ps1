# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (Windows client of the lab; backlog A5, docs/lab-checklist-0.7.6.md §1). Exports
# mstsc's event log and prints what it says per connection. NOT TESTED ON WINDOWS yet
# (written without a Windows host); the Python twin tests/lab/rdpcapture/evtx_summary.py
# prints the same summary from the exported file and is tested against real exports.
# Windows PowerShell 5.1 or pwsh 7.
#
#   rdp-eventlog.ps1 [-Out F.evtx] [-Clear]   export the live log to F.evtx (default
#        .\rdpclient-<yyyyMMdd-HHmmss>.evtx, wevtutil epl), print the summary of the
#        export; -Clear then empties the live log (wevtutil cl; needs an elevated
#        PowerShell), so the next run starts clean
#   rdp-eventlog.ps1 -Path F.evtx             only the summary of an earlier export
#   -Since "yyyy-MM-dd HH:mm"                 only connections that started then or later
#
# The log: channel Microsoft-Windows-TerminalServices-RDPClient/Operational (Event Viewer:
# Applications and Services Logs > Microsoft > Windows > TerminalServices-ClientActiveXCore
# > Microsoft-Windows-TerminalServices-RDPClient/Operational; provider
# Microsoft-Windows-TerminalServices-ClientActiveXCore).
# Summary: one block per connection (the events' correlation ActivityId), local time:
# 1024 the server name, 1025 connected, 1402/1401 GFX started (Version, AvcEnabled), 1026
# the disconnect reason, 226 state transitions with their error code; other ids counted.
# Event 1029 (a hash of the user name) is never printed. Exit 0, 1 bad arguments or no
# log, 2 wevtutil failed.

param(
    [string]$Out,
    [switch]$Clear,
    [string]$Path,
    [string]$Since
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Channel = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
$Reasons = @{ 1 = 'local disconnect'; 2 = 'remote disconnect by user'; 3 = 'remote disconnect by server'
    260 = 'DNS lookup failed'; 264 = 'connection timed out'; 516 = 'connection refused or unreachable'
    2308 = 'socket closed' }

function Fail([int]$code, [string]$msg) { Write-Error -ErrorAction Continue "rdp-eventlog: $msg"; exit $code }

# {Name: value} of an event's EventData
function Get-EventData($e) {
    $d = @{}
    foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
    return $d
}

function Format-Event($e, $d) {
    switch ($e.Id) {
        1024 { return "1024 connecting to $($d['Value'])" }
        1025 { return '1025 connected' }
        1402 { return '1402 GFX channel opened' }
        1401 { return "1401 GFX started: Version=$($d['Version']) AvcEnabled=$($d['AvcEnabled'])" }
        1026 {
            $v = $d['Value']; $t = ''
            if ($v -match '^\d+$' -and $Reasons.ContainsKey([int]$v)) { $t = " ($($Reasons[[int]$v]))" }
            return "1026 disconnect reason $v$t"
        }
        226 {
            $err = $d['Error Code']
            if ($err -match '^\d+$') { $err = '0x{0:x8}' -f [uint32][uint64]$err }
            $s = "226 $($d['StateTransitionName']): $($d['PreviousStateName']) -> $($d['NewStateName']) on $($d['EventName'])"
            if ($err) { $s += ", error $err" }
            return $s
        }
    }
    return $null
}

if ($Path -and ($Out -or $Clear)) { Fail 1 '-Path summarises an export; -Out and -Clear work on the live log' }
if (-not $Path) {
    if (-not (Get-WinEvent -ListLog $Channel -ErrorAction SilentlyContinue)) { Fail 1 "no log $Channel" }
    if (-not $Out) { $Out = Join-Path (Get-Location) ('rdpclient-{0}.evtx' -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    if (Test-Path $Out) { Fail 1 "$Out exists" }
    & wevtutil.exe epl $Channel $Out
    if ($LASTEXITCODE -ne 0) { Fail 2 "wevtutil epl failed ($LASTEXITCODE)" }
    Write-Output "exported $Channel to $Out"
    $Path = $Out
}
$start = if ($Since) { [datetime]::ParseExact($Since, @('yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss'), $null, 'AssumeLocal') } else { [datetime]::MinValue }

$events = @()
try { $events = @(Get-WinEvent -Path $Path -Oldest) }
catch [Exception] {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Fail 2 "Get-WinEvent: $($_.Exception.Message)" }
}
$groups = [ordered]@{}
foreach ($e in ($events | Sort-Object TimeCreated)) {
    $key = if ($e.ActivityId) { $e.ActivityId.ToString() } else { '' }
    if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
    [void]$groups[$key].Add($e)
}
$n = 0
foreach ($key in $groups.Keys) {
    $evs = $groups[$key]
    if ($evs[0].TimeCreated -lt $start) { continue }
    $n++
    $server = '(no 1024 event)'; $gfx = @()
    foreach ($e in $evs) {
        if ($e.Id -eq 1024) { $server = (Get-EventData $e)['Value'] }
        if ($e.Id -eq 1401) { $gfx += 'AvcEnabled=' + (Get-EventData $e)['AvcEnabled'] }
    }
    $g = if ($gfx.Count) { 'GFX ' + ($gfx -join ',') } else { 'no GFX' }
    $from = $evs[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff')
    $to = $evs[$evs.Count - 1].TimeCreated.ToString('HH:mm:ss.fff')
    Write-Output "===== connection ${n}: $server, mstsc pid $($evs[0].ProcessId), $from to $to, $g [activity {$key}]"
    $other = @{}
    foreach ($e in $evs) {
        $text = Format-Event $e (Get-EventData $e)
        if ($null -eq $text) { $other[$e.Id] = 1 + [int]$other[$e.Id] }
        else { Write-Output ('  {0} {1}' -f $e.TimeCreated.ToString('HH:mm:ss.fff'), $text) }
    }
    if ($other.Count) {
        Write-Output ('  other events: ' + (($other.Keys | Sort-Object | ForEach-Object { "${_}x$($other[$_])" }) -join ', '))
    }
}
if ($Clear) {
    & wevtutil.exe cl $Channel
    if ($LASTEXITCODE -ne 0) { Fail 2 "wevtutil cl failed ($LASTEXITCODE; elevated PowerShell needed)" }
    Write-Output "cleared $Channel (the export keeps the old events)"
}
exit 0
