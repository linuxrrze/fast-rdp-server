#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (reads mstsc's event log of lab connections; backlog A5,
# docs/lab-checklist-0.7.6.md §1). The same per-connection summary as
# tests/lab/windows/rdp-eventlog.ps1, from an exported .evtx on the analysis machine:
#
#   tests/lab/rdpcapture/evtx_summary.py RDPCLIENT.evtx [--utc] [--since "YYYY-MM-DD HH:MM"]
#
# The .evtx comes from tests/lab/windows/rdp-eventlog.ps1 (wevtutil epl of the channel
# Microsoft-Windows-TerminalServices-RDPClient/Operational, provider
# Microsoft-Windows-TerminalServices-ClientActiveXCore). Needs python-evtx
# (pip install python-evtx); without it the script says so and exits 3.
# One block per connection (the event's correlation ActivityID, in order of its first
# event), times in local time (--utc: UTC): 1024 the server name, 1025 connected, 1402/1401
# GFX started (Version, AvcEnabled), 1026 the disconnect reason, 226 state transitions with
# their error code; the other event ids counted. Never prints 1029 (a hash of the user
# name) or other trace payloads. --since (local time, or UTC with --utc) skips connections
# whose first event is older: the log keeps earlier runs unless it was cleared.
"""LAB ONLY: per-connection summary of mstsc's RDPClient/Operational event log (.evtx)."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import importlib.util
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# IMsTscAxEvents::OnDisconnected discReason values seen in practice (Microsoft's
# "Remote Desktop ActiveX control disconnect reasons"); others are printed as numbers
DISCONNECT = {1: "local disconnect", 2: "remote disconnect by user", 3: "remote disconnect by server",
              260: "DNS lookup failed", 264: "connection timed out", 516: "connection refused or unreachable",
              2308: "socket closed"}
SHOWN = {1024, 1025, 1026, 1401, 1402, 226}


def parse_xml(xml):
    """{time (aware UTC datetime), id, activity, pid, data} of one event's XML."""
    root = ET.fromstring(xml)
    sysn = root.find(f"{NS}System")
    eid = int(sysn.findtext(f"{NS}EventID"))
    t = sysn.find(f"{NS}TimeCreated").get("SystemTime")
    # python-evtx: "2026-10-26 19:57:22.281992+00:00"; Windows: "2026-10-26T19:57:22.2819920Z"
    t = t.replace("T", " ").replace("Z", "+00:00")
    if "." in t:
        head, rest = t.split(".", 1)
        frac = "".join(c for c in rest if c.isdigit())[:6]
        tz = rest[len("".join(c for c in rest if c.isdigit())):] or "+00:00"
        t = f"{head}.{frac}{tz}"
    when = dt.datetime.fromisoformat(t)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    corr = sysn.find(f"{NS}Correlation")
    ex = sysn.find(f"{NS}Execution")
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            data[d.get("Name")] = d.text or ""
    return {"time": when, "id": eid, "activity": (corr.get("ActivityID") if corr is not None else "") or "",
            "pid": ex.get("ProcessID") if ex is not None else "", "data": data}


def describe(ev):
    """One line for a shown event, None for one that is only counted."""
    d, eid = ev["data"], ev["id"]
    if eid == 1024:
        return f"1024 connecting to {d.get('Value', '?')}"
    if eid == 1025:
        return "1025 connected"
    if eid == 1402:
        return "1402 GFX channel opened"
    if eid == 1401:
        return f"1401 GFX started: Version={d.get('Version', '?')} AvcEnabled={d.get('AvcEnabled', '?')}"
    if eid == 1026:
        v = d.get("Value", "?")
        try:
            text = DISCONNECT.get(int(v))
        except ValueError:
            text = None
        return f"1026 disconnect reason {v}" + (f" ({text})" if text else "")
    if eid == 226:
        err = d.get("Error Code", "")
        try:
            err = f"{int(err):#010x}"
        except ValueError:
            pass
        return (f"226 {d.get('StateTransitionName', '?')}: {d.get('PreviousStateName', '?')} -> "
                f"{d.get('NewStateName', '?')} on {d.get('EventName', '?')}" + (f", error {err}" if err else ""))
    return None


def summarise(events, utc=False, since=None):
    """Lines: one block per connection (ActivityID), in order of its first event; with
    since (an aware datetime) only connections that started then or later."""
    groups = collections.OrderedDict()
    for ev in sorted(events, key=lambda e: e["time"]):
        groups.setdefault(ev["activity"], []).append(ev)
    if since is not None:
        groups = collections.OrderedDict((k, v) for k, v in groups.items() if v[0]["time"] >= since)

    def fmt(t):
        return (t if utc else t.astimezone()).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    lines = []
    for n, (act, evs) in enumerate(groups.items(), 1):
        server = next((e["data"].get("Value") for e in evs if e["id"] == 1024), None)
        gfx = [e for e in evs if e["id"] == 1401]
        head = f"===== connection {n}: {server or '(no 1024 event)'}, mstsc pid {evs[0]['pid'] or '?'}, "
        head += f"{fmt(evs[0]['time'])} to {fmt(evs[-1]['time'])[11:]}, "
        head += ("GFX " + ",".join(f"AvcEnabled={e['data'].get('AvcEnabled', '?')}" for e in gfx)) if gfx else "no GFX"
        lines.append(head + (f" [activity {act}]" if act else ""))
        other = collections.Counter()
        for e in evs:
            text = describe(e)
            if text is None:
                other[e["id"]] += 1
            else:
                lines.append(f"  {fmt(e['time'])[11:]} {text}")
        if other:
            lines.append("  other events: " + ", ".join(f"{k}x{v}" for k, v in sorted(other.items())))
    return lines


def load(path):
    """The events of an .evtx file (python-evtx)."""
    import Evtx.Evtx as evtx

    with evtx.Evtx(path) as log:
        return [parse_xml(r.xml()) for r in log.records()]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evtx", help="export of Microsoft-Windows-TerminalServices-RDPClient/Operational")
    ap.add_argument("--utc", action="store_true", help="times in UTC instead of local time")
    ap.add_argument("--since", help='only connections from then on, "YYYY-MM-DD HH:MM[:SS]"')
    a = ap.parse_args(argv)
    since = None
    if a.since:
        since = dt.datetime.fromisoformat(a.since)
        since = since.replace(tzinfo=dt.timezone.utc) if a.utc else since.astimezone()
    if importlib.util.find_spec("Evtx") is None:
        print("evtx_summary: needs python-evtx (pip install python-evtx)", file=sys.stderr)
        return 3
    for line in summarise(load(a.evtx), a.utc, since):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
