# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (reads captures of lab connections; see decode.py and
# docs/a5-capture-2026-10-26.md). Standard library only.
"""Minimal pcap/pcapng reader and TCP stream reassembly (Ethernet, Linux cooked v1/v2, IPv4)."""

from __future__ import annotations

import collections
import struct

_PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def packets(path):
    """Yields (timestamp, linktype, frame) for every packet of a pcap or pcapng file."""
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    if magic in _PCAP_MAGIC:
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(e + "I", data[20:24])[0]
        off = 24
        while off + 16 <= len(data):
            ts, tf, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
            off += 16
            yield ts + tf / (1e9 if nano else 1e6), linktype, data[off:off + incl]
            off += incl
    elif magic == b"\x0a\x0d\x0d\x0a":
        off, ifaces, e = 0, [], "<"
        while off + 12 <= len(data):
            btype, blen = struct.unpack(e + "II", data[off:off + 8])
            if btype == 0x0A0D0D0A:  # section header: its byte order mark decides
                e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                btype, blen = struct.unpack(e + "II", data[off:off + 8])
            body = data[off + 8:off + blen - 4]
            if btype == 1:  # interface description: link type, timestamp resolution
                lt, res, o = struct.unpack(e + "H", body[:2])[0], 1e-6, 8
                while o + 4 <= len(body):
                    code, ln = struct.unpack(e + "HH", body[o:o + 4])
                    if code == 0:
                        break
                    if code == 9:
                        v = body[o + 4]
                        res = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                    o += 4 + ((ln + 3) & ~3)
                ifaces.append((lt, res))
            elif btype == 6:  # enhanced packet
                iid, th, tl, incl, _orig = struct.unpack(e + "IIIII", body[:20])
                lt, res = ifaces[iid]
                yield ((th << 32) | tl) * res, lt, body[20:20 + incl]
            if blen < 12:
                break
            off += blen
    else:
        raise ValueError(f"{path}: not a pcap or pcapng file")


def ip_payload(lt, frame):
    """The IPv4 packet in a frame, or None."""
    if lt == 113:  # Linux cooked (SLL)
        proto, p = struct.unpack(">H", frame[14:16])[0], frame[16:]
    elif lt == 276:  # SLL2
        proto, p = struct.unpack(">H", frame[0:2])[0], frame[20:]
    elif lt == 1:  # Ethernet
        proto, p = struct.unpack(">H", frame[12:14])[0], frame[14:]
    else:
        return None
    return p if proto == 0x0800 else None


def tcp_segments(path, port=3389):
    """TCP segments to or from `port`, with the client endpoint they belong to."""
    for ts, lt, fr in packets(path):
        ip = ip_payload(lt, fr)
        if not ip or ip[9] != 6:
            continue
        ihl, tot = (ip[0] & 15) * 4, struct.unpack(">H", ip[2:4])[0]
        src, dst = ip[12:16], ip[16:20]
        t = ip[ihl:tot]
        sp, dp, seq, ack, offf, flags, win = struct.unpack(">HHIIBBH", t[:16])
        if port not in (sp, dp):
            continue
        cli = (bytes(src), sp) if dp == port else (bytes(dst), dp)
        yield dict(ts=ts, c2s=(dp == port), cli=cli, seq=seq, ack=ack, flags=flags, win=win,
                   payload=t[(offf >> 4) * 4:])


def fmt_addr(a):
    return ".".join(map(str, a[0])) + ":" + str(a[1])


def streams(path, port=3389):
    """Segments per client endpoint (address, port), in capture order."""
    conns = collections.OrderedDict()
    for s in tcp_segments(path, port):
        conns.setdefault(s["cli"], []).append(s)
    return conns


def reassemble(segs, c2s):
    """One direction of a connection as [(timestamp, bytes)] in sequence order, without
    retransmitted bytes."""
    out, nxt, pending = [], None, {}
    for s in segs:
        if s["c2s"] != c2s:
            continue
        if s["flags"] & 0x02:  # SYN
            nxt = (s["seq"] + 1) & 0xFFFFFFFF
            continue
        if nxt is None:
            nxt = s["seq"]
        if not s["payload"]:
            continue
        pending[s["seq"]] = (s["ts"], s["payload"])
        while True:
            hit = None
            for seq, (_ts, p) in list(pending.items()):
                if seq == nxt or ((nxt - seq) & 0xFFFFFFFF) < len(p):
                    hit = seq
                    break
                if ((seq - nxt) & 0xFFFFFFFF) > 0x7FFFFFFF:  # entirely old
                    del pending[seq]
            if hit is None:
                break
            ts, p = pending.pop(hit)
            cut = (nxt - hit) & 0xFFFFFFFF
            if cut < len(p):
                out.append((ts, p[cut:]))
                nxt = (nxt + len(p) - cut) & 0xFFFFFFFF
    return out
