#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY (decrypts captures of lab connections with the proxy's TLS key log; the key
# log decrypts everything, the code typed into the waiting screen and TLS passwords
# included: lab users only, never keep it with the capture longer than needed).
# Backlog A5 (docs/a5-capture-2026-10-26.md): what mstsc and the proxy said to each other,
# PDU by PDU, per connection.
#
#   tests/lab/rdpcapture/decode.py CAPTURE.pcap KEYLOG.txt [--port 3389]
#
# CAPTURE: tcpdump -w of the client side (pcap or pcapng; Ethernet or Linux cooked, IPv4);
# KEYLOG: /var/cache/fastrdp-proxy/tls-keylog.txt (proxy.ini [FastRDP] TlsKeyLogFile).
# Prints one timeline per TCP connection (seconds since its first packet), runs of the
# same PDU collapsed into one line ("x4 (until 0.244)"). Only PDU names, sizes and protocol
# fields (Set Error Info code, Control action, DVC names, input event classes); never key
# material or payload bytes. TLS 1.3 only (what freerdp-proxy negotiates with OpenSSL 3);
# connections without secrets in the key log are listed as such. Needs python3-cryptography.
"""LAB ONLY: per-connection RDP timeline from a capture and the proxy's TLS key log."""

from __future__ import annotations

import argparse
import bisect
import collections
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap import fmt_addr, reassemble, streams  # noqa: E402
from tls13 import Dir, load_keylog, records  # noqa: E402

PDU2 = {0x02: "Update", 0x14: "Control", 0x1B: "Input", 0x1F: "Synchronize", 0x21: "RefreshRect",
        0x22: "PlaySound", 0x23: "SuppressOutput", 0x24: "ShutdownRequest", 0x25: "ShutdownDenied",
        0x26: "SaveSessionInfo", 0x27: "FontList", 0x28: "FontMap", 0x29: "SetKbdIndicators",
        0x2B: "PersistentKeyList", 0x2C: "BitmapCacheError", 0x2D: "SetKbdImeStatus",
        0x2E: "OffscrCacheError", 0x2F: "SetErrorInfo", 0x30: "DrawNineGridError",
        0x31: "DrawGdiPlusError", 0x32: "ArcStatus", 0x36: "StatusInfo", 0x37: "MonitorLayout",
        0x38: "FrameAck"}
FPOUT = {0: "orders", 1: "bitmap", 2: "palette", 3: "sync", 4: "surfcmds", 5: "ptr-hidden",
         6: "ptr-default", 8: "ptr-pos", 9: "ptr-color", 10: "ptr-cached", 11: "ptr-new",
         12: "ptr-large"}
# fast-path input events ([MS-RDPBCGR] 2.2.8.1.2.2): name, bytes after the event header
FPIN = {0: ("scancode", 1), 1: ("mouse", 6), 2: ("mousex", 6), 3: ("sync", 0), 4: ("unicode", 2),
        5: ("relmouse", 6), 6: ("qoe", 4)}
DVC = {1: "Create", 2: "DataFirst", 3: "Data", 4: "Close", 5: "Caps", 6: "DataFirstComp",
       7: "DataComp", 8: "SoftSync"}
CONTROL = {1: "RequestControl", 2: "Granted", 3: "Detach", 4: "Cooperate"}


def joined(chunks):
    """The chunks as one buffer, and a function from an offset to its packet's timestamp."""
    buf = b"".join(c for _, c in chunks)
    offs, o = [], 0
    for _ts, c in chunks:
        offs.append(o)
        o += len(c)

    def ts_at(pos):
        return chunks[max(0, bisect.bisect_right(offs, pos) - 1)][0] if chunks else 0.0
    return buf, ts_at


def split_x224(buf):
    """Length of the cleartext X.224 Connection Request/Confirm before TLS."""
    o = 0
    while o + 4 <= len(buf) and buf[o] == 3:
        o += struct.unpack(">H", buf[o + 2:o + 4])[0]
    return o


def per_len(b, o):
    if b[o] & 0x80:
        return ((b[o] & 0x3F) << 8) | b[o + 1], o + 2
    return b[o], o + 1


def fast(pdu, hl, c2s):
    """A fast-path PDU: input event classes (client) or update types (server)."""
    flags = pdu[0] >> 6
    if flags & 0x2:  # FASTPATH_*_ENCRYPTED: RDP security, not used under TLS
        return f"FP encrypted {len(pdu)}B"
    body = pdu[hl:]
    if c2s:
        n, o = (pdu[0] >> 2) & 0xF, 0
        if n == 0 and body:
            n, o = body[0], 1
        evs = collections.Counter()
        for _ in range(n):
            if o >= len(body):
                break
            name, size = FPIN.get(body[o] >> 5, (f"event{body[o] >> 5}", 0))
            evs[name] += 1
            o += 1 + size
        return "FP-in " + ",".join(f"{k}x{v}" for k, v in evs.items())
    o, ups = 0, []
    while o + 3 <= len(body):
        h = body[o]
        code, frag, comp = h & 0xF, (h >> 4) & 3, h >> 6
        o += 2 if comp else 1
        sz = struct.unpack("<H", body[o:o + 2])[0]
        o += 2 + sz
        ups.append(FPOUT.get(code, f"code{code}") + (f"/frag{frag}" if frag else "") + ("/comp" if comp else ""))
    return "FP-out " + ",".join(ups)


def chandesc(name, d):
    """A static virtual channel chunk; drdynvc: the DVC command and a Create's channel name."""
    if len(d) < 8:
        return f"{len(d)}B"
    p, s = d[8:], f"{len(d)}B"
    if name == "drdynvc" and p:
        cmd = p[0] >> 4
        s += " dvc " + DVC.get(cmd, f"cmd{cmd}")
        if cmd == 1:
            nm = p[1 + (1, 2, 4, 4)[p[0] & 3]:].split(b"\x00")[0]  # after the channel id
            if nm and all(32 <= c < 127 for c in nm):  # the server's request names it
                s += " " + nm.decode("ascii")
    return s


def io_pdu(d):
    """A PDU on the I/O channel: security-header PDUs by flag, share control and data PDUs."""
    if len(d) >= 4:
        tl = struct.unpack("<H", d[:2])[0]
        if tl != len(d) and tl != 0x8000:  # a basic security header, not a share control header
            names = [n for bit, n in ((0x0040, "ClientInfo"), (0x0080, "License"), (0x1000, "AutoDetectReq"),
                                      (0x2000, "AutoDetectRsp"), (0x0400, "Heartbeat")) if tl & bit]
            if names:
                return "sec " + "/".join(names) + f" {len(d)}B"
    if len(d) < 6:
        return f"io {len(d)}B"
    t = struct.unpack("<H", d[2:4])[0] & 0xF
    if t == 1:
        return "DemandActive"
    if t == 3:
        return "ConfirmActive"
    if t == 6:
        return "DeactivateAll"
    if t == 7 and len(d) >= 18:
        p2, extra = d[14], ""
        if p2 == 0x2F and len(d) >= 22:
            extra = f" code={struct.unpack('<I', d[18:22])[0]:#x}"
        elif p2 == 0x23 and len(d) >= 19:
            extra = f" allow={d[18]}"
        elif p2 == 0x21 and len(d) >= 19:
            extra = f" n={d[18]}"
        elif p2 == 0x14 and len(d) >= 20:
            extra = " action=" + CONTROL.get(struct.unpack("<H", d[18:20])[0], "?")
        elif p2 == 0x02 and len(d) >= 20:
            extra = " type=" + FPOUT.get(struct.unpack("<H", d[18:20])[0], "?")
        elif p2 == 0x36 and len(d) >= 22:
            extra = f" status={struct.unpack('<I', d[18:22])[0]:#x}"
        return "Data " + PDU2.get(p2, f"pduType2 {p2:#x}") + extra
    return f"sharecontrol type {t}"


def slow(pdu, chan_names):
    """A TPKT PDU: X.224, MCS, I/O channel or static channel."""
    x = pdu[4:]
    if len(x) < 2:
        return "TPKT short"
    li, code = x[0], x[1] & 0xF0
    if code == 0xE0:
        return "X224 CR"
    if code == 0xD0:
        return "X224 CC"
    if code != 0xF0:
        return f"X224 type {code:#x}"
    m = x[li + 1:]
    if not m:
        return "X224 data empty"
    if m[:2] == b"\x7f\x65":
        return "MCS ConnectInitial"
    if m[:2] == b"\x7f\x66":
        return "MCS ConnectResponse"
    t = m[0] >> 2
    if t == 8 and len(m) >= 2:  # reason: 3 bits after the 6-bit choice ([T.125] PER)
        return f"MCS DisconnectProviderUltimatum reason={((m[0] & 3) << 1) | (m[1] >> 7)}"
    if t in (25, 26) and len(m) >= 7:  # SendDataRequest / SendDataIndication
        chan = struct.unpack(">H", m[3:5])[0]
        ln, o = per_len(m, 6)
        d = m[o:o + ln]
        if chan == 1003:
            return io_pdu(d)
        cn = chan_names.get(chan, str(chan))
        return f"chan {cn} {chandesc(cn, d)}"
    if t == 14 and len(m) >= 5:
        return f"MCS ChannelJoinRequest {struct.unpack('>H', m[3:5])[0]}"
    if t == 15 and len(m) >= 6:
        return f"MCS ChannelJoinConfirm {struct.unpack('>H', m[4:6])[0]}"
    names = {1: "ErectDomain", 10: "AttachUserRequest", 11: "AttachUserConfirm"}
    return "MCS " + names.get(t, f"type{t}")


def split_units(buf):
    """(offset, kind, PDU, fast-path header length) of the PDUs in decrypted application
    data: "credssp", "tpkt", "fast", or "rest" for what cannot be parsed."""
    o = 0
    while o < len(buf):
        b0 = buf[o]
        if b0 == 0x30 and o + 2 <= len(buf):  # CredSSP TSRequest (DER)
            ln, hl = buf[o + 1], 2
            if ln & 0x80:
                n = ln & 0x7F
                ln, hl = int.from_bytes(buf[o + 2:o + 2 + n], "big"), 2 + n
            yield o, "credssp", buf[o:o + hl + ln], 0
            o += hl + ln
        elif b0 == 0x03 and o + 4 <= len(buf):  # TPKT
            ln = struct.unpack(">H", buf[o + 2:o + 4])[0]
            yield o, "tpkt", buf[o:o + ln], 0
            o += max(ln, 4)
        elif b0 & 3 == 0 and o + 2 <= len(buf) and (o + 3 <= len(buf) or not buf[o + 1] & 0x80):
            l1 = buf[o + 1]  # fast-path
            ln, hl = (((l1 & 0x7F) << 8) | buf[o + 2], 3) if l1 & 0x80 else (l1, 2)
            yield o, "fast", buf[o:o + ln], hl
            o += max(ln, hl)
        else:
            yield o, "rest", buf[o:], 0
            return


def rdp_units(stream, c2s, chan_names):
    """[(timestamp, description)] of the decrypted application data of one direction."""
    buf, ts_at = joined(stream)
    res = []
    for o, kind, pdu, hl in split_units(buf):
        if kind == "credssp":
            desc = f"CredSSP TSRequest {len(pdu)}B"
        elif kind == "tpkt":
            desc = slow(pdu, chan_names)
        elif kind == "fast":
            desc = fast(pdu, hl, c2s)
        else:
            desc = f"unparsed, {len(pdu)}B left"
        res.append((ts_at(o), desc))
    return res


def tls_plain(buf, ts_at, direction):
    """[(timestamp, plaintext)] of the application data records of one direction."""
    out = []
    for o, hdr, body in records(buf):
        if hdr[0] == 23:
            ict, pt = direction.decrypt(hdr, body)
            if ict == 23:
                out.append((ts_at(o), pt))
    return out


def _gcc_block(m, btype):
    """The body of the first GCC user data block of type btype in an MCS Connect PDU whose
    length field fits (found by scanning: the PER/BER wrapping is not decoded)."""
    tag = struct.pack("<H", btype)
    o = m.find(tag)
    while o >= 0:
        if o + 4 <= len(m):
            ln = struct.unpack("<H", m[o + 2:o + 4])[0]
            if 4 <= ln and o + ln <= len(m):
                return m[o + 4:o + ln]
        o = m.find(tag, o + 1)
    return None


def channel_names(upt, dpt):
    """{MCS channel id: static channel name} from the Client Network Data (CS_NET, names in
    the order of the request) and the Server Network Data (SC_NET, the ids in that order)."""
    names, ids = [], []
    for stream, btype in ((upt, 0xC003), (dpt, 0x0C03)):
        buf, _ = joined(stream)
        for _o, kind, pdu, _hl in split_units(buf):
            if kind != "tpkt" or (b"\x7f\x65" not in pdu[:12] and b"\x7f\x66" not in pdu[:12]):
                continue
            body = _gcc_block(pdu, btype)
            if body is None:
                break
            if btype == 0xC003 and len(body) >= 4:
                n = struct.unpack("<I", body[:4])[0]
                names = [body[4 + 12 * i:12 + 12 * i].split(b"\x00")[0].decode("ascii", "replace")
                         for i in range(n) if 4 + 12 * (i + 1) <= len(body)]
            elif btype == 0x0C03 and len(body) >= 4:
                n = struct.unpack("<H", body[2:4])[0]
                ids = [struct.unpack("<H", body[4 + 2 * i:6 + 2 * i])[0]
                       for i in range(n) if 6 + 2 * i <= len(body)]
            break
    return dict(zip(ids, names))


def analyse(segs, keys):
    """The events of one connection, or None without its secrets in the key log."""
    ub, uts = joined(reassemble(segs, True))
    db, dts = joined(reassemble(segs, False))
    uo, do = split_x224(ub), split_x224(db)
    cr = suite = None
    for _o, hdr, body in records(ub[uo:]):
        if hdr[0] == 22 and body[0] == 1:  # ClientHello: client random
            cr = body[6:38]
            break
    for _o, hdr, body in records(db[do:]):
        if hdr[0] == 22 and body[0] == 2:  # ServerHello: cipher suite
            p = 39 + body[38]
            suite = struct.unpack(">H", body[p:p + 2])[0]
            break
    if cr is None or suite is None or cr not in keys:
        return None
    sec = keys[cr]
    try:
        up = Dir(suite, [sec["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], sec["CLIENT_TRAFFIC_SECRET_0"]])
        dn = Dir(suite, [sec["SERVER_HANDSHAKE_TRAFFIC_SECRET"], sec["SERVER_TRAFFIC_SECRET_0"]])
    except KeyError:
        return None  # not TLS 1.3
    upt = tls_plain(ub[uo:], lambda p: uts(p + uo), up)
    dpt = tls_plain(db[do:], lambda p: dts(p + do), dn)
    names = channel_names(upt, dpt)
    ev = [(t, "C>S", d) for t, d in rdp_units(upt, True, names)]
    ev += [(t, "S>C", d) for t, d in rdp_units(dpt, False, names)]
    ev.sort(key=lambda e: e[0])
    return ev


def collapse(events, t0):
    """Timeline lines; consecutive identical events become one line with a count."""
    lines, i = [], 0
    while i < len(events):
        t, d, desc = events[i]
        j = i
        while j + 1 < len(events) and events[j + 1][1:] == (d, desc):
            j += 1
        line = f"{t - t0:8.3f} {d} {desc}"
        if j > i:
            line += f"   x{j - i + 1} (until {events[j][0] - t0:.3f})"
        lines.append(line)
        i = j + 1
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture", help="pcap or pcapng of the client side")
    ap.add_argument("keylog", help="NSS key log (proxy.ini [FastRDP] TlsKeyLogFile)")
    ap.add_argument("--port", type=int, default=3389, help="the proxy's RDP port (default 3389)")
    a = ap.parse_args(argv)
    keys = load_keylog(a.keylog)
    for cli, segs in streams(a.capture, a.port).items():
        t0 = segs[0]["ts"]
        print(f"===== {fmt_addr(cli)} {time.strftime('%H:%M:%S', time.localtime(t0))}")
        ev = analyse(segs, keys)
        if ev is None:
            payload = sum(len(s["payload"]) for s in segs)
            print(f"   (no TLS 1.3 secrets in the key log: {len(segs)} segments, {payload} bytes)")
            continue
        for line in collapse(ev, t0):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
