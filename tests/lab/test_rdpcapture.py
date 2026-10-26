# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Offline tests of tests/lab/rdpcapture (the A5 capture analysis): HKDF-Expand-Label against
RFC 8448, a record round trip (with python3-cryptography), and the RDP PDU names."""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent / "rdpcapture"
sys.path.insert(0, str(HERE))
import decode  # noqa: E402
import evtx_summary  # noqa: E402
import tls13  # noqa: E402

HAVE_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None
HAVE_EVTX = importlib.util.find_spec("Evtx") is not None


class Hkdf(unittest.TestCase):
    def test_rfc8448_handshake_keys(self):
        # RFC 8448 3 (Simple 1-RTT Handshake): the server's handshake write key and IV
        secret = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        self.assertEqual(tls13.hkdf_expand_label(hashlib.sha256, secret, "key", 16).hex(),
                         "3fce516009c21727d0f2e4e86ee403bc")
        self.assertEqual(tls13.hkdf_expand_label(hashlib.sha256, secret, "iv", 12).hex(),
                         "5d313eb2671276ee13000b30")


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "needs python3-cryptography")
class Records(unittest.TestCase):
    def test_handshake_then_application_secret(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        secrets = [bytes([1]) * 32, bytes([2]) * 32]

        def seal(secret, seq, inner, ctype):
            key = tls13.hkdf_expand_label(hashlib.sha256, secret, "key", 16)
            iv = tls13.hkdf_expand_label(hashlib.sha256, secret, "iv", 12)
            nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack(">Q", seq)))
            pt = inner + bytes([ctype])
            hdr = b"\x17\x03\x03" + struct.pack(">H", len(pt) + 16)
            return hdr, AESGCM(key).encrypt(nonce, pt, hdr)

        d = tls13.Dir(0x1301, secrets)
        self.assertEqual(d.decrypt(*seal(secrets[0], 0, b"finished", 22)), (22, b"finished"))
        # the first record under the application secret switches over
        self.assertEqual(d.decrypt(*seal(secrets[1], 0, b"\x03\x00", 23)), (23, b"\x03\x00"))
        self.assertEqual(d.decrypt(*seal(secrets[1], 1, b"next", 23)), (23, b"next"))
        hdr, body = seal(secrets[0], 5, b"x", 23)
        with self.assertRaises(Exception):
            d.decrypt(hdr, body)


def io_pdu(share_type, data=b""):
    """A share control PDU on the I/O channel in TPKT / X.224 / MCS Send Data Indication."""
    sc = struct.pack("<HHH", 6 + len(data), 0x10 | share_type, 1002) + data
    mcs = bytes([26 << 2]) + struct.pack(">HH", 6, 1003) + b"\x70" + bytes([len(sc)]) + sc
    x224 = b"\x02\xf0\x80" + mcs
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


class Pdus(unittest.TestCase):
    def test_share_control(self):
        self.assertEqual(decode.slow(io_pdu(6, b"\x00" * 6), {}), "DeactivateAll")
        self.assertEqual(decode.slow(io_pdu(1, b"\x00" * 6), {}), "DemandActive")
        err = struct.pack("<IBBHBBH", 0x10000, 0, 1, 8, 0x2F, 0, 0) + struct.pack("<I", 0x409)
        self.assertEqual(decode.slow(io_pdu(7, err), {}), "Data SetErrorInfo code=0x409")

    def test_ultimatum_reason(self):
        # DisconnectProviderUltimatum, reason 3 (user requested), as FreeRDP writes it
        pdu = b"\x03\x00\x00\x09\x02\xf0\x80\x21\x80"
        self.assertEqual(decode.slow(pdu, {}), "MCS DisconnectProviderUltimatum reason=3")

    def test_fast_path_input_classes(self):
        # 3 events: QoE timestamp, one scancode, sync
        body = bytes([6 << 5]) + b"\x00" * 4 + bytes([0]) + b"\x1e" + bytes([3 << 5])
        pdu = bytes([3 << 2, 2 + len(body)]) + body
        self.assertEqual(decode.fast(pdu, 2, True), "FP-in qoex1,scancodex1,syncx1")

    def test_units_and_collapse(self):
        buf = io_pdu(6, b"\x00" * 6) + io_pdu(1, b"\x00" * 6)
        self.assertEqual([k for _o, k, _p, _h in decode.split_units(buf)], ["tpkt", "tpkt"])
        ev = [(10.0, "S>C", "FP-out bitmap"), (10.5, "S>C", "FP-out bitmap"), (11.0, "C>S", "x")]
        self.assertEqual(decode.collapse(ev, 10.0),
                         ["   0.000 S>C FP-out bitmap   x2 (until 0.500)", "   1.000 C>S x"])


def tpkt(payload):
    x224 = b"\x02\xf0\x80" + payload
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def send_data(chan, data, c2s):
    """MCS Send Data Request (client) or Indication (server) on chan."""
    ln = struct.pack(">H", 0x8000 | len(data))
    return tpkt(bytes([(25 if c2s else 26) << 2]) + struct.pack(">HH", 1007, chan) + b"\x70" + ln + data)


def share_data(pdu2, body=b""):
    return struct.pack("<IBBHBBH", 0x10000, 0, 1, 0, pdu2, 0, 0) + body


def dvc(cmd, cid, rest):
    """A drdynvc static channel chunk (CHANNEL_PDU_HEADER, first and last) with one DVC PDU."""
    p = bytes([cmd << 4]) + bytes([cid]) + rest
    return struct.pack("<II", len(p), 3) + p


def fp_bitmaps(n):
    """A fast-path output PDU with n unfragmented bitmap updates of 4 bytes."""
    body = b"".join(b"\x01" + struct.pack("<H", 4) + b"\x00" * 4 for _ in range(n))
    return bytes([0, 0x80 | ((len(body) + 3) >> 8), (len(body) + 3) & 0xFF]) + body


def seg(ts, c2s, flags=0x18):
    return dict(ts=ts, c2s=c2s, cli=(bytes([192, 0, 2, 9]), 50000), seq=0, ack=0, flags=flags, win=0,
                payload=b"")


class Summary(unittest.TestCase):
    """--summary and --compare on synthetic decrypted streams (decode.decrypt replaced)."""

    def conn(self, graphics=True, core_byte=0):
        cs_core = struct.pack("<HH", 0xC001, 12) + bytes([core_byte]) * 8
        cs_net = struct.pack("<HHI", 0xC003, 8 + 24, 2) + b"cliprdr\x00\x00\x00\x00\x00" + b"drdynvc\x00" + b"\x00" * 4
        sc_net = struct.pack("<HHHH", 0x0C03, 8 + 4, 1003, 2) + struct.pack("<HH", 1004, 1005)
        up = [(0.1, tpkt(b"\x7f\x65\x82\x00" + cs_core + cs_net)),
              (0.3, send_data(1003, struct.pack("<HHH", 6 + 4, 0x13, 1007) + b"conf", True)),
              (5.0, send_data(1003, struct.pack("<HHH", 6 + 18, 0x17, 1007) + share_data(0x21, b"\x01"), True))]
        down = [(0.2, tpkt(b"\x7f\x66\x82\x00" + sc_net)),
                (0.25, send_data(1003, struct.pack("<HHH", 10, 0x11, 1002) + b"\x00" * 4, False)),
                (1.0, fp_bitmaps(3)), (2.0, fp_bitmaps(2))]
        if graphics:
            down += [(9.0, send_data(1003, struct.pack("<HHH", 10, 0x16, 1002) + b"\x00" * 4, False)),
                     (9.1, send_data(1003, struct.pack("<HHH", 10, 0x11, 1002) + b"\x00" * 4, False)),
                     (9.2, send_data(1005, dvc(1, 1, b"Microsoft::Windows::RDS::Graphics\x00"), False)),
                     (9.3, send_data(1005, dvc(1, 2, b"Microsoft::Windows::RDS::Input\x00"), False)),
                     (9.5, fp_bitmaps(1))]
            up += [(9.25, send_data(1005, dvc(1, 1, struct.pack("<i", 0)), True)),
                   (9.35, send_data(1005, dvc(1, 2, struct.pack("<i", -1)), True))]
        else:
            down += [(90.0, send_data(1003, struct.pack("<HHH", 6 + 22, 0x17, 1002)
                                      + share_data(0x2F, struct.pack("<I", 0x409)), False)),
                     (90.1, tpkt(b"\x21\x80"))]
        segs = [seg(0.0, True, 0x02), seg(95.0 if not graphics else 30.0, not graphics, 0x04)]
        return segs, up, down

    def summarise(self, *conns):
        infos, orig = [], decode.decrypt
        try:
            for segs, up, down in conns:
                names = decode.channel_names(up, down)
                decode.decrypt = lambda _s, _k, up=up, down=down, names=names: (up, down, names)
                infos.append(decode.summary(segs, {}))
        finally:
            decode.decrypt = orig
        return infos

    def test_summary_fields(self):
        gfx, black = self.summarise(self.conn(True), self.conn(False))
        self.assertTrue(gfx["decrypted"])
        self.assertEqual(gfx["static_channels"], ["cliprdr", "drdynvc"])
        self.assertEqual(gfx["joins"], "skipped")
        # the Input DVC was refused by the client (status -1): requested, not created
        self.assertEqual(gfx["dvcs_created"], ["Microsoft::Windows::RDS::Graphics"])
        self.assertTrue(gfx["graphics"])
        self.assertEqual(gfx["reactivations"], 1)
        self.assertEqual((gfx["bitmaps_pre_session"], gfx["bitmaps_total"]), (5, 6))
        self.assertEqual(gfx["refresh_rect"], 1)
        self.assertEqual(gfx["tcp_end"], "RST from server at 30.0 s")
        self.assertFalse(black["graphics"])
        self.assertEqual(black["reactivations"], 0)
        self.assertIsNone(black["session_at"])
        self.assertEqual((black["bitmaps_pre_session"], black["bitmaps_total"]), (5, 5))
        self.assertEqual(black["set_error_info"], ["0x409"])
        self.assertEqual(black["ultimatum"], "3 from server")
        self.assertEqual(black["tcp_end"], "RST from client at 95.0 s")
        line = decode.summary_line(2, black)
        self.assertIn("Graphics no; reactivations 0; bitmaps pre-session 5/5 (no session)", line)
        self.assertIn("SetErrorInfo 0x409, ultimatum 3 from server", line)

    def test_compare_offsets_only(self):
        a, b = self.summarise(self.conn(True, core_byte=0x41), self.conn(False, core_byte=0x42))
        lines = decode.compare(1, a, 2, b)
        text = "\n".join(lines)
        self.assertIn("graphics: True | False", text)
        self.assertIn("reactivations: 1 | 0", text)
        self.assertIn("Client Core Data: differ at offsets 0-7 (lengths 8/8)", text)
        self.assertIn("Confirm Active: identical", text)
        self.assertNotIn("AAAA", text)  # never the bytes themselves
        self.assertNotIn("41", text.split("Client Core Data")[1])
        same = decode.compare(1, a, 1, a)
        self.assertIn("no difference in the summary fields", same[1])

    def test_not_decrypted(self):
        info = decode.summary([seg(0.0, True, 0x02), seg(1.5, True, 0x01)], {})
        self.assertFalse(info["decrypted"])
        self.assertIn("not decrypted", decode.summary_line(1, info))
        self.assertIn("FIN from client at 1.5 s", decode.summary_line(1, info))

    def test_byte_diff(self):
        self.assertEqual(decode.byte_diff(b"abc", b"abc"), "identical (3 bytes)")
        self.assertEqual(decode.byte_diff(b"abcd", b"aXcY"), "differ at offsets 1, 3 (lengths 4/4)")
        self.assertEqual(decode.byte_diff(b"ab", b"abcd"), "differ at offsets 2-3 (lengths 2/4)")
        self.assertEqual(decode.byte_diff(None, b"a"), "missing in one")

    def test_dvc_fields(self):
        self.assertEqual(decode.dvc_fields(dvc(1, 7, b"AUDIO_PLAYBACK_DVC\x00")), (1, 7, "AUDIO_PLAYBACK_DVC"))
        self.assertEqual(decode.dvc_fields(dvc(1, 7, struct.pack("<i", 0))), (1, 7, 0))
        self.assertEqual(decode.dvc_fields(dvc(4, 7, b"")), (4, 7, None))
        self.assertIsNone(decode.dvc_fields(b"\x00" * 8))


def event_xml(eid, when, activity="{a1}", pid="3992", **data):
    """An RDPClient/Operational event as python-evtx renders it."""
    d = "".join(f'<Data Name="{k.replace("_", " ")}">{v}</Data>' for k, v in data.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-TerminalServices-ClientActiveXCore"></Provider>'
            f'<EventID Qualifiers="">{eid}</EventID><TimeCreated SystemTime="{when}"></TimeCreated>'
            f'<Correlation ActivityID="{activity}" RelatedActivityID=""></Correlation>'
            f'<Execution ProcessID="{pid}" ThreadID="1"></Execution>'
            '<Channel>Microsoft-Windows-TerminalServices-RDPClient/Operational</Channel></System>'
            f'<EventData>{d}</EventData></Event>')


class EvtxSummary(unittest.TestCase):
    def events(self):
        x = [event_xml(1024, "2026-10-26 19:57:22.281992+00:00", Name="Server Name", Value="rdp1.example.com"),
             event_xml(1025, "2026-10-26 19:57:27.700731+00:00"),
             event_xml(1029, "2026-10-26 19:57:27.6+00:00", TraceMessage="SECRETHASH="),
             event_xml(1402, "2026-10-26 19:58:03.523039+00:00"),
             event_xml(1401, "2026-10-26T19:58:03.5317310Z", Version="0x000a0600", ClientMode="0", AvcEnabled="0"),
             event_xml(1026, "2026-10-26 19:58:08.017496+00:00", Name="Disconnect Reason", Value="1"),
             event_xml(1024, "2026-10-26 19:58:10.2+00:00", activity="{a2}", Name="Server Name", Value="rdp1.example.com"),
             event_xml(226, "2026-10-26 19:59:45.338953+00:00", activity="{a2}",
                       StateTransitionName="RDPClient_SSL", PreviousStateName="TsSslStateDisconnected",
                       NewStateName="TsSslStateDisconnected", EventName="TsSslEventInvalidState",
                       Error_Code="2147549183"),
             event_xml(1026, "2026-10-26 19:59:45.34+00:00", activity="{a2}", Name="Disconnect Reason", Value="2")]
        return [evtx_summary.parse_xml(e) for e in x]

    def test_per_connection(self):
        lines = evtx_summary.summarise(self.events(), utc=True)
        text = "\n".join(lines)
        self.assertEqual([ln for ln in lines if ln.startswith("=====")], [
            "===== connection 1: rdp1.example.com, mstsc pid 3992, 2026-10-26 19:57:22.281 to 19:58:08.017, "
            "GFX AvcEnabled=0 [activity {a1}]",
            "===== connection 2: rdp1.example.com, mstsc pid 3992, 2026-10-26 19:58:10.200 to 19:59:45.340, "
            "no GFX [activity {a2}]"])
        self.assertIn("  19:58:03.531 1401 GFX started: Version=0x000a0600 AvcEnabled=0", lines)
        self.assertIn("  19:58:08.017 1026 disconnect reason 1 (local disconnect)", lines)
        self.assertIn("  19:59:45.338 226 RDPClient_SSL: TsSslStateDisconnected -> TsSslStateDisconnected on "
                      "TsSslEventInvalidState, error 0x8000ffff", lines)
        self.assertIn("  other events: 1029x1", lines)
        self.assertNotIn("SECRETHASH", text)

    def test_since(self):
        import datetime as dt
        since = dt.datetime(2026, 10, 26, 19, 58, tzinfo=dt.timezone.utc)
        lines = evtx_summary.summarise(self.events(), utc=True, since=since)
        self.assertEqual(sum(ln.startswith("=====") for ln in lines), 1)
        self.assertIn("connection 1: rdp1.example.com, mstsc pid 3992, 2026-10-26 19:58:10", lines[0])

    @unittest.skipIf(HAVE_EVTX, "python-evtx installed")
    def test_without_python_evtx(self):
        self.assertEqual(evtx_summary.main(["/nonexistent.evtx"]), 3)


if __name__ == "__main__":
    unittest.main()
