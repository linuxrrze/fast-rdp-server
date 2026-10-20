# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""CTAPHID framing (CTAP 2.1, 11.2)."""

import struct
import unittest

from fastrdp_ewa import ctaphid as h


class Framing(unittest.TestCase):
    def test_init_packet_layout(self):
        # CTAP 2.1 11.2.4: CID | CMD|0x80 | BCNTH | BCNTL | DATA
        [r] = h.fragment(h.Message(0xFFFFFFFF, h.INIT, bytes(range(8))))
        self.assertEqual(r[:7].hex(), "ffffffff860008")
        self.assertEqual(r[7:15], bytes(range(8)))
        self.assertEqual(len(r), 64)
        self.assertEqual(r[15:], b"\0" * 49)

    def test_sizes(self):
        for n, packets in ((0, 1), (57, 1), (58, 2), (57 + 59, 2), (57 + 59 + 1, 3), (h.MAX_MESSAGE, 129)):
            with self.subTest(n):
                reports = h.fragment(h.Message(0x01020304, h.CBOR, bytes(n)))
                self.assertEqual(len(reports), packets)
                self.assertTrue(all(len(r) == 64 for r in reports))
                if packets > 1:
                    self.assertEqual([r[4] for r in reports[1:]], list(range(packets - 1)))
        with self.assertRaises(ValueError):
            h.fragment(h.Message(1, h.CBOR, bytes(h.MAX_MESSAGE + 1)))

    def test_roundtrip(self):
        payload = bytes(i % 251 for i in range(3000))
        a = h.Assembler()
        out = None
        for r in h.fragment(h.Message(0xCAFEBABE, h.CBOR, payload)):
            out = a.feed(r)
        self.assertEqual((out.cid, out.cmd, out.payload), (0xCAFEBABE, h.CBOR, payload))
        self.assertEqual(a.partial, {})

    def test_report_id_prefix_accepted(self):
        [r] = h.fragment(h.Message(7, h.PING, b"hi"))
        self.assertEqual(h.Assembler().feed(b"\0" + r).payload, b"hi")

    def test_interleaved_channels(self):
        a = h.Assembler()
        r1 = h.fragment(h.Message(1, h.CBOR, b"A" * 100))
        r2 = h.fragment(h.Message(2, h.CBOR, b"B" * 100))
        self.assertIsNone(a.feed(r1[0]))
        self.assertIsNone(a.feed(r2[0]))
        self.assertEqual(a.feed(r2[1]).payload, b"B" * 100)
        self.assertEqual(a.feed(r1[1]).payload, b"A" * 100)


class Errors(unittest.TestCase):
    def expect(self, code, reports, assembler=None):
        a = assembler or h.Assembler()
        with self.assertRaises(h.CtapHidError) as cm:
            for r in reports:
                a.feed(r)
        self.assertEqual(cm.exception.code, code)

    def test_bad_sequence(self):
        rs = h.fragment(h.Message(5, h.CBOR, bytes(200)))
        bad = rs[2][:4] + b"\x05" + rs[2][5:]
        self.expect(h.ERR_INVALID_SEQ, [rs[0], rs[1], bad])

    def test_wrong_report_size(self):
        self.expect(h.ERR_INVALID_LEN, [b"\0" * 10])

    def test_too_long(self):
        r = struct.pack(">IBH", 9, 0x80 | h.CBOR, h.MAX_MESSAGE + 1).ljust(64, b"\0")
        self.expect(h.ERR_INVALID_LEN, [r])

    def test_broadcast_only_for_init(self):
        self.expect(h.ERR_INVALID_CHANNEL, h.fragment(h.Message(h.BROADCAST_CID, h.CBOR, b"\x04")))

    def test_channel_zero(self):
        self.expect(h.ERR_INVALID_CHANNEL, h.fragment(h.Message(0, h.PING, b"")))

    def test_busy_channel(self):
        a = h.Assembler()
        a.feed(h.fragment(h.Message(3, h.CBOR, bytes(100)))[0])
        self.expect(h.ERR_CHANNEL_BUSY, h.fragment(h.Message(3, h.PING, b"x")), a)

    def test_init_aborts_pending(self):
        a = h.Assembler()
        a.feed(h.fragment(h.Message(3, h.CBOR, bytes(100)))[0])
        msg = a.feed(h.fragment(h.Message(3, h.INIT, bytes(8)))[0])
        self.assertEqual(msg.cmd, h.INIT)
        self.assertEqual(a.partial, {})

    def test_spurious_continuation_ignored(self):
        self.assertIsNone(h.Assembler().feed(struct.pack(">IB", 4, 0).ljust(64, b"\0")))


class Builders(unittest.TestCase):
    def test_init_response(self):
        p = h.init_response(b"12345678", 0x11223344, (1, 2, 3))
        self.assertEqual(p.hex(), "3132333435363738" "11223344" "02" "010203" "0c")
        with self.assertRaises(ValueError):
            h.init_response(b"short", 1)

    def test_error_and_keepalive(self):
        [e] = h.error(9, h.ERR_CHANNEL_BUSY)
        self.assertEqual(e[:8].hex(), "00000009bf000106")
        [k] = h.keepalive(9, h.STATUS_UPNEEDED)
        self.assertEqual(k[:8].hex(), "00000009bb000102")

    def test_report_descriptor(self):
        d = h.REPORT_DESCRIPTOR
        self.assertTrue(d.startswith(bytes.fromhex("06d0f1")))   # FIDO usage page
        self.assertEqual(d.count(bytes.fromhex("9540")), 2)      # 64-byte in/out reports
        self.assertEqual(len(d), 34)

    def test_new_cid(self):
        cid = h.new_cid({1, 2})
        self.assertNotIn(cid, (0, h.BROADCAST_CID, 1, 2))


if __name__ == "__main__":
    unittest.main()
