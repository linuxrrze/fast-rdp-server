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
import tls13  # noqa: E402

HAVE_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


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


if __name__ == "__main__":
    unittest.main()
