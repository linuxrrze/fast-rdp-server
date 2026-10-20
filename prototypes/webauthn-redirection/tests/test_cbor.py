# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""CBOR against RFC 8949 Appendix A examples, CTAP2 canonical ordering, hostile input."""

import math
import unittest

from fastrdp_ewa import cbor

# (value, hex) from RFC 8949 Appendix A
RFC_EXAMPLES = [
    (0, "00"), (1, "01"), (10, "0a"), (23, "17"), (24, "1818"), (25, "1819"), (100, "1864"),
    (1000, "1903e8"), (1000000, "1a000f4240"), (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"), (-1, "20"), (-10, "29"), (-100, "3863"),
    (-1000, "3903e7"), (False, "f4"), (True, "f5"), (None, "f6"), (cbor.Undefined, "f7"),
    (b"", "40"), (b"\x01\x02\x03\x04", "4401020304"), ("", "60"), ("a", "6161"),
    ("IETF", "6449455446"), ("\"\\", "62225c"), ("ü", "62c3bc"), ("水", "63e6b0b4"),
    ([], "80"), ([1, 2, 3], "83010203"), ([1, [2, 3], [4, 5]], "8301820203820405"),
    (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
    ({}, "a0"), ({1: 2, 3: 4}, "a201020304"), ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    (["a", {"b": "c"}], "826161a161626163"),
    (cbor.Tag(1, 1363896240), "c11a514b67b0"),
]


class Rfc8949(unittest.TestCase):
    def test_examples_encode_and_decode(self):
        for value, hx in RFC_EXAMPLES:
            with self.subTest(hx):
                self.assertEqual(cbor.encode(value).hex(), hx)
                self.assertEqual(cbor.decode(bytes.fromhex(hx)), value)

    def test_floats_decode(self):
        self.assertEqual(cbor.decode(bytes.fromhex("f93c00")), 1.0)
        self.assertEqual(cbor.decode(bytes.fromhex("f9c400")), -4.0)
        self.assertEqual(cbor.decode(bytes.fromhex("f97bff")), 65504.0)
        self.assertEqual(cbor.decode(bytes.fromhex("f90001")), 5.960464477539063e-08)
        self.assertTrue(math.isinf(cbor.decode(bytes.fromhex("f97c00"))))
        self.assertEqual(cbor.decode(bytes.fromhex("fa47c35000")), 100000.0)
        self.assertEqual(cbor.decode(bytes.fromhex("fb3ff199999999999a")), 1.1)
        self.assertEqual(cbor.decode(cbor.encode(1.5)), 1.5)

    def test_map_order_kept(self):
        m = {"command": 5, "flags": 0, "a": 1}
        self.assertEqual(list(cbor.decode(cbor.encode(m))), ["command", "flags", "a"])


class Canonical(unittest.TestCase):
    def test_ctap2_key_order(self):
        # CTAP 2.1 section 8: shorter encoded key first, then bytewise
        m = {"type": 1, "id": 2, 3: 0, 1: 0, -1: 0, "alg": 3}
        enc = cbor.encode(m, canonical=True)
        self.assertEqual(list(cbor.decode(enc)), [1, 3, -1, "id", "alg", "type"])
        self.assertTrue(cbor.is_canonical(enc))
        self.assertFalse(cbor.is_canonical(cbor.encode({"type": 1, "id": 2})))

    def test_non_minimal_integer_is_not_canonical(self):
        self.assertEqual(cbor.decode(bytes.fromhex("1800")), 0)
        self.assertFalse(cbor.is_canonical(bytes.fromhex("1800")))


class Hostile(unittest.TestCase):
    def test_refused(self):
        cases = {
            "truncated": "1a0000",
            "truncated bytes": "4501",
            "trailing": "0000",
            "indefinite array": "9f01ff",
            "indefinite bytes": "5f4101ff",
            "break": "ff",
            "reserved info": "1c",
            "bad utf-8": "62c328",
            "duplicate key": "a201010102",
            "array key": "a1800101",
            "huge array": "9bffffffffffffffff",
            "huge map": "bbffffffffffffffff",
        }
        for name, hx in cases.items():
            with self.subTest(name), self.assertRaises(cbor.CborError):
                cbor.decode(bytes.fromhex(hx))

    def test_depth_limit(self):
        with self.assertRaises(cbor.CborError):
            cbor.decode(b"\x81" * (cbor.MAX_DEPTH + 2) + b"\x00")
        deep = 0
        for _ in range(cbor.MAX_DEPTH + 2):
            deep = [deep]
        with self.assertRaises(cbor.CborError):
            cbor.encode(deep)

    def test_unencodable(self):
        with self.assertRaises(cbor.CborError):
            cbor.encode(object())
        with self.assertRaises(cbor.CborError):
            cbor.encode(1 << 64)

    def test_trailing_allowed_on_request(self):
        self.assertEqual(cbor.decode(b"\x01\x02", allow_trailing=True), (1, 1))


if __name__ == "__main__":
    unittest.main()
