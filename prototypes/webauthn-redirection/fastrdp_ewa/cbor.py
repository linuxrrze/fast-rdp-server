# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Minimal CBOR (RFC 8949), enough for [MS-RDPEWA] and CTAP2.

Python types: int, bytes, str, list, dict (insertion order kept), bool, None, float,
Undefined, Tag. Decoding keeps map order, so a decoded message re-encodes to the same
bytes (RDPEWA's examples use text keys in non-canonical order). encode(canonical=True)
sorts map keys as CTAP2 requires (CTAP 2.1 section 8: length-first, then bytewise).

Limits against hostile input: nesting depth, item count and indefinite lengths
(rejected: neither RDPEWA nor CTAP2 uses them).
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

MAX_DEPTH = 16
MAX_ITEMS = 100_000


class CborError(ValueError):
    pass


class _Undefined:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "undefined"


Undefined = _Undefined()


@dataclass(frozen=True)
class Tag:
    tag: int
    value: object


# ------------------------------------------------------------------ encoding
def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise CborError("negative length/argument")
    if n < 24:
        return bytes([major << 5 | n])
    if n < 1 << 8:
        return bytes([major << 5 | 24, n])
    if n < 1 << 16:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 1 << 32:
        return bytes([major << 5 | 26]) + struct.pack(">I", n)
    if n < 1 << 64:
        return bytes([major << 5 | 27]) + struct.pack(">Q", n)
    raise CborError("integer too large for CBOR")


def _canonical_key(encoded: bytes) -> tuple[int, bytes]:
    return len(encoded), encoded


def encode(obj, canonical: bool = False) -> bytes:
    out = bytearray()
    _enc(obj, out, canonical, 0)
    return bytes(out)


def _enc(obj, out: bytearray, canonical: bool, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CborError("nesting too deep")
    if obj is False:
        out += b"\xf4"
    elif obj is True:
        out += b"\xf5"
    elif obj is None:
        out += b"\xf6"
    elif obj is Undefined:
        out += b"\xf7"
    elif isinstance(obj, int):
        out += _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    elif isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        out += _head(2, len(b)) + b
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        out += _head(3, len(b)) + b
    elif isinstance(obj, (list, tuple)):
        out += _head(4, len(obj))
        for item in obj:
            _enc(item, out, canonical, depth + 1)
    elif isinstance(obj, dict):
        pairs = [(encode(k, canonical), v) for k, v in obj.items()]
        if canonical:
            pairs.sort(key=lambda kv: _canonical_key(kv[0]))
        out += _head(5, len(pairs))
        for k, v in pairs:
            out += k
            _enc(v, out, canonical, depth + 1)
    elif isinstance(obj, Tag):
        out += _head(6, obj.tag)
        _enc(obj.value, out, canonical, depth + 1)
    elif isinstance(obj, float):
        out += b"\xfb" + struct.pack(">d", obj)
    else:
        raise CborError(f"cannot encode {type(obj).__name__}")


# ------------------------------------------------------------------ decoding
class _Reader:
    def __init__(self, data: bytes):
        self.data = memoryview(bytes(data))
        self.pos = 0
        self.items = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise CborError(f"truncated CBOR at offset {self.pos}")
        b = bytes(self.data[self.pos:self.pos + n])
        self.pos += n
        return b

    def arg(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self.take(1)[0]
        if info == 25:
            return struct.unpack(">H", self.take(2))[0]
        if info == 26:
            return struct.unpack(">I", self.take(4))[0]
        if info == 27:
            return struct.unpack(">Q", self.take(8))[0]
        if info == 31:
            raise CborError("indefinite-length items are not supported")
        raise CborError(f"reserved additional information {info}")

    def item(self, depth: int = 0):
        if depth > MAX_DEPTH:
            raise CborError("nesting too deep")
        self.items += 1
        if self.items > MAX_ITEMS:
            raise CborError("too many items")
        ib = self.take(1)[0]
        major, info = ib >> 5, ib & 0x1F
        if major == 7:
            return self.simple(info)
        n = self.arg(info)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return self.take(n)
        if major == 3:
            try:
                return self.take(n).decode("utf-8")
            except UnicodeDecodeError:
                raise CborError("invalid UTF-8 in text string") from None
        if major == 4:
            if n > len(self.data) - self.pos:
                raise CborError("array longer than the input")
            return [self.item(depth + 1) for _ in range(n)]
        if major == 5:
            if n > len(self.data) - self.pos:
                raise CborError("map longer than the input")
            m = {}
            for _ in range(n):
                k = self.item(depth + 1)
                if isinstance(k, (list, dict)):
                    raise CborError("unsupported map key type")
                if k in m:
                    raise CborError(f"duplicate map key {k!r}")
                m[k] = self.item(depth + 1)
            return m
        return Tag(n, self.item(depth + 1))   # major 6

    def simple(self, info: int):
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info == 23:
            return Undefined
        if info == 25:
            return _half(struct.unpack(">H", self.take(2))[0])
        if info == 26:
            return struct.unpack(">f", self.take(4))[0]
        if info == 27:
            return struct.unpack(">d", self.take(8))[0]
        if info == 31:
            raise CborError("unexpected break")
        raise CborError(f"unsupported simple value {info}")


def _half(h: int) -> float:
    exp, mant = (h >> 10) & 0x1F, h & 0x3FF
    if exp == 0:
        val = math.ldexp(mant, -24)
    elif exp == 31:
        val = math.inf if mant == 0 else math.nan
    else:
        val = math.ldexp(mant + 1024, exp - 25)
    return -val if h & 0x8000 else val


def decode(data: bytes, allow_trailing: bool = False):
    """One CBOR item. With allow_trailing, returns (item, bytes consumed)."""
    r = _Reader(data)
    obj = r.item()
    if allow_trailing:
        return obj, r.pos
    if r.pos != len(r.data):
        raise CborError(f"{len(r.data) - r.pos} trailing bytes after the CBOR item")
    return obj


def is_canonical(data: bytes) -> bool:
    """True if data is CTAP2-canonical (re-encoding canonically gives the same bytes)."""
    try:
        return encode(decode(data), canonical=True) == bytes(data)
    except CborError:
        return False
