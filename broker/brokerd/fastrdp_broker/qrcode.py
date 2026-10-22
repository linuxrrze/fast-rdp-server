# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""QR code (ISO/IEC 18004) for the approval URL on the proxy's waiting screen.

Byte mode, error correction level M, the smallest version that fits, the mask with the
lowest penalty score (as the standard prescribes, so the result is the same symbol other
encoders produce). The proxy module only draws the rows the broker sends ("qr" in the
"mfa" progress message, protocol.py), so the module needs no QR library. Stdlib only."""

from __future__ import annotations

# Level M per version (index 0 unused): error correction codewords per block, blocks.
ECC_CODEWORDS_PER_BLOCK = (
    -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
    26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28)
ECC_BLOCKS = (
    -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
    17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49)
FORMAT_BITS_M = 0  # level M's two format bits (L 01, M 00, Q 11, H 10)

PENALTY_N1, PENALTY_N2, PENALTY_N3, PENALTY_N4 = 3, 3, 40, 10


class QrError(ValueError):
    pass


def raw_data_modules(version: int) -> int:
    """Modules left for data and error correction once the function patterns are drawn."""
    result = (16 * version + 128) * version + 64
    if version >= 2:
        align = version // 7 + 2
        result -= (25 * align - 10) * align - 55
        if version >= 7:
            result -= 36
    return result


def data_codewords(version: int) -> int:
    return raw_data_modules(version) // 8 - ECC_CODEWORDS_PER_BLOCK[version] * ECC_BLOCKS[version]


def _gf_mul(x: int, y: int) -> int:
    """Product in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1."""
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    """Reed-Solomon generator polynomial, highest coefficient (always 1) left out."""
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _codewords(data: bytes, version: int) -> list[int]:
    """Segment, terminator, padding, then the error correction blocks, interleaved."""
    bits: list[int] = []

    def put(value: int, n: int) -> None:
        bits.extend((value >> i) & 1 for i in reversed(range(n)))

    capacity = data_codewords(version) * 8
    put(0b0100, 4)  # byte mode
    put(len(data), 8 if version <= 9 else 16)
    for b in data:
        put(b, 8)
    put(0, min(4, capacity - len(bits)))
    put(0, -len(bits) % 8)
    pad = 0xEC
    while len(bits) < capacity:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

    blocks_n, ecc_len = ECC_BLOCKS[version], ECC_CODEWORDS_PER_BLOCK[version]
    raw = raw_data_modules(version) // 8
    short_n = blocks_n - raw % blocks_n
    short_len = raw // blocks_n
    divisor = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(blocks_n):
        dat = words[k:k + short_len - ecc_len + (0 if i < short_n else 1)]
        k += len(dat)
        ecc = _rs_remainder(dat, divisor)
        if i < short_n:
            dat.append(0)  # placeholder, skipped when interleaving
        blocks.append(dat + ecc)
    result = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc_len or j >= short_n:
                result.append(blk[i])
    return result


class _Symbol:
    def __init__(self, version: int):
        self.version = version
        self.size = version * 4 + 17
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.function = [[False] * self.size for _ in range(self.size)]

    def set_function(self, x: int, y: int, dark: bool) -> None:
        self.dark[y][x] = dark
        self.function[y][x] = True

    def alignment_positions(self) -> list[int]:
        if self.version == 1:
            return []
        n = self.version // 7 + 2
        step = (self.version * 8 + n * 3 + 5) // (n * 4 - 4) * 2
        return [6] + sorted(self.size - 7 - i * step for i in range(n - 1))

    def draw_function_patterns(self) -> None:
        size = self.size
        for i in range(size):
            self.set_function(6, i, i % 2 == 0)
            self.set_function(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        self.set_function(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = self.alignment_positions()
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue  # finder corners
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set_function(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format_bits(0)  # reserved now, drawn per mask later
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.version << 12 | rem
            for i in range(18):
                bit = (bits >> i) & 1 != 0
                a, b = size - 11 + i % 3, i // 3
                self.set_function(a, b, bit)
                self.set_function(b, a, bit)

    def draw_format_bits(self, mask: int) -> None:
        data = FORMAT_BITS_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412

        def bit(i: int) -> bool:
            return (bits >> i) & 1 != 0

        size = self.size
        for i in range(6):
            self.set_function(8, i, bit(i))
        self.set_function(8, 7, bit(6))
        self.set_function(8, 8, bit(7))
        self.set_function(7, 8, bit(8))
        for i in range(9, 15):
            self.set_function(14 - i, 8, bit(i))
        for i in range(8):
            self.set_function(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set_function(8, size - 15 + i, bit(i))
        self.set_function(8, size - 8, True)  # the dark module

    def draw_codewords(self, words: list[int]) -> None:
        size = self.size
        i, total = 0, len(words) * 8
        right = size - 1
        while right >= 1:
            if right == 6:
                right = 5  # skip the vertical timing pattern
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = (right + 1) & 2 == 0
                    y = size - 1 - vert if upward else vert
                    if not self.function[y][x] and i < total:
                        self.dark[y][x] = (words[i >> 3] >> (7 - (i & 7))) & 1 != 0
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        test = (
            lambda x, y: (x + y) % 2 == 0,
            lambda x, y: y % 2 == 0,
            lambda x, y: x % 3 == 0,
            lambda x, y: (x + y) % 3 == 0,
            lambda x, y: (x // 3 + y // 2) % 2 == 0,
            lambda x, y: x * y % 2 + x * y % 3 == 0,
            lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
        )[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.function[y][x] and test(x, y):
                    self.dark[y][x] = not self.dark[y][x]

    def penalty(self) -> int:
        size, result = self.size, 0

        def add_history(run: int, history: list[int]) -> None:
            if history[0] == 0:
                run += size  # the light border before the first run
            history.pop()
            history.insert(0, run)

        def finder_like(h: list[int]) -> int:
            n = h[1]
            core = n > 0 and h[2] == h[4] == h[5] == n and h[3] == n * 3
            return (int(core and h[0] >= n * 4 and h[6] >= n)
                    + int(core and h[6] >= n * 4 and h[0] >= n))

        for lines in (self.dark, [list(col) for col in zip(*self.dark)]):
            for line in lines:
                color, run, history = False, 0, [0] * 7
                for dark in line:
                    if dark == color:
                        run += 1
                        if run == 5:
                            result += PENALTY_N1
                        elif run > 5:
                            result += 1
                    else:
                        add_history(run, history)
                        if not color:
                            result += finder_like(history) * PENALTY_N3
                        color, run = dark, 1
                if color:  # terminate the line with the light border after it
                    add_history(run, history)
                    run = 0
                add_history(run + size, history)
                result += finder_like(history) * PENALTY_N3
        for y in range(size - 1):
            for x in range(size - 1):
                if self.dark[y][x] == self.dark[y][x + 1] == self.dark[y + 1][x] == self.dark[y + 1][x + 1]:
                    result += PENALTY_N2
        dark = sum(row.count(True) for row in self.dark)
        total = size * size
        result += ((abs(dark * 20 - total * 10) + total - 1) // total - 1) * PENALTY_N4
        return result


def encode(data: bytes, max_version: int = 40) -> list[str]:
    """The QR code for `data` as rows of "0" (light) and "1" (dark), without quiet zone.
    Raises QrError if it does not fit into `max_version`."""
    for version in range(1, max_version + 1):
        if 4 + (8 if version <= 9 else 16) + 8 * len(data) <= data_codewords(version) * 8:
            break
    else:
        raise QrError(f"{len(data)} bytes do not fit into a version {max_version} QR code (level M)")
    sym = _Symbol(version)
    sym.draw_function_patterns()
    sym.draw_codewords(_codewords(data, version))
    best, best_penalty = 0, None
    for mask in range(8):
        sym.apply_mask(mask)
        sym.draw_format_bits(mask)
        p = sym.penalty()
        if best_penalty is None or p < best_penalty:
            best, best_penalty = mask, p
        sym.apply_mask(mask)  # XOR: undone
    sym.apply_mask(best)
    sym.draw_format_bits(best)
    return ["".join("1" if d else "0" for d in row) for row in sym.dark]
