# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
#
# LAB ONLY: decrypts TLS 1.3 records of a lab capture with the NSS key log the proxy wrote
# (proxy.ini [FastRDP] TlsKeyLogFile, backlog A5). Nothing here prints key material.
# Needs python3-cryptography for the AEAD ciphers (HKDF itself is standard library).
"""TLS 1.3 record decryption from an NSS key log (RFC 8446 7.1, 7.3, 5.2)."""

from __future__ import annotations

import hashlib
import hmac
import struct

# cipher suite: hash, key length, AEAD class name in cryptography's aead module
SUITES = {0x1301: (hashlib.sha256, 16, "AESGCM"), 0x1302: (hashlib.sha384, 32, "AESGCM"),
          0x1303: (hashlib.sha256, 32, "ChaCha20Poly1305")}


def hkdf_expand_label(h, secret, label, length, context=b""):
    """HKDF-Expand-Label (RFC 8446 7.1)."""
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def load_keylog(path):
    """{client_random: {label: secret}} from an NSS key log file."""
    keys = {}
    with open(path) as fh:
        for line in fh:
            p = line.split()
            if len(p) == 3 and not p[0].startswith("#"):
                keys.setdefault(bytes.fromhex(p[1]), {})[p[0]] = bytes.fromhex(p[2])
    return keys


class Dir:
    """One direction of a connection: the handshake traffic secret, then the first
    application traffic secret (key updates are not followed)."""

    def __init__(self, suite, secrets):
        from cryptography.hazmat.primitives.ciphers import aead

        self.h, self.klen, cls = SUITES[suite]
        self.cls = getattr(aead, cls)
        self.secrets = list(secrets)
        self.stage = -1
        self.next()

    def next(self):
        self.stage += 1
        s = self.secrets[self.stage]
        self.aead = self.cls(hkdf_expand_label(self.h, s, "key", self.klen))
        self.iv = hkdf_expand_label(self.h, s, "iv", 12)
        self.seq = 0

    def decrypt(self, hdr, body):
        """(inner content type, plaintext) of one record; moves on to the application
        secret when the handshake secret no longer fits."""
        for attempt in range(2):
            nonce = bytes(a ^ b for a, b in zip(self.iv, b"\x00" * 4 + struct.pack(">Q", self.seq)))
            try:
                pt = self.aead.decrypt(nonce, body, hdr)
            except Exception:
                if attempt == 0 and self.stage + 1 < len(self.secrets):
                    self.next()
                    continue
                raise
            self.seq += 1
            pt = pt.rstrip(b"\x00")
            return pt[-1], pt[:-1]
        raise ValueError("record not decrypted")


def records(buf):
    """(offset, 5-byte header, body) of the complete TLS records in buf."""
    o = 0
    while o + 5 <= len(buf):
        ln = struct.unpack(">H", buf[o + 3:o + 5])[0]
        if o + 5 + ln > len(buf):
            break
        yield o, buf[o:o + 5], buf[o + 5:o + 5 + ln]
        o += 5 + ln
