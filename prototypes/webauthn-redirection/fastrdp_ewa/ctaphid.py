# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""CTAPHID framing (FIDO CTAP 2.1, section 11.2) for a virtual FIDO HID device.

A browser in the Linux session talks to /dev/hidraw*; a bridge behind /dev/uhid sees
64-byte HID reports. This module turns reports into messages and back:

  initialization packet   CID(4) | CMD(1, bit 7 set) | BCNT(2, big endian) | DATA(57)
  continuation packet     CID(4) | SEQ(1, 0..127)    | DATA(59)

Max message 57 + 128 * 59 = 7609 bytes. Channel 0xffffffff is the broadcast channel,
only valid for CTAPHID_INIT, which allocates a channel id.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

REPORT_SIZE = 64
INIT_DATA = REPORT_SIZE - 7
CONT_DATA = REPORT_SIZE - 5
MAX_MESSAGE = INIT_DATA + 128 * CONT_DATA
BROADCAST_CID = 0xFFFFFFFF

# commands (11.2.9), without the TYPE_INIT bit
PING = 0x01
MSG = 0x03
LOCK = 0x04
INIT = 0x06
WINK = 0x08
CBOR = 0x10
CANCEL = 0x11
KEEPALIVE = 0x3B
ERROR = 0x3F
TYPE_INIT = 0x80

# CTAPHID_ERROR codes (11.2.9.1.6)
ERR_INVALID_CMD = 0x01
ERR_INVALID_PAR = 0x02
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_MSG_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_LOCK_REQUIRED = 0x0A
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F

# KEEPALIVE status
STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2

# INIT response capabilities
CAPABILITY_WINK = 0x01
CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08      # no CTAPHID_MSG (U2F) support

# HID report descriptor of a FIDO authenticator (usage page 0xF1D0, usage 0x01;
# 64-byte input and output reports), as used with /dev/uhid (UHID_CREATE2.rd_data).
REPORT_DESCRIPTOR = bytes.fromhex(
    "06d0f1"     # Usage Page (FIDO Alliance)
    "0901"       # Usage (U2F Authenticator Device)
    "a101"       # Collection (Application)
    "0920"       #   Usage (Input Report Data)
    "1500" "26ff00" "7508" "9540"
    "8102"       #   Input (Data, Var, Abs)
    "0921"       #   Usage (Output Report Data)
    "1500" "26ff00" "7508" "9540"
    "9102"       #   Output (Data, Var, Abs)
    "c0"         # End Collection
)


class CtapHidError(Exception):
    def __init__(self, cid: int, code: int, msg: str):
        super().__init__(msg)
        self.cid, self.code = cid, code


@dataclass
class Message:
    cid: int
    cmd: int            # without TYPE_INIT
    payload: bytes


def fragment(msg: Message) -> list[bytes]:
    """Message -> 64-byte reports (zero-padded)."""
    if len(msg.payload) > MAX_MESSAGE:
        raise ValueError("payload too large for CTAPHID")
    if not 0 <= msg.cmd < 0x80:
        raise ValueError("command out of range")
    data = msg.payload
    reports = [struct.pack(">IBH", msg.cid, TYPE_INIT | msg.cmd, len(data)) + data[:INIT_DATA]]
    data = data[INIT_DATA:]
    seq = 0
    while data:
        reports.append(struct.pack(">IB", msg.cid, seq) + data[:CONT_DATA])
        data = data[CONT_DATA:]
        seq += 1
    return [r.ljust(REPORT_SIZE, b"\0") for r in reports]


@dataclass
class _Partial:
    cmd: int
    total: int
    data: bytearray
    seq: int = 0


@dataclass
class Assembler:
    """Reassembles reports from the host (browser) into messages, per channel.

    feed() returns a complete Message, None while one is incomplete, or raises
    CtapHidError with the CTAPHID_ERROR code the device must answer with."""
    partial: dict[int, _Partial] = field(default_factory=dict)

    def feed(self, report: bytes) -> Message | None:
        report = bytes(report)
        if len(report) == REPORT_SIZE + 1 and report[0] == 0:
            report = report[1:]          # hidraw/uhid output reports may carry report id 0
        if len(report) != REPORT_SIZE:
            raise CtapHidError(0, ERR_INVALID_LEN, f"report of {len(report)} bytes")
        cid = struct.unpack(">I", report[:4])[0]
        if cid == 0:
            raise CtapHidError(cid, ERR_INVALID_CHANNEL, "channel 0 is reserved")
        if report[4] & TYPE_INIT:
            cmd = report[4] & 0x7F
            total = struct.unpack(">H", report[5:7])[0]
            if cid in self.partial and cmd != INIT:
                # a new request while one is in progress on this channel
                raise CtapHidError(cid, ERR_CHANNEL_BUSY, "transaction in progress")
            if cid == BROADCAST_CID and cmd != INIT:
                raise CtapHidError(cid, ERR_INVALID_CHANNEL, "broadcast channel is only for INIT")
            if total > MAX_MESSAGE:
                raise CtapHidError(cid, ERR_INVALID_LEN, f"message of {total} bytes")
            self.partial.pop(cid, None)  # INIT aborts a pending transaction (11.2.9.1.3)
            p = _Partial(cmd, total, bytearray(report[7:7 + min(total, INIT_DATA)]))
        else:
            p = self.partial.get(cid)
            if p is None:
                return None              # spurious continuation: ignored (11.2.4)
            seq = report[4]
            if seq != p.seq:
                del self.partial[cid]
                raise CtapHidError(cid, ERR_INVALID_SEQ, f"sequence {seq}, expected {p.seq}")
            p.seq += 1
            p.data += report[5:5 + min(p.total - len(p.data), CONT_DATA)]
        if len(p.data) >= p.total:
            self.partial.pop(cid, None)
            return Message(cid, p.cmd, bytes(p.data))
        self.partial[cid] = p
        return None


def init_response(nonce: bytes, new_cid: int, version: tuple[int, int, int] = (0, 1, 0),
                  capabilities: int = CAPABILITY_CBOR | CAPABILITY_NMSG) -> bytes:
    """CTAPHID_INIT response payload (11.2.9.1.3): nonce | CID | protocol 2 | version | caps."""
    if len(nonce) != 8:
        raise ValueError("INIT nonce is 8 bytes")
    return nonce + struct.pack(">IBBBBB", new_cid, 2, *version, capabilities)


def error(cid: int, code: int) -> list[bytes]:
    return fragment(Message(cid, ERROR, bytes([code])))


def keepalive(cid: int, status: int = STATUS_PROCESSING) -> list[bytes]:
    return fragment(Message(cid, KEEPALIVE, bytes([status])))


def new_cid(used: set[int]) -> int:
    while True:
        cid = struct.unpack(">I", os.urandom(4))[0]
        if cid not in (0, BROADCAST_CID) and cid not in used:
            return cid
