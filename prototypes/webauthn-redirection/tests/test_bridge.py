# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Bridge: a browser's CTAPHID traffic -> RDPEWA requests -> the client's answer back,
with the security policy (RP ID allow-list, rate limit, consent, one operation)."""

import os
import struct
import unittest

import spec_vectors as V
from fastrdp_ewa import bridge, cbor, ctaphid, rdpewa


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Browser:
    """The host side: what Chromium/Firefox send to a FIDO HID device."""

    def __init__(self, br: bridge.Bridge):
        self.br = br
        self.cid = None
        self.sent: list[bytes] = []      # RDPEWA requests the bridge produced

    def send(self, cid, cmd, payload) -> list[ctaphid.Message]:
        out = []
        for r in ctaphid.fragment(ctaphid.Message(cid, cmd, payload)):
            reports, req = self.br.handle_report(r)
            out += reports
            if req:
                self.sent.append(req)
        return self.parse(out)

    @staticmethod
    def parse(reports) -> list[ctaphid.Message]:
        a, msgs = ctaphid.Assembler(), []
        for r in reports:
            m = a.feed(r)
            if m:
                msgs.append(m)
        return msgs

    def init(self):
        nonce = os.urandom(8)
        [m] = self.send(ctaphid.BROADCAST_CID, ctaphid.INIT, nonce)
        assert m.payload[:8] == nonce
        self.cid = struct.unpack(">I", m.payload[8:12])[0]
        return m

    def ctap(self, command, body=None):
        payload = bytes([command]) + (cbor.encode(body, canonical=True) if body is not None else b"")
        return self.send(self.cid, ctaphid.CBOR, payload)


def get_assertion(rp_id="ctap.dev", uv=True, pin=False):
    m = {1: rp_id, 2: b"\x11" * 32, 5: {"up": True, "uv": uv} if uv else {"up": True}}
    if pin:
        m.update({6: b"\x22" * 16, 7: 1})
    return m


def make_credential(rp_id="ctap.dev"):
    return {1: b"\x33" * 32, 2: {"id": rp_id, "name": "x"}, 3: {"id": b"u1", "name": "alice"},
            4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True, "uv": True}}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.policy = bridge.Policy(allowed_rp_ids=["ctap.dev", ".corp.example"], max_per_minute=3)
        self.br = bridge.Bridge("session-alice", self.policy, clock=self.clock)
        self.b = Browser(self.br)
        self.b.init()

    def status(self, msgs):
        cbor_msgs = [m for m in msgs if m.cmd == ctaphid.CBOR]
        return cbor_msgs[-1].payload[0] if cbor_msgs else None

    def test_init_and_ping(self):
        [m] = self.b.send(self.b.cid, ctaphid.PING, b"hello")
        self.assertEqual((m.cmd, m.payload), (ctaphid.PING, b"hello"))
        [e] = self.b.send(0x12345678, ctaphid.PING, b"x")       # never allocated
        self.assertEqual((e.cmd, e.payload), (ctaphid.ERROR, bytes([ctaphid.ERR_INVALID_CHANNEL])))

    def test_get_info_is_local(self):
        [m] = self.b.ctap(bridge.AUTHN_GET_INFO)
        info = cbor.decode(m.payload[1:])
        self.assertEqual(m.payload[0], 0)
        self.assertIn("FIDO_2_1", info[1])
        self.assertEqual(info[4]["uv"], True)
        self.assertNotIn("clientPin", info[4])    # the browser must not run the PIN protocol here
        self.assertEqual(self.b.sent, [])

    def test_get_assertion_forwarded_and_answered(self):
        msgs = self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion(pin=True))
        self.assertEqual(msgs[0].cmd, ctaphid.KEEPALIVE)
        [raw] = self.b.sent
        req = rdpewa.Request.decode(raw)
        self.assertEqual((req.command, req.ctap_command, req.rp_id_of_request()),
                         (rdpewa.WEB_AUTHN, rdpewa.CMD_GET_ASSERTION, "ctap.dev"))
        self.assertTrue(req.flags & rdpewa.FLAG_UV_REQUIRED)
        self.assertEqual(req.webauthn_para["userVerification"], rdpewa.UV_REQUIRED)
        self.assertNotIn(6, req.ctap_map())       # pinUvAuthParam dropped: the client does UV
        self.assertEqual(req.ctap_map()[2], b"\x11" * 32)   # clientDataHash passes unchanged
        # busy: a second operation waits; keepalives tell the browser to wait for a touch
        self.assertEqual(self.status(self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())),
                         bridge.CTAP2_ERR_CHANNEL_BUSY)
        [k] = Browser.parse(self.br.tick())
        self.assertEqual(k.payload, bytes([ctaphid.STATUS_UPNEEDED]))
        # the client answers with the specification's GetAssertion response
        answer = struct.pack("<I", 0) + V.GET_ASSERTION_RESPONSE_CBOR
        [m] = Browser.parse(self.br.handle_client(answer))
        expected = rdpewa.WebAuthnResult.decode(V.GET_ASSERTION_RESPONSE_CBOR).ctap_response
        self.assertEqual((m.cid, m.payload[0]), (self.b.cid, 0))
        self.assertEqual(cbor.decode(m.payload[1:]), expected)
        self.assertIsNone(self.br.pending)

    def test_make_credential_resident_key(self):
        self.b.ctap(bridge.AUTHN_MAKE_CREDENTIAL, make_credential("vpn.corp.example"))
        req = rdpewa.Request.decode(self.b.sent[-1])
        self.assertEqual(req.ctap_command, rdpewa.CMD_MAKE_CREDENTIAL)
        self.assertIs(req.webauthn_para["requireResident"], True)
        self.assertEqual(req.rp_id_of_request(), "vpn.corp.example")

    def test_rp_not_allowed(self):
        for rp in ("mail.google.com", "corp.example.evil", "xctap.dev"):
            with self.subTest(rp):
                st = self.status(self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion(rp)))
                self.assertEqual(st, bridge.CTAP2_ERR_OPERATION_DENIED)
        self.assertEqual(self.b.sent, [])
        self.assertIn("RP ID not allowed", self.br.log[-1])

    def test_empty_allow_list_forwards_nothing(self):
        self.policy.allowed_rp_ids = []
        self.assertEqual(self.status(self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())),
                         bridge.CTAP2_ERR_OPERATION_DENIED)

    def test_rate_limit(self):
        for _ in range(3):
            self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
            self.br.handle_client(struct.pack("<I", rdpewa.NTE_USER_CANCELLED))
        self.assertEqual(self.status(self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())),
                         bridge.CTAP2_ERR_OPERATION_DENIED)
        self.clock.t += 61
        self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
        self.assertEqual(len(self.b.sent), 4)

    def test_local_consent(self):
        asked = []
        self.policy.confirm = lambda rp, op: asked.append((rp, op)) or False
        st = self.status(self.b.ctap(bridge.AUTHN_MAKE_CREDENTIAL, make_credential()))
        self.assertEqual((st, asked), (bridge.CTAP2_ERR_OPERATION_DENIED, [("ctap.dev", "create")]))

    def test_cancel(self):
        self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
        tid = rdpewa.Request.decode(self.b.sent[-1]).transaction_id
        msgs = self.b.send(self.b.cid, ctaphid.CANCEL, b"")
        self.assertEqual(self.status(msgs), bridge.CTAP2_ERR_KEEPALIVE_CANCEL)
        cancel = rdpewa.Request.decode(self.b.sent[-1])
        self.assertEqual((cancel.command, cancel.request), (rdpewa.CANCEL_CUR_OP, tid))
        self.assertEqual(self.br.handle_client(b"\0\0\0\0" + V.GET_ASSERTION_RESPONSE_CBOR), [])  # late answer dropped

    def test_client_errors(self):
        for answer, code in ((struct.pack("<I", rdpewa.NTE_USER_CANCELLED), bridge.CTAP2_ERR_KEEPALIVE_CANCEL),
                             (struct.pack("<I", 0x80004005), bridge.CTAP2_ERR_OPERATION_DENIED),
                             (b"\0\0\0\0garbage", bridge.CTAP2_ERR_OPERATION_DENIED),
                             (b"\0", bridge.CTAP2_ERR_OPERATION_DENIED)):
            with self.subTest(answer):
                self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
                self.clock.t += 61
                self.assertEqual(self.status(Browser.parse(self.br.handle_client(answer))), code)

    def test_timeout(self):
        self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
        self.clock.t += (self.policy.timeout_ms + 6000) / 1000
        self.assertEqual(self.status(Browser.parse(self.br.tick())), bridge.CTAP2_ERR_USER_ACTION_TIMEOUT)
        self.assertIsNone(self.br.pending)

    def test_unsupported_commands(self):
        for cmd in (bridge.AUTHN_CLIENT_PIN, bridge.AUTHN_GET_NEXT_ASSERTION, 0x0A, 0x41):
            with self.subTest(cmd):
                self.assertEqual(self.status(self.b.ctap(cmd, {1: 1})), bridge.CTAP1_ERR_INVALID_COMMAND)
        [e] = self.b.send(self.b.cid, ctaphid.MSG, b"\0\x01\0\0")       # no U2F
        self.assertEqual(e.payload, bytes([ctaphid.ERR_INVALID_CMD]))
        self.assertEqual(self.b.sent, [])

    def test_bad_cbor(self):
        st = self.status(self.b.send(self.b.cid, ctaphid.CBOR, b"\x02\xff"))
        self.assertEqual(st, bridge.CTAP2_ERR_INVALID_CBOR)
        st = self.status(self.b.ctap(bridge.AUTHN_GET_ASSERTION, {2: b"x"}))   # no RP ID
        self.assertEqual(st, bridge.CTAP2_ERR_INVALID_CBOR)

    def test_sessions_are_separate(self):
        # Each session has its own bridge (and its own uhid device and DVC): a channel
        # allocated in one session is unknown to another, and so are its operations.
        other = bridge.Bridge("session-bob", bridge.Policy(allowed_rp_ids=["ctap.dev"]))
        reports, req = other.handle_report(
            ctaphid.fragment(ctaphid.Message(self.b.cid, ctaphid.CBOR, b"\x02" + cbor.encode(get_assertion())))[0])
        self.assertIsNone(req)
        self.assertEqual(Browser.parse(reports)[0].payload, bytes([ctaphid.ERR_INVALID_CHANNEL]))
        self.b.ctap(bridge.AUTHN_GET_ASSERTION, get_assertion())
        self.assertEqual(other.handle_client(b"\0\0\0\0" + V.GET_ASSERTION_RESPONSE_CBOR), [])
        self.assertIsNotNone(self.br.pending)

    def test_policy_matching(self):
        p = bridge.Policy(allowed_rp_ids=["Login.Example.COM", ".corp.example"])
        self.assertTrue(p.rp_allowed("login.example.com"))
        self.assertTrue(p.rp_allowed("corp.example"))
        self.assertTrue(p.rp_allowed("a.b.corp.example."))
        self.assertFalse(p.rp_allowed("example.com"))
        self.assertFalse(p.rp_allowed("evilcorp.example"))


if __name__ == "__main__":
    unittest.main()
