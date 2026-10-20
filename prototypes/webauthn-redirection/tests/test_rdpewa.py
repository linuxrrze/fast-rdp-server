# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""[MS-RDPEWA] messages against the specification's own examples (section 4)."""

import hashlib
import json
import struct
import unittest

import spec_vectors as V
from fastrdp_ewa import cbor, rdpewa


class SpecRequests(unittest.TestCase):
    def roundtrip(self, data: bytes) -> rdpewa.Request:
        req = rdpewa.Request.decode(data)
        self.assertEqual(req.encode(), data, "re-encoding must reproduce the spec bytes")
        return req

    def test_simple_requests(self):
        api = self.roundtrip(V.API_VERSION_REQUEST)
        # the example titled API_VERSION carries command 5 (specification erratum)
        self.assertEqual((api.command, api.flags, api.timeout, api.transaction_id), (5, 0, 0, b"\0" * 16))
        self.assertEqual(self.roundtrip(V.IUVPAA_REQUEST).command, rdpewa.IUVPAA)
        cancel = self.roundtrip(V.CANCEL_REQUEST)
        self.assertEqual(cancel.command, rdpewa.CANCEL_CUR_OP)
        self.assertEqual(cancel.request.hex(), "7fdfbddf000000000000000000000000")

    def test_make_credential(self):
        req = self.roundtrip(V.MAKE_CREDENTIAL_REQUEST)
        self.assertEqual(req.command, rdpewa.WEB_AUTHN)
        self.assertEqual(req.timeout, 300000)
        self.assertEqual(req.transaction_id.hex(), "26c98f33fcd61d4dba5b27570f8293df")
        self.assertTrue(req.flags & rdpewa.FLAG_UV_REQUIRED)
        self.assertTrue(req.flags & rdpewa.FLAG_HMAC_SECRET_EXTENSION)
        self.assertEqual(req.ctap_command, rdpewa.CMD_MAKE_CREDENTIAL)
        self.assertEqual(req.rp_id_of_request(), "ctap.dev")
        m = req.ctap_map()
        self.assertEqual(m[1].hex(), "19eedf1f51a140b34b316293b10c2bc0e6c53860771bb1dda4a82e5de94a4e7c")
        self.assertEqual(m[2], {"id": "ctap.dev", "name": "WebAuthn Test Server"})
        self.assertEqual(m[3]["name"], "mike@example.com")
        self.assertEqual([p["alg"] for p in m[4]], [-7, -257])
        self.assertEqual(m[7], {"rk": True})
        para = req.webauthn_para
        self.assertEqual((para["attachment"], para["requireResident"], para["userVerification"],
                          para["attestationPreference"]), (rdpewa.ATTACHMENT_CROSS_PLATFORM, True,
                                                           rdpewa.UV_REQUIRED, rdpewa.ATTESTATION_DIRECT))
        cd = json.loads(req.client_data_json)
        self.assertEqual((cd["type"], cd["origin"]), ("webauthn.create", "https://ctap.dev"))
        self.assertEqual(set(req.extra), {"filterHybridTransport", "thirdPartyPayment"})

    def test_get_assertion(self):
        req = self.roundtrip(V.GET_ASSERTION_REQUEST)
        self.assertEqual(req.ctap_command, rdpewa.CMD_GET_ASSERTION)
        self.assertEqual(req.rp_id_of_request(), "ctap.dev")
        m = req.ctap_map()
        self.assertEqual(len(m[3]), 2)
        self.assertEqual(m[5], {"up": True})
        self.assertIs(req.extra["filterHybridTransport"], True)
        self.assertIn("hmacSecretSaltValues", req.extra)
        self.assertEqual(json.loads(req.client_data_json)["type"], "webauthn.get")

    def test_metadata_requests(self):
        cred = self.roundtrip(V.GET_CREDENTIALS_REQUEST)
        self.assertEqual((cred.command, cred.rp_id, cred.rp_id_of_request()),
                         (rdpewa.GET_CREDENTIALS, "ctap.dev", "ctap.dev"))
        self.assertEqual(self.roundtrip(V.GET_AUTHENTICATOR_LIST_REQUEST).command, rdpewa.GET_AUTHENTICATOR_LIST)


class SpecResponses(unittest.TestCase):
    def test_make_credential_response(self):
        r = rdpewa.Response.decode(struct.pack("<I", 0) + V.MAKE_CREDENTIAL_RESPONSE_CBOR)
        self.assertTrue(r.ok)
        res = r.as_webauthn()
        self.assertEqual(res.device_info["manufacturer"], "Yubico")
        self.assertEqual(res.device_info["aaGuid"].hex(), "9f2d52d85b57664888a9ba99fa02f35b")
        self.assertEqual((res.status, res.ctap_status), (0, rdpewa.CTAP2_OK))
        self.assertEqual(res.ctap_response[1], "packed")
        auth_data = res.ctap_response[2]
        self.assertEqual(auth_data[:32], hashlib.sha256(b"ctap.dev").digest(), "rpIdHash")
        self.assertTrue(auth_data[32] & 0x04, "UV flag")
        self.assertEqual(res.ctap_response[3]["alg"], -7)
        self.assertEqual(len(res.ctap_response[3]["x5c"]), 1)

    def test_get_assertion_response(self):
        res = rdpewa.Response.decode(b"\0\0\0\0" + V.GET_ASSERTION_RESPONSE_CBOR).as_webauthn()
        self.assertEqual(set(res.ctap_response), {1, 2, 3, 4})
        # authData: rpIdHash(32) | flags | signCount. The specification's GetAssertion
        # example is not for ctap.dev (its rpIdHash differs from the MakeCredential one).
        self.assertGreaterEqual(len(res.ctap_response[2]), 37)
        self.assertTrue(res.ctap_response[2][32] & 0x01, "UP flag")
        self.assertEqual(res.device_info["credentialListIndexPlusOne"], 2)
        # what the bridge hands back to the browser: status byte + canonical CTAP map
        payload = res.ctaphid_payload
        self.assertEqual(payload[0], 0)
        self.assertTrue(cbor.is_canonical(payload[1:]))
        self.assertEqual(cbor.decode(payload[1:]), res.ctap_response)

    def test_authenticator_list(self):
        a = rdpewa.Response.decode(b"\0\0\0\0" + V.GET_AUTHENTICATOR_LIST_RESPONSE_CBOR).as_array()
        self.assertEqual((a[0][1], a[0][3], a[0][5]), (1, "Windows Hello", False))

    def test_simple_payloads(self):
        self.assertEqual(rdpewa.Response.decode(bytes.fromhex("0000000004000000")).as_uint32(), 4)
        r = rdpewa.Response.uint32(1)
        self.assertEqual(r.encode(), bytes.fromhex("0000000001000000"))
        cancelled = rdpewa.Response.decode(struct.pack("<I", rdpewa.NTE_USER_CANCELLED))
        self.assertFalse(cancelled.ok)
        with self.assertRaises(rdpewa.RdpewaError):
            rdpewa.Response.decode(b"\0\0")

    def test_webauthn_result_roundtrip(self):
        res = rdpewa.WebAuthnResult({"providerType": "Hid"}, 0, 0, {1: {"id": b"x", "type": "public-key"}})
        back = rdpewa.Response.decode(rdpewa.Response.webauthn(res).encode()).as_webauthn()
        self.assertEqual((back.device_info, back.ctap_response), (res.device_info, res.ctap_response))
        err = rdpewa.WebAuthnResult({}, 0, 0x27, None)    # CTAP2_ERR_OPERATION_DENIED, no map
        self.assertEqual(rdpewa.WebAuthnResult.decode(err.encode()).ctaphid_payload, b"\x27")


class Building(unittest.TestCase):
    def test_webauthn_without_request_is_unusable(self):
        req = rdpewa.Request.decode(cbor.encode({"command": 5}))
        with self.assertRaises(rdpewa.RdpewaError):
            req.ctap_map()

    def test_make_webauthn_request(self):
        req = rdpewa.make_webauthn_request(rdpewa.CMD_GET_ASSERTION, {2: b"h" * 32, 1: "example.com"},
                                           flags=rdpewa.FLAG_UV_REQUIRED, timeout=30000)
        back = rdpewa.Request.decode(req.encode())
        self.assertEqual(back.rp_id_of_request(), "example.com")
        self.assertTrue(cbor.is_canonical(back.request[1:]))
        self.assertEqual(len(back.transaction_id), 16)
        with self.assertRaises(rdpewa.RdpewaError):
            rdpewa.make_webauthn_request(0x06, {})

    def test_refused(self):
        bad = {
            "not a map": cbor.encode([1]),
            "no command": cbor.encode({"flags": 0}),
            "bool command": cbor.encode({"command": True}),
            "negative flags": cbor.encode({"command": 5, "flags": -1, "request": b"\x01\xa0"}),
            "short transactionId": cbor.encode({"command": 6, "transactionId": b"\0" * 8}),
            "WEB_AUTHN without CTAP command": cbor.encode({"command": 5, "request": b"\x06\xa0"}),
            "CANCEL without GUID": cbor.encode({"command": 7, "request": b"\0"}),
            "webAuthNPara not a map": cbor.encode({"command": 6, "webAuthNPara": 1}),
            "rpId not text": cbor.encode({"command": 9, "rpId": b"x"}),
        }
        for name, data in bad.items():
            with self.subTest(name), self.assertRaises((rdpewa.RdpewaError, cbor.CborError)):
                rdpewa.Request.decode(data)

    def test_case_insensitive_keys(self):
        # the field list spells "transactionid", the examples "transactionId"
        req = rdpewa.Request.decode(cbor.encode({"command": 6, "transactionid": b"\1" * 16}))
        self.assertEqual(req.transaction_id, b"\1" * 16)


if __name__ == "__main__":
    unittest.main()
