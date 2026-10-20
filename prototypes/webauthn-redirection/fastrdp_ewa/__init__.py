# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Prototype: protocol-independent core of server-side WebAuthn redirection ([MS-RDPEWA])
for Linux sessions. Not used by fastrdp; see docs/webauthn-redirection.md.

  cbor     minimal CBOR (RFC 8949) with CTAP2 canonical encoding
  rdpewa   WebAuthN_Channel request/response messages ([MS-RDPEWA] 2.2)
  ctaphid  CTAPHID framing for a virtual FIDO HID device (CTAP 2.1, 11.2)
  bridge   CTAPHID/CTAP2 <-> RDPEWA mapping with the security policy hooks
"""
