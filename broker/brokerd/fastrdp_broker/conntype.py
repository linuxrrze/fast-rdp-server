# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""Connection type for the proxy's back-end hop ([MS-RDPBCGR] 2.2.1.3.2 connectionType).

xrdp picks its encoder profile (gfx.toml `[x264.<type>]`, `[ffmpeg.<type>]`) from the
connection type in the Client Core Data. mstsc sends CONNECTION_TYPE_AUTODETECT (7) by
default and the proxy does no network auto-detection, and xrdp 0.10.6.1 encodes type 7
like `lan` (uncapped). The broker therefore tells the proxy module which type to send to
xrdp instead:

- the client chose a type itself (1..6: `.rdp` `connection type:i:N`, FreeRDP
  `/network:`): unchanged;
- otherwise (7, unset, invalid) and the client's socket address is in
  `[network] lan_networks`: `lan`;
- otherwise: `[network] xrdp_autodetect_profile` (`default` = unchanged).
"""

from __future__ import annotations

import ipaddress

# connectionType values 1..6, named like xrdp's gfx.toml sections
NAMES = ("modem", "broadband_low", "satellite", "broadband_high", "wan", "lan")
AUTODETECT = 7
# `default` = do not change the type (xrdp then encodes type 7 like `lan`)
PROFILES = (*NAMES, "default")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(values: object) -> tuple[Network, ...]:
    """CIDR strings (IPv4/IPv6) -> networks; ValueError names the first bad entry."""
    if not isinstance(values, list):
        raise ValueError("must be a list of CIDRs, e.g. [\"10.0.0.0/8\", \"2001:db8::/32\"]")
    nets = []
    for v in values:
        if not isinstance(v, str):
            raise ValueError(f"{v!r} is not a CIDR string")
        try:
            nets.append(ipaddress.ip_network(v.strip(), strict=True))
        except ValueError as exc:
            raise ValueError(f"{v!r}: {exc}") from None
    return tuple(nets)


def address_in(address: str | None, networks: tuple[Network, ...]) -> bool:
    """True if the client's socket address lies in one of the networks. IPv4-mapped
    IPv6 addresses (::ffff:a.b.c.d, from dual-stack listeners) count as IPv4."""
    if not address or not networks:
        return False
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in networks)


def for_backend(
    client_type: object, client_address: str | None, lan_networks: tuple[Network, ...], profile: str
) -> str | None:
    """Connection type name to send to the back-end, or None to leave the client's.

    client_type: the connectionType the client sent (0 = RNS_UD_CS_VALID_CONNECTION_TYPE
    not set); anything that is not an int counts as unset."""
    if isinstance(client_type, int) and not isinstance(client_type, bool) and 1 <= client_type <= 6:
        return None  # explicit client choice
    if address_in(client_address, lan_networks):
        return "lan"
    return None if profile == "default" else profile
