# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
"""KDCs and kpasswd servers of one realm from DNS SRV records, as JSON (role web_gateway).

    python3 fastrdp_kdcproxy_srv.py <realm>
    -> {"kerberos": ["dc1.example.com:88", ...], "kpasswd": ["dc1.example.com:464", ...]}

Run on the host (its resolver, like krb5 with dns_lookup_kdc) with dnspython, which
python3-kdcproxy depends on. TCP records only: the proxy talks TCP to the KDCs.
Sorted by priority, then weight (highest first), then name, so a re-run writes the same file.
"""

import json
import sys

import dns.exception
import dns.resolver


def lookup(name):
    try:
        answer = dns.resolver.resolve(name, "SRV")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        sys.exit(f"SRV lookup {name} failed: {exc}")
    recs = sorted(answer, key=lambda r: (r.priority, -r.weight, str(r.target).lower()))
    # RFC 2782: a target of "." means the service is not offered
    return [f"{str(r.target).rstrip('.').lower()}:{r.port}" for r in recs if str(r.target) != "."]


def main():
    if len(sys.argv) != 2 or not sys.argv[1]:
        sys.exit("usage: fastrdp_kdcproxy_srv.py <realm>")
    domain = sys.argv[1].lower()
    print(json.dumps({"kerberos": lookup(f"_kerberos._tcp.{domain}"),
                      "kpasswd": lookup(f"_kpasswd._tcp.{domain}")}))


if __name__ == "__main__":
    main()
