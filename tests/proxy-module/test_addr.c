/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] AllowTlsFrom matching (broker/proxy-module/fastrdp_addr.h), libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>

#include "../../broker/proxy-module/fastrdp_addr.h"

static int failures;

static void check(const char* list, const char* peer, int want, unsigned want_invalid)
{
	unsigned invalid = 99;
	const int got = fastrdp_addr_allowed(list, peer, &invalid);
	if (got != want || invalid != want_invalid)
	{
		printf("FAIL list=\"%s\" peer=%s: allowed %d (want %d), invalid %u (want %u)\n",
		       list ? list : "(null)", peer ? peer : "(null)", got, want, invalid, want_invalid);
		failures++;
	}
}

int main(void)
{
	const char* loopback = "127.0.0.1,::1";

	/* empty list: everybody (today's behaviour) */
	check(NULL, "203.0.113.7", 1, 0);
	check("", "203.0.113.7", 1, 0);
	check(" , ,", "2001:db8::1", 1, 0);
	check("", NULL, 1, 0);

	/* the web-only default */
	check(loopback, "127.0.0.1", 1, 0);
	check(loopback, "::1", 1, 0);
	check(loopback, "::ffff:127.0.0.1", 1, 0); /* dual-stack listener, IPv4 client */
	check(loopback, "127.0.0.2", 0, 0);
	check(loopback, "203.0.113.7", 0, 0);
	check(loopback, "::ffff:203.0.113.7", 0, 0);
	check(loopback, "::2", 0, 0);
	check(loopback, "", 0, 0);
	check(loopback, NULL, 0, 0);
	check(loopback, "not-an-address", 0, 0);

	/* CIDR, blanks around entries */
	check(" 10.0.0.0/8 , 192.168.1.0/24 ", "10.200.3.4", 1, 0);
	check("10.0.0.0/8, 192.168.1.0/24", "192.168.1.255", 1, 0);
	check("10.0.0.0/8, 192.168.1.0/24", "192.168.2.1", 0, 0);
	check("192.168.1.128/25", "192.168.1.129", 1, 0);
	check("192.168.1.128/25", "192.168.1.127", 0, 0);
	check("172.16.0.0/12", "172.31.255.255", 1, 0);
	check("172.16.0.0/12", "172.32.0.0", 0, 0);
	check("0.0.0.0/0", "198.51.100.1", 1, 0);
	check("0.0.0.0/0", "2001:db8::1", 0, 0); /* IPv4 range, IPv6 peer */
	check("::/0", "2001:db8::1", 1, 0);
	check("::/0", "::ffff:10.0.0.1", 0, 0); /* mapped peers count as IPv4 */
	check("fd00::/8", "fd12:3456::1", 1, 0);
	check("fd00::/8", "fe80::1", 0, 0);
	check("2001:db8::/33", "2001:db8:7fff::1", 1, 0);
	check("2001:db8::/33", "2001:db8:8000::1", 0, 0);
	check("127.0.0.1/32", "127.0.0.1", 1, 0);

	/* IPv4-mapped entries */
	check("::ffff:10.0.0.0/104", "10.1.2.3", 1, 0);
	check("::ffff:10.0.0.0/104", "11.1.2.3", 0, 0);
	check("::ffff:127.0.0.1", "127.0.0.1", 1, 0);
	check("::ffff:0.0.0.0/64", "10.0.0.1", 0, 1); /* wider than the mapped space */

	/* invalid entries never match and are counted; valid ones still work */
	check("127.0.0.1/33", "127.0.0.1", 0, 1);
	check("::1/129", "::1", 0, 1);
	check("10.0.0.0/", "10.0.0.1", 0, 1);
	check("10.0.0.0/-1", "10.0.0.1", 0, 1);
	check("10.0.0.0/8x", "10.0.0.1", 0, 1);
	check("localhost, 127.0.0.1", "127.0.0.1", 1, 1);
	check("[::1]", "::1", 0, 1);
	check("10.0.0.0/8 192.168.0.0/16", "10.0.0.1", 0, 1); /* blank is not a separator */
	check("0000000000000000000000000000000000000000000000000000000000000000000", "127.0.0.1", 0, 1);
	check("bogus", NULL, 0, 1);

	if (failures)
		return 1;
	printf("ok   AllowTlsFrom address matching (%s)\n", "fastrdp_addr.h");
	return 0;
}
