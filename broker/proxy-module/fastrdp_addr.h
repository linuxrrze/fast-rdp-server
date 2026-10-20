/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * Address lists for [FastRDP] AllowTlsFrom: comma-separated IPv4/IPv6 addresses and
 * CIDR ranges ("127.0.0.1, ::1, 10.0.0.0/8, fd00::/8"). libc only, so that
 * tests/proxy-module/test_addr.c can test it without FreeRDP.
 *
 * IPv4-mapped IPv6 addresses (::ffff:a.b.c.d, what a dual-stack listener reports for
 * IPv4 clients) count as the IPv4 address, both as peer and as list entry (a mapped
 * entry's prefix counts from bit 96). An IPv4 peer never matches a native IPv6 entry.
 */
#ifndef FASTRDP_ADDR_H
#define FASTRDP_ADDR_H

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
	int family; /* AF_INET or AF_INET6 */
	unsigned char bytes[16];
} fastrdpAddr;

/* Parses one address; IPv4-mapped IPv6 becomes IPv4 (*mapped tells). 0 if invalid. */
static int fastrdp_addr_parse(const char* s, fastrdpAddr* out, int* mapped)
{
	static const unsigned char v4mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	memset(out, 0, sizeof(*out));
	*mapped = 0;
	if (inet_pton(AF_INET, s, out->bytes) == 1)
	{
		out->family = AF_INET;
		return 1;
	}
	if (inet_pton(AF_INET6, s, out->bytes) != 1)
		return 0;
	out->family = AF_INET6;
	if (memcmp(out->bytes, v4mapped, sizeof(v4mapped)) == 0)
	{
		memmove(out->bytes, out->bytes + 12, 4);
		memset(out->bytes + 4, 0, 12);
		out->family = AF_INET;
		*mapped = 1;
	}
	return 1;
}

static int fastrdp_addr_prefix_match(const fastrdpAddr* a, const fastrdpAddr* net, unsigned bits)
{
	if (a->family != net->family)
		return 0;
	const unsigned full = bits / 8;
	const unsigned rest = bits % 8;
	if (memcmp(a->bytes, net->bytes, full) != 0)
		return 0;
	if (rest == 0)
		return 1;
	const unsigned char mask = (unsigned char)(0xff << (8 - rest));
	return (a->bytes[full] & mask) == (net->bytes[full] & mask);
}

/* One list entry against the peer (NULL: only validate): 1 match, 0 no match, -1 invalid. */
static int fastrdp_addr_entry_match(const char* entry, const fastrdpAddr* peer)
{
	char buf[64];
	const size_t len = strlen(entry);
	if (len == 0 || len >= sizeof(buf))
		return -1;
	memcpy(buf, entry, len + 1);

	long bits = -1;
	char* slash = strchr(buf, '/');
	if (slash)
	{
		*slash = '\0';
		char* end = NULL;
		if (!isdigit((unsigned char)slash[1]))
			return -1;
		bits = strtol(slash + 1, &end, 10);
		if (*end != '\0')
			return -1;
	}

	fastrdpAddr net;
	int mapped = 0;
	if (!fastrdp_addr_parse(buf, &net, &mapped))
		return -1;
	const long max = (net.family == AF_INET && !mapped) ? 32 : 128;
	if (bits < 0)
		bits = max;
	if (bits > max)
		return -1;
	if (mapped)
	{
		/* ::ffff:a.b.c.d/N: N counts IPv6 bits. Below 96 the range covers more than the
		 * mapped space; such an entry is not meaningful for an address list. */
		if (bits < 96)
			return -1;
		bits -= 96;
	}
	return peer && fastrdp_addr_prefix_match(peer, &net, (unsigned)bits);
}

/* Is `peer` (a numeric address as inet_ntop prints it) in `list`? An empty list (NULL,
 * "", only separators/blanks) allows every peer. An unparsable peer is never allowed by a
 * non-empty list. *invalid (optional) receives the number of unparsable entries; they
 * never match. */
static int fastrdp_addr_allowed(const char* list, const char* peer, unsigned* invalid)
{
	unsigned bad = 0;
	int entries = 0;
	int allowed = 0;
	fastrdpAddr p;
	int mapped = 0;
	const int peer_ok = peer && fastrdp_addr_parse(peer, &p, &mapped);

	for (const char* c = list ? list : ""; *c;)
	{
		while (*c == ',' || isspace((unsigned char)*c))
			c++;
		const char* start = c;
		while (*c && *c != ',')
			c++;
		const char* end = c;
		while (end > start && isspace((unsigned char)end[-1]))
			end--;
		if (end == start)
			continue;
		entries++;
		char entry[64];
		const size_t n = (size_t)(end - start);
		int r = -1;
		if (n < sizeof(entry))
		{
			memcpy(entry, start, n);
			entry[n] = '\0';
			r = fastrdp_addr_entry_match(entry, peer_ok ? &p : NULL);
		}
		if (r < 0)
			bad++;
		else if (r > 0)
			allowed = 1;
	}
	if (invalid)
		*invalid = bad;
	if (entries == 0)
		return 1;
	return peer_ok && allowed;
}

#endif /* FASTRDP_ADDR_H */
