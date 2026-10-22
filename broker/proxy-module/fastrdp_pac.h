/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * Group SIDs from a PAC_LOGON_INFO buffer ([MS-PAC] 2.5: KERB_VALIDATION_INFO, NDR with
 * the [MS-RPCE] 2.2.6 type serialization version 1 headers): the domain groups
 * (LogonDomainId + GroupIds), ExtraSids (other domains' universal groups, the well-known
 * S-1-18-x "asserted identity" SIDs) and resource groups (ResourceGroupDomainSid +
 * ResourceGroupIds). The user's own SID is not a group and is never reported.
 *
 * The buffer comes from patches/freerdp/0005 (SECPKG_ATTR_KERBEROS_PAC_LOGON_INFO), which
 * hands it over only from a PAC whose server signature verified with the service key: the
 * KDC wrote it. It is still parsed as untrusted input: every read is bounds-checked, counts
 * must match their arrays, and a buffer that does not parse in full yields nothing.
 * Groups whose attributes lack SE_GROUP_ENABLED or carry SE_GROUP_USE_FOR_DENY_ONLY are
 * left out. libc only, so that tests/proxy-module/test_pac.c can test it without FreeRDP.
 */
#ifndef FASTRDP_PAC_H
#define FASTRDP_PAC_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum
{
	FASTRDP_PAC_GROUPS = 1 << 0,   /* LogonDomainId + GroupIds */
	FASTRDP_PAC_EXTRA = 1 << 1,    /* ExtraSids */
	FASTRDP_PAC_RESOURCE = 1 << 2, /* ResourceGroupDomainSid + ResourceGroupIds */
	FASTRDP_PAC_ALL = 7
};

#define FASTRDP_PAC_MAX_GROUPS 1024        /* per array; Windows tokens hold at most 1024 SIDs */
#define FASTRDP_PAC_SID_LEN 192            /* "S-1-" + 6-byte authority + 15 x 10 digits */
#define FASTRDP_SE_GROUP_ENABLED 0x4u
#define FASTRDP_SE_GROUP_USE_FOR_DENY_ONLY 0x10u

typedef int (*fastrdp_pac_emit)(void* ctx, const char* sid);

typedef struct
{
	const unsigned char* buf;
	size_t len;
	size_t pos;
} fastrdpNdr;

static int fastrdp_ndr_align4(fastrdpNdr* n)
{
	const size_t pad = (4 - (n->pos & 3)) & 3;
	if (n->len - n->pos < pad)
		return 0;
	n->pos += pad;
	return 1;
}

static int fastrdp_ndr_u32(fastrdpNdr* n, uint32_t* v)
{
	if (!fastrdp_ndr_align4(n) || n->len - n->pos < 4)
		return 0;
	const unsigned char* p = n->buf + n->pos;
	*v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	n->pos += 4;
	return 1;
}

static int fastrdp_ndr_skip(fastrdpNdr* n, size_t bytes)
{
	if (n->len - n->pos < bytes)
		return 0;
	n->pos += bytes;
	return 1;
}

/* RPC_UNICODE_STRING buffer (conformant varying WCHAR array) of a non-null pointer */
static int fastrdp_ndr_skip_string(fastrdpNdr* n, uint32_t ptr, uint16_t length)
{
	uint32_t max = 0, offset = 0, actual = 0;
	if (!ptr)
		return 1;
	if (!fastrdp_ndr_u32(n, &max) || !fastrdp_ndr_u32(n, &offset) || !fastrdp_ndr_u32(n, &actual))
		return 0;
	if (offset != 0 || actual > max || actual != length / 2u)
		return 0;
	return fastrdp_ndr_skip(n, (size_t)actual * 2) && fastrdp_ndr_align4(n);
}

/* RPC_SID ([MS-DTYP] 2.4.2.3) of a non-null pointer, formatted into out (NUL-terminated) */
static int fastrdp_ndr_sid(fastrdpNdr* n, char out[FASTRDP_PAC_SID_LEN])
{
	uint32_t max = 0;
	if (!fastrdp_ndr_u32(n, &max) || max > 15 || n->len - n->pos < 8)
		return 0;
	const unsigned char* p = n->buf + n->pos;
	if (p[0] != 1 || p[1] != max)
		return 0;
	uint64_t authority = 0;
	for (int i = 2; i < 8; i++)
		authority = (authority << 8) | p[i];
	n->pos += 8;
	int o = (authority >> 32) ? snprintf(out, FASTRDP_PAC_SID_LEN, "S-1-0x%012" PRIX64, authority)
	                          : snprintf(out, FASTRDP_PAC_SID_LEN, "S-1-%" PRIu64, authority);
	for (uint32_t i = 0; i < max; i++)
	{
		uint32_t sub = 0;
		if (o < 0 || o >= FASTRDP_PAC_SID_LEN || !fastrdp_ndr_u32(n, &sub))
			return 0;
		o += snprintf(out + o, FASTRDP_PAC_SID_LEN - (size_t)o, "-%" PRIu32, sub);
	}
	return o > 0 && o < FASTRDP_PAC_SID_LEN;
}

static int fastrdp_pac_enabled(uint32_t attributes)
{
	return (attributes & FASTRDP_SE_GROUP_ENABLED) &&
	       !(attributes & FASTRDP_SE_GROUP_USE_FOR_DENY_ONLY);
}

/* GROUP_MEMBERSHIP array of a non-null pointer: domain SID + RID per enabled group */
static int fastrdp_ndr_groups(fastrdpNdr* n, uint32_t count, const char* domain, int emit_them,
                              fastrdp_pac_emit emit, void* ctx)
{
	uint32_t max = 0;
	if (!fastrdp_ndr_u32(n, &max) || max != count)
		return 0;
	for (uint32_t i = 0; i < count; i++)
	{
		uint32_t rid = 0, attributes = 0;
		if (!fastrdp_ndr_u32(n, &rid) || !fastrdp_ndr_u32(n, &attributes))
			return 0;
		if (emit_them && domain[0] && fastrdp_pac_enabled(attributes))
		{
			char sid[FASTRDP_PAC_SID_LEN + 16];
			(void)snprintf(sid, sizeof(sid), "%s-%" PRIu32, domain, rid);
			if (!emit(ctx, sid))
				return 0;
		}
	}
	return 1;
}

/* One pass over buf; emits the SIDs of the kinds in `kinds` (0: validate only). Group
 * arrays come before their domain SID on the wire, so they are read twice: once to skip,
 * once (after the domain SID) to emit. */
static int fastrdp_pac_walk(const unsigned char* buf, size_t len, unsigned kinds,
                            fastrdp_pac_emit emit, void* ctx)
{
	fastrdpNdr n = { buf, len, 0 };
	uint32_t ptr = 0;

	/* [MS-RPCE] 2.2.6.1 common header (version 1, little-endian, length 8) and 2.2.6.2
	 * private header (object length, filler) */
	if (len < 16 || buf[0] != 1 || buf[1] != 0x10 || buf[2] != 8 || buf[3] != 0)
		return 0;
	n.pos = 8;
	uint32_t objlen = 0, filler = 0;
	if (!fastrdp_ndr_u32(&n, &objlen) || !fastrdp_ndr_u32(&n, &filler) || objlen > len - 16)
		return 0;
	n.len = 16 + (size_t)objlen;

	/* top-level referent, then the fixed part of KERB_VALIDATION_INFO (216 bytes) */
	if (!fastrdp_ndr_u32(&n, &ptr) || !ptr || n.len - n.pos < 216)
		return 0;
	const unsigned char* f = buf + n.pos;
#define FASTRDP_U16(o) ((uint16_t)(f[o] | (f[(o) + 1] << 8)))
#define FASTRDP_U32(o) \
	((uint32_t)f[o] | ((uint32_t)f[(o) + 1] << 8) | ((uint32_t)f[(o) + 2] << 16) | \
	 ((uint32_t)f[(o) + 3] << 24))
	/* six RPC_UNICODE_STRINGs at 48..95, two more at 136 and 144 */
	static const size_t strings[] = { 48, 56, 64, 72, 80, 88, 136, 144 };
	const uint32_t group_count = FASTRDP_U32(108), group_ptr = FASTRDP_U32(112);
	const uint32_t domain_ptr = FASTRDP_U32(152);
	const uint32_t sid_count = FASTRDP_U32(196), extra_ptr = FASTRDP_U32(200);
	const uint32_t resdom_ptr = FASTRDP_U32(204), res_count = FASTRDP_U32(208);
	const uint32_t res_ptr = FASTRDP_U32(212);
	uint16_t slen[8];
	uint32_t sptr[8];
	for (size_t i = 0; i < 8; i++)
	{
		slen[i] = FASTRDP_U16(strings[i]);
		sptr[i] = FASTRDP_U32(strings[i] + 4);
	}
#undef FASTRDP_U16
#undef FASTRDP_U32
	n.pos += 216;
	if (group_count > FASTRDP_PAC_MAX_GROUPS || sid_count > FASTRDP_PAC_MAX_GROUPS ||
	    res_count > FASTRDP_PAC_MAX_GROUPS || (!group_ptr && group_count) ||
	    (!extra_ptr && sid_count) || (!res_ptr && res_count) || !domain_ptr)
		return 0;

	/* deferred pointers in declaration order */
	for (size_t i = 0; i < 6; i++)
		if (!fastrdp_ndr_skip_string(&n, sptr[i], slen[i]))
			return 0;
	const size_t groups_at = n.pos;
	if (group_ptr && !fastrdp_ndr_groups(&n, group_count, "", 0, emit, ctx))
		return 0;
	for (size_t i = 6; i < 8; i++)
		if (!fastrdp_ndr_skip_string(&n, sptr[i], slen[i]))
			return 0;
	char domain[FASTRDP_PAC_SID_LEN];
	if (!fastrdp_ndr_sid(&n, domain))
		return 0;
	if (group_ptr && (kinds & FASTRDP_PAC_GROUPS))
	{
		fastrdpNdr g = { n.buf, n.len, groups_at };
		if (!fastrdp_ndr_groups(&g, group_count, domain, 1, emit, ctx))
			return 0;
	}

	if (extra_ptr)
	{
		/* KERB_SID_AND_ATTRIBUTES array, then the SIDs of its non-null pointers */
		uint32_t max = 0, attributes[FASTRDP_PAC_MAX_GROUPS];
		uint8_t present[FASTRDP_PAC_MAX_GROUPS];
		if (!fastrdp_ndr_u32(&n, &max) || max != sid_count)
			return 0;
		for (uint32_t i = 0; i < sid_count; i++)
		{
			uint32_t p = 0;
			if (!fastrdp_ndr_u32(&n, &p) || !fastrdp_ndr_u32(&n, &attributes[i]))
				return 0;
			present[i] = p != 0;
		}
		for (uint32_t i = 0; i < sid_count; i++)
		{
			char sid[FASTRDP_PAC_SID_LEN];
			if (!present[i])
				continue;
			if (!fastrdp_ndr_sid(&n, sid))
				return 0;
			if ((kinds & FASTRDP_PAC_EXTRA) && fastrdp_pac_enabled(attributes[i]) && !emit(ctx, sid))
				return 0;
		}
	}

	char resdom[FASTRDP_PAC_SID_LEN] = "";
	if (resdom_ptr && !fastrdp_ndr_sid(&n, resdom))
		return 0;
	if (res_ptr &&
	    !fastrdp_ndr_groups(&n, res_count, resdom, (kinds & FASTRDP_PAC_RESOURCE) != 0, emit, ctx))
		return 0;
	return 1;
}

/**
 * Calls emit(ctx, "S-1-...") for each enabled group SID of the kinds in `kinds`
 * (FASTRDP_PAC_*), in wire order. Returns 1 if the whole buffer parsed; 0 if it is
 * malformed (then emit was never called) or emit returned 0 (stop).
 */
static int fastrdp_pac_group_sids(const unsigned char* buf, size_t len, unsigned kinds,
                                  fastrdp_pac_emit emit, void* ctx)
{
	if (!buf || !fastrdp_pac_walk(buf, len, 0, emit, ctx))
		return 0;
	return fastrdp_pac_walk(buf, len, kinds, emit, ctx);
}

#endif /* FASTRDP_PAC_H */
