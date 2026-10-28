/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The drdynvc and RDPGFX PDUs of the waiting screen over GFX
 * (broker/proxy-module/fastrdp_gfx.h): bytes of the server PDUs ([MS-RDPEDYC],
 * [MS-RDPEGFX]), DVC fragmentation and reassembly, the RDP_SEGMENTED_DATA wrapper, the
 * parsers for the client's answers and the choice of the capability set. libc only; the
 * e2e test (tests/proxy-e2e/run.sh) checks them against FreeRDP's client.
 * Build and run: make test-proxy-module */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../broker/proxy-module/fastrdp_gfx.h"

static int failures;

#define CHECK(cond, ...)                \
	do                                  \
	{                                   \
		if (!(cond))                    \
		{                               \
			printf("FAIL %s: ", #cond); \
			printf(__VA_ARGS__);        \
			printf("\n");               \
			failures++;                 \
		}                               \
	} while (0)

static int same(const fastrdpBuf* b, const uint8_t* want, size_t n)
{
	return !b->failed && b->len == n && memcmp(b->data, want, n) == 0;
}

/* the PDUs fastrdp_dvc_send_message() hands out, reassembled like a client would */
typedef struct
{
	unsigned pdus;
	size_t largest;
	fastrdpDvcReasm r;
	uint8_t out[8192];
	size_t out_len;
	int complete, error;
	unsigned first_cmd;
} sink;

static int collect(void* ctx, const uint8_t* pdu, size_t len)
{
	sink* k = ctx;
	fastrdpDvcPdu p;
	if (k->pdus++ == 0)
		k->first_cmd = pdu[0] >> 4;
	if (len > k->largest)
		k->largest = len;
	if (!fastrdp_dvc_parse(pdu, len, &p) || p.chid != 0x7D00)
	{
		k->error = 1;
		return 1;
	}
	const uint8_t* msg = NULL;
	size_t n = 0;
	const int rc = fastrdp_dvc_reasm(&k->r, &p, sizeof(k->out), &msg, &n);
	if (rc < 0)
		k->error = 1;
	if (rc > 0)
	{
		memcpy(k->out, msg, n);
		k->out_len = n;
		k->complete++;
	}
	return 1;
}

static void test_dvc_server(void)
{
	fastrdpBuf b = { 0 };
	fastrdp_dvc_caps_request(&b);
	static const uint8_t caps[] = { 0x50, 0x00, 0x01, 0x00 };
	CHECK(same(&b, caps, sizeof(caps)), "caps request");
	fastrdp_buf_free(&b);

	fastrdp_dvc_create_request(&b, 0x7D00, "AB");
	static const uint8_t create[] = { 0x11, 0x00, 0x7D, 'A', 'B', 0 };
	CHECK(same(&b, create, sizeof(create)), "create request, 2-byte id");
	fastrdp_buf_free(&b);
	fastrdp_dvc_create_request(&b, 7, "A");
	static const uint8_t create1[] = { 0x10, 0x07, 'A', 0 };
	CHECK(same(&b, create1, sizeof(create1)), "create request, 1-byte id");
	fastrdp_buf_free(&b);
	fastrdp_dvc_create_request(&b, 0x12345, "A");
	static const uint8_t create4[] = { 0x12, 0x45, 0x23, 0x01, 0x00, 'A', 0 };
	CHECK(same(&b, create4, sizeof(create4)), "create request, 4-byte id");
	fastrdp_buf_free(&b);

	fastrdp_dvc_close(&b, 0x7D00);
	static const uint8_t close[] = { 0x41, 0x00, 0x7D };
	CHECK(same(&b, close, sizeof(close)), "close");
	fastrdp_buf_free(&b);

	/* a short message: one DYNVC_DATA */
	sink k = { 0 };
	static const uint8_t small[] = { 1, 2, 3 };
	CHECK(fastrdp_dvc_send_message(0x7D00, small, sizeof(small), collect, &k), "send small");
	CHECK(k.pdus == 1 && k.first_cmd == FASTRDP_DVC_DATA && k.complete == 1 && k.out_len == 3 &&
	          memcmp(k.out, small, 3) == 0 && !k.error,
	      "small message: %u PDUs, cmd %u", k.pdus, k.first_cmd);
	fastrdp_buf_free(&k.r.buf);

	/* exactly filling one PDU, and one byte more */
	for (size_t len = 1597; len <= 1598; len++)
	{
		uint8_t* m = malloc(len);
		for (size_t i = 0; i < len; i++)
			m[i] = (uint8_t)(i * 7);
		memset(&k, 0, sizeof(k));
		CHECK(fastrdp_dvc_send_message(0x7D00, m, len, collect, &k), "send %zu", len);
		CHECK(k.complete == 1 && k.out_len == len && memcmp(k.out, m, len) == 0 && !k.error &&
		          k.largest <= FASTRDP_DVC_MAX_PDU && k.pdus == (len == 1597 ? 1u : 2u),
		      "%zu bytes: %u PDUs, largest %zu", len, k.pdus, k.largest);
		fastrdp_buf_free(&k.r.buf);
		free(m);
	}

	/* a long message: DYNVC_DATA_FIRST with the length, then DYNVC_DATA */
	uint8_t big[5000];
	for (size_t i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 31 + 5);
	memset(&k, 0, sizeof(k));
	CHECK(fastrdp_dvc_send_message(0x7D00, big, sizeof(big), collect, &k), "send big");
	CHECK(k.first_cmd == FASTRDP_DVC_DATA_FIRST && k.pdus == 4 && k.largest == FASTRDP_DVC_MAX_PDU &&
	          k.complete == 1 && k.out_len == sizeof(big) && memcmp(k.out, big, sizeof(big)) == 0 &&
	          !k.error,
	      "big message: %u PDUs, largest %zu, complete %d", k.pdus, k.largest, k.complete);
	fastrdp_buf_free(&k.r.buf);
}

static void test_dvc_client(void)
{
	fastrdpDvcPdu p;
	static const uint8_t caps[] = { 0x50, 0x00, 0x03, 0x00 };
	CHECK(fastrdp_dvc_parse(caps, sizeof(caps), &p) && p.cmd == FASTRDP_DVC_CAPS && p.value == 3,
	      "caps response");
	CHECK(!fastrdp_dvc_parse(caps, 3, &p), "short caps response");
	static const uint8_t ok[] = { 0x11, 0x00, 0x7D, 0x00, 0x00, 0x00, 0x00 };
	CHECK(fastrdp_dvc_parse(ok, sizeof(ok), &p) && p.cmd == FASTRDP_DVC_CREATE && p.chid == 0x7D00 &&
	          p.value == 0,
	      "create response ok");
	static const uint8_t refused[] = { 0x11, 0x00, 0x7D, 0x01, 0x00, 0x00, 0x80 };
	CHECK(fastrdp_dvc_parse(refused, sizeof(refused), &p) && (int32_t)p.value < 0,
	      "create response refused");
	CHECK(!fastrdp_dvc_parse(ok, 5, &p), "short create response");
	static const uint8_t close[] = { 0x41, 0x00, 0x7D };
	CHECK(fastrdp_dvc_parse(close, sizeof(close), &p) && p.cmd == FASTRDP_DVC_CLOSE && p.chid == 0x7D00,
	      "close");
	static const uint8_t bad_cb[] = { 0x43, 0, 0, 0, 0 };
	CHECK(!fastrdp_dvc_parse(bad_cb, sizeof(bad_cb), &p), "cbChId 3");
	static const uint8_t first[] = { 0x25, 0x00, 0x7D, 0x05, 0x00, 'a', 'b' };
	CHECK(fastrdp_dvc_parse(first, sizeof(first), &p) && p.cmd == FASTRDP_DVC_DATA_FIRST &&
	          p.value == 5 && p.data_len == 2 && p.data[0] == 'a',
	      "data first");
	static const uint8_t soft[] = { 0x80 };
	CHECK(fastrdp_dvc_parse(soft, sizeof(soft), &p) && p.cmd == 8, "unused command passes");
	CHECK(!fastrdp_dvc_parse(soft, 0, &p), "empty");

	/* reassembly limits */
	fastrdpDvcReasm r = { 0 };
	const uint8_t* msg = NULL;
	size_t len = 0;
	CHECK(fastrdp_dvc_parse(first, sizeof(first), &p) && fastrdp_dvc_reasm(&r, &p, 4, &msg, &len) < 0,
	      "total above the limit refused");
	CHECK(fastrdp_dvc_reasm(&r, &p, 100, &msg, &len) == 0, "first part");
	static const uint8_t rest_too_long[] = { 0x31, 0x00, 0x7D, 'c', 'd', 'e', 'f' };
	CHECK(fastrdp_dvc_parse(rest_too_long, sizeof(rest_too_long), &p) &&
	          fastrdp_dvc_reasm(&r, &p, 100, &msg, &len) < 0,
	      "more than announced refused");
	fastrdp_buf_free(&r.buf);
}

/* undoes fastrdp_zgfx_wrap() (uncompressed segments only) */
static int unwrap(const uint8_t* p, size_t n, uint8_t* out, size_t* out_len)
{
	size_t o = 0;
	*out_len = 0;
	if (n >= 2 && p[0] == FASTRDP_ZGFX_SINGLE && p[1] == FASTRDP_ZGFX_RDP8)
	{
		memcpy(out, p + 2, n - 2);
		*out_len = n - 2;
		return 1;
	}
	if (n < 7 || p[0] != FASTRDP_ZGFX_MULTIPART)
		return 0;
	const unsigned count = fastrdp_get_u16(p + 1);
	const uint32_t total = fastrdp_get_u32(p + 3);
	o = 7;
	for (unsigned i = 0; i < count; i++)
	{
		const uint32_t size = fastrdp_get_u32(p + o);
		if (p[o + 4] != FASTRDP_ZGFX_RDP8)
			return 0;
		memcpy(out + *out_len, p + o + 5, size - 1);
		*out_len += size - 1;
		o += 4 + size;
	}
	return o == n && *out_len == total;
}

static void test_zgfx(void)
{
	fastrdpBuf b = { 0 };
	static const uint8_t small[] = { 9, 8, 7 };
	fastrdp_zgfx_wrap(&b, small, sizeof(small));
	static const uint8_t want[] = { 0xE0, 0x04, 9, 8, 7 };
	CHECK(same(&b, want, sizeof(want)), "single segment");
	fastrdp_buf_free(&b);

	const size_t n = 70000;
	uint8_t* big = malloc(n);
	uint8_t* back = malloc(n);
	for (size_t i = 0; i < n; i++)
		big[i] = (uint8_t)(i ^ (i >> 8));
	fastrdp_zgfx_wrap(&b, big, n);
	size_t got = 0;
	CHECK(!b.failed && b.data[0] == 0xE1 && fastrdp_get_u16(b.data + 1) == 2 &&
	          fastrdp_get_u32(b.data + 7) == 65536,
	      "multipart header");
	CHECK(unwrap(b.data, b.len, back, &got) && got == n && memcmp(back, big, n) == 0,
	      "multipart round trip");
	fastrdp_buf_free(&b);
	free(big);
	free(back);
}

static void test_gfx_server(void)
{
	fastrdpBuf b = { 0 };
	const fastrdpGfxMonitor m[2] = { { 0, 0, 1279, 799, 1 }, { 1280, 0, 2559, 799, 0 } };
	fastrdp_gfx_reset_graphics(&b, 2560, 800, m, 2);
	CHECK(!b.failed && b.len == FASTRDP_GFX_RESET_GRAPHICS_SIZE &&
	          fastrdp_get_u16(b.data) == FASTRDP_GFX_RESETGRAPHICS &&
	          fastrdp_get_u32(b.data + 4) == FASTRDP_GFX_RESET_GRAPHICS_SIZE &&
	          fastrdp_get_u32(b.data + 8) == 2560 && fastrdp_get_u32(b.data + 12) == 800 &&
	          fastrdp_get_u32(b.data + 16) == 2 && fastrdp_get_u32(b.data + 20 + 8) == 1279 &&
	          fastrdp_get_u32(b.data + 20 + 16) == 1 && fastrdp_get_u32(b.data + 40) == 1280 &&
	          fastrdp_get_u32(b.data + 40 + 16) == 0,
	      "reset graphics: %zu bytes", b.len);
	fastrdp_buf_free(&b);

	const fastrdpGfxCaps caps = { 0x000A0600u, 4, { 0x20, 0, 0, 0 } };
	fastrdp_gfx_caps_confirm(&b, &caps);
	static const uint8_t confirm[] = { 0x13, 0, 0, 0, 20, 0, 0, 0, 0x00, 0x06, 0x0A, 0x00,
		                               4,    0, 0, 0, 0x20, 0, 0, 0 };
	CHECK(same(&b, confirm, sizeof(confirm)), "caps confirm");
	fastrdp_buf_free(&b);

	fastrdp_gfx_create_surface(&b, 1, 1280, 800);
	static const uint8_t create[] = { 0x09, 0, 0, 0, 15, 0, 0, 0, 1, 0, 0x00, 0x05, 0x20, 0x03, 0x20 };
	CHECK(same(&b, create, sizeof(create)), "create surface");
	fastrdp_buf_free(&b);

	fastrdp_gfx_map_surface(&b, 1, 0, 0);
	static const uint8_t map[] = { 0x0F, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	CHECK(same(&b, map, sizeof(map)), "map surface to output");
	fastrdp_buf_free(&b);

	const fastrdpGfxRect r = { 10, 20, 74, 84 };
	fastrdp_gfx_solid_fill(&b, 1, 0x1e1f24u, &r, 1);
	static const uint8_t fill[] = { 0x04, 0, 0, 0, 24, 0, 0, 0, 1,  0, 0x24, 0x1f,
		                            0x1e, 0xff, 1, 0, 10, 0, 20, 0, 74, 0, 84,   0 };
	CHECK(same(&b, fill, sizeof(fill)), "solid fill");
	fastrdp_buf_free(&b);

	static const uint8_t px[] = { 1, 2, 3, 4 };
	fastrdp_gfx_wire_to_surface1(&b, 1, FASTRDP_GFX_CODEC_PLANAR, &r, px, sizeof(px));
	static const uint8_t w2s[] = { 0x01, 0, 0, 0, 29, 0, 0, 0, 1, 0, 0x0A, 0, 0x20, 10, 0,
		                           20,   0, 74, 0, 84, 0, 4, 0, 0, 0, 1, 2, 3, 4 };
	CHECK(same(&b, w2s, sizeof(w2s)), "wire to surface 1");
	fastrdp_buf_free(&b);

	fastrdp_gfx_start_frame(&b, 7, 13, 45, 30, 250);
	const uint32_t ts = (13u << 22) | (45u << 16) | (30u << 10) | 250u;
	CHECK(!b.failed && b.len == 16 && fastrdp_get_u16(b.data) == FASTRDP_GFX_STARTFRAME &&
	          fastrdp_get_u32(b.data + 8) == ts && fastrdp_get_u32(b.data + 12) == 7,
	      "start frame");
	fastrdp_gfx_end_frame(&b, 7);
	fastrdp_gfx_delete_surface(&b, 1);
	fastrdp_gfx_cache_import_reply(&b);
	/* several PDUs in one message, walked like the client walks them */
	size_t off = 0;
	unsigned cmd = 0, seen[4] = { 0 }, n = 0;
	const uint8_t* body = NULL;
	size_t blen = 0;
	while (n < 4 && fastrdp_gfx_next(b.data, b.len, &off, &cmd, &body, &blen) > 0)
		seen[n++] = cmd;
	CHECK(n == 4 && seen[0] == FASTRDP_GFX_STARTFRAME && seen[1] == FASTRDP_GFX_ENDFRAME &&
	          seen[2] == FASTRDP_GFX_DELETESURFACE && seen[3] == FASTRDP_GFX_CACHEIMPORTREPLY &&
	          off == b.len,
	      "PDU walk: %u PDUs", n);
	fastrdp_buf_free(&b);
}

/* a CapsAdvertise body with the given sets (version, flags, data length) */
static size_t advertise(uint8_t* out, const uint32_t* versions, const uint32_t* flags,
                        const uint32_t* lens, unsigned n)
{
	size_t o = 2;
	out[0] = (uint8_t)n;
	out[1] = 0;
	for (unsigned i = 0; i < n; i++)
	{
		for (int k = 0; k < 4; k++)
		{
			out[o + k] = (uint8_t)(versions[i] >> (8 * k));
			out[o + 4 + k] = (uint8_t)(lens[i] >> (8 * k));
		}
		o += 8;
		memset(out + o, 0, lens[i]);
		for (int k = 0; k < 4 && (uint32_t)k < lens[i]; k++)
			out[o + k] = (uint8_t)(flags[i] >> (8 * k));
		o += lens[i];
	}
	return o;
}

static void test_caps(void)
{
	uint8_t body[512];
	fastrdpGfxCaps c;
	/* mstsc-like: 8.0 ... 10.7 and an undocumented one */
	const uint32_t v1[] = { 0x00080004u, 0x00080105u, 0x000A0600u, 0x000A0701u, 0x000B0101u };
	const uint32_t f1[] = { 0, 0x10, 0, 0x10, 0 };
	const uint32_t l1[] = { 4, 4, 4, 4, 4 };
	size_t n = advertise(body, v1, f1, l1, 5);
	CHECK(fastrdp_gfx_choose_caps(body, n, &c) && c.version == 0x000A0701u && c.len == 4 &&
	          c.data[0] == (0x10 | FASTRDP_GFX_CAPS_AVC_DISABLED),
	      "highest documented, AVC disabled: version 0x%08x flags 0x%02x", c.version, c.data[0]);
	/* 8.1 only: AVC420 cleared */
	n = advertise(body, &v1[1], &f1[1], &l1[1], 1);
	CHECK(fastrdp_gfx_choose_caps(body, n, &c) && c.version == 0x00080105u && c.data[0] == 0,
	      "8.1: AVC420 cleared (0x%02x)", c.data[0]);
	/* 10.1: 16 reserved bytes, left as they are */
	const uint32_t v2[] = { 0x000A0100u }, f2[] = { 0 }, l2[] = { 16 };
	n = advertise(body, v2, f2, l2, 1);
	CHECK(fastrdp_gfx_choose_caps(body, n, &c) && c.version == 0x000A0100u && c.len == 16 &&
	          c.data[0] == 0,
	      "10.1 unchanged");
	/* 8.0 only */
	n = advertise(body, v1, f1, l1, 1);
	CHECK(fastrdp_gfx_choose_caps(body, n, &c) && c.version == 0x00080004u, "8.0 only");
	/* nothing documented, and malformed */
	n = advertise(body, &v1[4], &f1[4], &l1[4], 1);
	CHECK(!fastrdp_gfx_choose_caps(body, n, &c), "unknown version only");
	n = advertise(body, v1, f1, l1, 5);
	CHECK(!fastrdp_gfx_choose_caps(body, n - 3, &c), "truncated");
	body[0] = 9; /* more sets announced than there are */
	CHECK(!fastrdp_gfx_choose_caps(body, n, &c), "count too high");

	char name[16];
	fastrdp_gfx_version_name(0x000A0601u, name, sizeof(name));
	CHECK(strcmp(name, "10.6") == 0, "version name %s", name);

	static const uint8_t ack[] = { 0xff, 0xff, 0xff, 0xff, 3, 0, 0, 0, 2, 0, 0, 0 };
	fastrdpGfxAck a;
	CHECK(fastrdp_gfx_frame_ack(ack, sizeof(ack), &a) && a.queue_depth == FASTRDP_GFX_SUSPEND_ACKS &&
	          a.frame_id == 3 && a.decoded == 2,
	      "frame acknowledge");
	CHECK(!fastrdp_gfx_frame_ack(ack, 11, &a), "short frame acknowledge");

	/* a client PDU whose length runs past the message */
	static const uint8_t bad[] = { 0x0D, 0, 0, 0, 40, 0, 0, 0, 1, 2 };
	size_t off = 0;
	unsigned cmd = 0;
	const uint8_t* b = NULL;
	size_t blen = 0;
	CHECK(fastrdp_gfx_next(bad, sizeof(bad), &off, &cmd, &b, &blen) < 0, "overlong PDU");
}

int main(void)
{
	test_dvc_server();
	test_dvc_client();
	test_zgfx();
	test_gfx_server();
	test_caps();
	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok   fastrdp_gfx.h\n");
	return 0;
}
