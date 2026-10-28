/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The waiting screen over the Graphics Pipeline ([FastRDP] WaitingScreenGfx, backlog A5/A8):
 * the bytes of the few dynamic virtual channel ([MS-RDPEDYC]) and RDPGFX ([MS-RDPEGFX]) PDUs
 * the module speaks itself on the front's drdynvc static channel during the wait, and the
 * parsers for what the client answers. FreeRDP's server channel code (WTS DVC manager,
 * channels/rdpgfx/server) does not fit the proxy (docs/a8-gfx-waiting-screen-feasibility.md),
 * so the module writes them. libc only (tests/proxy-module/test_gfx.c); the e2e test checks
 * them against FreeRDP's client parsers.
 *
 * Server to client: DVC Capabilities Request version 1, Create Request, Close, Data First /
 * Data of at most FASTRDP_DVC_MAX_PDU bytes; RDPGFX CapsConfirm, ResetGraphics,
 * CreateSurface, MapSurfaceToOutput, SolidFill, WireToSurface1, StartFrame, EndFrame,
 * DeleteSurface, CacheImportReply, each message in an uncompressed RDP_SEGMENTED_DATA
 * wrapper ([MS-RDPEGFX] 2.2.5: ZGFX segments, bulk header without PACKET_COMPRESSED).
 * Client to server: DVC Capabilities Response, Create Response, Data First / Data, Close;
 * RDPGFX CapsAdvertise, FrameAcknowledge, CacheImportOffer, QoEFrameAcknowledge (client to
 * server RDPGFX PDUs are not wrapped). */
#ifndef FASTRDP_GFX_H
#define FASTRDP_GFX_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FASTRDP_GFX_CHANNEL "Microsoft::Windows::RDS::Graphics"
#define FASTRDP_DVC_MAX_PDU 1600 /* [MS-RDPEDYC] 2.2.3: a DVC PDU, header included */

/* DVC Cmd ([MS-RDPEDYC] 2.2) */
#define FASTRDP_DVC_CREATE 0x01
#define FASTRDP_DVC_DATA_FIRST 0x02
#define FASTRDP_DVC_DATA 0x03
#define FASTRDP_DVC_CLOSE 0x04
#define FASTRDP_DVC_CAPS 0x05

/* RDPGFX cmdId ([MS-RDPEGFX] 2.2.1.5) */
#define FASTRDP_GFX_WIRETOSURFACE_1 0x0001
#define FASTRDP_GFX_SOLIDFILL 0x0004
#define FASTRDP_GFX_CREATESURFACE 0x0009
#define FASTRDP_GFX_DELETESURFACE 0x000A
#define FASTRDP_GFX_STARTFRAME 0x000B
#define FASTRDP_GFX_ENDFRAME 0x000C
#define FASTRDP_GFX_FRAMEACKNOWLEDGE 0x000D
#define FASTRDP_GFX_RESETGRAPHICS 0x000E
#define FASTRDP_GFX_MAPSURFACETOOUTPUT 0x000F
#define FASTRDP_GFX_CACHEIMPORTOFFER 0x0010
#define FASTRDP_GFX_CACHEIMPORTREPLY 0x0011
#define FASTRDP_GFX_CAPSADVERTISE 0x0012
#define FASTRDP_GFX_CAPSCONFIRM 0x0013
#define FASTRDP_GFX_QOEFRAMEACKNOWLEDGE 0x0016

#define FASTRDP_GFX_CODEC_UNCOMPRESSED 0x0000
#define FASTRDP_GFX_CODEC_PLANAR 0x000A
#define FASTRDP_GFX_XRGB_8888 0x20
#define FASTRDP_GFX_SUSPEND_ACKS 0xFFFFFFFFu /* FrameAcknowledge queueDepth */
#define FASTRDP_GFX_RESET_GRAPHICS_SIZE 340  /* [MS-RDPEGFX] 2.2.2.14: the PDU, padded */
#define FASTRDP_GFX_MAX_MONITORS 16
#define FASTRDP_GFX_CAPS_MAX 64 /* bytes of capsData kept (the largest documented set: 16) */

/* capability set versions ([MS-RDPEGFX] 2.2.3), most preferred first: the highest documented
 * one the client advertises is confirmed (10.6 is what mstsc got from xrdp and
 * gnome-remote-desktop in the A5 lab runs) */
static const uint32_t fastrdp_gfx_versions[] = {
	0x000A0701u, /* 10.7 */
	0x000A0600u, /* 10.6 */
	0x000A0601u, /* 10.6 as first documented (errata) */
	0x000A0502u, /* 10.5 */
	0x000A0400u, /* 10.4 */
	0x000A0301u, /* 10.3 */
	0x000A0200u, /* 10.2 */
	0x000A0100u, /* 10.1: 16 reserved bytes, no flags */
	0x000A0002u, /* 10.0 */
	0x00080105u, /* 8.1 */
	0x00080004u, /* 8.0 */
};
#define FASTRDP_GFX_CAPS_AVC420_ENABLED 0x10u /* 8.1 */
#define FASTRDP_GFX_CAPS_AVC_DISABLED 0x20u   /* 10.0, 10.2 and later */

/* ------------------------------------------------------------------ buffer */

typedef struct
{
	uint8_t* data;
	size_t len, cap;
	int failed; /* an allocation failed: the content is incomplete */
} fastrdpBuf;

static void fastrdp_buf_free(fastrdpBuf* b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

static void fastrdp_buf_put(fastrdpBuf* b, const void* p, size_t n)
{
	if (b->failed || n == 0)
		return;
	if (b->len + n > b->cap)
	{
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->len + n)
			cap *= 2;
		uint8_t* d = realloc(b->data, cap);
		if (!d)
		{
			b->failed = 1;
			return;
		}
		b->data = d;
		b->cap = cap;
	}
	memcpy(b->data + b->len, p, n);
	b->len += n;
}

static void fastrdp_buf_u8(fastrdpBuf* b, unsigned v)
{
	const uint8_t x = (uint8_t)v;
	fastrdp_buf_put(b, &x, 1);
}

static void fastrdp_buf_u16(fastrdpBuf* b, unsigned v)
{
	const uint8_t x[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
	fastrdp_buf_put(b, x, 2);
}

static void fastrdp_buf_u32(fastrdpBuf* b, uint32_t v)
{
	const uint8_t x[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
	fastrdp_buf_put(b, x, 4);
}

static void fastrdp_buf_set_u32(fastrdpBuf* b, size_t at, uint32_t v)
{
	if (b->failed || at + 4 > b->len)
		return;
	b->data[at] = (uint8_t)v;
	b->data[at + 1] = (uint8_t)(v >> 8);
	b->data[at + 2] = (uint8_t)(v >> 16);
	b->data[at + 3] = (uint8_t)(v >> 24);
}

static uint16_t fastrdp_get_u16(const uint8_t* p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t fastrdp_get_u32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* --------------------------------------------------------- DVC, server side */

/* cbChId / Sp / Len encoding of a value: 0 = 1 byte, 1 = 2 bytes, 2 = 4 bytes */
static unsigned fastrdp_dvc_cb(uint32_t v)
{
	return v <= 0xff ? 0 : v <= 0xffff ? 1 : 2;
}

static size_t fastrdp_dvc_cb_bytes(unsigned cb)
{
	return cb == 0 ? 1 : cb == 1 ? 2 : 4;
}

static void fastrdp_dvc_put_var(fastrdpBuf* b, unsigned cb, uint32_t v)
{
	if (cb == 0)
		fastrdp_buf_u8(b, v);
	else if (cb == 1)
		fastrdp_buf_u16(b, v);
	else
		fastrdp_buf_u32(b, v);
}

/* DYNVC_CAPS_VERSION1 ([MS-RDPEDYC] 2.2.1.1.1), as FreeRDP's own server sends it */
static void fastrdp_dvc_caps_request(fastrdpBuf* b)
{
	fastrdp_buf_u8(b, FASTRDP_DVC_CAPS << 4);
	fastrdp_buf_u8(b, 0); /* Pad */
	fastrdp_buf_u16(b, 1);
}

/* DYNVC_CREATE_REQ (2.2.2.1), version 1: no priority */
static void fastrdp_dvc_create_request(fastrdpBuf* b, uint32_t chid, const char* name)
{
	const unsigned cb = fastrdp_dvc_cb(chid);
	fastrdp_buf_u8(b, (FASTRDP_DVC_CREATE << 4) | cb);
	fastrdp_dvc_put_var(b, cb, chid);
	fastrdp_buf_put(b, name, strlen(name) + 1);
}

/* DYNVC_CLOSE (2.2.4) */
static void fastrdp_dvc_close(fastrdpBuf* b, uint32_t chid)
{
	const unsigned cb = fastrdp_dvc_cb(chid);
	fastrdp_buf_u8(b, (FASTRDP_DVC_CLOSE << 4) | cb);
	fastrdp_dvc_put_var(b, cb, chid);
}

typedef int (*fastrdpDvcSendFn)(void* ctx, const uint8_t* pdu, size_t len);

/* One message on channel chid as DVC data PDUs (2.2.3) of at most FASTRDP_DVC_MAX_PDU bytes:
 * a single DYNVC_DATA if it fits, else DYNVC_DATA_FIRST with the total length and
 * DYNVC_DATA for the rest. send() gets each PDU; 0 if one was not sent. */
static int fastrdp_dvc_send_message(uint32_t chid, const uint8_t* msg, size_t len,
                                    fastrdpDvcSendFn send, void* ctx)
{
	uint8_t pdu[FASTRDP_DVC_MAX_PDU];
	const unsigned cb = fastrdp_dvc_cb(chid);
	const size_t idlen = fastrdp_dvc_cb_bytes(cb);
	size_t off = 0;
	if (len > 0xffffffffu)
		return 0;
	for (int first = 1; first || off < len; first = 0)
	{
		fastrdpBuf h = { pdu, 0, sizeof(pdu), 0 }; /* never grows: at most 9 bytes */
		size_t room;
		if (first && 1 + idlen + len <= FASTRDP_DVC_MAX_PDU)
		{
			fastrdp_buf_u8(&h, (FASTRDP_DVC_DATA << 4) | cb);
			fastrdp_dvc_put_var(&h, cb, chid);
		}
		else if (first)
		{
			const unsigned sp = fastrdp_dvc_cb((uint32_t)len);
			fastrdp_buf_u8(&h, (FASTRDP_DVC_DATA_FIRST << 4) | (sp << 2) | cb);
			fastrdp_dvc_put_var(&h, cb, chid);
			fastrdp_dvc_put_var(&h, sp, (uint32_t)len);
		}
		else
		{
			fastrdp_buf_u8(&h, (FASTRDP_DVC_DATA << 4) | cb);
			fastrdp_dvc_put_var(&h, cb, chid);
		}
		room = FASTRDP_DVC_MAX_PDU - h.len;
		const size_t n = len - off < room ? len - off : room;
		if (n)
			memcpy(pdu + h.len, msg + off, n);
		off += n;
		if (!send(ctx, pdu, h.len + n))
			return 0;
	}
	return 1;
}

/* --------------------------------------------------------- DVC, client side */

typedef struct
{
	unsigned cmd, sp, cb;
	uint32_t chid;
	uint32_t value; /* Caps: version; Create: CreationStatus (an HRESULT); Data First: Length */
	const uint8_t* data; /* Data First, Data: the payload */
	size_t data_len;
} fastrdpDvcPdu;

static uint32_t fastrdp_dvc_get_var(const uint8_t* p, unsigned cb)
{
	return cb == 0 ? p[0] : cb == 1 ? fastrdp_get_u16(p) : fastrdp_get_u32(p);
}

/* One DVC PDU from the client; 0 if malformed. Commands the module does not use are
 * returned with their cmd only. */
static int fastrdp_dvc_parse(const uint8_t* p, size_t n, fastrdpDvcPdu* out)
{
	memset(out, 0, sizeof(*out));
	if (n < 1)
		return 0;
	out->cmd = p[0] >> 4;
	out->sp = (p[0] >> 2) & 3;
	out->cb = p[0] & 3;
	if (out->cmd == FASTRDP_DVC_CAPS)
	{
		if (n < 4)
			return 0;
		out->value = fastrdp_get_u16(p + 2);
		return 1;
	}
	if (out->cmd < FASTRDP_DVC_CREATE || out->cmd > FASTRDP_DVC_CLOSE)
		return 1;
	if (out->cb == 3)
		return 0;
	size_t o = 1;
	const size_t idlen = fastrdp_dvc_cb_bytes(out->cb);
	if (n < o + idlen)
		return 0;
	out->chid = fastrdp_dvc_get_var(p + o, out->cb);
	o += idlen;
	switch (out->cmd)
	{
		case FASTRDP_DVC_CREATE:
			if (n < o + 4)
				return 0;
			out->value = fastrdp_get_u32(p + o);
			return 1;
		case FASTRDP_DVC_DATA_FIRST:
		{
			if (out->sp == 3)
				return 0;
			const size_t llen = fastrdp_dvc_cb_bytes(out->sp);
			if (n < o + llen)
				return 0;
			out->value = fastrdp_dvc_get_var(p + o, out->sp);
			o += llen;
		}
		/* fall through */
		case FASTRDP_DVC_DATA:
			out->data = p + o;
			out->data_len = n - o;
			return 1;
		default: /* Close */
			return 1;
	}
}

/* Reassembly of one channel's messages from Data First / Data PDUs. */
typedef struct
{
	fastrdpBuf buf;
	size_t total;
	int active; /* a Data First came, the message is not complete yet */
} fastrdpDvcReasm;

/* 1: *msg / *len hold a complete message (valid until the next call), 0: more to come,
 * -1: malformed or larger than max (the state is reset). */
static int fastrdp_dvc_reasm(fastrdpDvcReasm* r, const fastrdpDvcPdu* pdu, size_t max,
                             const uint8_t** msg, size_t* len)
{
	if (pdu->cmd == FASTRDP_DVC_DATA_FIRST)
	{
		r->buf.len = 0;
		r->buf.failed = 0;
		r->active = 0;
		if (pdu->value > max || pdu->data_len > pdu->value)
			return -1;
		r->total = pdu->value;
		fastrdp_buf_put(&r->buf, pdu->data, pdu->data_len);
		if (r->buf.failed)
			return -1;
		r->active = r->buf.len < r->total;
		if (r->active)
			return 0;
		*msg = r->buf.data;
		*len = r->buf.len;
		return 1;
	}
	if (pdu->cmd != FASTRDP_DVC_DATA)
		return -1;
	if (!r->active)
	{
		if (pdu->data_len > max)
			return -1;
		*msg = pdu->data;
		*len = pdu->data_len;
		return 1;
	}
	if (r->buf.len + pdu->data_len > r->total)
	{
		r->active = 0;
		return -1;
	}
	fastrdp_buf_put(&r->buf, pdu->data, pdu->data_len);
	if (r->buf.failed)
	{
		r->active = 0;
		return -1;
	}
	if (r->buf.len < r->total)
		return 0;
	r->active = 0;
	*msg = r->buf.data;
	*len = r->buf.len;
	return 1;
}

/* ------------------------------------------------------------ RDPGFX, server */

#define FASTRDP_ZGFX_SINGLE 0xE0
#define FASTRDP_ZGFX_MULTIPART 0xE1
#define FASTRDP_ZGFX_RDP8 0x04 /* bulk header: PACKET_COMPR_TYPE_RDP8, not compressed */
#define FASTRDP_ZGFX_SEGMENT 65535

/* RDP_SEGMENTED_DATA ([MS-RDPEGFX] 2.2.5.1) around an RDPGFX message, uncompressed */
static void fastrdp_zgfx_wrap(fastrdpBuf* out, const uint8_t* data, size_t len)
{
	if (len <= FASTRDP_ZGFX_SEGMENT)
	{
		fastrdp_buf_u8(out, FASTRDP_ZGFX_SINGLE);
		fastrdp_buf_u8(out, FASTRDP_ZGFX_RDP8);
		fastrdp_buf_put(out, data, len);
		return;
	}
	const size_t segments = (len + FASTRDP_ZGFX_SEGMENT - 1) / FASTRDP_ZGFX_SEGMENT;
	if (segments > 0xffff || len > 0xffffffffu)
	{
		out->failed = 1;
		return;
	}
	fastrdp_buf_u8(out, FASTRDP_ZGFX_MULTIPART);
	fastrdp_buf_u16(out, (unsigned)segments);
	fastrdp_buf_u32(out, (uint32_t)len);
	for (size_t off = 0; off < len; off += FASTRDP_ZGFX_SEGMENT)
	{
		const size_t n = len - off < FASTRDP_ZGFX_SEGMENT ? len - off : FASTRDP_ZGFX_SEGMENT;
		fastrdp_buf_u32(out, (uint32_t)n + 1);
		fastrdp_buf_u8(out, FASTRDP_ZGFX_RDP8);
		fastrdp_buf_put(out, data + off, n);
	}
}

/* RDPGFX_HEADER (2.2.1.5); fastrdp_gfx_end() fills in pduLength */
static size_t fastrdp_gfx_begin(fastrdpBuf* b, unsigned cmd)
{
	const size_t at = b->len;
	fastrdp_buf_u16(b, cmd);
	fastrdp_buf_u16(b, 0); /* flags */
	fastrdp_buf_u32(b, 0);
	return at;
}

static void fastrdp_gfx_end(fastrdpBuf* b, size_t at)
{
	fastrdp_buf_set_u32(b, at + 4, (uint32_t)(b->len - at));
}

typedef struct
{
	uint32_t version;
	uint32_t len;
	uint8_t data[FASTRDP_GFX_CAPS_MAX];
} fastrdpGfxCaps;

static void fastrdp_gfx_caps_confirm(fastrdpBuf* b, const fastrdpGfxCaps* caps)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_CAPSCONFIRM);
	fastrdp_buf_u32(b, caps->version);
	fastrdp_buf_u32(b, caps->len);
	fastrdp_buf_put(b, caps->data, caps->len);
	fastrdp_gfx_end(b, at);
}

typedef struct
{
	int32_t left, top, right, bottom; /* inclusive, desktop coordinates */
	int primary;
} fastrdpGfxMonitor;

/* RDPGFX_RESET_GRAPHICS_PDU (2.2.2.14): at least one, at most 16 monitors */
static void fastrdp_gfx_reset_graphics(fastrdpBuf* b, uint32_t w, uint32_t h,
                                       const fastrdpGfxMonitor* m, unsigned n)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_RESETGRAPHICS);
	if (n > FASTRDP_GFX_MAX_MONITORS)
		n = FASTRDP_GFX_MAX_MONITORS;
	fastrdp_buf_u32(b, w);
	fastrdp_buf_u32(b, h);
	fastrdp_buf_u32(b, n);
	for (unsigned i = 0; i < n; i++)
	{
		fastrdp_buf_u32(b, (uint32_t)m[i].left);
		fastrdp_buf_u32(b, (uint32_t)m[i].top);
		fastrdp_buf_u32(b, (uint32_t)m[i].right);
		fastrdp_buf_u32(b, (uint32_t)m[i].bottom);
		fastrdp_buf_u32(b, m[i].primary ? 1 : 0); /* TS_MONITOR_PRIMARY */
	}
	while (b->len - at < FASTRDP_GFX_RESET_GRAPHICS_SIZE && !b->failed)
		fastrdp_buf_u8(b, 0);
	fastrdp_gfx_end(b, at);
}

static void fastrdp_gfx_create_surface(fastrdpBuf* b, unsigned sid, unsigned w, unsigned h)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_CREATESURFACE);
	fastrdp_buf_u16(b, sid);
	fastrdp_buf_u16(b, w);
	fastrdp_buf_u16(b, h);
	fastrdp_buf_u8(b, FASTRDP_GFX_XRGB_8888);
	fastrdp_gfx_end(b, at);
}

static void fastrdp_gfx_map_surface(fastrdpBuf* b, unsigned sid, uint32_t x, uint32_t y)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_MAPSURFACETOOUTPUT);
	fastrdp_buf_u16(b, sid);
	fastrdp_buf_u16(b, 0); /* reserved */
	fastrdp_buf_u32(b, x);
	fastrdp_buf_u32(b, y);
	fastrdp_gfx_end(b, at);
}

static void fastrdp_gfx_delete_surface(fastrdpBuf* b, unsigned sid)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_DELETESURFACE);
	fastrdp_buf_u16(b, sid);
	fastrdp_gfx_end(b, at);
}

/* RDPGFX_RECT16: right and bottom exclusive */
typedef struct
{
	unsigned left, top, right, bottom;
} fastrdpGfxRect;

static void fastrdp_gfx_put_rect(fastrdpBuf* b, const fastrdpGfxRect* r)
{
	fastrdp_buf_u16(b, r->left);
	fastrdp_buf_u16(b, r->top);
	fastrdp_buf_u16(b, r->right);
	fastrdp_buf_u16(b, r->bottom);
}

/* rgb: 0x00RRGGBB */
static void fastrdp_gfx_solid_fill(fastrdpBuf* b, unsigned sid, uint32_t rgb,
                                   const fastrdpGfxRect* r, unsigned n)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_SOLIDFILL);
	fastrdp_buf_u16(b, sid);
	fastrdp_buf_u8(b, rgb & 0xff); /* RDPGFX_COLOR32: B, G, R, XA */
	fastrdp_buf_u8(b, (rgb >> 8) & 0xff);
	fastrdp_buf_u8(b, (rgb >> 16) & 0xff);
	fastrdp_buf_u8(b, 0xff);
	fastrdp_buf_u16(b, n);
	for (unsigned i = 0; i < n; i++)
		fastrdp_gfx_put_rect(b, &r[i]);
	fastrdp_gfx_end(b, at);
}

static void fastrdp_gfx_wire_to_surface1(fastrdpBuf* b, unsigned sid, unsigned codec,
                                         const fastrdpGfxRect* r, const uint8_t* data,
                                         size_t len)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_WIRETOSURFACE_1);
	fastrdp_buf_u16(b, sid);
	fastrdp_buf_u16(b, codec);
	fastrdp_buf_u8(b, FASTRDP_GFX_XRGB_8888);
	fastrdp_gfx_put_rect(b, r);
	fastrdp_buf_u32(b, (uint32_t)len);
	fastrdp_buf_put(b, data, len);
	fastrdp_gfx_end(b, at);
}

/* timestamp: hours, minutes, seconds, milliseconds of the time of day (2.2.2.11) */
static void fastrdp_gfx_start_frame(fastrdpBuf* b, uint32_t frame_id, unsigned h, unsigned m,
                                    unsigned s, unsigned ms)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_STARTFRAME);
	fastrdp_buf_u32(b, ((uint32_t)h << 22) | ((uint32_t)m << 16) | ((uint32_t)s << 10) | ms);
	fastrdp_buf_u32(b, frame_id);
	fastrdp_gfx_end(b, at);
}

static void fastrdp_gfx_end_frame(fastrdpBuf* b, uint32_t frame_id)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_ENDFRAME);
	fastrdp_buf_u32(b, frame_id);
	fastrdp_gfx_end(b, at);
}

/* no cache entries imported: the module uses no cache */
static void fastrdp_gfx_cache_import_reply(fastrdpBuf* b)
{
	const size_t at = fastrdp_gfx_begin(b, FASTRDP_GFX_CACHEIMPORTREPLY);
	fastrdp_buf_u16(b, 0);
	fastrdp_gfx_end(b, at);
}

/* ------------------------------------------------------------ RDPGFX, client */

/* The next RDPGFX PDU of a client message at *off: 1 (cmd and body), 0 at the end, -1 if
 * malformed. */
static int fastrdp_gfx_next(const uint8_t* p, size_t n, size_t* off, unsigned* cmd,
                            const uint8_t** body, size_t* body_len)
{
	if (*off >= n)
		return 0;
	if (n - *off < 8)
		return -1;
	const uint8_t* h = p + *off;
	const uint32_t len = fastrdp_get_u32(h + 4);
	if (len < 8 || len > n - *off)
		return -1;
	*cmd = fastrdp_get_u16(h);
	*body = h + 8;
	*body_len = len - 8;
	*off += len;
	return 1;
}

/* From a CapsAdvertise body (2.2.2.18): the set to confirm, the highest documented version
 * the client offers, its capsData as advertised but without AVC (the module sends planar
 * only). 0 if none is usable. */
static int fastrdp_gfx_choose_caps(const uint8_t* body, size_t n, fastrdpGfxCaps* out)
{
	size_t best = sizeof(fastrdp_gfx_versions) / sizeof(fastrdp_gfx_versions[0]);
	memset(out, 0, sizeof(*out));
	if (n < 2)
		return 0;
	const unsigned count = fastrdp_get_u16(body);
	size_t o = 2;
	for (unsigned i = 0; i < count; i++)
	{
		if (n - o < 8)
			return 0;
		const uint32_t version = fastrdp_get_u32(body + o);
		const uint32_t len = fastrdp_get_u32(body + o + 4);
		o += 8;
		if (len > n - o)
			return 0;
		for (size_t k = 0; k < best; k++)
			if (fastrdp_gfx_versions[k] == version && len <= FASTRDP_GFX_CAPS_MAX)
			{
				best = k;
				out->version = version;
				out->len = len;
				memcpy(out->data, body + o, len);
				break;
			}
		o += len;
	}
	if (!out->version)
		return 0;
	if (out->len >= 4 && out->version == 0x00080105u)
		out->data[0] &= (uint8_t)~FASTRDP_GFX_CAPS_AVC420_ENABLED;
	else if (out->len >= 4 && out->version >= 0x000A0002u && out->version != 0x000A0100u)
		out->data[0] |= FASTRDP_GFX_CAPS_AVC_DISABLED;
	return 1;
}

/* "10.6" for the log */
static void fastrdp_gfx_version_name(uint32_t v, char* out, size_t size)
{
	if (v == 0x000A0601u)
		v = 0x000A0600u;
	(void)snprintf(out, size, "%u.%u", (unsigned)(v >> 16), (unsigned)((v >> 8) & 0xff));
}

typedef struct
{
	uint32_t queue_depth, frame_id, decoded;
} fastrdpGfxAck;

static int fastrdp_gfx_frame_ack(const uint8_t* body, size_t n, fastrdpGfxAck* ack)
{
	if (n < 12)
		return 0;
	ack->queue_depth = fastrdp_get_u32(body);
	ack->frame_id = fastrdp_get_u32(body + 4);
	ack->decoded = fastrdp_get_u32(body + 8);
	return 1;
}

#endif /* FASTRDP_GFX_H */
