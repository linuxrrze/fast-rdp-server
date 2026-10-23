/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Diagnostics of the front connection (backlog A5: the next Connect in the same mstsc
 * shows no waiting screen, a fresh mstsc does): one line per connection with what the
 * client announced, so two connections of one mstsc process can be compared, the names of
 * Save Session Info types, the client's name made safe for the log, and a rate limit for
 * per-PDU lines. Never a secret: of the auto-reconnect cookie only whether it is there
 * and its logon id (the server's session number), never the verifier. libc only
 * (tests/proxy-module/test_frontdiag.c). */
#ifndef FASTRDP_FRONTDIAG_H
#define FASTRDP_FRONTDIAG_H

#include <stdio.h>
#include <string.h>

#define FASTRDP_FRONT_NAME 32 /* bytes of the client name in the log, NUL included */
#define FASTRDP_PDU_LOG_FIRST 8 /* per-PDU lines logged in full, then every 100th */

typedef struct
{
	const char* client_name; /* Client Core Data clientName, client-controlled */
	unsigned build;          /* clientBuild */
	unsigned width, height, bpp;
	unsigned monitors;        /* Client Monitor Data entries, 0 if none */
	unsigned desktop_scale;   /* Client Core Data desktopScaleFactor (100 = none) */
	unsigned device_scale;    /* deviceScaleFactor */
	int gfx;                  /* RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL */
	int dynvc;                /* the client joined drdynvc */
	int bitmap_cache;         /* bitmap cache capability */
	unsigned bitmap_cache_version;
	int persist;              /* persistent bitmap cache negotiated: Persistent Key List PDUs */
	unsigned glyph_level, offscreen_level;
	int arc;                  /* Client Info carried an auto-reconnect cookie */
	unsigned arc_logon_id;
	unsigned performance_flags;
	unsigned connection_type;
	int autodetect, heartbeat, monitor_layout, status_info, multitransport;
	unsigned keyboard_layout;
} fastrdpFrontInfo;

/* Printable ASCII (0x20-0x7e) of `in`, others as '?', at most FASTRDP_FRONT_NAME - 1 bytes;
 * a double quote becomes '?' as well, so the name cannot end the quoted field. */
static void fastrdp_front_safe_name(const char* in, char* out, size_t size)
{
	size_t n = 0;
	if (!out || size == 0)
		return;
	if (size > FASTRDP_FRONT_NAME)
		size = FASTRDP_FRONT_NAME;
	for (; in && *in && n + 1 < size; in++)
	{
		const unsigned char c = (unsigned char)*in;
		out[n++] = (c >= 0x20 && c <= 0x7e && c != '"') ? (char)c : '?';
	}
	out[n] = '\0';
}

static const char* fastrdp_yes(int v)
{
	return v ? "yes" : "no";
}

/* One line, e.g. `client "PC1" build 26100, 1920x1080 32 bpp, monitors 1, scale 100/100,
 * gfx yes, dynvc yes, bitmap cache v2 persist yes, glyph 0 offscreen 0, auto-reconnect
 * cookie yes (logon id 3), performance flags 0x00000080, connection type 7, autodetect yes,
 * heartbeat no, monitor layout yes, status info no, multitransport no, keyboard 0x00000407`.
 * Returns what snprintf returns. */
static int fastrdp_front_describe(const fastrdpFrontInfo* f, char* out, size_t size)
{
	char name[FASTRDP_FRONT_NAME];
	char arc[48] = "no";
	fastrdp_front_safe_name(f->client_name, name, sizeof(name));
	if (f->arc)
		(void)snprintf(arc, sizeof(arc), "yes (logon id %u)", f->arc_logon_id);
	return snprintf(out, size,
	                "client \"%s\" build %u, %ux%u %u bpp, monitors %u, scale %u/%u, gfx %s, "
	                "dynvc %s, bitmap cache %s v%u persist %s, glyph %u offscreen %u, "
	                "auto-reconnect cookie %s, performance flags 0x%08x, connection type %u, "
	                "autodetect %s, heartbeat %s, monitor layout %s, status info %s, "
	                "multitransport %s, keyboard 0x%08x",
	                name, f->build, f->width, f->height, f->bpp, f->monitors, f->desktop_scale,
	                f->device_scale, fastrdp_yes(f->gfx), fastrdp_yes(f->dynvc),
	                fastrdp_yes(f->bitmap_cache), f->bitmap_cache_version, fastrdp_yes(f->persist),
	                f->glyph_level, f->offscreen_level, arc, f->performance_flags,
	                f->connection_type, fastrdp_yes(f->autodetect), fastrdp_yes(f->heartbeat),
	                fastrdp_yes(f->monitor_layout), fastrdp_yes(f->status_info),
	                fastrdp_yes(f->multitransport), f->keyboard_layout);
}

/* [MS-RDPBCGR] 2.2.10.1.1 infoType */
static const char* fastrdp_save_session_info_name(unsigned type)
{
	switch (type)
	{
		case 0:
			return "logon (v1)";
		case 1:
			return "logon (v2)";
		case 2:
			return "plain notify";
		case 3:
			return "extended (auto-reconnect cookie / logon errors)";
		default:
			return "unknown";
	}
}

/* Counts one event; nonzero if it is to be logged: the first FASTRDP_PDU_LOG_FIRST, then
 * every 100th, so a client repeating a PDU cannot flood the log. */
static int fastrdp_pdu_log_this(unsigned* count)
{
	const unsigned n = ++*count;
	return n <= FASTRDP_PDU_LOG_FIRST || n % 100 == 0;
}

#endif
