/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * The waiting screen's panel ([FastRDP] WaitingScreen, fastrdp_plugin.c waiting_screen_*()):
 * lines of text from the broker, an optional countdown and an optional QR code, laid out
 * for the client's desktop and drawn into a 32-bit BGRX image. libc only, so that
 * tests/proxy-module/test_panel.c can test it without FreeRDP.
 *
 * Text is UTF-8; code points the font lacks (fastrdp_font.h: printable Latin-1 and a few
 * typographic characters) and malformed sequences become '?'. Lines are wrapped at
 * blanks to the columns that fit. The QR code comes from the broker as rows of '0' and
 * '1' (protocol.py "qr"); it is drawn dark on white with a quiet zone of 4 modules and at
 * least 4 pixels per module, or left out if that does not fit.
 * Every size is bounded here, whatever the broker or the client's desktop size says.
 */
#ifndef FASTRDP_PANEL_H
#define FASTRDP_PANEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fastrdp_font.h"

#define FASTRDP_PANEL_MAX_LINES 16  /* after wrapping, countdown not counted */
#define FASTRDP_PANEL_MAX_COLS 56   /* glyphs per line */
#define FASTRDP_PANEL_MAX_GLYPHS 240 /* per source line before wrapping */
#define FASTRDP_PANEL_LABEL_MAX 40  /* countdown label glyphs */
#define FASTRDP_QR_MIN 21
#define FASTRDP_QR_MAX 177
#define FASTRDP_QR_QUIET 4    /* modules of light border on each side */
#define FASTRDP_QR_MIN_PX 4   /* pixels per module, at least */
#define FASTRDP_QR_MAX_PX 8   /* and at most (font scale 2) */
#define FASTRDP_PANEL_MARGIN 16 /* to the desktop's edges */

/* colours, 0xRRGGBB */
#define FASTRDP_COLOR_SCREEN 0x000000u
#define FASTRDP_COLOR_PANEL 0xf2f2f2u
#define FASTRDP_COLOR_TEXT 0x1a1a1au
#define FASTRDP_COLOR_ACCENT 0x2f6db5u
#define FASTRDP_COLOR_QR_LIGHT 0xffffffu
#define FASTRDP_COLOR_QR_DARK 0x000000u

typedef struct
{
	int x, y;
	unsigned w, h;
} fastrdpRect;

typedef struct
{
	/* content */
	unsigned nsrc;
	unsigned short src[FASTRDP_PANEL_MAX_LINES][FASTRDP_PANEL_MAX_GLYPHS];
	unsigned srclen[FASTRDP_PANEL_MAX_LINES];
	unsigned short label[FASTRDP_PANEL_LABEL_MAX];
	unsigned labellen;
	int countdown; /* show the countdown line */
	unsigned qr_size;
	unsigned char qr[FASTRDP_QR_MAX * FASTRDP_QR_MAX]; /* 1 = dark */

	/* layout (fastrdp_panel_layout()); positions inside the panel unless noted */
	fastrdpRect rect; /* the panel on the desktop */
	unsigned scale;   /* font pixels per font dot */
	unsigned pad, cols, line_h, accent_h;
	unsigned nlines;
	unsigned short lines[FASTRDP_PANEL_MAX_LINES][FASTRDP_PANEL_MAX_COLS];
	unsigned linelen[FASTRDP_PANEL_MAX_LINES];
	unsigned text_x, text_y;
	fastrdpRect countdown_rect;
	int show_qr;
	unsigned qr_px; /* pixels per module */
	fastrdpRect qr_rect;
} fastrdpPanel;

/* Decodes one UTF-8 code point from s[0..len); returns the bytes used (>= 1), *cp is
 * 0xFFFD for a malformed or overlong sequence. */
static unsigned fastrdp_utf8_next(const unsigned char* s, size_t len, unsigned* cp)
{
	const unsigned c = s[0];
	unsigned need = 0, min = 0, v = 0;
	if (c < 0x80)
	{
		*cp = c;
		return 1;
	}
	if ((c & 0xe0) == 0xc0)
		need = 1, min = 0x80, v = c & 0x1f;
	else if ((c & 0xf0) == 0xe0)
		need = 2, min = 0x800, v = c & 0x0f;
	else if ((c & 0xf8) == 0xf0)
		need = 3, min = 0x10000, v = c & 0x07;
	else
	{
		*cp = 0xfffd;
		return 1;
	}
	if (len < need + 1)
	{
		*cp = 0xfffd;
		return 1;
	}
	for (unsigned i = 1; i <= need; i++)
	{
		if ((s[i] & 0xc0) != 0x80)
		{
			*cp = 0xfffd;
			return 1;
		}
		v = (v << 6) | (s[i] & 0x3f);
	}
	*cp = (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) ? 0xfffd : v;
	return need + 1;
}

/* UTF-8 text to glyph indices (fastrdp_font_index(); '?' for anything else, control
 * characters become blanks). Returns the glyph count, at most max. */
static unsigned fastrdp_glyphs(const char* text, unsigned short* out, unsigned max)
{
	const unsigned char* s = (const unsigned char*)text;
	size_t len = strlen(text);
	unsigned n = 0;
	while (len > 0 && n < max)
	{
		unsigned cp = 0;
		const unsigned used = fastrdp_utf8_next(s, len, &cp);
		s += used;
		len -= used;
		if (cp < 0x20 || cp == 0x7f)
			cp = ' ';
		const int g = fastrdp_font_index(cp);
		out[n++] = (unsigned short)(g >= 0 ? g : fastrdp_font_index('?'));
	}
	return n;
}

static void fastrdp_panel_init(fastrdpPanel* p)
{
	memset(p, 0, sizeof(*p));
}

/* Replaces the text; lines beyond FASTRDP_PANEL_MAX_LINES are dropped, NULL lines are
 * empty. Keeps the QR code and the countdown. */
static void fastrdp_panel_set_text(fastrdpPanel* p, const char* const* lines, unsigned n)
{
	p->nsrc = n < FASTRDP_PANEL_MAX_LINES ? n : FASTRDP_PANEL_MAX_LINES;
	for (unsigned i = 0; i < p->nsrc; i++)
		p->srclen[i] = lines[i] ? fastrdp_glyphs(lines[i], p->src[i], FASTRDP_PANEL_MAX_GLYPHS) : 0;
}

/* label NULL: no countdown line. */
static void fastrdp_panel_set_countdown(fastrdpPanel* p, const char* label)
{
	p->countdown = label != NULL;
	p->labellen = label ? fastrdp_glyphs(label, p->label, FASTRDP_PANEL_LABEL_MAX) : 0;
}

/* The QR code as n rows of n '0'/'1' characters (n = 21, 25, ..., 177: versions 1..40).
 * Returns 0 and removes any QR code if the rows are not that. n = 0 removes it. */
static int fastrdp_panel_set_qr(fastrdpPanel* p, const char* const* rows, unsigned n)
{
	p->qr_size = 0;
	if (n == 0)
		return 1;
	if (n < FASTRDP_QR_MIN || n > FASTRDP_QR_MAX || (n - 17) % 4 != 0)
		return 0;
	for (unsigned y = 0; y < n; y++)
	{
		if (!rows[y] || strlen(rows[y]) != n)
			return 0;
		for (unsigned x = 0; x < n; x++)
		{
			const char c = rows[y][x];
			if (c != '0' && c != '1')
				return 0;
			p->qr[y * n + x] = c == '1';
		}
	}
	p->qr_size = n;
	return 1;
}

/* Word wrap of every source line to `cols`; returns the widest line in glyphs. */
static unsigned fastrdp_panel_wrap(fastrdpPanel* p, unsigned cols, unsigned max_lines)
{
	const int blank = fastrdp_font_index(' ');
	const int dot = fastrdp_font_index('.');
	unsigned widest = 0;
	p->nlines = 0;
	for (unsigned i = 0; i < p->nsrc; i++)
	{
		const unsigned short* g = p->src[i];
		unsigned len = p->srclen[i], at = 0;
		do
		{
			if (p->nlines == max_lines)
			{
				/* no room: the last line ends in "..." */
				unsigned short* last = p->lines[max_lines - 1];
				unsigned* ll = &p->linelen[max_lines - 1];
				if (*ll + 3 > cols)
					*ll = cols >= 3 ? cols - 3 : 0;
				for (unsigned k = 0; k < 3 && *ll < cols; k++)
					last[(*ll)++] = (unsigned short)dot;
				if (*ll > widest)
					widest = *ll;
				return widest;
			}
			while (at < len && g[at] == blank && at > 0)
				at++; /* blanks at a wrap point */
			unsigned take = len - at;
			if (take > cols)
			{
				take = cols;
				/* break after the last blank that keeps the line non-empty */
				for (unsigned k = cols; k > 0; k--)
					if (g[at + k] == blank)
					{
						take = k;
						break;
					}
			}
			memcpy(p->lines[p->nlines], g + at, take * sizeof(*g));
			unsigned l = take;
			while (l > 0 && g[at + l - 1] == blank)
				l--;
			p->linelen[p->nlines++] = l;
			if (l > widest)
				widest = l;
			at += take;
		} while (at < len);
	}
	return widest;
}

/* Lays the panel out for a desktop of desk_w x desk_h: font scale 2 (3 from 2560x1440,
 * 1 on small desktops), at most FASTRDP_PANEL_MAX_COLS columns, the QR code to the right of the
 * text if it fits with FASTRDP_QR_MIN_PX, the panel centred. Returns 0 if the desktop
 * is too small for any panel. */
static int fastrdp_panel_layout(fastrdpPanel* p, unsigned desk_w, unsigned desk_h)
{
	static const char* const sample = "0:00"; /* widest countdown digits */
	if (desk_w < 160 || desk_h < 100 || desk_w > 32768 || desk_h > 32768)
		return 0;
	const unsigned max_scale = (desk_w >= 2560 && desk_h >= 1440) ? 3 : 2;
	for (unsigned scale = max_scale; scale >= 1; scale--)
	{
		for (int with_qr = p->qr_size > 0; with_qr >= 0; with_qr--)
		{
			const unsigned cw = FASTRDP_FONT_W * scale;
			const unsigned pad = 12 * scale;
			const unsigned line_h = (FASTRDP_FONT_H + 4) * scale;
			const unsigned accent_h = 3 * scale;
			unsigned qr_px = 0, qr_total = 0;
			if (with_qr)
			{
				const unsigned modules = p->qr_size + 2 * FASTRDP_QR_QUIET;
				qr_px = (140 * scale) / modules;
				if (qr_px < FASTRDP_QR_MIN_PX)
					qr_px = FASTRDP_QR_MIN_PX;
				if (qr_px > FASTRDP_QR_MAX_PX * scale / 2)
					qr_px = FASTRDP_QR_MAX_PX * scale / 2;
				qr_total = modules * qr_px;
			}
			const unsigned outer = 2 * FASTRDP_PANEL_MARGIN + 2 * pad + (with_qr ? qr_total + pad : 0);
			if (desk_w <= outer)
				continue;
			unsigned cols = (desk_w - outer) / cw;
			if (cols > FASTRDP_PANEL_MAX_COLS)
				cols = FASTRDP_PANEL_MAX_COLS;
			const unsigned min_cols = with_qr ? 20 : (scale == 2 ? 24 : 12);
			if (cols < min_cols)
				continue;
			const unsigned avail_h = desk_h - 2 * FASTRDP_PANEL_MARGIN;
			const unsigned fixed_h = 2 * pad + accent_h + (p->countdown ? line_h + line_h / 2 : 0);
			if (avail_h <= fixed_h + line_h || (with_qr && avail_h < qr_total + 2 * pad + accent_h))
				continue;
			unsigned max_lines = (avail_h - fixed_h) / line_h;
			if (max_lines > FASTRDP_PANEL_MAX_LINES)
				max_lines = FASTRDP_PANEL_MAX_LINES;
			unsigned widest = fastrdp_panel_wrap(p, cols, max_lines);
			if (p->countdown)
			{
				unsigned cd = p->labellen + 1 + (unsigned)strlen(sample);
				if (cd > cols)
				{
					p->labellen = cols > 5 ? cols - 5 : 0;
					cd = p->labellen + 1 + (unsigned)strlen(sample);
				}
				if (cd > widest)
					widest = cd;
			}
			if (widest < 16 && cols >= 16)
				widest = 16;
			const unsigned text_w = widest * cw;
			const unsigned text_h = p->nlines * line_h + (p->countdown ? line_h / 2 + line_h : 0);
			const unsigned body_h = (with_qr && qr_total > text_h) ? qr_total : text_h;
			p->scale = scale;
			p->pad = pad;
			p->cols = cols;
			p->line_h = line_h;
			p->accent_h = accent_h;
			p->show_qr = with_qr;
			p->qr_px = qr_px;
			p->rect.w = 2 * pad + text_w + (with_qr ? pad + qr_total : 0);
			p->rect.h = accent_h + 2 * pad + body_h;
			p->rect.x = (int)((desk_w - p->rect.w) / 2);
			p->rect.y = (int)((desk_h - p->rect.h) / 2);
			p->text_x = pad;
			p->text_y = accent_h + pad + (body_h - text_h) / 2;
			p->countdown_rect.x = (int)pad;
			p->countdown_rect.y = (int)(p->text_y + p->nlines * line_h + line_h / 2);
			p->countdown_rect.w = p->countdown ? text_w : 0;
			p->countdown_rect.h = p->countdown ? line_h : 0;
			p->qr_rect.x = (int)(2 * pad + text_w);
			p->qr_rect.y = (int)(accent_h + pad + (body_h - qr_total) / 2);
			p->qr_rect.w = p->qr_rect.h = qr_total;
			return 1;
		}
	}
	return 0;
}

static void fastrdp_fill(unsigned char* img, unsigned stride, unsigned img_h, fastrdpRect r,
                         unsigned rgb)
{
	for (unsigned y = 0; y < r.h && (unsigned)r.y + y < img_h; y++)
	{
		unsigned char* px = img + ((size_t)r.y + y) * stride + (size_t)r.x * 4;
		for (unsigned x = 0; x < r.w && ((size_t)r.x + x) * 4 < stride; x++, px += 4)
		{
			px[0] = rgb & 0xff;
			px[1] = (rgb >> 8) & 0xff;
			px[2] = (rgb >> 16) & 0xff;
			px[3] = 0xff;
		}
	}
}

static void fastrdp_draw_glyphs(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                                unsigned img_h, unsigned x0, unsigned y0,
                                const unsigned short* g, unsigned n)
{
	const unsigned s = p->scale;
	const unsigned top = (p->line_h - FASTRDP_FONT_H * s) / 2;
	for (unsigned i = 0; i < n; i++)
	{
		if (g[i] >= FASTRDP_FONT_GLYPHS)
			continue;
		const unsigned char* rows = fastrdp_font[g[i]];
		for (unsigned r = 0; r < FASTRDP_FONT_H; r++)
			for (unsigned c = 0; c < FASTRDP_FONT_W; c++)
				if (rows[r] & (0x80 >> c))
				{
					const fastrdpRect dot = { (int)(x0 + (i * FASTRDP_FONT_W + c) * s),
						                      (int)(y0 + top + r * s), s, s };
					fastrdp_fill(img, stride, img_h, dot, FASTRDP_COLOR_TEXT);
				}
	}
}

/* "m:ss" (minutes up to 99) */
static void fastrdp_countdown_text(long seconds, char out[8])
{
	if (seconds < 0)
		seconds = 0;
	if (seconds > 99 * 60 + 59)
		seconds = 99 * 60 + 59;
	(void)snprintf(out, 8, "%ld:%02ld", seconds / 60, seconds % 60);
}

/* Redraws the countdown line ("<label> m:ss") inside the panel image. */
static void fastrdp_panel_draw_countdown(const fastrdpPanel* p, unsigned char* img,
                                         unsigned stride, long seconds)
{
	if (!p->countdown)
		return;
	fastrdp_fill(img, stride, p->rect.h, p->countdown_rect, FASTRDP_COLOR_PANEL);
	unsigned short g[FASTRDP_PANEL_LABEL_MAX + 8];
	unsigned n = p->labellen;
	memcpy(g, p->label, n * sizeof(*g));
	if (n > 0)
		g[n++] = (unsigned short)fastrdp_font_index(' ');
	char digits[8];
	fastrdp_countdown_text(seconds, digits);
	n += fastrdp_glyphs(digits, g + n, 6);
	if (n > p->countdown_rect.w / (FASTRDP_FONT_W * p->scale))
		n = p->countdown_rect.w / (FASTRDP_FONT_W * p->scale);
	fastrdp_draw_glyphs(p, img, stride, p->rect.h, (unsigned)p->countdown_rect.x,
	                    (unsigned)p->countdown_rect.y, g, n);
}

/* Draws the whole panel into img (rect.w x rect.h pixels, BGRX, stride >= rect.w * 4). */
static void fastrdp_panel_draw(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                               long seconds)
{
	const fastrdpRect all = { 0, 0, p->rect.w, p->rect.h };
	const fastrdpRect accent = { 0, 0, p->rect.w, p->accent_h };
	fastrdp_fill(img, stride, p->rect.h, all, FASTRDP_COLOR_PANEL);
	fastrdp_fill(img, stride, p->rect.h, accent, FASTRDP_COLOR_ACCENT);
	for (unsigned i = 0; i < p->nlines; i++)
		fastrdp_draw_glyphs(p, img, stride, p->rect.h, p->text_x, p->text_y + i * p->line_h,
		                    p->lines[i], p->linelen[i]);
	fastrdp_panel_draw_countdown(p, img, stride, seconds);
	if (!p->show_qr)
		return;
	fastrdp_fill(img, stride, p->rect.h, p->qr_rect, FASTRDP_COLOR_QR_LIGHT);
	for (unsigned y = 0; y < p->qr_size; y++)
		for (unsigned x = 0; x < p->qr_size; x++)
			if (p->qr[y * p->qr_size + x])
			{
				const fastrdpRect m = { p->qr_rect.x + (int)((x + FASTRDP_QR_QUIET) * p->qr_px),
					                    p->qr_rect.y + (int)((y + FASTRDP_QR_QUIET) * p->qr_px),
					                    p->qr_px, p->qr_px };
				fastrdp_fill(img, stride, p->rect.h, m, FASTRDP_COLOR_QR_DARK);
			}
}

/* a and b overlap; *out = the intersection */
static int fastrdp_rect_intersect(fastrdpRect a, fastrdpRect b, fastrdpRect* out)
{
	const long x0 = a.x > b.x ? a.x : b.x;
	const long y0 = a.y > b.y ? a.y : b.y;
	const long ax1 = (long)a.x + a.w, bx1 = (long)b.x + b.w;
	const long ay1 = (long)a.y + a.h, by1 = (long)b.y + b.h;
	const long x1 = ax1 < bx1 ? ax1 : bx1;
	const long y1 = ay1 < by1 ? ay1 : by1;
	if (x1 <= x0 || y1 <= y0)
		return 0;
	out->x = (int)x0;
	out->y = (int)y0;
	out->w = (unsigned)(x1 - x0);
	out->h = (unsigned)(y1 - y0);
	return 1;
}

/* The smallest rectangle around a and b (an empty one counts as nothing). */
static fastrdpRect fastrdp_rect_union(fastrdpRect a, fastrdpRect b)
{
	if (a.w == 0 || a.h == 0)
		return b;
	if (b.w == 0 || b.h == 0)
		return a;
	const long x0 = a.x < b.x ? a.x : b.x;
	const long y0 = a.y < b.y ? a.y : b.y;
	const long ax1 = (long)a.x + a.w, bx1 = (long)b.x + b.w;
	const long ay1 = (long)a.y + a.h, by1 = (long)b.y + b.h;
	const fastrdpRect r = { (int)x0, (int)y0, (unsigned)((ax1 > bx1 ? ax1 : bx1) - x0),
		                    (unsigned)((ay1 > by1 ? ay1 : by1) - y0) };
	return r;
}

#endif /* FASTRDP_PANEL_H */
