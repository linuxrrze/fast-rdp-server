/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * The waiting screen's panel ([FastRDP] WaitingScreen, fastrdp_plugin.c waiting_screen_*()):
 * lines of text from the broker, an optional countdown and an optional QR code, laid out
 * for the client's desktop and drawn into a 32-bit BGRX image: a white card with rounded
 * corners and a soft shadow on the dark screen, a lock icon beside the first line (the
 * title, semibold), the other lines below it (a line that is a URL in the accent colour),
 * the QR code on the right, and the countdown with a shrinking bar at the bottom.
 * libc only, so that tests/proxy-module/test_panel.c can test it without FreeRDP.
 * The desktop picker ([broker] desktop_picker, fastrdp_plugin.c ws_picker_*()) adds up to
 * FASTRDP_PANEL_MAX_OPTIONS rounded rows below the text (a key badge "1".."9" and the
 * label), the selected one filled with the accent colour, and a hint line;
 * fastrdp_panel_hit() finds the row under a click.
 *
 * Text is UTF-8; code points the font lacks (fastrdp_font.h: printable Latin-1 and a few
 * typographic characters) and malformed sequences become '?'. Glyphs are antialiased
 * (Roboto, 4-bit coverage) and blended onto the card; lines are wrapped by pixel width at
 * blanks, after '/', '-', '&', '?' and '=' (URLs), long words anywhere. The QR code comes
 * from the broker as rows of '0' and '1' (protocol.py "qr"); it is drawn dark on white
 * with a quiet zone of 4 modules and at least 4 pixels per module, or left out if that
 * does not fit. Sizes: the font's larger step from 3200x1800, then smaller paddings and
 * fonts until the panel fits; every size is bounded here, whatever the broker or the
 * client's desktop size says.
 */
#ifndef FASTRDP_PANEL_H
#define FASTRDP_PANEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fastrdp_font.h"

#define FASTRDP_PANEL_MAX_LINES 16   /* after wrapping, countdown not counted */
#define FASTRDP_PANEL_MAX_COLS 160   /* glyphs per wrapped line */
#define FASTRDP_PANEL_MAX_GLYPHS 240 /* per source line before wrapping */
#define FASTRDP_PANEL_LABEL_MAX 40   /* countdown label glyphs */
#define FASTRDP_PANEL_HINT_MAX 120   /* picker hint glyphs */
#define FASTRDP_QR_MIN 21
#define FASTRDP_QR_MAX 177
#define FASTRDP_QR_QUIET 4  /* modules of light border on each side */
#define FASTRDP_QR_MIN_PX 4 /* pixels per module, at least */
#define FASTRDP_PANEL_MARGIN 16      /* to the desktop's edges */
#define FASTRDP_PANEL_MAX_OPTIONS 9  /* picker rows: keys 1..9 */
#define FASTRDP_PANEL_OPTION_MAX 48  /* glyphs per picker label */

/* colours, 0xRRGGBB */
#define FASTRDP_COLOR_SCREEN 0x1e1f24u /* the desktop around the card */
#define FASTRDP_COLOR_PANEL 0xffffffu  /* the card */
#define FASTRDP_COLOR_TITLE 0x16171bu
#define FASTRDP_COLOR_TEXT 0x3a3c42u
#define FASTRDP_COLOR_MUTED 0x6b6e76u
#define FASTRDP_COLOR_ACCENT 0x2b63d9u
#define FASTRDP_COLOR_ACCENT_TINT 0xe6edfbu /* icon background */
#define FASTRDP_COLOR_ROW 0xf1f2f4u         /* picker rows not selected */
#define FASTRDP_COLOR_LINE 0xe3e4e8u        /* divider, bar track, QR border */
#define FASTRDP_COLOR_SELECTED_TEXT 0xffffffu /* on the accent colour */
#define FASTRDP_COLOR_SELECTED_KEY 0x5582e1u  /* key badge on the accent colour */
#define FASTRDP_COLOR_QR_LIGHT 0xffffffu
#define FASTRDP_COLOR_QR_DARK 0x000000u
#define FASTRDP_SHADOW_ALPHA 110u /* darkest shadow, of 255 */

/* line styles */
#define FASTRDP_LINE_TITLE 0
#define FASTRDP_LINE_BODY 1
#define FASTRDP_LINE_LINK 2

typedef struct
{
	int x, y;
	unsigned w, h;
} fastrdpRect;

/* One set of sizes (fastrdp_panel_layout() tries them in order), pixels. */
typedef struct
{
	unsigned step;                        /* fastrdp_faces[step] */
	unsigned char title, body, small;     /* fastrdpFontStyle of each role */
	unsigned pad, radius, blur, drop;     /* card padding and corners, shadow size and offset */
	unsigned icon, icon_gap;              /* lock icon (0: none) and its distance to the title */
	unsigned title_lh, body_lh, small_lh; /* line heights */
	unsigned gap, para, section;          /* below the title, between paragraphs, sections */
	unsigned row_h, row_gap, row_r;       /* picker rows */
	unsigned max_w, min_w;                /* text column */
	unsigned qr_target, qr_max_px, qr_gap;
	unsigned bar_h;
} fastrdpLook;

static const fastrdpLook fastrdp_looks[] = {
	/* large desktops (from 3200x1800): the larger font step */
	{ .step = 1, .title = FASTRDP_FONT_TITLE, .body = FASTRDP_FONT_BODY, .small = FASTRDP_FONT_SMALL,
	  .pad = 48, .radius = 20, .blur = 40, .drop = 12, .icon = 60, .icon_gap = 24, .title_lh = 50,
	  .body_lh = 38, .small_lh = 30, .gap = 15, .para = 12, .section = 30, .row_h = 63, .row_gap = 12,
	  .row_r = 12, .max_w = 780, .min_w = 510, .qr_target = 324, .qr_max_px = 9, .qr_gap = 36,
	  .bar_h = 9 },
	{ .step = 0, .title = FASTRDP_FONT_TITLE, .body = FASTRDP_FONT_BODY, .small = FASTRDP_FONT_SMALL,
	  .pad = 32, .radius = 14, .blur = 28, .drop = 8, .icon = 40, .icon_gap = 16, .title_lh = 33,
	  .body_lh = 26, .small_lh = 20, .gap = 10, .para = 8, .section = 20, .row_h = 42, .row_gap = 8,
	  .row_r = 10, .max_w = 520, .min_w = 340, .qr_target = 216, .qr_max_px = 6, .qr_gap = 24,
	  .bar_h = 6 },
	/* small desktops */
	{ .step = 0, .title = FASTRDP_FONT_TITLE, .body = FASTRDP_FONT_BODY, .small = FASTRDP_FONT_SMALL,
	  .pad = 20, .radius = 10, .blur = 12, .drop = 4, .icon = 32, .icon_gap = 12, .title_lh = 32,
	  .body_lh = 24, .small_lh = 19, .gap = 6, .para = 4, .section = 14, .row_h = 32, .row_gap = 4,
	  .row_r = 8, .max_w = 460, .min_w = 240, .qr_target = 160, .qr_max_px = 5, .qr_gap = 16,
	  .bar_h = 5 },
	/* tiny ones: no icon, no shadow, the body font for the title, the small one for text */
	{ .step = 0, .title = FASTRDP_FONT_BODY, .body = FASTRDP_FONT_SMALL, .small = FASTRDP_FONT_SMALL,
	  .pad = 10, .radius = 6, .blur = 0, .drop = 0, .icon = 0, .icon_gap = 0, .title_lh = 22,
	  .body_lh = 18, .small_lh = 18, .gap = 4, .para = 2, .section = 6, .row_h = 22, .row_gap = 2,
	  .row_r = 5, .max_w = 400, .min_w = 100, .qr_target = 120, .qr_max_px = 4, .qr_gap = 10,
	  .bar_h = 4 },
};
#define FASTRDP_PANEL_LOOKS (sizeof(fastrdp_looks) / sizeof(fastrdp_looks[0]))

typedef struct
{
	/* content */
	unsigned nsrc;
	unsigned short src[FASTRDP_PANEL_MAX_LINES][FASTRDP_PANEL_MAX_GLYPHS];
	unsigned srclen[FASTRDP_PANEL_MAX_LINES];
	unsigned short label[FASTRDP_PANEL_LABEL_MAX];
	unsigned labellen;
	int countdown;            /* show the countdown line */
	unsigned countdown_total; /* seconds the bar stands for; 0: no bar */
	unsigned qr_size;
	unsigned char qr[FASTRDP_QR_MAX * FASTRDP_QR_MAX]; /* 1 = dark */
	unsigned nopt;                                     /* picker rows */
	unsigned short opt[FASTRDP_PANEL_MAX_OPTIONS][FASTRDP_PANEL_OPTION_MAX];
	unsigned optlen[FASTRDP_PANEL_MAX_OPTIONS];
	unsigned selected;
	unsigned short hint[FASTRDP_PANEL_HINT_MAX];
	unsigned hintlen;

	/* layout (fastrdp_panel_layout()); positions inside the panel unless noted */
	fastrdpRect rect; /* the panel (card and shadow) on the desktop */
	const fastrdpLook* look;
	unsigned step; /* font size step, fastrdp_faces[] */
	fastrdpRect card;
	unsigned nlines;
	unsigned short lines[FASTRDP_PANEL_MAX_LINES][FASTRDP_PANEL_MAX_COLS];
	unsigned linelen[FASTRDP_PANEL_MAX_LINES];
	unsigned char line_style[FASTRDP_PANEL_MAX_LINES]; /* FASTRDP_LINE_* */
	unsigned char line_src[FASTRDP_PANEL_MAX_LINES];   /* source line */
	unsigned line_x[FASTRDP_PANEL_MAX_LINES], line_y[FASTRDP_PANEL_MAX_LINES]; /* line box */
	unsigned text_x, text_y, text_w; /* text column */
	fastrdpRect icon;
	unsigned row_h, opt_y; /* picker rows: pitch, top of the first */
	unsigned opt_h;        /* height of a row */
	fastrdpRect hint_rect;
	unsigned divider_y; /* 0: none */
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

static unsigned short fastrdp_glyph(unsigned cp)
{
	return (unsigned short)fastrdp_font_index(cp);
}

static void fastrdp_panel_init(fastrdpPanel* p)
{
	memset(p, 0, sizeof(*p));
}

/* Replaces the text; lines beyond FASTRDP_PANEL_MAX_LINES are dropped, NULL lines are
 * empty. The first line is the title. Keeps the QR code and the countdown. */
static void fastrdp_panel_set_text(fastrdpPanel* p, const char* const* lines, unsigned n)
{
	p->nsrc = n < FASTRDP_PANEL_MAX_LINES ? n : FASTRDP_PANEL_MAX_LINES;
	for (unsigned i = 0; i < p->nsrc; i++)
		p->srclen[i] = lines[i] ? fastrdp_glyphs(lines[i], p->src[i], FASTRDP_PANEL_MAX_GLYPHS) : 0;
}

/* label NULL: no countdown line. Without fastrdp_panel_set_countdown_total() no bar. */
static void fastrdp_panel_set_countdown(fastrdpPanel* p, const char* label)
{
	p->countdown = label != NULL;
	p->countdown_total = 0;
	p->labellen = label ? fastrdp_glyphs(label, p->label, FASTRDP_PANEL_LABEL_MAX) : 0;
}

/* The countdown's full length: its bar shrinks from there to 0 seconds. */
static void fastrdp_panel_set_countdown_total(fastrdpPanel* p, unsigned seconds)
{
	p->countdown_total = p->countdown ? seconds : 0;
}

/* The picker's rows: labels[0..n) behind the keys 1..n (n beyond
 * FASTRDP_PANEL_MAX_OPTIONS dropped, labels cut to FASTRDP_PANEL_OPTION_MAX glyphs, NULL
 * empty), `selected` filled with the accent colour, `hint` (NULL: none) one line below
 * them. n = 0 removes the rows and the hint. */
static void fastrdp_panel_set_options(fastrdpPanel* p, const char* const* labels, unsigned n,
                                      unsigned selected, const char* hint)
{
	p->nopt = n < FASTRDP_PANEL_MAX_OPTIONS ? n : FASTRDP_PANEL_MAX_OPTIONS;
	for (unsigned i = 0; i < p->nopt; i++)
		p->optlen[i] = labels[i] ? fastrdp_glyphs(labels[i], p->opt[i], FASTRDP_PANEL_OPTION_MAX) : 0;
	p->selected = selected < p->nopt ? selected : 0;
	p->hintlen = (p->nopt && hint) ? fastrdp_glyphs(hint, p->hint, FASTRDP_PANEL_HINT_MAX) : 0;
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

static const fastrdpFace* fastrdp_face(const fastrdpPanel* p, unsigned style)
{
	return &fastrdp_faces[p->look->step][style];
}

/* The face of a line style. */
static const fastrdpFace* fastrdp_line_face(const fastrdpPanel* p, unsigned style)
{
	return fastrdp_face(p, style == FASTRDP_LINE_TITLE ? p->look->title : p->look->body);
}

/* A glyph's advance in whole pixels. */
static unsigned fastrdp_adv(const fastrdpFace* f, unsigned short g)
{
	return g < FASTRDP_FONT_GLYPHS ? (f->glyphs[g].adv64 + 32u) / 64 : 0;
}

/* Width of g[0..n) in pixels (pens move in 1/64 pixel, fastrdp_draw_text()). */
static unsigned fastrdp_text_width(const fastrdpFace* f, const unsigned short* g, unsigned n)
{
	unsigned long w = 0;
	for (unsigned i = 0; i < n; i++)
		if (g[i] < FASTRDP_FONT_GLYPHS)
			w += f->glyphs[g[i]].adv64;
	return (unsigned)((w + 63) / 64);
}

/* Glyphs of g[0..n) that fit w pixels, room for a trailing "…" left if they do not all
 * fit (*cut set). */
static unsigned fastrdp_text_fit(const fastrdpFace* f, const unsigned short* g, unsigned n,
                                 unsigned w, int* cut)
{
	*cut = 0;
	if (fastrdp_text_width(f, g, n) <= w)
		return n;
	*cut = 1;
	const unsigned long ell = f->glyphs[fastrdp_glyph(0x2026)].adv64, w64 = (unsigned long)w * 64;
	unsigned long x = 0;
	unsigned k = 0;
	while (k < n && x + f->glyphs[g[k]].adv64 + ell <= w64)
		x += f->glyphs[g[k++]].adv64;
	return k;
}

/* the line may break after this glyph */
static int fastrdp_break_after(unsigned short g)
{
	return g == fastrdp_glyph('/') || g == fastrdp_glyph('-') || g == fastrdp_glyph('&') ||
	       g == fastrdp_glyph('?') || g == fastrdp_glyph('=');
}

static int fastrdp_is_url(const unsigned short* g, unsigned n)
{
	static const char* const schemes[] = { "https://", "http://" };
	for (unsigned s = 0; s < 2; s++)
	{
		const unsigned len = (unsigned)strlen(schemes[s]);
		unsigned k = 0;
		while (k < len && k < n && g[k] == fastrdp_glyph((unsigned char)schemes[s][k]))
			k++;
		if (k == len)
			return 1;
	}
	return 0;
}

/* Ends line i in "…" within w pixels. */
static void fastrdp_ellipsize(fastrdpPanel* p, unsigned i, unsigned w)
{
	const fastrdpFace* f = fastrdp_line_face(p, p->line_style[i]);
	const unsigned short ell = fastrdp_glyph(0x2026);
	unsigned* n = &p->linelen[i];
	while (*n > 0 && (*n >= FASTRDP_PANEL_MAX_COLS ||
	                  fastrdp_text_width(f, p->lines[i], *n) + fastrdp_adv(f, ell) > w))
		(*n)--;
	p->lines[i][(*n)++] = ell;
}

/* Wraps every source line into p->lines: the title (source line 0) to title_w pixels,
 * the others to w, at most max_lines lines; the last one ends in "…" if the text does
 * not fit. Returns the widest line, the title's offset included. */
static unsigned fastrdp_panel_wrap(fastrdpPanel* p, unsigned w, unsigned title_w,
                                   unsigned title_x, unsigned max_lines)
{
	const unsigned short blank = fastrdp_glyph(' ');
	unsigned widest = 0;
	p->nlines = 0;
	for (unsigned i = 0; i < p->nsrc; i++)
	{
		const unsigned short* g = p->src[i];
		const unsigned len = p->srclen[i];
		const unsigned style =
		    i == 0 ? FASTRDP_LINE_TITLE : fastrdp_is_url(g, len) ? FASTRDP_LINE_LINK : FASTRDP_LINE_BODY;
		const fastrdpFace* f = fastrdp_line_face(p, style);
		const unsigned lw = style == FASTRDP_LINE_TITLE ? title_w : w;
		unsigned at = 0;
		do
		{
			if (p->nlines == max_lines)
			{
				const unsigned last = max_lines - 1;
				fastrdp_ellipsize(p, last, p->line_style[last] == FASTRDP_LINE_TITLE ? title_w : w);
				const unsigned x = p->line_style[last] == FASTRDP_LINE_TITLE ? title_x : 0;
				const fastrdpFace* lf = fastrdp_line_face(p, p->line_style[last]);
				const unsigned lwid = x + fastrdp_text_width(lf, p->lines[last], p->linelen[last]);
				return lwid > widest ? lwid : widest;
			}
			while (at > 0 && at < len && g[at] == blank)
				at++; /* blanks at a wrap point */
			unsigned long x = 0;
			unsigned k = at, brk = at;
			while (k < len && k - at < FASTRDP_PANEL_MAX_COLS)
			{
				const unsigned a = f->glyphs[g[k]].adv64;
				if (g[k] == blank)
					brk = k;
				if (x + a > (unsigned long)lw * 64 && k > at)
					break;
				x += a;
				k++;
				if (fastrdp_break_after(g[k - 1]) && k < len)
					brk = k;
			}
			const unsigned end = (k < len && brk > at) ? brk : k;
			unsigned n = end - at;
			while (n > 0 && g[at + n - 1] == blank)
				n--;
			const unsigned l = p->nlines++;
			memcpy(p->lines[l], g + at, n * sizeof(*g));
			p->linelen[l] = n;
			p->line_style[l] = (unsigned char)style;
			p->line_src[l] = (unsigned char)i;
			const unsigned lwid =
			    (style == FASTRDP_LINE_TITLE ? title_x : 0) + fastrdp_text_width(f, g + at, n);
			if (lwid > widest)
				widest = lwid;
			at = end;
		} while (at < len);
	}
	return widest;
}

static unsigned fastrdp_line_height(const fastrdpPanel* p, unsigned style)
{
	return style == FASTRDP_LINE_TITLE ? p->look->title_lh : p->look->body_lh;
}

/* Places the wrapped lines from y on (line_x, line_y); returns the height used. */
static unsigned fastrdp_panel_place_lines(fastrdpPanel* p, unsigned x, unsigned y, unsigned title_x)
{
	const fastrdpLook* k = p->look;
	unsigned ntitle = 0;
	while (ntitle < p->nlines && p->line_style[ntitle] == FASTRDP_LINE_TITLE)
		ntitle++;
	unsigned at = y;
	if (ntitle > 0 || k->icon)
	{
		/* the icon beside the title's first line */
		const unsigned title_h = ntitle * k->title_lh;
		const unsigned head_h = k->icon > title_h ? k->icon : title_h;
		const unsigned first = k->icon > k->title_lh ? (k->icon - k->title_lh) / 2 : 0;
		for (unsigned i = 0; i < ntitle; i++)
		{
			p->line_x[i] = x + title_x;
			p->line_y[i] = at + first + i * k->title_lh;
		}
		p->icon.x = (int)x;
		p->icon.y = (int)(at + (k->title_lh > k->icon ? (k->title_lh - k->icon) / 2 : 0));
		p->icon.w = p->icon.h = k->icon;
		at += (title_h + first > head_h ? title_h + first : head_h);
		if (p->nlines > ntitle)
			at += k->gap;
	}
	for (unsigned i = ntitle; i < p->nlines; i++)
	{
		if (i > ntitle && p->line_src[i] != p->line_src[i - 1])
			at += k->para;
		p->line_x[i] = x;
		p->line_y[i] = at;
		at += fastrdp_line_height(p, p->line_style[i]);
	}
	return at - y;
}

/* The widest digit: every digit of the countdown takes that much (tabular figures). */
static unsigned fastrdp_digit_cell(const fastrdpFace* f)
{
	unsigned cell = 0;
	for (unsigned d = '0'; d <= '9'; d++)
		if (fastrdp_adv(f, fastrdp_glyph(d)) > cell)
			cell = fastrdp_adv(f, fastrdp_glyph(d));
	return cell;
}

/* One layout attempt with look k; 0 if it does not fit the desktop. */
static int fastrdp_panel_try(fastrdpPanel* p, const fastrdpLook* k, int with_qr, unsigned desk_w,
                             unsigned desk_h)
{
	p->look = k;
	p->step = k->step;
	const fastrdpFace* body = fastrdp_face(p, k->body);
	const fastrdpFace* small = fastrdp_face(p, k->small);
	const unsigned avail_w = desk_w - 2 * FASTRDP_PANEL_MARGIN;
	const unsigned avail_h = desk_h - 2 * FASTRDP_PANEL_MARGIN;
	unsigned qr_px = 0, qr_total = 0, qr_col = 0;
	if (with_qr)
	{
		const unsigned modules = p->qr_size + 2 * FASTRDP_QR_QUIET;
		qr_px = k->qr_target / modules;
		if (qr_px < FASTRDP_QR_MIN_PX)
			qr_px = FASTRDP_QR_MIN_PX;
		if (qr_px > k->qr_max_px)
			qr_px = k->qr_max_px;
		qr_total = modules * qr_px;
		qr_col = k->qr_gap + qr_total + 2; /* and a 1-pixel border */
	}
	const unsigned fixed_w = 2 * k->blur + 2 * k->pad + qr_col;
	if (avail_w < fixed_w + k->min_w)
		return 0;
	const unsigned w = avail_w - fixed_w < k->max_w ? avail_w - fixed_w : k->max_w;
	const unsigned title_x = k->icon ? k->icon + k->icon_gap : 0;
	if (w < title_x + 4 * body->size)
		return 0;

	const unsigned options_h = p->nopt ? k->section + p->nopt * k->row_h +
	                                         (p->nopt - 1) * k->row_gap +
	                                         (p->hintlen ? k->gap + k->small_lh : 0)
	                                   : 0;
	const int divider = k->blur > 0;
	const unsigned countdown_h =
	    p->countdown ? k->section + (divider ? 1 + k->section : 0) + k->body_lh : 0;
	unsigned widest = 0, text_h = 0, body_h = 0, max_lines = FASTRDP_PANEL_MAX_LINES;
	for (;; max_lines--)
	{
		if (max_lines == 0)
			return 0;
		widest = fastrdp_panel_wrap(p, w, w - title_x, title_x, max_lines);
		text_h = fastrdp_panel_place_lines(p, 0, 0, title_x);
		body_h = text_h + options_h;
		if (with_qr && qr_total + 2 > body_h)
			body_h = qr_total + 2;
		if (2 * k->blur + 2 * k->pad + body_h + countdown_h <= avail_h)
			break;
	}

	/* the text column: the widest line, the picker rows and hint, the countdown */
	unsigned text_w = widest > k->min_w ? widest : k->min_w;
	const unsigned badge = k->row_h * 3 / 5, inset = (k->row_h - badge) / 2;
	for (unsigned i = 0; i < p->nopt; i++)
	{
		const unsigned rw = 2 * inset + badge + inset + fastrdp_text_width(body, p->opt[i], p->optlen[i]);
		if (rw > text_w)
			text_w = rw;
	}
	if (p->hintlen && fastrdp_text_width(small, p->hint, p->hintlen) > text_w)
		text_w = fastrdp_text_width(small, p->hint, p->hintlen);
	const unsigned cd_w = fastrdp_text_width(small, p->label, p->labellen) +
	                      fastrdp_adv(small, fastrdp_glyph(' ')) + 5 * fastrdp_digit_cell(body) +
	                      (p->countdown_total ? 4 * k->row_h : 0);
	if (p->countdown && !with_qr && cd_w > text_w)
		text_w = cd_w;
	if (text_w > w)
		text_w = w;

	p->show_qr = with_qr;
	p->qr_px = qr_px;
	p->card.x = (int)k->blur;
	p->card.y = (int)(k->blur - k->drop);
	p->card.w = 2 * k->pad + text_w + qr_col;
	p->card.h = 2 * k->pad + body_h + countdown_h;
	p->rect.w = p->card.w + 2 * k->blur;
	p->rect.h = p->card.h + 2 * k->blur;
	p->rect.x = (int)((desk_w - p->rect.w) / 2);
	p->rect.y = (int)((desk_h - p->rect.h) / 2);
	p->text_x = (unsigned)p->card.x + k->pad;
	p->text_y = (unsigned)p->card.y + k->pad;
	p->text_w = text_w;
	(void)fastrdp_panel_place_lines(p, p->text_x, p->text_y, title_x);
	p->opt_y = p->text_y + text_h + k->section;
	p->row_h = k->row_h + k->row_gap;
	p->opt_h = k->row_h;
	p->hint_rect.x = (int)p->text_x;
	p->hint_rect.y = (int)(p->opt_y + p->nopt * k->row_h + (p->nopt ? p->nopt - 1 : 0) * k->row_gap + k->gap);
	p->hint_rect.w = p->hintlen ? text_w : 0;
	p->hint_rect.h = p->hintlen ? k->small_lh : 0;
	const unsigned bottom = p->text_y + body_h;
	p->divider_y = (p->countdown && divider) ? bottom + k->section : 0;
	p->countdown_rect.x = (int)p->text_x;
	p->countdown_rect.y = (int)(bottom + k->section + (divider ? 1 + k->section : 0));
	p->countdown_rect.w = p->countdown ? p->card.w - 2 * k->pad : 0;
	p->countdown_rect.h = p->countdown ? k->body_lh : 0;
	p->qr_rect.x = (int)(p->text_x + text_w + k->qr_gap + 1);
	p->qr_rect.y = (int)p->text_y + 1;
	p->qr_rect.w = p->qr_rect.h = qr_total;
	if (!k->icon)
		p->icon.w = p->icon.h = 0;
	return 1;
}

/* Lays the panel out for a desktop of desk_w x desk_h: the larger font step from
 * 3200x1800, smaller paddings, icon and fonts on small desktops, the QR code to the right
 * of the text as long as some look fits with it, the panel centred. Returns 0 if the
 * desktop is too small for any panel. */
static int fastrdp_panel_layout(fastrdpPanel* p, unsigned desk_w, unsigned desk_h)
{
	if (desk_w < 160 || desk_h < 100 || desk_w > 32768 || desk_h > 32768)
		return 0;
	const unsigned first = (desk_w >= 3200 && desk_h >= 1800) ? 0 : 1;
	for (int with_qr = p->qr_size > 0; with_qr >= 0; with_qr--)
		for (unsigned i = first; i < FASTRDP_PANEL_LOOKS; i++)
			if (fastrdp_panel_try(p, &fastrdp_looks[i], with_qr, desk_w, desk_h))
				return 1;
	return 0;
}

/* ------------------------------------------------------------------ drawing */

/* r inside the panel image, empty if nothing of it is */
static fastrdpRect fastrdp_panel_clip(const fastrdpPanel* p, fastrdpRect r)
{
	fastrdpRect out = { 0, 0, 0, 0 };
	const long x0 = r.x > 0 ? r.x : 0, y0 = r.y > 0 ? r.y : 0;
	const long x1 = (long)r.x + r.w < (long)p->rect.w ? (long)r.x + r.w : (long)p->rect.w;
	const long y1 = (long)r.y + r.h < (long)p->rect.h ? (long)r.y + r.h : (long)p->rect.h;
	if (x1 > x0 && y1 > y0)
	{
		out.x = (int)x0;
		out.y = (int)y0;
		out.w = (unsigned)(x1 - x0);
		out.h = (unsigned)(y1 - y0);
	}
	return out;
}

/* Blends rgb with coverage a (0..255) onto the pixel. */
static void fastrdp_blend(unsigned char* px, unsigned rgb, unsigned a)
{
	const unsigned na = 255 - a;
	px[0] = (unsigned char)((px[0] * na + (rgb & 0xff) * a + 127) / 255);
	px[1] = (unsigned char)((px[1] * na + ((rgb >> 8) & 0xff) * a + 127) / 255);
	px[2] = (unsigned char)((px[2] * na + ((rgb >> 16) & 0xff) * a + 127) / 255);
	px[3] = 0xff;
}

/* the pixel at (x, y) if it is inside clip (clipped to the image already), else NULL */
static unsigned char* fastrdp_px(unsigned char* img, unsigned stride, fastrdpRect clip, long x,
                                 long y)
{
	if (x < clip.x || y < clip.y || x >= (long)clip.x + clip.w || y >= (long)clip.y + clip.h)
		return NULL;
	return img + (size_t)y * stride + (size_t)x * 4;
}

/* Fills r (inside clip) with rgb. */
static void fastrdp_fill(unsigned char* img, unsigned stride, fastrdpRect clip, fastrdpRect r,
                         unsigned rgb)
{
	fastrdpRect o;
	const long x0 = r.x > clip.x ? r.x : clip.x, y0 = r.y > clip.y ? r.y : clip.y;
	const long x1 = (long)r.x + r.w < (long)clip.x + clip.w ? (long)r.x + r.w : (long)clip.x + clip.w;
	const long y1 = (long)r.y + r.h < (long)clip.y + clip.h ? (long)r.y + r.h : (long)clip.y + clip.h;
	if (x1 <= x0 || y1 <= y0)
		return;
	o.x = (int)x0;
	o.y = (int)y0;
	o.w = (unsigned)(x1 - x0);
	o.h = (unsigned)(y1 - y0);
	for (unsigned y = 0; y < o.h; y++)
	{
		unsigned char* px = img + ((size_t)o.y + y) * stride + (size_t)o.x * 4;
		for (unsigned x = 0; x < o.w; x++, px += 4)
		{
			px[0] = rgb & 0xff;
			px[1] = (rgb >> 8) & 0xff;
			px[2] = (rgb >> 16) & 0xff;
			px[3] = 0xff;
		}
	}
}

/* Coverage (0..16) of pixel (x, y) by the rectangle r with corners of the given radius:
 * 4x4 samples, in eighths of a pixel. */
static unsigned fastrdp_rrect_samples(fastrdpRect r, unsigned radius, long x, long y)
{
	const long rad8 = (long)radius * 8;
	const long l = ((long)r.x + radius) * 8, rt = ((long)r.x + r.w - radius) * 8;
	const long t = ((long)r.y + radius) * 8, b = ((long)r.y + r.h - radius) * 8;
	unsigned n = 0;
	for (long sy = y * 8 + 1; sy < y * 8 + 8; sy += 2)
		for (long sx = x * 8 + 1; sx < x * 8 + 8; sx += 2)
		{
			if (sx < (long)r.x * 8 || sx >= ((long)r.x + r.w) * 8 || sy < (long)r.y * 8 ||
			    sy >= ((long)r.y + r.h) * 8)
				continue;
			const long dx = sx < l ? l - sx : sx > rt ? sx - rt : 0;
			const long dy = sy < t ? t - sy : sy > b ? sy - b : 0;
			n += dx * dx + dy * dy <= rad8 * rad8;
		}
	return n;
}

/* Fills r with rounded, antialiased corners (inside clip). */
static void fastrdp_fill_rrect(unsigned char* img, unsigned stride, fastrdpRect clip, fastrdpRect r,
                               unsigned radius, unsigned rgb)
{
	if (radius * 2 > r.w)
		radius = r.w / 2;
	if (radius * 2 > r.h)
		radius = r.h / 2;
	const fastrdpRect inner_h = { r.x + (int)radius, r.y, r.w - 2 * radius, r.h };
	const fastrdpRect inner_v = { r.x, r.y + (int)radius, r.w, r.h - 2 * radius };
	fastrdp_fill(img, stride, clip, inner_h, rgb);
	fastrdp_fill(img, stride, clip, inner_v, rgb);
	/* the four corner squares */
	for (unsigned c = 0; c < 4; c++)
	{
		const long cx = (c & 1) ? (long)r.x + r.w - radius : r.x;
		const long cy = (c & 2) ? (long)r.y + r.h - radius : r.y;
		for (long y = cy; y < cy + (long)radius; y++)
			for (long x = cx; x < cx + (long)radius; x++)
			{
				unsigned char* px = fastrdp_px(img, stride, clip, x, y);
				const unsigned n = px ? fastrdp_rrect_samples(r, radius, x, y) : 0;
				if (n)
					fastrdp_blend(px, rgb, n * 255 / 16);
			}
	}
}

static unsigned fastrdp_isqrt(unsigned long v)
{
	unsigned long r = 0, bit = 1ul << 30;
	while (bit > v)
		bit >>= 2;
	while (bit)
	{
		if (v >= r + bit)
		{
			v -= r + bit;
			r = (r >> 1) + bit;
		}
		else
			r >>= 1;
		bit >>= 2;
	}
	return (unsigned)r;
}

/* The card's shadow: darker towards the card (offset down by drop), gone after blur. */
static void fastrdp_draw_shadow(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                                fastrdpRect clip)
{
	const fastrdpLook* k = p->look;
	if (!k->blur)
		return;
	const long rad = k->radius * 16, blur = k->blur * 16;
	const long l = ((long)p->card.x + k->radius) * 16, rt = ((long)p->card.x + p->card.w - k->radius) * 16;
	const long t = ((long)p->card.y + k->drop + k->radius) * 16;
	const long b = ((long)p->card.y + k->drop + p->card.h - k->radius) * 16;
	for (long y = clip.y; y < (long)clip.y + clip.h; y++)
		for (long x = clip.x; x < (long)clip.x + clip.w; x++)
		{
			const long sx = x * 16 + 8, sy = y * 16 + 8;
			const long dx = sx < l ? l - sx : sx > rt ? sx - rt : 0;
			const long dy = sy < t ? t - sy : sy > b ? sy - b : 0;
			const long d = (long)fastrdp_isqrt((unsigned long)(dx * dx + dy * dy)) - rad;
			if (d >= blur)
				continue;
			const long f = d <= 0 ? blur : blur - d;
			const unsigned a = (unsigned)(FASTRDP_SHADOW_ALPHA * f / blur * f / blur);
			if (a)
				fastrdp_blend(img + (size_t)y * stride + (size_t)x * 4, 0x000000, a);
		}
}

/* Draws n glyphs of face f, the pen starting at x on the baseline, inside clip; returns
 * the pen's position after them. The pen moves in 1/64 pixel, each glyph lands on the
 * nearest whole pixel. */
static long fastrdp_draw_text(unsigned char* img, unsigned stride, fastrdpRect clip,
                              const fastrdpFace* f, long x, long baseline, const unsigned short* g,
                              unsigned n, unsigned rgb)
{
	long pen = x * 64;
	for (unsigned i = 0; i < n; i++)
	{
		if (g[i] >= FASTRDP_FONT_GLYPHS)
			continue;
		const fastrdpGlyph* gl = &f->glyphs[g[i]];
		const char* t = f->data + gl->off;
		const unsigned total = (unsigned)gl->w * gl->h;
		const long gx = (pen + 32) / 64 + gl->x, gy = baseline - gl->y;
		for (unsigned at = 0; at < total;)
		{
			const unsigned c = fastrdp_font_token(*t++);
			unsigned v = c, run = 1;
			if (c >= 16)
			{
				v = c < 16 + 37 ? 0 : 15;
				run = (c < 16 + 37 ? c - 16 : c - 16 - 37) + 2;
			}
			if (run > total - at)
				run = total - at;
			for (unsigned j = 0; v && j < run; j++)
			{
				unsigned char* px = fastrdp_px(img, stride, clip, gx + (long)((at + j) % gl->w),
				                               gy + (long)((at + j) / gl->w));
				if (px)
					fastrdp_blend(px, rgb, v * 17);
			}
			at += run;
		}
		pen += gl->adv64;
	}
	return (pen + 63) / 64;
}

/* the baseline of text in face f centred vertically in a box at top, h high */
static long fastrdp_baseline(const fastrdpFace* f, long top, unsigned h)
{
	return top + ((long)h - (long)(f->ascent + f->descent)) / 2 + (long)f->ascent;
}

/* Draws g[0..n) at x in a box at top, h high, cut with "…" to w pixels. */
static void fastrdp_draw_text_box(unsigned char* img, unsigned stride, fastrdpRect clip,
                                  const fastrdpFace* f, long x, long top, unsigned h, unsigned w,
                                  const unsigned short* g, unsigned n, unsigned rgb)
{
	int cut = 0;
	const unsigned fit = fastrdp_text_fit(f, g, n, w, &cut);
	const long base = fastrdp_baseline(f, top, h);
	x = fastrdp_draw_text(img, stride, clip, f, x, base, g, fit, rgb);
	if (cut)
	{
		const unsigned short ell = fastrdp_glyph(0x2026);
		(void)fastrdp_draw_text(img, stride, clip, f, x, base, &ell, 1, rgb);
	}
}

/* The lock icon: a lock in the accent colour on a tinted circle, 4x4 samples. */
static void fastrdp_draw_icon(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                              fastrdpRect clip)
{
	const fastrdpRect r = p->icon;
	if (r.w == 0)
		return;
	const float s = (float)r.w, c = s / 2;
	const float bx0 = s * 0.29f, bx1 = s * 0.71f, by0 = s * 0.45f, by1 = s * 0.76f, br = s * 0.05f;
	const float sy = s * 0.42f, so = s * 0.165f, si = s * 0.165f - s * 0.07f; /* shackle */
	const float kx = c, ky = s * 0.585f, kr = s * 0.055f;                       /* keyhole */
	for (unsigned y = 0; y < r.h; y++)
		for (unsigned x = 0; x < r.w; x++)
		{
			unsigned char* px = fastrdp_px(img, stride, clip, r.x + (long)x, r.y + (long)y);
			if (!px)
				continue;
			unsigned disc = 0, lock = 0;
			for (unsigned j = 0; j < 4; j++)
				for (unsigned i = 0; i < 4; i++)
				{
					const float fx = (float)x + (float)(2 * i + 1) / 8, fy = (float)y + (float)(2 * j + 1) / 8;
					const float dx = fx - c, dy = fy - c;
					disc += dx * dx + dy * dy <= c * c;
					/* body: a rounded rectangle without the keyhole */
					const float qx = fx < bx0 + br ? bx0 + br - fx : fx > bx1 - br ? fx - (bx1 - br) : 0;
					const float qy = fy < by0 + br ? by0 + br - fy : fy > by1 - br ? fy - (by1 - br) : 0;
					const int in_body = fx >= bx0 && fx <= bx1 && fy >= by0 && fy <= by1 &&
					                    qx * qx + qy * qy <= br * br;
					const float kdx = fx - kx, kdy = fy - ky;
					const int in_key = kdx * kdx + kdy * kdy <= kr * kr ||
					                   (fx >= kx - kr * 0.45f && fx <= kx + kr * 0.45f && fy >= ky &&
					                    fy <= ky + kr * 2.6f);
					/* shackle: half a ring and its legs down into the body */
					const float hx = fx - c, hy = fy - sy;
					const float d2 = hx * hx + hy * hy;
					const int in_ring = fy <= sy && d2 <= so * so && d2 >= si * si;
					const int in_legs = fy > sy && fy < by0 + br && ((hx >= -so && hx <= -si) || (hx >= si && hx <= so));
					lock += (in_body && !in_key) || in_ring || in_legs;
				}
			if (disc)
				fastrdp_blend(px, FASTRDP_COLOR_ACCENT_TINT, disc * 255 / 16);
			if (lock)
				fastrdp_blend(px, FASTRDP_COLOR_ACCENT, lock * 255 / 16);
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

/* Redraws the countdown line ("<label> m:ss" and the bar of the time left) inside the
 * panel image; nothing outside countdown_rect changes. */
static void fastrdp_panel_draw_countdown(const fastrdpPanel* p, unsigned char* img,
                                         unsigned stride, long seconds)
{
	if (!p->countdown || !p->look)
		return;
	const fastrdpLook* k = p->look;
	const fastrdpRect r = p->countdown_rect;
	const fastrdpRect clip = fastrdp_panel_clip(p, r);
	const fastrdpFace* small = fastrdp_face(p, k->small);
	const fastrdpFace* body = fastrdp_face(p, k->body);
	fastrdp_fill(img, stride, clip, r, FASTRDP_COLOR_PANEL);
	char digits[8];
	fastrdp_countdown_text(seconds, digits);
	const unsigned cell = fastrdp_digit_cell(body);
	const unsigned short blank = fastrdp_glyph(' ');
	unsigned digits_w = 0;
	for (const char* d = digits; *d; d++)
		digits_w += *d == ':' ? fastrdp_adv(body, fastrdp_glyph(':')) : cell;
	const unsigned room = r.w > digits_w + fastrdp_adv(small, blank)
	                          ? r.w - digits_w - fastrdp_adv(small, blank)
	                          : 0;
	int cut = 0;
	const unsigned n = fastrdp_text_fit(small, p->label, p->labellen, room, &cut);
	long x = r.x;
	const long base = fastrdp_baseline(body, r.y, r.h);
	x = fastrdp_draw_text(img, stride, clip, small, x, base, p->label, n, FASTRDP_COLOR_MUTED);
	if (cut)
	{
		const unsigned short ell = fastrdp_glyph(0x2026);
		x = fastrdp_draw_text(img, stride, clip, small, x, base, &ell, 1, FASTRDP_COLOR_MUTED);
	}
	if (p->labellen)
		x += fastrdp_adv(small, blank);
	for (const char* d = digits; *d; d++)
	{
		const unsigned short g = fastrdp_glyph((unsigned char)*d);
		const unsigned adv = fastrdp_adv(body, g);
		const unsigned w = *d == ':' ? adv : cell;
		(void)fastrdp_draw_text(img, stride, clip, body, x + (long)(w - adv) / 2, base, &g, 1,
		                        FASTRDP_COLOR_TITLE);
		x += w;
	}
	/* the bar: the rest of the line, at least four rows high wide */
	const long bar_x = x + (long)k->row_h / 2, end = (long)r.x + r.w;
	if (!p->countdown_total || end - bar_x < (long)k->row_h * 2)
		return;
	const unsigned bw = (unsigned)(end - bar_x);
	const fastrdpRect track = { (int)bar_x, r.y + (int)(r.h - k->bar_h) / 2, bw, k->bar_h };
	fastrdp_fill_rrect(img, stride, clip, track, k->bar_h / 2, FASTRDP_COLOR_LINE);
	const unsigned long left = seconds < 0 ? 0 : (unsigned long)seconds;
	unsigned fw = (unsigned)((unsigned long)bw * (left < p->countdown_total ? left : p->countdown_total) /
	                         p->countdown_total);
	if (fw > 0 && fw < k->bar_h)
		fw = k->bar_h;
	if (fw > 0)
	{
		const fastrdpRect fill = { track.x, track.y, fw, k->bar_h };
		fastrdp_fill_rrect(img, stride, clip, fill, k->bar_h / 2, FASTRDP_COLOR_ACCENT);
	}
}

/* Picker row i inside the panel (empty if there is none). */
static fastrdpRect fastrdp_panel_option_rect(const fastrdpPanel* p, unsigned i)
{
	const fastrdpRect none = { 0, 0, 0, 0 };
	if (i >= p->nopt)
		return none;
	const fastrdpRect r = { (int)p->text_x, (int)(p->opt_y + i * p->row_h), p->text_w, p->opt_h };
	return r;
}

/* Redraws picker row i inside the panel image: accent-filled while selected; nothing
 * outside its rectangle changes. */
static void fastrdp_panel_draw_option(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                                      unsigned i)
{
	const fastrdpRect r = fastrdp_panel_option_rect(p, i);
	if (r.w == 0 || !p->look)
		return;
	const fastrdpLook* k = p->look;
	const fastrdpRect clip = fastrdp_panel_clip(p, r);
	const fastrdpFace* body = fastrdp_face(p, k->body);
	const int sel = i == p->selected;
	fastrdp_fill(img, stride, clip, r, FASTRDP_COLOR_PANEL);
	fastrdp_fill_rrect(img, stride, clip, r, k->row_r, sel ? FASTRDP_COLOR_ACCENT : FASTRDP_COLOR_ROW);
	/* the key: a digit on a badge */
	const unsigned badge = r.h * 3 / 5, inset = (r.h - badge) / 2;
	const fastrdpRect b = { r.x + (int)inset, r.y + (int)inset, badge, badge };
	fastrdp_fill_rrect(img, stride, clip, b, badge / 4, sel ? FASTRDP_COLOR_SELECTED_KEY : FASTRDP_COLOR_PANEL);
	const unsigned short key = fastrdp_glyph('1' + i);
	const unsigned kw = fastrdp_adv(body, key);
	(void)fastrdp_draw_text(img, stride, clip, body, b.x + (long)(badge - kw) / 2,
	                        fastrdp_baseline(body, b.y, badge), &key, 1,
	                        sel ? FASTRDP_COLOR_SELECTED_TEXT : FASTRDP_COLOR_MUTED);
	const long x = b.x + (long)badge + (long)inset;
	const long end = (long)r.x + r.w - (long)inset;
	if (end > x)
		fastrdp_draw_text_box(img, stride, clip, body, x, r.y, r.h, (unsigned)(end - x), p->opt[i],
		                      p->optlen[i], sel ? FASTRDP_COLOR_SELECTED_TEXT : FASTRDP_COLOR_TITLE);
}

/* The picker row at desktop position (x, y); -1 if none. */
static int fastrdp_panel_hit(const fastrdpPanel* p, long x, long y)
{
	for (unsigned i = 0; i < p->nopt; i++)
	{
		const fastrdpRect r = fastrdp_panel_option_rect(p, i);
		const long x0 = (long)p->rect.x + r.x, y0 = (long)p->rect.y + r.y;
		if (x >= x0 && x < x0 + (long)r.w && y >= y0 && y < y0 + (long)r.h)
			return (int)i;
	}
	return -1;
}

static unsigned fastrdp_line_color(unsigned style)
{
	return style == FASTRDP_LINE_TITLE  ? FASTRDP_COLOR_TITLE
	       : style == FASTRDP_LINE_LINK ? FASTRDP_COLOR_ACCENT
	                                    : FASTRDP_COLOR_TEXT;
}

/* Draws the whole panel into img (rect.w x rect.h pixels, BGRX, stride >= rect.w * 4). */
static void fastrdp_panel_draw(const fastrdpPanel* p, unsigned char* img, unsigned stride,
                               long seconds)
{
	if (!p->look)
		return;
	const fastrdpLook* k = p->look;
	const fastrdpRect all = { 0, 0, p->rect.w, p->rect.h };
	const fastrdpRect clip = fastrdp_panel_clip(p, all);
	fastrdp_fill(img, stride, clip, all, FASTRDP_COLOR_SCREEN);
	fastrdp_draw_shadow(p, img, stride, clip);
	fastrdp_fill_rrect(img, stride, clip, p->card, k->radius, FASTRDP_COLOR_PANEL);
	fastrdp_draw_icon(p, img, stride, clip);
	for (unsigned i = 0; i < p->nlines; i++)
	{
		const fastrdpFace* f = fastrdp_line_face(p, p->line_style[i]);
		const unsigned lh = fastrdp_line_height(p, p->line_style[i]);
		(void)fastrdp_draw_text(img, stride, clip, f, p->line_x[i],
		                        fastrdp_baseline(f, p->line_y[i], lh), p->lines[i], p->linelen[i],
		                        fastrdp_line_color(p->line_style[i]));
	}
	for (unsigned i = 0; i < p->nopt; i++)
		fastrdp_panel_draw_option(p, img, stride, i);
	if (p->hintlen)
		fastrdp_draw_text_box(img, stride, clip, fastrdp_face(p, k->small), p->hint_rect.x,
		                      p->hint_rect.y, p->hint_rect.h, p->hint_rect.w, p->hint, p->hintlen,
		                      FASTRDP_COLOR_MUTED);
	if (p->divider_y)
	{
		const fastrdpRect line = { p->card.x + (int)k->pad, (int)p->divider_y, p->card.w - 2 * k->pad, 1 };
		fastrdp_fill(img, stride, clip, line, FASTRDP_COLOR_LINE);
	}
	fastrdp_panel_draw_countdown(p, img, stride, seconds);
	if (!p->show_qr)
		return;
	/* the QR code on a white tile with a thin border */
	const fastrdpRect border = { p->qr_rect.x - 1, p->qr_rect.y - 1, p->qr_rect.w + 2, p->qr_rect.h + 2 };
	const unsigned qr_r = p->qr_px; /* the quiet zone's corner modules stay light */
	fastrdp_fill_rrect(img, stride, clip, border, qr_r + 1, FASTRDP_COLOR_LINE);
	fastrdp_fill_rrect(img, stride, clip, p->qr_rect, qr_r, FASTRDP_COLOR_QR_LIGHT);
	for (unsigned y = 0; y < p->qr_size; y++)
		for (unsigned x = 0; x < p->qr_size; x++)
			if (p->qr[y * p->qr_size + x])
			{
				const fastrdpRect m = { p->qr_rect.x + (int)((x + FASTRDP_QR_QUIET) * p->qr_px),
					                    p->qr_rect.y + (int)((y + FASTRDP_QR_QUIET) * p->qr_px),
					                    p->qr_px, p->qr_px };
				fastrdp_fill(img, stride, clip, m, FASTRDP_COLOR_QR_DARK);
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
