/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The waiting screen's panel (broker/proxy-module/fastrdp_panel.h): UTF-8 to glyphs, the
 * generated font tables, blending, word wrap by pixel width, layout for desktop sizes,
 * QR code validation and drawing, countdown redraw and bar, the desktop picker's rows
 * (layout, selection, hit-testing). libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>

#include "../../broker/proxy-module/fastrdp_panel.h"

static int failures;

#define QR_ROWS (FASTRDP_QR_MAX + 8) /* room for oversized test codes */

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

static int g(unsigned cp)
{
	return fastrdp_font_index(cp);
}

static void test_glyphs(void)
{
	unsigned short out[32];
	unsigned n = fastrdp_glyphs("Gr\xc3\xbc\xc3\x9f" "e", out, 32); /* Grüße */
	CHECK(n == 5 && out[2] == g(0xfc) && out[3] == g(0xdf), "n=%u", n);
	n = fastrdp_glyphs("\xe2\x82\xac\xe2\x80\xa6\xe2\x80\x9e", out, 32); /* euro sign, ellipsis, „ */
	CHECK(n == 3 && out[0] == g(0x20ac) && out[1] == g(0x2026) && out[2] == g(0x201e), "n=%u", n);
	n = fastrdp_glyphs("\xe6\x97\xa5", out, 32); /* CJK: not in the font */
	CHECK(n == 1 && out[0] == g('?'), "n=%u", n);
	/* malformed: lone continuation, truncated sequence, overlong '/', surrogate */
	n = fastrdp_glyphs("\x80" "a\xc3", out, 32);
	CHECK(n == 3 && out[0] == g('?') && out[1] == g('a') && out[2] == g('?'), "n=%u", n);
	n = fastrdp_glyphs("\xc0\xaf\xed\xa0\x80", out, 32);
	CHECK(n == 2 && out[0] == g('?') && out[1] == g('?'), "n=%u", n);
	n = fastrdp_glyphs("a\tb\x1b", out, 32); /* control characters: blanks */
	CHECK(n == 4 && out[1] == g(' ') && out[3] == g(' '), "n=%u", n);
	n = fastrdp_glyphs("abcdef", out, 4); /* bounded */
	CHECK(n == 4, "n=%u", n);
	CHECK(g(0x7f) < 0 && g(0x9f) < 0 && g(0xa0) >= 0 && g(0xff) == 0x5f + 0x5f && g(0x2014) >= 0 &&
	          g(0x2014) != g('-') && g(0x20ac) == FASTRDP_FONT_GLYPHS - 1,
	      "font index");
}

/* every glyph's tokens cover exactly its bitmap; printable glyphs advance and have ink */
static void test_font(void)
{
	for (unsigned s = 0; s < FASTRDP_FONT_STEPS; s++)
		for (unsigned k = 0; k < FASTRDP_FONT_STYLES; k++)
		{
			const fastrdpFace* f = &fastrdp_faces[s][k];
			unsigned bad = 0, inked = 0;
			for (unsigned i = 0; i < FASTRDP_FONT_GLYPHS; i++)
			{
				const fastrdpGlyph* gl = &f->glyphs[i];
				const char* t = f->data + gl->off;
				unsigned at = 0, ink = 0;
				while (at < (unsigned)gl->w * gl->h)
				{
					const unsigned c = fastrdp_font_token(*t++);
					bad += c >= 16 + 2 * 37;
					ink += c != 0 && c < 16 + 37 ? 0 : c != 0;
					at += c < 16 ? 1 : (c < 16 + 37 ? c - 16 : c - 16 - 37) + 2;
				}
				bad += at != (unsigned)gl->w * gl->h;
				if (i != (unsigned)g(' ') && i != (unsigned)g(0xa0) && i != (unsigned)g(0xad) &&
				    i != (unsigned)g(0x2009) && i != (unsigned)g(0x202f))
					inked += gl->w > 0 && gl->h > 0;
				if (i < (unsigned)g(0xad) && gl->adv64 == 0)
					bad++;
			}
			CHECK(bad == 0 && inked == FASTRDP_FONT_GLYPHS - 5, "face %u/%u: %u bad, %u inked", s, k,
			      bad, inked);
		}
	CHECK(fastrdp_faces[1][FASTRDP_FONT_BODY].size > fastrdp_faces[0][FASTRDP_FONT_BODY].size &&
	          fastrdp_faces[0][FASTRDP_FONT_TITLE].size > fastrdp_faces[0][FASTRDP_FONT_BODY].size &&
	          fastrdp_faces[0][FASTRDP_FONT_BODY].size > fastrdp_faces[0][FASTRDP_FONT_SMALL].size,
	      "sizes");
}

static void test_blend(void)
{
	unsigned char px[4] = { 0x11, 0x22, 0x33, 0 };
	fastrdp_blend(px, 0xaabbcc, 0);
	CHECK(px[0] == 0x11 && px[1] == 0x22 && px[2] == 0x33 && px[3] == 0xff, "coverage 0");
	fastrdp_blend(px, 0xaabbcc, 255);
	CHECK(px[0] == 0xcc && px[1] == 0xbb && px[2] == 0xaa, "coverage 255");
	px[0] = px[1] = px[2] = 0;
	fastrdp_blend(px, 0xffffff, 128);
	CHECK(px[0] == 128 && px[1] == 128 && px[2] == 128, "half: %u", px[0]);

	/* a glyph on white: only white, the text colour and blends between them; ink where
	 * the glyph's bitmap is and nowhere else */
	enum { W = 40, H = 40 };
	static unsigned char img[W * H * 4];
	memset(img, 0xff, sizeof(img));
	const fastrdpRect clip = { 0, 0, W, H };
	const fastrdpFace* f = &fastrdp_faces[0][FASTRDP_FONT_TITLE];
	const unsigned short gl = (unsigned short)g('W');
	const long end = fastrdp_draw_text(img, W * 4, clip, f, 5, 30, &gl, 1, 0x000000);
	const fastrdpGlyph* m = &f->glyphs[gl];
	unsigned full = 0, partial = 0, outside = 0, odd = 0;
	for (unsigned y = 0; y < H; y++)
		for (unsigned x = 0; x < W; x++)
		{
			const unsigned char* px2 = img + (y * W + x) * 4;
			const int in = (long)x >= 5 + m->x && (long)x < 5 + m->x + m->w && (long)y >= 30 - m->y &&
			               (long)y < 30 - m->y + m->h;
			odd += px2[0] != px2[1] || px2[1] != px2[2];
			if (px2[0] == 0)
				full++;
			else if (px2[0] != 0xff)
				partial++;
			if (px2[0] != 0xff && !in)
				outside++;
		}
	CHECK(end == 5 + (long)fastrdp_text_width(f, &gl, 1) && full > 20 && partial > 10 && outside == 0 && odd == 0,
	      "glyph: %u full, %u partial, %u outside", full, partial, outside);

	/* clipped at the image's edges */
	memset(img, 0xff, sizeof(img));
	const fastrdpRect small = { 10, 10, 8, 8 };
	(void)fastrdp_draw_text(img, W * 4, small, f, 2, 25, &gl, 1, 0x000000);
	unsigned beyond = 0;
	for (unsigned y = 0; y < H; y++)
		for (unsigned x = 0; x < W; x++)
			beyond += img[(y * W + x) * 4] != 0xff && (x < 10 || x >= 18 || y < 10 || y >= 18);
	CHECK(beyond == 0, "%u pixels outside the clip", beyond);
}

static int qr_rows(fastrdpPanel* p, unsigned n, char rows[][QR_ROWS], int pattern)
{
	const char* ptrs[QR_ROWS];
	for (unsigned y = 0; y < n; y++)
	{
		for (unsigned x = 0; x < n; x++)
			rows[y][x] = ((x * 7 + y * 3 + (unsigned)pattern) % 5 < 2) ? '1' : '0';
		rows[y][n] = '\0';
		ptrs[y] = rows[y];
	}
	return fastrdp_panel_set_qr(p, ptrs, n);
}

static char rows[QR_ROWS][QR_ROWS];

static void test_qr_validation(fastrdpPanel* p)
{
	CHECK(qr_rows(p, 21, rows, 0) && p->qr_size == 21, "version 1");
	CHECK(qr_rows(p, 177, rows, 0) && p->qr_size == 177, "version 40");
	CHECK(!qr_rows(p, 17, rows, 0) && p->qr_size == 0, "too small");
	CHECK(!qr_rows(p, 22, rows, 0) && p->qr_size == 0, "not a QR size");
	CHECK(!qr_rows(p, 181, rows, 0), "too large");
	const char* ptrs[21];
	(void)qr_rows(p, 21, rows, 0);
	for (unsigned i = 0; i < 21; i++)
		ptrs[i] = rows[i];
	rows[5][7] = 'x';
	CHECK(!fastrdp_panel_set_qr(p, ptrs, 21) && p->qr_size == 0, "bad character");
	rows[5][7] = '1';
	rows[9][20] = '\0';
	CHECK(!fastrdp_panel_set_qr(p, ptrs, 21), "short row");
	ptrs[3] = NULL;
	CHECK(!fastrdp_panel_set_qr(p, ptrs, 21), "missing row");
	CHECK(fastrdp_panel_set_qr(p, NULL, 0) && p->qr_size == 0, "removed");
}

static unsigned char* draw(const fastrdpPanel* p, long seconds)
{
	unsigned char* img = malloc((size_t)p->rect.w * p->rect.h * 4); /* exact size: ASan */
	if (img)
		fastrdp_panel_draw(p, img, p->rect.w * 4, seconds);
	return img;
}

static unsigned pixel(const fastrdpPanel* p, const unsigned char* img, unsigned x, unsigned y)
{
	const unsigned char* px = img + ((size_t)y * p->rect.w + x) * 4;
	return (unsigned)px[2] << 16 | (unsigned)px[1] << 8 | px[0];
}

static int inside(fastrdpRect r, unsigned w, unsigned h)
{
	return r.x >= 0 && r.y >= 0 && (unsigned)r.x + r.w <= w && (unsigned)r.y + r.h <= h;
}

static int within(fastrdpRect r, fastrdpRect outer)
{
	return r.x >= outer.x && r.y >= outer.y && (long)r.x + r.w <= (long)outer.x + outer.w &&
	       (long)r.y + r.h <= (long)outer.y + outer.h;
}

/* the panel inside the desktop, the card inside the panel, every line inside the text
 * column (the QR code right of it) */
static void check_bounds(const fastrdpPanel* p, unsigned w, unsigned h)
{
	CHECK(inside(p->rect, w, h) && p->rect.x >= FASTRDP_PANEL_MARGIN &&
	          p->rect.y >= FASTRDP_PANEL_MARGIN,
	      "%ux%u: panel %d,%d %ux%u off the desktop", w, h, p->rect.x, p->rect.y, p->rect.w, p->rect.h);
	CHECK(inside(p->card, p->rect.w, p->rect.h), "%ux%u: card outside the panel", w, h);
	for (unsigned i = 0; i < p->nlines; i++)
	{
		const fastrdpFace* f = fastrdp_line_face(p, p->line_style[i]);
		const unsigned lw = fastrdp_text_width(f, p->lines[i], p->linelen[i]);
		const fastrdpRect r = { (int)p->line_x[i], (int)p->line_y[i], lw,
			                    fastrdp_line_height(p, p->line_style[i]) };
		const fastrdpRect col = { (int)p->text_x, (int)p->text_y, p->text_w, p->card.h };
		CHECK(within(r, col) && p->linelen[i] <= FASTRDP_PANEL_MAX_COLS,
		      "%ux%u: line %u (%u px at %d) outside the text column (%u px)", w, h, i, lw, r.x,
		      p->text_w);
	}
	if (p->show_qr)
		CHECK(within(p->qr_rect, p->card) && p->qr_rect.x > (int)(p->text_x + p->text_w),
		      "%ux%u: QR code", w, h);
	if (p->countdown)
		CHECK(within(p->countdown_rect, p->card), "%ux%u: countdown", w, h);
	if (p->icon.w)
		CHECK(within(p->icon, p->card), "%ux%u: icon", w, h);
}

static void test_layout_and_draw(fastrdpPanel* p)
{
	static const char* const text[] = {
		"Approve this login",
		"Sign in at https://rdp1.lab.example.com/web/approve and approve the login of alice "
		"from 192.0.2.10, or scan the code with your phone.",
		"https://rdp1.lab.example.com/web/approve",
		"",
		NULL,
	};
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, text, 5);
	fastrdp_panel_set_countdown(p, "Time left:");
	fastrdp_panel_set_countdown_total(p, 90);
	CHECK(qr_rows(p, 29, rows, 1), "QR version 3");

	CHECK(fastrdp_panel_layout(p, 1920, 1080), "1920x1080");
	CHECK(p->step == 0 && p->look == &fastrdp_looks[1] && p->show_qr &&
	          p->qr_px >= FASTRDP_QR_MIN_PX,
	      "step %u qr %d px %u", p->step, p->show_qr, p->qr_px);
	CHECK(p->rect.x == (int)((1920 - p->rect.w) / 2) && p->rect.y == (int)((1080 - p->rect.h) / 2),
	      "centred");
	CHECK(p->nlines >= 6 && p->line_style[0] == FASTRDP_LINE_TITLE &&
	          p->line_style[1] == FASTRDP_LINE_BODY && p->line_style[p->nlines - 3] == FASTRDP_LINE_LINK &&
	          p->linelen[p->nlines - 1] == 0,
	      "wrapped into %u lines", p->nlines);
	check_bounds(p, 1920, 1080);
	CHECK(p->qr_rect.w == (29 + 8) * p->qr_px, "quiet zone of 4 modules");

	unsigned char* img = draw(p, 75);
	CHECK(img != NULL, "image");
	if (img)
	{
		/* every module, sampled in its centre; the quiet zone stays light */
		unsigned bad = 0;
		for (unsigned y = 0; y < 29 + 8; y++)
			for (unsigned x = 0; x < 29 + 8; x++)
			{
				const int in = x >= 4 && y >= 4 && x < 33 && y < 33;
				const int dark = in && p->qr[(y - 4) * 29 + (x - 4)];
				const unsigned c = pixel(p, img, (unsigned)p->qr_rect.x + x * p->qr_px + p->qr_px / 2,
				                         (unsigned)p->qr_rect.y + y * p->qr_px + p->qr_px / 2);
				bad += c != (dark ? FASTRDP_COLOR_QR_DARK : FASTRDP_COLOR_QR_LIGHT);
			}
		CHECK(bad == 0, "%u QR modules wrong", bad);
		/* the title and the body drawn in their colours, the link in the accent colour */
		unsigned ink[3] = { 0, 0, 0 };
		static const unsigned color[3] = { FASTRDP_COLOR_TITLE, FASTRDP_COLOR_TEXT, FASTRDP_COLOR_ACCENT };
		for (unsigned i = 0; i < p->nlines; i++)
			for (unsigned y = p->line_y[i]; y < p->line_y[i] + fastrdp_line_height(p, p->line_style[i]); y++)
				for (unsigned x = p->text_x; x < p->text_x + p->text_w; x++)
					ink[p->line_style[i]] += pixel(p, img, x, y) == color[p->line_style[i]];
		CHECK(ink[0] > 100 && ink[1] > 100 && ink[2] > 30, "text pixels: %u %u %u", ink[0], ink[1],
		      ink[2]);
		/* screen around, the card's corner rounded, the shadow below it, the icon */
		const fastrdpRect c = p->card;
		CHECK(pixel(p, img, 0, 0) == FASTRDP_COLOR_SCREEN &&
		          pixel(p, img, (unsigned)c.x, (unsigned)c.y) != FASTRDP_COLOR_PANEL &&
		          pixel(p, img, (unsigned)c.x + c.w / 2, (unsigned)c.y) == FASTRDP_COLOR_PANEL &&
		          pixel(p, img, (unsigned)c.x + c.w / 2, (unsigned)c.y + c.h + 2) < FASTRDP_COLOR_SCREEN &&
		          pixel(p, img, (unsigned)p->icon.x + p->icon.w / 2, (unsigned)p->icon.y + p->icon.h / 2) ==
		              FASTRDP_COLOR_ACCENT,
		      "card");

		/* countdown: a redraw changes nothing outside its rectangle */
		const size_t size = (size_t)p->rect.w * p->rect.h * 4;
		unsigned char* before = malloc(size);
		if (before)
		{
			memcpy(before, img, size);
			fastrdp_panel_draw_countdown(p, img, p->rect.w * 4, 74);
			unsigned changed_in = 0, changed_out = 0;
			for (unsigned y = 0; y < p->rect.h; y++)
				for (unsigned x = 0; x < p->rect.w; x++)
				{
					const size_t o = ((size_t)y * p->rect.w + x) * 4;
					if (memcmp(before + o, img + o, 4) == 0)
						continue;
					const fastrdpRect r = p->countdown_rect;
					if ((int)x >= r.x && x < r.x + r.w && (int)y >= r.y && y < r.y + r.h)
						changed_in++;
					else
						changed_out++;
				}
			CHECK(changed_in > 0 && changed_out == 0, "countdown redraw: %u in, %u outside",
			      changed_in, changed_out);
			free(before);
		}
		/* the bar shrinks with the time left, empty at 0:00 */
		unsigned bar[3];
		static const long left[3] = { 90, 45, 0 };
		for (unsigned k = 0; k < 3; k++)
		{
			fastrdp_panel_draw_countdown(p, img, p->rect.w * 4, left[k]);
			bar[k] = 0;
			const fastrdpRect r = p->countdown_rect;
			for (unsigned y = (unsigned)r.y; y < (unsigned)r.y + r.h; y++)
				for (unsigned x = (unsigned)r.x; x < (unsigned)r.x + r.w; x++)
					bar[k] += pixel(p, img, x, y) == FASTRDP_COLOR_ACCENT;
		}
		CHECK(bar[0] > 2 * bar[1] - 20 && bar[1] > 100 && bar[2] == 0, "bar: %u %u %u", bar[0],
		      bar[1], bar[2]);
		free(img);
	}

	/* every desktop size: inside the desktop, drawn within the image (ASan) */
	static const unsigned sizes[][2] = { { 1024, 768 }, { 1280, 720 },  { 1366, 768 }, { 1920, 1200 },
		                                  { 2560, 1440 }, { 3840, 2160 }, { 800, 600 },  { 640, 480 },
		                                  { 400, 300 },   { 320, 240 },   { 160, 100 } };
	for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++)
	{
		const unsigned w = sizes[k][0], h = sizes[k][1];
		if (!fastrdp_panel_layout(p, w, h))
		{
			CHECK(w <= 320, "%ux%u: no layout", w, h);
			continue;
		}
		check_bounds(p, w, h);
		CHECK(w < 640 || p->show_qr, "%ux%u: no QR code", w, h);
		free(draw(p, 30));
	}
	CHECK(fastrdp_panel_layout(p, 320, 240), "320x240");
	CHECK(!fastrdp_panel_layout(p, 159, 600) && !fastrdp_panel_layout(p, 800, 99) &&
	          !fastrdp_panel_layout(p, 40000, 600),
	      "unusable desktop sizes");
	CHECK(fastrdp_panel_layout(p, 3199, 1800) && p->step == 0, "3199x1800");
	CHECK(fastrdp_panel_layout(p, 3200, 1800) && p->step == 1 && p->qr_px <= 9, "3200x1800");
	CHECK(fastrdp_panel_layout(p, 8192, 8192) && p->step == 1, "8192x8192");
	check_bounds(p, 8192, 8192);

	/* the largest QR code still fits a large desktop with at least 4 pixels per module */
	CHECK(qr_rows(p, 177, rows, 2) && fastrdp_panel_layout(p, 1920, 1080) && p->show_qr &&
	          p->qr_px == FASTRDP_QR_MIN_PX,
	      "version 40: qr %d px %u", p->show_qr, p->qr_px);
	check_bounds(p, 1920, 1080);
	free(draw(p, 0));
}

/* the widest line in pixels */
static unsigned widest(const fastrdpPanel* p)
{
	unsigned w = 0;
	for (unsigned i = 0; i < p->nlines; i++)
	{
		const unsigned lw =
		    fastrdp_text_width(fastrdp_line_face(p, p->line_style[i]), p->lines[i], p->linelen[i]);
		w = lw > w ? lw : w;
	}
	return w;
}

static void test_wrap(fastrdpPanel* p)
{
	char longword[300];
	memset(longword, 'x', sizeof(longword) - 1);
	longword[sizeof(longword) - 1] = '\0';
	const char* lines[FASTRDP_PANEL_MAX_LINES + 4];
	for (unsigned i = 0; i < FASTRDP_PANEL_MAX_LINES + 4; i++)
		lines[i] = longword;
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, lines, FASTRDP_PANEL_MAX_LINES + 4);
	CHECK(p->nsrc == FASTRDP_PANEL_MAX_LINES && p->srclen[0] == FASTRDP_PANEL_MAX_GLYPHS,
	      "source lines bounded: %u x %u", p->nsrc, p->srclen[0]);
	CHECK(fastrdp_panel_layout(p, 1920, 1080), "layout");
	const unsigned last = p->nlines - 1;
	CHECK(p->nlines == FASTRDP_PANEL_MAX_LINES, "%u lines", p->nlines);
	CHECK(p->linelen[last] > 0 && p->lines[last][p->linelen[last] - 1] == g(0x2026),
	      "truncated with an ellipsis");
	check_bounds(p, 1920, 1080);
	free(draw(p, 0));
	/* fewer lines where the desktop is lower */
	CHECK(fastrdp_panel_layout(p, 1920, 400) && p->nlines < FASTRDP_PANEL_MAX_LINES &&
	          p->lines[p->nlines - 1][p->linelen[p->nlines - 1] - 1] == g(0x2026),
	      "1920x400: %u lines", p->nlines);
	check_bounds(p, 1920, 400);

	/* short words wrap at blanks (the title too), never past the column */
	static const char* const words[] = { "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk",
		                                 "llll mmmm nnnn oooo pppp qqqq rrrr ssss tttt uuuu vvvv "
		                                 "wwww xxxx yyyy zzzz" };
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, words, 2);
	CHECK(fastrdp_panel_layout(p, 400, 400), "400x400");
	check_bounds(p, 400, 400);
	CHECK(p->nlines > 3, "%u lines", p->nlines);
	for (unsigned i = 0; i < p->nlines; i++)
		CHECK(p->linelen[i] % 5 == 4 && p->lines[i][0] != g(' '), "line %u breaks inside a word", i);

	/* German: umlauts are glyphs of their own, the line breaks at blanks */
	static const char* const german[] = { "Anmeldung best\xc3\xa4tigen",
		                                  "Melden Sie sich auf der Freigabeseite an und best\xc3\xa4tigen "
		                                  "Sie diese Anmeldung f\xc3\xbcr \xc3\x84rzte und \xc3\x96sterreicher." };
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, german, 2);
	CHECK(fastrdp_panel_layout(p, 640, 480), "640x480");
	check_bounds(p, 640, 480);
	CHECK(p->nlines >= 3 && p->linelen[0] == 20 && p->lines[0][14] == g(0xe4), "title: %u glyphs",
	      p->linelen[0]);
	for (unsigned i = 1; i + 1 < p->nlines; i++)
		CHECK(p->lines[i + 1][0] != g(' ') && p->src[1][0] == g('M'), "line %u", i);

	/* a URL breaks after '/', a long word anywhere, both within the column */
	static const char* const url[] = {
		"Title",
		"https://approval.very-long-host-name.lab.example.com/web/approve/session/0123456789abcdef",
		"Donaudampfschifffahrtsgesellschaftskapit\xc3\xa4nswitwenrentenversicherungsanstaltsgeb\xc3\xa4ude",
	};
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, url, 3);
	CHECK(fastrdp_panel_layout(p, 640, 480), "640x480 URL");
	check_bounds(p, 640, 480);
	unsigned link = 0, slash = 0;
	for (unsigned i = 0; i < p->nlines; i++)
		if (p->line_style[i] == FASTRDP_LINE_LINK)
		{
			link++;
			if (i + 1 < p->nlines && p->line_style[i + 1] == FASTRDP_LINE_LINK)
				slash += p->lines[i][p->linelen[i] - 1] == g('/');
		}
	CHECK(link >= 2 && slash == link - 1, "URL on %u lines, %u broken after '/'", link, slash);
	CHECK(widest(p) <= p->text_w && p->line_style[p->nlines - 1] == FASTRDP_LINE_BODY &&
	          p->line_src[p->nlines - 1] == 2 && p->line_src[p->nlines - 2] == 2,
	      "long word split");
	free(draw(p, 0));
}

/* desktop picker: rows below the text, inside the panel, one under the other; a click in a
 * row's middle hits it, beside a row, between rows or outside the panel nothing */
static void check_rows(const fastrdpPanel* p, unsigned w, unsigned h)
{
	check_bounds(p, w, h);
	for (unsigned i = 0; i < p->nopt; i++)
	{
		const fastrdpRect r = fastrdp_panel_option_rect(p, i);
		CHECK(within(r, p->card) && r.h >= p->look->body_lh, "%ux%u: row %u outside", w, h, i);
		CHECK(r.y >= (int)(p->line_y[p->nlines - 1] + fastrdp_line_height(p, p->line_style[p->nlines - 1])),
		      "%ux%u: row %u over the text", w, h, i);
		CHECK(i == 0 || r.y == fastrdp_panel_option_rect(p, i - 1).y + (int)p->row_h,
		      "%ux%u: row %u not below row %u", w, h, i, i - 1);
		const long cx = p->rect.x + r.x + (long)r.w / 2, cy = p->rect.y + r.y + (long)r.h / 2;
		CHECK(fastrdp_panel_hit(p, cx, cy) == (int)i, "%ux%u: centre of row %u hits %d", w, h, i,
		      fastrdp_panel_hit(p, cx, cy));
		CHECK(fastrdp_panel_hit(p, p->rect.x + r.x, p->rect.y + r.y) == (int)i &&
		          fastrdp_panel_hit(p, p->rect.x + r.x + (long)r.w - 1, p->rect.y + r.y + (long)r.h - 1) ==
		              (int)i,
		      "%ux%u: corners of row %u", w, h, i);
		CHECK(fastrdp_panel_hit(p, p->rect.x + r.x - 1, cy) == -1 &&
		          fastrdp_panel_hit(p, p->rect.x + r.x + (long)r.w, cy) == -1,
		      "%ux%u: beside row %u", w, h, i);
		CHECK(i == 0 || p->row_h == r.h || fastrdp_panel_hit(p, cx, p->rect.y + r.y - 1) == -1,
		      "%ux%u: between rows %u and %u", w, h, i - 1, i);
	}
	if (p->nopt)
	{
		const fastrdpRect last = fastrdp_panel_option_rect(p, p->nopt - 1);
		CHECK(p->hint_rect.y >= last.y + (int)last.h && within(p->hint_rect, p->card),
		      "%ux%u: hint below the rows", w, h);
		CHECK(!p->countdown || p->countdown_rect.y >= p->hint_rect.y + (int)p->hint_rect.h,
		      "%ux%u: countdown below the hint", w, h);
	}
	CHECK(fastrdp_panel_hit(p, p->rect.x + (long)p->rect.w / 2, p->rect.y + 1) == -1 &&
	          fastrdp_panel_hit(p, -5, -5) == -1 && fastrdp_panel_hit(p, 40000, 40000) == -1,
	      "%ux%u: hits outside the rows", w, h);
}

static void test_options(fastrdpPanel* p)
{
	static const char* const title[] = { "Choose your desktop" };
	static const char* const labels[] = { "Xfce",  "GNOME (running)", "KDE Plasma", "MATE",
		                                  "Cinnamon", "LXQt", "Plasma (X11)", "Sway",
		                                  "Labwc", "Wayfire (left out)" };
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, title, 1);
	fastrdp_panel_set_countdown(p, "Starting in");
	fastrdp_panel_set_countdown_total(p, 20);
	fastrdp_panel_set_options(p, labels, 10, 1, "1-9 or arrows and Enter, or click. Esc: Xfce");
	CHECK(p->nopt == FASTRDP_PANEL_MAX_OPTIONS && p->selected == 1 && p->hintlen > 0,
	      "rows bounded: %u, selected %u", p->nopt, p->selected);
	CHECK(p->optlen[0] == 4 && p->opt[0][0] == g('X') && p->optlen[8] == 5, "\"Xfce\": %u glyphs",
	      p->optlen[0]);

	static const unsigned sizes[][2] = { { 1920, 1080 }, { 2560, 1440 }, { 1366, 768 }, { 1024, 768 },
		                                  { 800, 600 },   { 640, 480 },   { 3840, 2160 } };
	for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++)
	{
		const unsigned w = sizes[k][0], h = sizes[k][1];
		CHECK(fastrdp_panel_layout(p, w, h), "%ux%u: no layout", w, h);
		CHECK(p->nlines == 1, "%ux%u: title on %u lines", w, h, p->nlines);
		check_rows(p, w, h);
		free(draw(p, 5));
	}
	/* nine rows do not fit 320x240 with any look: no panel; three do */
	CHECK(!fastrdp_panel_layout(p, 320, 240), "320x240 with nine rows");
	fastrdp_panel_set_options(p, labels, 3, 7, NULL);
	CHECK(p->selected == 0 && p->hintlen == 0, "selection out of range: %u", p->selected);
	CHECK(fastrdp_panel_layout(p, 320, 240), "320x240 with three rows");
	check_rows(p, 320, 240);

	/* drawing: the selected row is accent-filled with light text, the others are not;
	 * redrawing one row after a new selection changes nothing outside both rows */
	fastrdp_panel_set_options(p, labels, 4, 2, "hint");
	CHECK(fastrdp_panel_layout(p, 1920, 1080), "1920x1080");
	unsigned char* img = draw(p, 10);
	CHECK(img != NULL, "image");
	if (!img)
		return;
	const fastrdpRect r1 = fastrdp_panel_option_rect(p, 1), r2 = fastrdp_panel_option_rect(p, 2);
	CHECK(pixel(p, img, (unsigned)r2.x + 1, (unsigned)r2.y + r2.h / 2) == FASTRDP_COLOR_ACCENT &&
	          pixel(p, img, (unsigned)r1.x + 1, (unsigned)r1.y + r1.h / 2) == FASTRDP_COLOR_ROW &&
	          pixel(p, img, (unsigned)r2.x, (unsigned)r2.y) != FASTRDP_COLOR_ACCENT,
	      "selected row filled, corners rounded");
	unsigned light = 0;
	for (unsigned y = (unsigned)r2.y; y < (unsigned)r2.y + r2.h; y++)
		for (unsigned x = (unsigned)r2.x; x < (unsigned)r2.x + r2.w; x++)
			light += pixel(p, img, x, y) == FASTRDP_COLOR_SELECTED_TEXT;
	CHECK(light > 50, "selected row has %u text pixels", light);
	const size_t size = (size_t)p->rect.w * p->rect.h * 4;
	unsigned char* before = malloc(size);
	if (before)
	{
		memcpy(before, img, size);
		p->selected = 1;
		fastrdp_panel_draw_option(p, img, p->rect.w * 4, 1);
		fastrdp_panel_draw_option(p, img, p->rect.w * 4, 2);
		unsigned outside = 0, in = 0;
		for (unsigned y = 0; y < p->rect.h; y++)
			for (unsigned x = 0; x < p->rect.w; x++)
			{
				const size_t o = ((size_t)y * p->rect.w + x) * 4;
				const int row = (int)y >= r1.y && y < (unsigned)r2.y + r2.h && (int)x >= r1.x &&
				                x < (unsigned)r1.x + r1.w;
				if (memcmp(before + o, img + o, 4) != 0)
					row ? in++ : outside++;
			}
		CHECK(in > 0 && outside == 0, "row redraw: %u in, %u outside", in, outside);
		CHECK(pixel(p, img, (unsigned)r1.x + 1, (unsigned)r1.y + r1.h / 2) == FASTRDP_COLOR_ACCENT &&
		          pixel(p, img, (unsigned)r2.x + 1, (unsigned)r2.y + r2.h / 2) == FASTRDP_COLOR_ROW,
		      "selection moved");
		free(before);
	}
	free(img);

	/* a long label is cut to the row; no rows: the panel is as before */
	char longlabel[200];
	memset(longlabel, 'w', sizeof(longlabel) - 1);
	longlabel[sizeof(longlabel) - 1] = '\0';
	const char* const one[] = { longlabel, NULL };
	fastrdp_panel_set_options(p, one, 2, 0, NULL);
	CHECK(p->optlen[0] == FASTRDP_PANEL_OPTION_MAX && p->optlen[1] == 0, "label cut: %u, %u",
	      p->optlen[0], p->optlen[1]);
	CHECK(fastrdp_panel_layout(p, 640, 480), "640x480 with a long label");
	check_rows(p, 640, 480);
	free(draw(p, 0));
	fastrdp_panel_set_options(p, NULL, 0, 0, "ignored");
	CHECK(p->nopt == 0 && p->hintlen == 0 && fastrdp_panel_layout(p, 1920, 1080) &&
	          fastrdp_panel_hit(p, 960, 540) == -1,
	      "rows removed");
}

static void test_rects(void)
{
	const fastrdpRect a = { 10, 20, 100, 50 }, b = { 60, 0, 100, 30 }, e = { 5, 5, 0, 0 };
	fastrdpRect r;
	CHECK(fastrdp_rect_intersect(a, b, &r) && r.x == 60 && r.y == 20 && r.w == 50 && r.h == 10,
	      "intersection %d,%d %ux%u", r.x, r.y, r.w, r.h);
	const fastrdpRect far = { 200, 200, 5, 5 }, touching = { 110, 20, 5, 5 };
	CHECK(!fastrdp_rect_intersect(a, far, &r) && !fastrdp_rect_intersect(a, touching, &r),
	      "disjoint");
	r = fastrdp_rect_union(a, b);
	CHECK(r.x == 10 && r.y == 0 && r.w == 150 && r.h == 70, "union %d,%d %ux%u", r.x, r.y, r.w, r.h);
	r = fastrdp_rect_union(e, a);
	CHECK(r.x == a.x && r.w == a.w, "union with an empty rectangle");
	CHECK(fastrdp_isqrt(0) == 0 && fastrdp_isqrt(15) == 3 && fastrdp_isqrt(16) == 4 &&
	          fastrdp_isqrt(1000000) == 1000,
	      "isqrt");
}

int main(void)
{
	fastrdpPanel* p = calloc(1, sizeof(*p));
	if (!p)
		return 2;
	test_glyphs();
	test_font();
	test_blend();
	test_rects();
	test_qr_validation(p);
	test_layout_and_draw(p);
	test_wrap(p);
	test_options(p);
	free(p);
	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok: panel\n");
	return 0;
}
