/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The waiting screen's panel (broker/proxy-module/fastrdp_panel.h): UTF-8 to glyphs, word
 * wrap, layout for desktop sizes, QR code validation and drawing, countdown redraw. libc
 * only. Build and run: make test-proxy-module */
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
	n = fastrdp_glyphs("\xe2\x82\xac\xe2\x80\xa6", out, 32); /* euro sign, ellipsis */
	CHECK(n == 2 && out[0] == g(0x20ac) && out[1] == g(0x2026), "n=%u", n);
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
	CHECK(g(0x7f) < 0 && g(0x9f) < 0 && g(0xa0) >= 0 && g(0xff) == 0x5f + 0x5f && g(0x2014) == g('-'),
	      "font index");
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

static void test_layout_and_draw(fastrdpPanel* p)
{
	static const char* const text[] = {
		"Approve this login",
		"Sign in at https://rdp1.lab.example.com/web/approve and approve the login of alice "
		"from 192.0.2.10, or scan the code with your phone.",
		"",
		NULL,
	};
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, text, 4);
	fastrdp_panel_set_countdown(p, "Time left:");
	CHECK(qr_rows(p, 29, rows, 1), "QR version 3");

	CHECK(fastrdp_panel_layout(p, 1920, 1080), "1920x1080");
	CHECK(p->scale == 2 && p->show_qr && p->qr_px >= FASTRDP_QR_MIN_PX, "scale %u qr %d px %u",
	      p->scale, p->show_qr, p->qr_px);
	CHECK(p->rect.x == (int)((1920 - p->rect.w) / 2) && p->rect.y == (int)((1080 - p->rect.h) / 2),
	      "centred");
	CHECK(p->nlines > 3 && p->cols <= FASTRDP_PANEL_MAX_COLS, "wrapped into %u lines", p->nlines);
	for (unsigned i = 0; i < p->nlines; i++)
		CHECK(p->linelen[i] <= p->cols, "line %u: %u > %u", i, p->linelen[i], p->cols);
	CHECK(inside(p->qr_rect, p->rect.w, p->rect.h) &&
	          inside(p->countdown_rect, p->rect.w, p->rect.h),
	      "QR and countdown inside the panel");
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
		/* text drawn in the text column, accent bar on top */
		unsigned ink = 0;
		for (unsigned y = p->text_y; y < p->text_y + p->line_h; y++)
			for (unsigned x = p->text_x; x < (unsigned)p->qr_rect.x; x++)
				ink += pixel(p, img, x, y) == FASTRDP_COLOR_TEXT;
		CHECK(ink > 50, "first line has %u text pixels", ink);
		CHECK(pixel(p, img, 1, 1) == FASTRDP_COLOR_ACCENT, "accent bar");

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
		free(img);
	}

	/* small desktops: scale 1, then without the QR code, then no panel at all */
	CHECK(fastrdp_panel_layout(p, 640, 480), "640x480");
	CHECK(p->rect.w <= 640 - 2 * FASTRDP_PANEL_MARGIN && p->rect.h <= 480 - 2 * FASTRDP_PANEL_MARGIN,
	      "640x480: %ux%u", p->rect.w, p->rect.h);
	CHECK(fastrdp_panel_layout(p, 400, 300) && p->show_qr && p->scale == 1,
	      "400x300: qr %d scale %u", p->show_qr, p->scale);
	CHECK(fastrdp_panel_layout(p, 320, 240) && !p->show_qr && p->scale == 1,
	      "320x240: qr %d scale %u", p->show_qr, p->scale);
	free(draw(p, 0));
	CHECK(!fastrdp_panel_layout(p, 159, 600) && !fastrdp_panel_layout(p, 800, 99) &&
	          !fastrdp_panel_layout(p, 40000, 600),
	      "unusable desktop sizes");
	CHECK(fastrdp_panel_layout(p, 2559, 1440) && p->scale == 2, "2559x1440");
	CHECK(fastrdp_panel_layout(p, 2560, 1440) && p->scale == 3 && p->qr_px <= 12, "2560x1440");
	CHECK(fastrdp_panel_layout(p, 8192, 8192) && p->scale == 3, "8192x8192");

	/* the largest QR code still fits a large desktop with at least 4 pixels per module */
	CHECK(qr_rows(p, 177, rows, 2) && fastrdp_panel_layout(p, 1920, 1080) && p->show_qr &&
	          p->qr_px == FASTRDP_QR_MIN_PX,
	      "version 40: qr %d px %u", p->show_qr, p->qr_px);
	free(draw(p, 0));
}

static void test_wrap_limits(fastrdpPanel* p)
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
	CHECK(p->linelen[last] <= p->cols && p->lines[last][p->linelen[last] - 1] == g('.'),
	      "truncated with dots");
	CHECK(p->rect.h <= 1080, "height %u", p->rect.h);
	free(draw(p, 0));

	/* a long word is split hard, short words wrap at blanks */
	static const char* const words[] = { "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk "
		                                 "llll mmmm nnnn oooo pppp" };
	fastrdp_panel_init(p);
	fastrdp_panel_set_text(p, words, 1);
	CHECK(fastrdp_panel_layout(p, 600, 400), "600x400");
	for (unsigned i = 0; i < p->nlines; i++)
		CHECK(p->linelen[i] % 5 == 4 && p->lines[i][0] != g(' '), "line %u breaks inside a word", i);
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
}

int main(void)
{
	fastrdpPanel* p = calloc(1, sizeof(*p));
	if (!p)
		return 2;
	test_glyphs();
	test_rects();
	test_qr_validation(p);
	test_layout_and_draw(p);
	test_wrap_limits(p);
	free(p);
	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok: panel\n");
	return 0;
}
