/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The waiting screen's code field (broker/proxy-module/fastrdp_code.h): digits by
 * scancode on every layout, the keypad only with NumLock, Unicode digits, Backspace, Esc,
 * Enter, fixed and open lengths, the mask, wiping. libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>

#include "../../broker/proxy-module/fastrdp_code.h"

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

static int all_zero(const fastrdpCode* c)
{
	for (size_t i = 0; i < sizeof(c->buf); i++)
		if (c->buf[i])
			return 0;
	return c->len == 0;
}

static void test_top_row_and_submit(void)
{
	fastrdpCode c;
	char out[FASTRDP_CODE_MAX + 1];
	fastrdp_code_reset(&c, 6);
	/* 1 2 3 4 5 by position (0x02..0x06), then 0 (0x0b): the sixth digit submits */
	static const unsigned keys[] = { 0x02, 0x03, 0x04, 0x05, 0x06 };
	for (unsigned i = 0; i < 5; i++)
		CHECK(fastrdp_code_key(&c, keys[i], 0) == FASTRDP_CODE_CHANGED, "key %u", i);
	CHECK(fastrdp_code_key(&c, 0x0b, 0) == FASTRDP_CODE_SUBMIT, "sixth");
	CHECK(fastrdp_code_key(&c, 0x02, 0) == FASTRDP_CODE_NONE, "full field takes no more");
	CHECK(fastrdp_code_take(&c, out) && strcmp(out, "123450") == 0, "out=%s", out);
	CHECK(all_zero(&c), "wiped after take");
	CHECK(!fastrdp_code_take(&c, out), "empty field gives nothing");
}

static void test_keypad_needs_numlock(void)
{
	fastrdpCode c;
	fastrdp_code_reset(&c, 6);
	CHECK(fastrdp_code_key(&c, 0x52, 0) == FASTRDP_CODE_NONE && c.len == 0, "keypad 0 without NumLock");
	CHECK(fastrdp_code_key(&c, 0x47, 0) == FASTRDP_CODE_NONE, "keypad 7 without NumLock");
	CHECK(fastrdp_code_key(&c, 0x52, 1) == FASTRDP_CODE_CHANGED && c.buf[0] == '0', "keypad 0");
	CHECK(fastrdp_code_key(&c, 0x49, 1) == FASTRDP_CODE_CHANGED && c.buf[1] == '9', "keypad 9");
	CHECK(fastrdp_code_key(&c, 0x4f, 1) == FASTRDP_CODE_CHANGED && c.buf[2] == '1', "keypad 1");
	CHECK(fastrdp_code_key(&c, 0x152, 1) == FASTRDP_CODE_NONE, "extended Insert is no digit");
}

static void test_editing(void)
{
	fastrdpCode c;
	char mask[FASTRDP_CODE_MASK_MAX];
	fastrdp_code_reset(&c, 6);
	CHECK(fastrdp_code_key(&c, 0x0e, 0) == FASTRDP_CODE_NONE, "Backspace on empty");
	fastrdp_code_key(&c, 0x02, 0);
	fastrdp_code_key(&c, 0x03, 0);
	fastrdp_code_mask(&c, mask, sizeof(mask));
	CHECK(strcmp(mask, "\xe2\x80\xa2\xe2\x80\xa2____") == 0, "mask=%s", mask);
	CHECK(fastrdp_code_key(&c, 0x0e, 0) == FASTRDP_CODE_CHANGED && c.len == 1 && c.buf[1] == 0, "Backspace");
	CHECK(fastrdp_code_key(&c, 0x1c, 0) == FASTRDP_CODE_NONE, "Enter before the code is complete");
	CHECK(fastrdp_code_key(&c, 0x01, 0) == FASTRDP_CODE_CHANGED && all_zero(&c), "Esc clears");
	CHECK(fastrdp_code_key(&c, 0x01, 0) == FASTRDP_CODE_NONE, "Esc on empty");
	CHECK(fastrdp_code_key(&c, 0x1e, 0) == FASTRDP_CODE_NONE, "a letter key");
}

static void test_open_length(void)
{
	fastrdpCode c;
	char out[FASTRDP_CODE_MAX + 1];
	char mask[FASTRDP_CODE_MASK_MAX];
	fastrdp_code_reset(&c, 0);
	for (unsigned i = 0; i < 3; i++)
		fastrdp_code_char(&c, '7');
	CHECK(fastrdp_code_char(&c, '\r') == FASTRDP_CODE_NONE, "three digits are too few");
	fastrdp_code_char(&c, '8');
	fastrdp_code_mask(&c, mask, sizeof(mask));
	CHECK(strlen(mask) == 12 && !strchr(mask, '_'), "mask=%s", mask);
	CHECK(fastrdp_code_key(&c, 0x11c, 0) == FASTRDP_CODE_SUBMIT, "keypad Enter");
	for (unsigned i = 0; i < 20; i++)
		fastrdp_code_char(&c, '1');
	CHECK(c.len == FASTRDP_CODE_MAX, "at most %d, len=%u", FASTRDP_CODE_MAX, c.len);
	CHECK(fastrdp_code_take(&c, out) && strlen(out) == FASTRDP_CODE_MAX, "out=%s", out);
	fastrdp_code_reset(&c, 3); /* out of range: until Enter */
	CHECK(c.digits == 0, "digits=%u", c.digits);
	fastrdp_code_reset(&c, 11);
	CHECK(c.digits == 0, "digits=%u", c.digits);
}

static void test_unicode(void)
{
	fastrdpCode c;
	fastrdp_code_reset(&c, 6);
	CHECK(fastrdp_code_char(&c, '&') == FASTRDP_CODE_NONE, "AZERTY '1' without Shift (Unicode)");
	CHECK(fastrdp_code_char(&c, 0x0661) == FASTRDP_CODE_NONE, "Arabic-Indic one");
	CHECK(fastrdp_code_char(&c, '4') == FASTRDP_CODE_CHANGED, "4");
	CHECK(fastrdp_code_char(&c, 0x08) == FASTRDP_CODE_CHANGED && c.len == 0, "Backspace");
}

static void test_small_mask_buffer(void)
{
	fastrdpCode c;
	char mask[5];
	fastrdp_code_reset(&c, 6);
	fastrdp_code_char(&c, '1');
	fastrdp_code_char(&c, '2');
	fastrdp_code_mask(&c, mask, sizeof(mask));
	CHECK(strlen(mask) < sizeof(mask), "bounded: %zu", strlen(mask));
}

int main(void)
{
	test_top_row_and_submit();
	test_keypad_needs_numlock();
	test_editing();
	test_open_length();
	test_unicode();
	test_small_mask_buffer();
	if (failures)
		return 1;
	printf("test_code: ok\n");
	return 0;
}
