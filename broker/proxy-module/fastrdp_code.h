/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The code field of the waiting screen ([mfa] mode code_or_web, protocol.py
 * "code_entry"): the digits of an authenticator code, typed in the RDP window and sent to
 * the broker, which has Keycloak check them. libc only (tests/proxy-module/test_code.c).
 *
 * Keys count by scancode, i.e. by position, so the top-row digits work on every layout
 * (AZERTY without Shift too): 0x02..0x0a = 1..9, 0x0b = 0; the numeric keypad with
 * NumLock; Backspace deletes the last digit, Esc clears the field, Enter submits. Clients
 * that type characters (Unicode keyboard events) send '0'-'9', Backspace (0x08) and
 * Enter ('\r'); other characters are ignored. The caller counts a key on its release, as
 * the desktop picker does. The digits are shown masked and wiped once sent; nothing here
 * logs them. */
#ifndef FASTRDP_CODE_H
#define FASTRDP_CODE_H

#include <stddef.h>
#include <string.h>

#define FASTRDP_CODE_MIN 4  /* digits, as the broker accepts (ui.CODE_DIGITS) */
#define FASTRDP_CODE_MAX 10
#define FASTRDP_CODE_MASK_MAX (FASTRDP_CODE_MAX * 3 + 1) /* "\xe2\x80\xa2" per digit + NUL */

typedef enum
{
	FASTRDP_CODE_NONE = 0, /* nothing changed */
	FASTRDP_CODE_CHANGED,  /* the field shows something else now */
	FASTRDP_CODE_SUBMIT    /* complete: send it (fastrdp_code_take()) */
} fastrdpCodeEvent;

typedef struct
{
	unsigned digits; /* the code's length; 0: until Enter */
	unsigned len;
	char buf[FASTRDP_CODE_MAX + 1];
} fastrdpCode;

static void fastrdp_code_wipe(fastrdpCode* c)
{
	volatile char* p = c->buf;
	for (size_t i = 0; i < sizeof(c->buf); i++)
		p[i] = 0;
	c->len = 0;
}

/* An empty field for codes of `digits` digits (0 or out of range: until Enter). */
static void fastrdp_code_reset(fastrdpCode* c, unsigned digits)
{
	fastrdp_code_wipe(c);
	c->digits = (digits >= FASTRDP_CODE_MIN && digits <= FASTRDP_CODE_MAX) ? digits : 0;
}

static fastrdpCodeEvent fastrdp_code_digit(fastrdpCode* c, unsigned d)
{
	const unsigned max = c->digits ? c->digits : FASTRDP_CODE_MAX;
	if (d > 9 || c->len >= max)
		return FASTRDP_CODE_NONE;
	c->buf[c->len++] = (char)('0' + d);
	return (c->digits && c->len == c->digits) ? FASTRDP_CODE_SUBMIT : FASTRDP_CODE_CHANGED;
}

static fastrdpCodeEvent fastrdp_code_backspace(fastrdpCode* c)
{
	if (c->len == 0)
		return FASTRDP_CODE_NONE;
	c->buf[--c->len] = 0;
	return FASTRDP_CODE_CHANGED;
}

static fastrdpCodeEvent fastrdp_code_enter(const fastrdpCode* c)
{
	const unsigned min = c->digits ? c->digits : FASTRDP_CODE_MIN;
	return c->len >= min ? FASTRDP_CODE_SUBMIT : FASTRDP_CODE_NONE;
}

/* A released key: scancode | 0x100 if extended. */
static fastrdpCodeEvent fastrdp_code_key(fastrdpCode* c, unsigned key, int num_lock)
{
	/* numeric keypad 0-9 by scancode (0x52 = 0, 0x4f = 1 ... 0x49 = 9), not extended */
	static const unsigned char keypad[10] = { 0x52, 0x4f, 0x50, 0x51, 0x4b,
		                                      0x4c, 0x4d, 0x47, 0x48, 0x49 };
	if (key >= 0x02 && key <= 0x0a) /* top row 1-9 */
		return fastrdp_code_digit(c, key - 0x01);
	if (key == 0x0b) /* top row 0 */
		return fastrdp_code_digit(c, 0);
	if (num_lock)
		for (unsigned d = 0; d < 10; d++)
			if (key == keypad[d])
				return fastrdp_code_digit(c, d);
	switch (key)
	{
		case 0x0e: /* Backspace */
			return fastrdp_code_backspace(c);
		case 0x01: /* Esc */
			if (c->len == 0)
				return FASTRDP_CODE_NONE;
			fastrdp_code_wipe(c);
			return FASTRDP_CODE_CHANGED;
		case 0x1c:  /* Enter */
		case 0x11c: /* keypad Enter */
			return fastrdp_code_enter(c);
		default:
			return FASTRDP_CODE_NONE;
	}
}

/* A released Unicode key. */
static fastrdpCodeEvent fastrdp_code_char(fastrdpCode* c, unsigned ch)
{
	if (ch >= '0' && ch <= '9')
		return fastrdp_code_digit(c, ch - '0');
	if (ch == 0x08)
		return fastrdp_code_backspace(c);
	if (ch == '\r' || ch == '\n')
		return fastrdp_code_enter(c);
	return FASTRDP_CODE_NONE;
}

/* The field as shown: a bullet (U+2022) per digit typed, then "_" for the ones still
 * missing (only with a known length). UTF-8, NUL-terminated, at most size bytes. */
static void fastrdp_code_mask(const fastrdpCode* c, char* out, size_t size)
{
	size_t at = 0;
	if (size == 0)
		return;
	for (unsigned i = 0; i < c->len && at + 3 < size; i++)
	{
		memcpy(out + at, "\xe2\x80\xa2", 3);
		at += 3;
	}
	for (unsigned i = c->len; i < c->digits && at + 1 < size; i++)
		out[at++] = '_';
	out[at] = 0;
}

/* Copies the complete code into out (FASTRDP_CODE_MAX + 1 bytes) and empties the field. */
static int fastrdp_code_take(fastrdpCode* c, char* out)
{
	if (fastrdp_code_enter(c) != FASTRDP_CODE_SUBMIT)
		return 0;
	memcpy(out, c->buf, c->len + 1);
	fastrdp_code_wipe(c);
	return 1;
}

#endif
