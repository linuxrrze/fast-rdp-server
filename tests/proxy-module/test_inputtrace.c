/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] InputTrace's event classes (broker/proxy-module/fastrdp_inputtrace.h): every
 * digit key, whether on the top row, on the keypad (NumLock on or off) or typed as a
 * character, falls into one class per source, so the trace never tells which digit was
 * typed; no class string contains a digit. libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>
#include <string.h>

#include "../../broker/proxy-module/fastrdp_inputtrace.h"

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

static int has_digit(const char* s)
{
	for (; *s; s++)
		if (*s >= '0' && *s <= '9')
			return 1;
	return 0;
}

static void test_digit_keys_share_a_class(void)
{
	/* top row 1..0 */
	for (unsigned key = 0x02; key <= 0x0b; key++)
		CHECK(strcmp(fastrdp_trace_key_class(key, 0), "top-row digit") == 0, "key 0x%x", key);
	static const unsigned keypad[] = { 0x52, 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47, 0x48, 0x49 };
	for (unsigned i = 0; i < 10; i++)
	{
		CHECK(strcmp(fastrdp_trace_key_class(keypad[i], 1), "keypad digit") == 0, "keypad %u", i);
		CHECK(strcmp(fastrdp_trace_key_class(keypad[i], 0), "keypad digit key (NumLock off)") == 0,
		      "keypad %u off", i);
	}
	/* keypad minus/plus and Del are no digits */
	CHECK(strcmp(fastrdp_trace_key_class(0x4a, 1), "other") == 0, "keypad minus");
	CHECK(strcmp(fastrdp_trace_key_class(0x4e, 1), "other") == 0, "keypad plus");
	CHECK(strcmp(fastrdp_trace_key_class(0x53, 1), "other") == 0, "keypad Del");
}

static void test_control_keys(void)
{
	CHECK(strcmp(fastrdp_trace_key_class(0x0e, 0), "backspace") == 0, "backspace");
	CHECK(strcmp(fastrdp_trace_key_class(0x01, 0), "esc") == 0, "esc");
	CHECK(strcmp(fastrdp_trace_key_class(0x1c, 0), "enter") == 0, "enter");
	CHECK(strcmp(fastrdp_trace_key_class(0x11c, 0), "keypad enter") == 0, "keypad enter");
	CHECK(strcmp(fastrdp_trace_key_class(0x2a, 0), "modifier") == 0, "shift");
	CHECK(strcmp(fastrdp_trace_key_class(0x138, 0), "modifier") == 0, "altgr");
	CHECK(strcmp(fastrdp_trace_key_class(0x45, 0), "num lock") == 0, "numlock");
	CHECK(strcmp(fastrdp_trace_key_class(0x10, 0), "other") == 0, "Q/A");
	CHECK(strcmp(fastrdp_trace_key_class(0x148, 0), "other (extended)") == 0, "up arrow");
}

static void test_characters(void)
{
	for (unsigned ch = '0'; ch <= '9'; ch++)
		CHECK(strcmp(fastrdp_trace_char_class(ch), "digit") == 0, "char %c", ch);
	for (unsigned ch = 0xff10; ch <= 0xff19; ch++)
		CHECK(strcmp(fastrdp_trace_char_class(ch), "full-width digit") == 0, "char U+%04X", ch);
	CHECK(strcmp(fastrdp_trace_char_class(0x08), "backspace") == 0, "backspace");
	CHECK(strcmp(fastrdp_trace_char_class('\r'), "enter") == 0, "CR");
	CHECK(strcmp(fastrdp_trace_char_class('\n'), "enter") == 0, "LF");
	CHECK(strcmp(fastrdp_trace_char_class(0x1b), "esc") == 0, "esc");
	/* AZERTY's unshifted digit row, ASCII and not: one class, nothing to tell them apart */
	static const unsigned azerty[] = { '&', 0xe9, '"', '\'', '(', '-', 0xe8, '_', 0xe7, 0xe0 };
	for (unsigned i = 0; i < 10; i++)
		CHECK(strcmp(fastrdp_trace_char_class(azerty[i]), "other") == 0, "AZERTY %u", i);
	CHECK(strcmp(fastrdp_trace_char_class(0x01), "other") == 0, "control");
}

static void test_no_class_names_a_digit(void)
{
	for (unsigned key = 0; key < 0x200; key++)
	{
		CHECK(!has_digit(fastrdp_trace_key_class(key, 0)), "key 0x%x", key);
		CHECK(!has_digit(fastrdp_trace_key_class(key, 1)), "key 0x%x numlock", key);
	}
	for (unsigned ch = 0; ch < 0x10000; ch++)
		CHECK(!has_digit(fastrdp_trace_char_class(ch)), "char U+%04X", ch);
}

int main(void)
{
	test_digit_keys_share_a_class();
	test_control_keys();
	test_characters();
	test_no_class_names_a_digit();
	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("test_inputtrace: ok\n");
	return 0;
}
