/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] InputTrace (lab only, off by default): names the CLASS of each input event
 * the waiting screen reads (code field, desktop picker), for the client lab
 * (docs/lab-waiting-screen-input.md). Never a value: no digit, no scancode or character
 * of a key, no pointer position. A digit typed on the top row, on the keypad or as a
 * character is "top-row digit", "keypad digit" or "digit" alike, and the keypad keys
 * without NumLock (Home, Up, ... on the digit keys) are one class too, so the log never
 * tells which digit was typed. Non-digit keys are only grouped (modifier, other): a
 * character that is no digit can still betray one (AZERTY '&' is 1 without Shift), so it
 * is never named either. libc only (tests/proxy-module/test_inputtrace.c). */
#ifndef FASTRDP_INPUTTRACE_H
#define FASTRDP_INPUTTRACE_H

/* A keyboard event: scancode | 0x100 if extended (as fastrdp_code_key()). */
static const char* fastrdp_trace_key_class(unsigned key, int num_lock)
{
	/* keypad 0-9 (not extended): 0x47-0x49, 0x4b-0x4d, 0x4f-0x52 */
	const int keypad = (key >= 0x47 && key <= 0x52 && key != 0x4a && key != 0x4e);
	if (key >= 0x02 && key <= 0x0b)
		return "top-row digit";
	if (keypad)
		return num_lock ? "keypad digit" : "keypad digit key (NumLock off)";
	switch (key)
	{
		case 0x0e:
			return "backspace";
		case 0x01:
			return "esc";
		case 0x1c:
			return "enter";
		case 0x11c:
			return "keypad enter";
		case 0x2a:  /* left Shift */
		case 0x36:  /* right Shift */
		case 0x1d:  /* left Ctrl */
		case 0x11d: /* right Ctrl */
		case 0x38:  /* left Alt */
		case 0x138: /* right Alt (AltGr) */
		case 0x15b: /* left Windows */
		case 0x15c: /* right Windows */
			return "modifier";
		case 0x3a:
			return "caps lock";
		case 0x45:
			return "num lock";
		default:
			return (key & 0x100) ? "other (extended)" : "other";
	}
}

/* A Unicode keyboard event (a character, UTF-16 code unit). */
static const char* fastrdp_trace_char_class(unsigned ch)
{
	if (ch >= '0' && ch <= '9')
		return "digit";
	if (ch >= 0xff10 && ch <= 0xff19) /* full-width digits (Japanese input method) */
		return "full-width digit";
	if (ch == 0x08)
		return "backspace";
	if (ch == '\r' || ch == '\n')
		return "enter";
	if (ch == 0x1b)
		return "esc";
	/* one class for all other characters: AZERTY's unshifted digit row mixes ASCII
	 * (& " ' ( - _) and non-ASCII (é è ç à), so even that split would hint at digits */
	return "other";
}

#endif
