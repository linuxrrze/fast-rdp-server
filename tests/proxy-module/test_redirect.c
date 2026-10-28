/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Self-redirection and logon notification (broker/proxy-module/fastrdp_redirect.h): which
 * input before the first Font List counts as carried-over state, the routing token (made,
 * recognised, too old, forged formats), the per-address limit, and who sends the one logon
 * notification. libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>
#include <string.h>

#include "../../broker/proxy-module/fastrdp_redirect.h"

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

static long long age_of(const char* s, long long now)
{
	return fastrdp_sr_token_age(s, strlen(s), now);
}

int main(void)
{
	/* the burst */
	fastrdpBurst none = { 0 };
	const fastrdpBurst mstsc = { 1, 10, 0, 1, 1 };
	const fastrdpBurst mouse = { 0, 0, 0, 3, 1 };
	const fastrdpBurst unicode = { 0, 0, 2, 0, 0 };
	CHECK(!fastrdp_burst_any(&none) && !fastrdp_burst_carryover(&none), "no input");
	CHECK(fastrdp_burst_carryover(&mstsc), "mstsc's burst counts");
	CHECK(fastrdp_burst_any(&mouse) && !fastrdp_burst_carryover(&mouse), "mouse and QoE alone do not");
	CHECK(fastrdp_burst_carryover(&unicode), "Unicode keys count");
	char text[128];
	fastrdp_burst_describe(&mstsc, text, sizeof(text));
	CHECK(strcmp(text, "1 sync, 10 scancodes, 0 unicode, 1 mouse, 1 QoE") == 0, "%s", text);

	/* the token */
	const long long now = 1793000000LL;
	char tok[FASTRDP_SR_TOKEN_MAX], back[128];
	CHECK(fastrdp_sr_token(tok, sizeof(tok), now, 0x0123456789abcdefULL), "token made");
	CHECK(strcmp(tok, "fastrdp-self-redirect.1793000000.0123456789abcdef") == 0, "%s", tok);
	CHECK(!fastrdp_sr_token(tok, 20, now, 1), "a token too long for the buffer");
	(void)fastrdp_sr_token(tok, sizeof(tok), now, 0x0123456789abcdefULL);
	(void)snprintf(back, sizeof(back), FASTRDP_SR_COOKIE "%s", tok);
	CHECK(age_of(back, now) == 0, "fresh token: %lld", age_of(back, now));
	CHECK(age_of(back, now + 61) == 61, "61 s old");
	CHECK(age_of(back, now - 3) == 0, "slightly in the future counts as new");
	CHECK(age_of(back, now - 60) == -1, "far in the future: not ours");
	(void)snprintf(back, sizeof(back), FASTRDP_SR_COOKIE "%s\r\n", tok);
	CHECK(age_of(back, now + 5) == 5, "with CR LF");
	CHECK(age_of(tok, now) == -1, "without the cookie prefix (FreeRDP keeps it)");
	CHECK(age_of("Cookie: msts=3640205228.15629.0000", now) == -1, "a Connection Broker cookie");
	CHECK(age_of("Cookie: msts=fastrdp-self-redirect.1793000000.0123456789ABCDEF", now) == -1,
	      "upper-case nonce");
	CHECK(age_of("Cookie: msts=fastrdp-self-redirect.1793000000.0123", now) == -1, "short nonce");
	CHECK(age_of("Cookie: msts=fastrdp-self-redirect.x.0123456789abcdef", now) == -1, "no time");
	CHECK(age_of("Cookie: msts=fastrdp-self-redirect.-5.0123456789abcdef", now) == -1,
	      "negative time");
	CHECK(fastrdp_sr_token_age(NULL, 0, now) == -1, "no token");
	char huge[300];
	memset(huge, 'a', sizeof(huge) - 1);
	huge[sizeof(huge) - 1] = '\0';
	memcpy(huge, back, strlen(back));
	CHECK(age_of(huge, now) == -1, "overlong token");

	/* the limit */
	static fastrdpSrLimit l;
	long long ago = -1;
	CHECK(fastrdp_sr_limit_take(&l, "192.0.2.1", now, 30, &ago), "first redirection");
	CHECK(!fastrdp_sr_limit_take(&l, "192.0.2.1", now + 10, 30, &ago) && ago == 10,
	      "second within 30 s refused (%lld)", ago);
	CHECK(fastrdp_sr_limit_take(&l, "192.0.2.2", now + 10, 30, &ago), "another address");
	CHECK(fastrdp_sr_limit_take(&l, "192.0.2.1", now + 30, 30, &ago), "after 30 s again");
	CHECK(!fastrdp_sr_limit_take(&l, "192.0.2.1", now + 31, 30, &ago), "and then not");
	CHECK(fastrdp_sr_limit_take(&l, "192.0.2.1", now - 100, 30, &ago), "clock went back");
	CHECK(fastrdp_sr_limit_take(&l, "", now, 30, &ago) && !fastrdp_sr_limit_take(&l, NULL, now, 30, &ago),
	      "no address: one shared slot");
	/* full table: the oldest entry goes */
	static fastrdpSrLimit full;
	char addr[32];
	for (int i = 0; i < FASTRDP_SR_SLOTS; i++)
	{
		(void)snprintf(addr, sizeof(addr), "10.0.0.%d", i);
		(void)fastrdp_sr_limit_take(&full, addr, now + i, 30, &ago);
	}
	CHECK(fastrdp_sr_limit_take(&full, "10.1.0.1", now + 70, 30, &ago), "new address in a full table");
	CHECK(fastrdp_sr_limit_take(&full, "10.0.0.0", now + 71, 30, &ago), "the oldest was replaced");
	CHECK(!fastrdp_sr_limit_take(&full, "10.0.0.63", now + 72, 30, &ago), "a recent one kept");

	/* logon notification */
	CHECK(fastrdp_logon_notify_due(1, 1, FASTRDP_LOGON_NONE), "due once the back-end is up");
	CHECK(!fastrdp_logon_notify_due(0, 1, FASTRDP_LOGON_NONE), "LogonNotify=false");
	CHECK(!fastrdp_logon_notify_due(1, 0, FASTRDP_LOGON_NONE), "back-end not up yet");
	CHECK(!fastrdp_logon_notify_due(1, 1, FASTRDP_LOGON_PROXY), "sent already");
	CHECK(!fastrdp_logon_notify_due(1, 1, FASTRDP_LOGON_BACKEND), "the back-end sent one");
	CHECK(!fastrdp_logon_forward(2, FASTRDP_LOGON_PROXY) && !fastrdp_logon_forward(0, FASTRDP_LOGON_PROXY),
	      "back-end logon notification after the proxy's: dropped");
	CHECK(fastrdp_logon_forward(3, FASTRDP_LOGON_PROXY), "auto-reconnect cookie always passes");
	CHECK(fastrdp_logon_forward(1, FASTRDP_LOGON_NONE) && fastrdp_logon_forward(1, FASTRDP_LOGON_BACKEND),
	      "the back-end's own passes");

	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok   fastrdp_redirect.h\n");
	return 0;
}
