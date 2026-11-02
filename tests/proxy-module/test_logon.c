/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Logon notification (broker/proxy-module/fastrdp_logon.h): who sends the one logon
 * notification. libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>

#include "../../broker/proxy-module/fastrdp_logon.h"

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

int main(void)
{
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
	printf("ok   fastrdp_logon.h\n");
	return 0;
}
