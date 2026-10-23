/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The front connection's diagnostics (broker/proxy-module/fastrdp_frontdiag.h): the line
 * names what the client announced, the client's name cannot break or forge log lines, the
 * auto-reconnect cookie shows only presence and logon id, and per-PDU lines are limited.
 * libc only. Build and run: make test-proxy-module */
#include <stdio.h>
#include <string.h>

#include "../../broker/proxy-module/fastrdp_frontdiag.h"

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
	char line[512];
	fastrdpFrontInfo f = { .client_name = "DESKTOP-AALN4PJ", .build = 26100, .width = 1920,
		                   .height = 1080, .bpp = 32, .monitors = 1, .desktop_scale = 100,
		                   .device_scale = 100, .gfx = 1, .dynvc = 1, .bitmap_cache = 1,
		                   .bitmap_cache_version = 2, .persist = 1, .arc = 0,
		                   .performance_flags = 0x80, .connection_type = 7, .autodetect = 1,
		                   .monitor_layout = 1, .keyboard_layout = 0x407 };
	fastrdp_front_describe(&f, line, sizeof(line));
	CHECK(strstr(line, "client \"DESKTOP-AALN4PJ\" build 26100, 1920x1080 32 bpp") != NULL, "%s", line);
	CHECK(strstr(line, "gfx yes, dynvc yes, bitmap cache yes v2 persist yes") != NULL, "%s", line);
	CHECK(strstr(line, "auto-reconnect cookie no,") != NULL, "%s", line);
	CHECK(strstr(line, "performance flags 0x00000080, connection type 7") != NULL, "%s", line);
	CHECK(strstr(line, "keyboard 0x00000407") != NULL, "%s", line);

	f.arc = 1;
	f.arc_logon_id = 3;
	fastrdp_front_describe(&f, line, sizeof(line));
	CHECK(strstr(line, "auto-reconnect cookie yes (logon id 3),") != NULL, "%s", line);

	/* the client's name: no newline, no quote, no control or non-ASCII byte, bounded */
	char name[FASTRDP_FRONT_NAME];
	fastrdp_front_safe_name("PC\n[INFO] forged\"x\x1b\xc3\xa4", name, sizeof(name));
	CHECK(strcmp(name, "PC?[INFO] forged?x???") == 0, "%s", name);
	fastrdp_front_safe_name("0123456789012345678901234567890123456789", name, sizeof(name));
	CHECK(strlen(name) == FASTRDP_FRONT_NAME - 1, "%zu", strlen(name));
	fastrdp_front_safe_name(NULL, name, sizeof(name));
	CHECK(name[0] == '\0', "%s", name);
	f.client_name = NULL;
	fastrdp_front_describe(&f, line, sizeof(line));
	CHECK(strstr(line, "client \"\" build") != NULL, "%s", line);
	CHECK(strchr(line, '\n') == NULL, "%s", line);

	CHECK(strcmp(fastrdp_save_session_info_name(0), "logon (v1)") == 0, "type 0");
	CHECK(strcmp(fastrdp_save_session_info_name(2), "plain notify") == 0, "type 2");
	CHECK(strncmp(fastrdp_save_session_info_name(3), "extended", 8) == 0, "type 3");
	CHECK(strcmp(fastrdp_save_session_info_name(9), "unknown") == 0, "type 9");

	unsigned count = 0, logged = 0;
	for (int i = 0; i < 1000; i++)
		logged += fastrdp_pdu_log_this(&count) ? 1 : 0;
	CHECK(count == 1000, "%u", count);
	CHECK(logged == FASTRDP_PDU_LOG_FIRST + 10, "%u", logged); /* 1-8, 100, 200, ..., 1000 */

	if (failures)
		return 1;
	printf("test_frontdiag: ok\n");
	return 0;
}
