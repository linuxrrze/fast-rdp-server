// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
// run_journald.sh: logs through WLog as freerdp-proxy does, with WLOG_APPENDER=JOURNALD
// from the environment. Prints the time before each message, keeps running for 2 s after
// each, then dies by SIGKILL, as on a crash or systemd's stop timeout: whatever stdio still
// buffers is lost, so only messages flushed right away reach the (fake) journald.
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <winpr/wlog.h>

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(void)
{
	wLog* log = WLog_Get("com.fastrdp.e2e.journald");
	if (!log)
		return 2;
	printf("%.6f info\n", now());
	(void)fflush(stdout);
	WLog_Print(log, WLOG_INFO, "e2e journald line 1 (info)");
	sleep(2);
	printf("%.6f warn\n", now());
	(void)fflush(stdout);
	WLog_Print(log, WLOG_WARN, "e2e journald line 2 (warn)");
	sleep(2);
	(void)raise(SIGKILL);
	return 3;
}
