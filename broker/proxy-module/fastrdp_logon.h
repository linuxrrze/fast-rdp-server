/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] LogonNotify (backlog A5): one logon notification per connection, from the
 * proxy or the back-end, whichever comes first (the session's state, changed atomically).
 * libc only (tests/proxy-module/test_logon.c). */
#ifndef FASTRDP_LOGON_H
#define FASTRDP_LOGON_H

#include <stdint.h>

#define FASTRDP_LOGON_NONE 0
#define FASTRDP_LOGON_PROXY 1   /* the proxy sent INFOTYPE_LOGON_PLAINNOTIFY */
#define FASTRDP_LOGON_BACKEND 2 /* the back-end's notification came first, forwarded */

/* Save Session Info types that notify a logon ([MS-RDPBCGR] 2.2.10.1.1): INFOTYPE_LOGON,
 * INFOTYPE_LOGON_LONG, INFOTYPE_LOGON_PLAINNOTIFY; not INFOTYPE_LOGON_EXTENDED_INF (the
 * auto-reconnect cookie or a logon error) */
static int fastrdp_is_logon_notification(uint32_t type)
{
	return type <= 2;
}

/* The proxy sends its own once the back-end session is up, if nobody sent one yet. */
static int fastrdp_logon_notify_due(int enabled, int backend_up, int state)
{
	return enabled && backend_up && state == FASTRDP_LOGON_NONE;
}

/* A back-end Save Session Info of `type` while the state is `state`: forwarded unless it is a
 * logon notification after the proxy's own. */
static int fastrdp_logon_forward(uint32_t type, int state)
{
	return !fastrdp_is_logon_notification(type) || state != FASTRDP_LOGON_PROXY;
}

#endif /* FASTRDP_LOGON_H */
