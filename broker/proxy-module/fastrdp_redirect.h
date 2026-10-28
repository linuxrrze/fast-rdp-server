/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] SelfRedirect (backlog A5): an mstsc that carries state over from its previous
 * connection sends input (a QoE timestamp, scancodes, a synchronize event, a mouse event)
 * between its Control Request and its Font List at the *first* activation of a new
 * connection, as if it were a reactivation (docs/a5-capture-2026-10-26.md, run 2). For
 * such a client the proxy sends a Server Redirection PDU ([MS-RDPBCGR] 2.2.13, 3.2.5.13.1)
 * to itself, so the client opens a new connection. The redirected connection carries a
 * routing token (the PDU's LoadBalanceInfo, sent back in the X.224 Connection Request) that
 * marks it: such a connection is never redirected again. A per-address limit stops a
 * client that ignores the token from looping.
 * Here: the input classes counted before the first Font List and the decision, the token,
 * the rate limit; and the decisions for [FastRDP] LogonNotify. libc only
 * (tests/proxy-module/test_redirect.c). */
#ifndef FASTRDP_REDIRECT_H
#define FASTRDP_REDIRECT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* FreeRDP's server takes a routing token only with one of its known prefixes (nego.c);
 * its writer puts "Cookie: msts=" in front of the LoadBalanceInfo and CR LF after it
 * (rdp_write_enhanced_security_redirection_packet()), so the module passes only the rest */
#define FASTRDP_SR_COOKIE "Cookie: msts="
#define FASTRDP_SR_PREFIX "fastrdp-self-redirect."
#define FASTRDP_SR_TOKEN_MAX 64
#define FASTRDP_SR_TOKEN_TTL_S 120 /* a token younger than this marks a redirected connection */
#define FASTRDP_SR_FUTURE_S 5      /* clock steps: a token at most this far ahead still counts */
#define FASTRDP_SR_INTERVAL_S 30   /* at most one self-redirection per client address */
#define FASTRDP_SR_SLOTS 64
#define FASTRDP_SR_ADDR 64

/* Input events the client sent before its first Font List, by class. */
typedef struct
{
	unsigned sync, keys, unicode, mouse, qoe;
} fastrdpBurst;

static int fastrdp_burst_any(const fastrdpBurst* b)
{
	return b->sync + b->keys + b->unicode + b->mouse + b->qoe > 0;
}

/* The client carries keyboard state over from an earlier activation: a synchronize or a
 * key event before its first activation finished. A fresh mstsc (and FreeRDP) sends no
 * input before the Font List; a mouse move or a QoE timestamp alone does not count. */
static int fastrdp_burst_carryover(const fastrdpBurst* b)
{
	return b->sync + b->keys + b->unicode > 0;
}

/* "1 sync, 10 scancodes, 0 unicode, 1 mouse, 1 QoE" for the log */
static void fastrdp_burst_describe(const fastrdpBurst* b, char* out, size_t size)
{
	(void)snprintf(out, size, "%u sync, %u scancodes, %u unicode, %u mouse, %u QoE", b->sync,
	               b->keys, b->unicode, b->mouse, b->qoe);
}

/* The LoadBalanceInfo for a self-redirection at `now` (seconds since the epoch):
 * FASTRDP_SR_PREFIX "<now>.<nonce, 16 hex digits>". 0 if it does not fit. */
static int fastrdp_sr_token(char* out, size_t size, long long now, uint64_t nonce)
{
	const int n = snprintf(out, size, FASTRDP_SR_PREFIX "%lld.%016llx", now,
	                       (unsigned long long)nonce);
	return n > 0 && (size_t)n < size;
}

/* Age in seconds of a self-redirection token as the client sent it back (the X.224 routing
 * token: FASTRDP_SR_COOKIE, the token, maybe CR LF), or -1 if it is not one, is malformed,
 * or lies more than FASTRDP_SR_FUTURE_S in the future. */
static long long fastrdp_sr_token_age(const char* tok, size_t len, long long now)
{
	const size_t cl = strlen(FASTRDP_SR_COOKIE), pl = strlen(FASTRDP_SR_PREFIX);
	char buf[FASTRDP_SR_TOKEN_MAX + 32];
	if (!tok || len < cl + pl || len >= sizeof(buf))
		return -1;
	memcpy(buf, tok, len);
	buf[len] = '\0';
	while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n'))
		buf[--len] = '\0';
	if (strncmp(buf, FASTRDP_SR_COOKIE, cl) != 0 || strncmp(buf + cl, FASTRDP_SR_PREFIX, pl) != 0)
		return -1;
	const char* p = buf + cl + pl;
	char* end = NULL;
	const long long t = strtoll(p, &end, 10);
	if (end == p || *end != '.' || t <= 0)
		return -1;
	p = end + 1;
	if (strlen(p) != 16 || strspn(p, "0123456789abcdef") != 16)
		return -1;
	if (t > now + FASTRDP_SR_FUTURE_S)
		return -1;
	return t > now ? 0 : now - t;
}

/* Self-redirections by client address (the TCP peer, not anything the client claims). */
typedef struct
{
	char addr[FASTRDP_SR_ADDR];
	long long t;
} fastrdpSrSlot;

typedef struct
{
	fastrdpSrSlot slot[FASTRDP_SR_SLOTS];
} fastrdpSrLimit;

/* 1 (and the redirection recorded at `now`) if `addr` had none within `interval` seconds;
 * else 0 and *ago the seconds since the last one. The oldest slot is reused when full. */
static int fastrdp_sr_limit_take(fastrdpSrLimit* l, const char* addr, long long now,
                                 long long interval, long long* ago)
{
	fastrdpSrSlot* free_slot = NULL;
	fastrdpSrSlot* oldest = &l->slot[0];
	if (!addr || !*addr)
		addr = "?";
	for (size_t i = 0; i < FASTRDP_SR_SLOTS; i++)
	{
		fastrdpSrSlot* s = &l->slot[i];
		if (s->addr[0] && strncmp(s->addr, addr, FASTRDP_SR_ADDR - 1) == 0)
		{
			if (now - s->t < interval && now >= s->t)
			{
				if (ago)
					*ago = now - s->t;
				return 0;
			}
			s->t = now;
			return 1;
		}
		if (!s->addr[0] && !free_slot)
			free_slot = s;
		if (s->t < oldest->t)
			oldest = s;
	}
	fastrdpSrSlot* s = free_slot ? free_slot : oldest;
	(void)snprintf(s->addr, sizeof(s->addr), "%s", addr);
	s->t = now;
	return 1;
}

/* [FastRDP] LogonNotify: one logon notification per connection, from the proxy or the
 * back-end, whichever comes first (the session's state, changed atomically) */
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

#endif /* FASTRDP_REDIRECT_H */
