/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Group SIDs from PAC_LOGON_INFO (broker/proxy-module/fastrdp_pac.h), libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>
#include <stdlib.h>

#include "../../broker/proxy-module/fastrdp_pac.h"

static int failures;

typedef struct
{
	char sids[64][FASTRDP_PAC_SID_LEN + 16];
	size_t n;
	size_t stop_after; /* emit returns 0 after this many (0: never) */
} Seen;

static int collect(void* ctx, const char* sid)
{
	Seen* s = ctx;
	if (s->n < 64)
		(void)snprintf(s->sids[s->n], sizeof(s->sids[0]), "%s", sid);
	s->n++;
	return !(s->stop_after && s->n >= s->stop_after);
}

static void expect(const char* what, const unsigned char* buf, size_t len, unsigned kinds,
                   int want_ok, const char* const* want)
{
	Seen s = { 0 };
	const int ok = fastrdp_pac_group_sids(buf, len, kinds, collect, &s);
	size_t nwant = 0;
	while (want && want[nwant])
		nwant++;
	int good = (ok == want_ok) && (s.n == nwant);
	for (size_t i = 0; good && i < nwant; i++)
		good = strcmp(s.sids[i], want[i]) == 0;
	printf("%s %s\n", good ? "ok  " : "FAIL", what);
	if (!good)
	{
		printf("     returned %d, %zu SIDs:", ok, s.n);
		for (size_t i = 0; i < s.n && i < 64; i++)
			printf(" %s", s.sids[i]);
		printf("\n");
		failures++;
	}
}

static size_t unhex(const char* hex, unsigned char* out, size_t max)
{
	size_t n = 0;
	for (; hex[0] && hex[1] && n < max; hex += 2)
		(void)sscanf(hex, "%2hhx", &out[n++]);
	return n;
}

/* Windows Server 2003 DC account (Samba torture PAC, via MIT krb5 1.22.1
 * src/lib/krb5/krb/t_pac.c saved_pac): group 516 and ExtraSid S-1-5-9 */
static const char* const W2003[] = {
	"01100800ccccccccc8010000000000000000020030dfa6cb4f7dc501ffffffffffffff7fffffffffffffff7fc03c4e59"
	"6273c501c03c4e596273c501ffffffffffffff7f16001600040002000000000008000200000000000c00020000000000"
	"100002000000000014000200000000001800020065000000ed03000004020000010000001c0002002000000000000000"
	"000000000000000000000000140016002000020016001800240002002800020000000000000000000021000000000000"
	"000000000000000000000000000000000000000000000000010000002c0002000000000000000000000000000b000000"
	"000000000b00000057003200300030003300460049004e0041004c002400000000000000000000000000000000000000"
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000"
	"04020000070000000b000000000000000a00000057003200300030003300460049004e0041004c000c00000000000000"
	"0b000000570049004e0032004b0033005400480049004e004b00000004000000010400000000000515000000112fafb5"
	"90041bec503becdc0100000030000200070000000100000001010000000000050900000000000000",
	NULL
};

/* S4U2Self PAC from Windows (t_pac.c s4u_pac_regular): Domain Users only */
static const char* const S4U[] = {
	"01100800cccccccc9001000000000000000002000000000000000000ffffffffffffff7fffffffffffffff7fc936fd57"
	"5b59d401c936fd575b59d401ffffffffffffff7f0a000a00040002000a000a0008000200000000000c00020000000000"
	"1000020000000000140002000000000018000200000000007604000001020000010000001c0002002000000000000000"
	"000000000000000000000000060008002000020008000a00240002002800020000000000000000001002000000000000"
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000"
	"0000000005000000770032006b00380075000000050000000000000005000000770032006b0038007500000000000000"
	"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000"
	"01020000070000000400000000000000030000005700440043000000050000000000000004000000410043004d004500"
	"0400000001040000000000051500000074a08d003fa5c2e96091e12200000000",
	NULL
};

static size_t join(const char* const* parts, unsigned char* out, size_t max)
{
	char hex[4096] = "";
	for (; *parts; parts++)
		strncat(hex, *parts, sizeof(hex) - strlen(hex) - 1);
	return unhex(hex, out, max);
}

/* --- NDR writer for synthetic KERB_VALIDATION_INFO */
typedef struct
{
	unsigned char b[2048];
	size_t n;
} W;

static void w32(W* w, uint32_t v)
{
	while (w->n & 3)
		w->b[w->n++] = 0;
	for (int i = 0; i < 4; i++)
		w->b[w->n++] = (unsigned char)(v >> (8 * i));
}

static void wsid(W* w, uint64_t authority, const uint32_t* sub, uint8_t count)
{
	w32(w, count);
	w->b[w->n++] = 1;
	w->b[w->n++] = count;
	for (int i = 5; i >= 0; i--)
		w->b[w->n++] = (unsigned char)(authority >> (8 * i));
	for (uint8_t i = 0; i < count; i++)
		w32(w, sub[i]);
}

/* user "bob" in S-1-5-21-1-2-3: groups 513, 1105 and disabled 1200; ExtraSids
 * S-1-18-4, S-1-18-1, deny-only S-1-5-21-9-9-9-512, a null entry, S-1-5-21-9-9-9-1300;
 * resource groups S-1-5-21-7-7-7-600 */
static size_t synthetic(unsigned char* out)
{
	W w = { .n = 0 };
	static const unsigned char hdr[] = { 1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 0,
		                                 0, 0, 0, 0 };
	memcpy(w.b, hdr, sizeof(hdr));
	w.n = sizeof(hdr);
	w32(&w, 0x20000); /* referent */
	const size_t fixed = w.n;
	memset(w.b + fixed, 0, 216);
	w.n += 216;
	unsigned char* f = w.b + fixed;
#define PUT16(o, v) (f[o] = (unsigned char)(v), f[(o) + 1] = (unsigned char)((v) >> 8))
#define PUT32(o, v) (PUT16(o, (v) & 0xffff), PUT16((o) + 2, (uint32_t)(v) >> 16))
	PUT16(48, 6);     /* EffectiveName "bob" */
	PUT16(50, 6);
	PUT32(52, 0x20004);
	PUT32(100, 1104);  /* UserId */
	PUT32(104, 513);   /* PrimaryGroupId */
	PUT32(108, 3);     /* GroupCount */
	PUT32(112, 0x20008);
	PUT32(152, 0x2000c); /* LogonDomainId */
	PUT32(196, 5);       /* SidCount */
	PUT32(200, 0x20010);
	PUT32(204, 0x20014); /* ResourceGroupDomainSid */
	PUT32(208, 1);
	PUT32(212, 0x20018);
	/* EffectiveName buffer */
	w32(&w, 3);
	w32(&w, 0);
	w32(&w, 3);
	for (const char* c = "bob"; *c; c++)
	{
		w.b[w.n++] = (unsigned char)*c;
		w.b[w.n++] = 0;
	}
	/* GroupIds */
	w32(&w, 3);
	const uint32_t groups[][2] = { { 513, 7 }, { 1105, 7 }, { 1200, 0 } };
	for (size_t i = 0; i < 3; i++)
	{
		w32(&w, groups[i][0]);
		w32(&w, groups[i][1]);
	}
	/* LogonDomainId */
	const uint32_t dom[] = { 21, 1, 2, 3 };
	wsid(&w, 5, dom, 4);
	/* ExtraSids */
	w32(&w, 5);
	const uint32_t extra_attr[] = { 7, 7, 0x17, 7, 7 };
	const uint32_t extra_ptr[] = { 0x2001c, 0x20020, 0x20024, 0, 0x20028 };
	for (size_t i = 0; i < 5; i++)
	{
		w32(&w, extra_ptr[i]);
		w32(&w, extra_attr[i]);
	}
	const uint32_t key_trust[] = { 4 }, asserted[] = { 1 };
	const uint32_t admins[] = { 21, 9, 9, 9, 512 }, ama[] = { 21, 9, 9, 9, 1300 };
	wsid(&w, 18, key_trust, 1);
	wsid(&w, 18, asserted, 1);
	wsid(&w, 5, admins, 5);
	wsid(&w, 5, ama, 5);
	/* ResourceGroupDomainSid, ResourceGroupIds */
	const uint32_t res[] = { 21, 7, 7, 7 };
	wsid(&w, 5, res, 4);
	w32(&w, 1);
	w32(&w, 600);
	w32(&w, 0x20000007);
#undef PUT16
#undef PUT32
	/* private header: object length */
	const uint32_t objlen = (uint32_t)(w.n - 16);
	for (int i = 0; i < 4; i++)
		w.b[8 + i] = (unsigned char)(objlen >> (8 * i));
	memcpy(out, w.b, w.n);
	return w.n;
}

static int never(void* ctx, const char* sid)
{
	(void)sid;
	(*(int*)ctx)++;
	return 1;
}

int main(void)
{
	unsigned char buf[2048];
	size_t n = join(W2003, buf, sizeof(buf));
	expect("Windows 2003 DC account: 516 and S-1-5-9", buf, n, FASTRDP_PAC_ALL, 1,
	       (const char* const[]){ "S-1-5-21-3048156945-3961193616-3706469200-516", "S-1-5-9",
	                              NULL });
	expect("Windows 2003: ExtraSids only", buf, n, FASTRDP_PAC_EXTRA, 1,
	       (const char* const[]){ "S-1-5-9", NULL });
	buf[1] = 0x00; /* big-endian NDR */
	expect("Windows 2003: big-endian NDR refused", buf, n, FASTRDP_PAC_ALL, 0, NULL);

	n = join(S4U, buf, sizeof(buf));
	expect("Windows S4U2Self: Domain Users", buf, n, FASTRDP_PAC_ALL, 1,
	       (const char* const[]){ "S-1-5-21-9281652-3921847615-585208160-513", NULL });

	n = synthetic(buf);
	expect("synthetic: all kinds, wire order, disabled and deny-only left out", buf, n,
	       FASTRDP_PAC_ALL, 1,
	       (const char* const[]){ "S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-1105", "S-1-18-4",
	                              "S-1-18-1", "S-1-5-21-9-9-9-1300", "S-1-5-21-7-7-7-600",
	                              NULL });
	expect("synthetic: ExtraSids first (the module's order)", buf, n, FASTRDP_PAC_EXTRA, 1,
	       (const char* const[]){ "S-1-18-4", "S-1-18-1", "S-1-5-21-9-9-9-1300", NULL });
	expect("synthetic: groups and resource groups", buf, n,
	       FASTRDP_PAC_GROUPS | FASTRDP_PAC_RESOURCE, 1,
	       (const char* const[]){ "S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-1105",
	                              "S-1-5-21-7-7-7-600", NULL });
	{
		Seen s = { .stop_after = 2 };
		const int ok = fastrdp_pac_group_sids(buf, n, FASTRDP_PAC_ALL, collect, &s);
		printf("%s emit can stop the walk\n", (!ok && s.n == 2) ? "ok  " : "FAIL");
		failures += !(!ok && s.n == 2);
	}

	/* every truncation and every single-byte change: never a crash, nothing emitted for
	 * a buffer that does not parse (run under -fsanitize=address,undefined to see more) */
	{
		int emitted = 0, bad = 0;
		for (size_t cut = 0; cut < n; cut++)
		{
			unsigned char* t = malloc(cut ? cut : 1);
			memcpy(t, buf, cut);
			emitted = 0;
			if (fastrdp_pac_group_sids(t, cut, FASTRDP_PAC_ALL, never, &emitted) || emitted)
				bad++;
			free(t);
		}
		printf("%s truncated buffers refused without output (%zu lengths)\n", bad ? "FAIL" : "ok  ",
		       n);
		failures += bad != 0;
		size_t parsed = 0;
		for (size_t i = 0; i < n; i++)
			for (unsigned v = 0; v < 256; v += 51)
			{
				unsigned char* t = malloc(n);
				memcpy(t, buf, n);
				t[i] ^= (unsigned char)(v | 1);
				emitted = 0;
				parsed += (size_t)fastrdp_pac_group_sids(t, n, FASTRDP_PAC_ALL, never, &emitted);
				free(t);
			}
		printf("ok   %zu mutated buffers walked (%zu still parse)\n", n * 6, parsed);
	}
	expect("NULL buffer", NULL, 0, FASTRDP_PAC_ALL, 0, NULL);

	if (failures)
		printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
