/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Mechanisms a CredSSP client offers (broker/proxy-module/fastrdp_spnego.h), libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>

#include "../../broker/proxy-module/fastrdp_spnego.h"

static int failures;

/* minimal DER writer: tag + definite length (short or long form) + content */
static size_t tlv(unsigned char* out, unsigned char tag, const unsigned char* v, size_t n)
{
	size_t o = 0;
	out[o++] = tag;
	if (n < 0x80)
		out[o++] = (unsigned char)n;
	else if (n < 0x100)
	{
		out[o++] = 0x81;
		out[o++] = (unsigned char)n;
	}
	else
	{
		out[o++] = 0x82;
		out[o++] = (unsigned char)(n >> 8);
		out[o++] = (unsigned char)n;
	}
	memmove(out + o, v, n);
	return o + n;
}

static const unsigned char OID_KRB5[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
static const unsigned char OID_MSKRB5[] = { 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 };
static const unsigned char OID_U2U[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03 };
static const unsigned char OID_NTLM[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const unsigned char OID_NEGOEX[] = { 0x2b, 0x06, 0x01, 0x04, 0x01,
	                                        0x82, 0x37, 0x02, 0x02, 0x1e };
static const unsigned char OID_SPNEGO[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
static const unsigned char NTLM_NEGOTIATE[] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 1, 0, 0, 0 };

typedef struct
{
	const unsigned char* oid;
	size_t len;
} Oid;
#define O(x) { x, sizeof(x) }

/* TSRequest { version 6, negoTokens { { negoToken = token } } } */
static size_t tsrequest(unsigned char* out, const unsigned char* token, size_t toklen)
{
	unsigned char a[4096], b[4096], c[4096];
	static const unsigned char version[] = { 0xa0, 0x03, 0x02, 0x01, 0x06 };
	size_t n = tlv(a, 0x04, token, toklen); /* OCTET STRING */
	n = tlv(b, 0xa0, a, n);                 /* negoToken [0] */
	n = tlv(a, 0x30, b, n);                 /* NegoDataItem */
	n = tlv(b, 0x30, a, n);                 /* NegoData */
	n = tlv(a, 0xa1, b, n);                 /* negoTokens [1] */
	memcpy(c, version, sizeof(version));
	memcpy(c + sizeof(version), a, n);
	return tlv(out, 0x30, c, sizeof(version) + n);
}

/* GSS InitialContextToken { SPNEGO, negTokenInit { mechTypes, mechToken (optional) } } */
static size_t spnego_init(unsigned char* out, const Oid* mechs, size_t count,
                          const unsigned char* opt, size_t optlen)
{
	unsigned char a[4096], b[4096], m[1024];
	size_t mn = 0;
	for (size_t i = 0; i < count; i++)
		mn += tlv(m + mn, 0x06, mechs[i].oid, mechs[i].len);
	size_t n = tlv(a, 0x30, m, mn); /* MechTypeList */
	n = tlv(b, 0xa0, a, n);         /* mechTypes [0] */
	if (opt)
	{
		/* reqFlags [1] left out; mechToken [2] OCTET STRING */
		unsigned char t[2048];
		size_t tn = tlv(t, 0x04, opt, optlen);
		n += tlv(b + n, 0xa2, t, tn);
	}
	n = tlv(a, 0x30, b, n);  /* NegTokenInit */
	n = tlv(b, 0xa0, a, n);  /* negTokenInit [0] */
	size_t on = tlv(a, 0x06, OID_SPNEGO, sizeof(OID_SPNEGO));
	memcpy(a + on, b, n);
	return tlv(out, 0x60, a, on + n);
}

static void check(const char* what, const unsigned char* pdu, size_t n, unsigned want,
                  int want_ntlm_only)
{
	const unsigned got = fastrdp_tsrequest_mechs(pdu, n);
	const int ntlm_only = (got & FASTRDP_MECH_NTLM) && !(got & FASTRDP_MECH_ANY_KERBEROS);
	char names[96];
	if (got != want || ntlm_only != want_ntlm_only)
	{
		printf("FAIL %s: mechs 0x%x (%s), want 0x%x; NTLM only %d, want %d\n", what, got,
		       fastrdp_mech_names(got, names, sizeof(names)), want, ntlm_only, want_ntlm_only);
		failures++;
	}
}

int main(void)
{
	unsigned char tok[4096], pdu[4096], big[600];
	size_t n;

	/* Windows with an AD ticket: [MS-KRB5, KRB5, NegoEx, NTLM], optimistic AP-REQ */
	const Oid win[] = { O(OID_MSKRB5), O(OID_KRB5), O(OID_NEGOEX), O(OID_NTLM) };
	memset(big, 0x6e, sizeof(big)); /* AP-REQ stand-in, long-form lengths everywhere */
	n = spnego_init(tok, win, 4, big, sizeof(big));
	n = tsrequest(pdu, tok, n);
	check("Windows, Kerberos ticket", pdu, n,
	      FASTRDP_MECH_MS_KRB5 | FASTRDP_MECH_KRB5 | FASTRDP_MECH_NEGOEX | FASTRDP_MECH_NTLM, 0);

	/* Windows without a ticket (IP address, no KDC, Entra-only): [NegoEx, NTLM] */
	const Oid noticket[] = { O(OID_NEGOEX), O(OID_NTLM) };
	n = spnego_init(tok, noticket, 2, NTLM_NEGOTIATE, sizeof(NTLM_NEGOTIATE));
	n = tsrequest(pdu, tok, n);
	check("Windows, no ticket", pdu, n, FASTRDP_MECH_NEGOEX | FASTRDP_MECH_NTLM, 1);

	/* FreeRDP /auth-pkg-list:'none,ntlm' and WinPR's default [U2U, KRB5, NTLM] */
	const Oid ntlm[] = { O(OID_NTLM) };
	n = spnego_init(tok, ntlm, 1, NTLM_NEGOTIATE, sizeof(NTLM_NEGOTIATE));
	n = tsrequest(pdu, tok, n);
	check("FreeRDP, NTLM only", pdu, n, FASTRDP_MECH_NTLM, 1);
	const Oid winpr[] = { O(OID_U2U), O(OID_KRB5), O(OID_NTLM) };
	n = spnego_init(tok, winpr, 3, NULL, 0);
	n = tsrequest(pdu, tok, n);
	check("FreeRDP, default list", pdu, n,
	      FASTRDP_MECH_U2U | FASTRDP_MECH_KRB5 | FASTRDP_MECH_NTLM, 0);

	/* bare NTLMSSP and bare Kerberos GSS tokens (no SPNEGO) */
	n = tsrequest(pdu, NTLM_NEGOTIATE, sizeof(NTLM_NEGOTIATE));
	check("bare NTLMSSP", pdu, n, FASTRDP_MECH_NTLM, 1);
	{
		unsigned char g[64];
		size_t gn = tlv(g, 0x06, OID_KRB5, sizeof(OID_KRB5));
		memcpy(g + gn, "\x01\x00\x6e\x00", 4);
		n = tlv(tok, 0x60, g, gn + 4);
		n = tsrequest(pdu, tok, n);
		check("bare Kerberos", pdu, n, FASTRDP_MECH_KRB5, 0);
	}

	/* An unknown OID only: neither NTLM nor Kerberos */
	static const unsigned char other[] = { 0x2a, 0x03, 0x04 };
	const Oid oth[] = { O(other) };
	n = spnego_init(tok, oth, 1, NULL, 0);
	n = tsrequest(pdu, tok, n);
	check("unknown mechanism", pdu, n, FASTRDP_MECH_OTHER, 0);

	/* the NTLM OID inside the opaque optimistic token does not count */
	unsigned char fake[32];
	size_t fn = tlv(fake, 0x06, OID_NTLM, sizeof(OID_NTLM));
	const Oid krb[] = { O(OID_KRB5) };
	n = spnego_init(tok, krb, 1, fake, fn);
	n = tsrequest(pdu, tok, n);
	check("NTLM OID in the mechToken", pdu, n, FASTRDP_MECH_KRB5, 0);

	/* not a TSRequest, truncated, garbage: 0 */
	const Oid ntlm1[] = { O(OID_NTLM) };
	n = spnego_init(tok, ntlm1, 1, NTLM_NEGOTIATE, sizeof(NTLM_NEGOTIATE));
	n = tsrequest(pdu, tok, n);
	for (size_t cut = 0; cut < n; cut++)
		if (fastrdp_tsrequest_mechs(pdu, cut) != 0)
		{
			printf("FAIL truncated TSRequest (%zu of %zu bytes) parsed\n", cut, n);
			failures++;
			break;
		}
	static const unsigned char tpkt[] = { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00 };
	check("X.224 TPKT", tpkt, sizeof(tpkt), 0, 0);
	static const unsigned char bad[] = { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0xa1 };
	check("oversized length", bad, sizeof(bad), 0, 0);
	static const unsigned char version_only[] = { 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x06 };
	check("TSRequest without negoTokens", version_only, sizeof(version_only), 0, 0);

	/* Kerberos token id of the optimistic token. mstsc under CredSSP: mechTypes
	 * [MS-KRB5, KRB5, NegoEx, NTLM], mechToken = U2U KERB-TGT-REQUEST for
	 * TERMSRV/<fqdn> without realm. For TERMSRV/fastrdp-server.linux-ng.de that token is
	 * 78 bytes, the size in the proxy's debug log of the failing Windows 11 login. */
	{
		unsigned char a[256], b[256], c[256], g[1024];
		static const unsigned char pvno_msgtype[] = { 0xa0, 0x03, 0x02, 0x01, 0x05,
			                                          0xa1, 0x03, 0x02, 0x01, 0x10 };
		static const unsigned char nametype[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
		size_t an = tlv(a, 0x1b, (const unsigned char*)"TERMSRV", 7);
		an += tlv(a + an, 0x1b, (const unsigned char*)"fastrdp-server.linux-ng.de", 26);
		size_t bn = tlv(b, 0x30, a, an);  /* name-string SEQUENCE OF GeneralString */
		an = tlv(a, 0xa1, b, bn);         /* [1] */
		memcpy(c, nametype, sizeof(nametype));
		memcpy(c + sizeof(nametype), a, an);
		bn = tlv(b, 0x30, c, sizeof(nametype) + an); /* PrincipalName */
		an = tlv(a, 0xa2, b, bn);                    /* server-name [2] */
		memcpy(c, pvno_msgtype, sizeof(pvno_msgtype));
		memcpy(c + sizeof(pvno_msgtype), a, an);
		bn = tlv(b, 0x30, c, sizeof(pvno_msgtype) + an); /* KERB-TGT-REQUEST */
		size_t gn = tlv(g, 0x06, OID_U2U, sizeof(OID_U2U));
		g[gn++] = 0x04; /* TOK_ID 04 00 */
		g[gn++] = 0x00;
		memcpy(g + gn, b, bn);
		const size_t u2ulen = tlv(c, 0x60, g, gn + bn);
		if (u2ulen != 78)
		{
			printf("FAIL mstsc U2U token is %zu bytes, want 78\n", u2ulen);
			failures++;
		}
		n = spnego_init(tok, win, 4, c, u2ulen);
		n = tsrequest(pdu, tok, n);
		check("Windows, user-to-user", pdu, n,
		      FASTRDP_MECH_MS_KRB5 | FASTRDP_MECH_KRB5 | FASTRDP_MECH_NEGOEX | FASTRDP_MECH_NTLM,
		      0);
		if (fastrdp_tsrequest_krb5_tok(pdu, n) != FASTRDP_KRB5_TOK_TGT_REQ)
		{
			printf("FAIL mstsc U2U: token id 0x%04x\n", fastrdp_tsrequest_krb5_tok(pdu, n));
			failures++;
		}
		for (size_t cut = 0; cut < n; cut++)
			if (fastrdp_tsrequest_krb5_tok(pdu, cut) != 0)
			{
				printf("FAIL truncated U2U TSRequest (%zu of %zu bytes) parsed\n", cut, n);
				failures++;
				break;
			}

		/* AP-REQ under the KRB5 OID, optimistic (Windows with a plain Kerberos ticket) */
		gn = tlv(g, 0x06, OID_KRB5, sizeof(OID_KRB5));
		g[gn++] = 0x01;
		g[gn++] = 0x00;
		memcpy(g + gn, big, sizeof(big));
		static unsigned char apreq[700];
		const size_t apn = tlv(apreq, 0x60, g, gn + sizeof(big));
		n = spnego_init(tok, win, 4, apreq, apn);
		n = tsrequest(pdu, tok, n);
		if (fastrdp_tsrequest_krb5_tok(pdu, n) != FASTRDP_KRB5_TOK_AP_REQ)
		{
			printf("FAIL Windows AP-REQ: token id 0x%04x\n", fastrdp_tsrequest_krb5_tok(pdu, n));
			failures++;
		}
		/* bare U2U token (no SPNEGO) */
		n = tsrequest(pdu, c, u2ulen);
		if (fastrdp_tsrequest_krb5_tok(pdu, n) != FASTRDP_KRB5_TOK_TGT_REQ)
		{
			printf("FAIL bare U2U token\n");
			failures++;
		}
		/* no optimistic token, NTLM token, opaque stand-in: 0 */
		n = spnego_init(tok, winpr, 3, NULL, 0);
		n = tsrequest(pdu, tok, n);
		const unsigned none = fastrdp_tsrequest_krb5_tok(pdu, n);
		n = spnego_init(tok, noticket, 2, NTLM_NEGOTIATE, sizeof(NTLM_NEGOTIATE));
		n = tsrequest(pdu, tok, n);
		const unsigned ntlmtok = fastrdp_tsrequest_krb5_tok(pdu, n);
		n = spnego_init(tok, win, 4, big, sizeof(big));
		n = tsrequest(pdu, tok, n);
		const unsigned opaque = fastrdp_tsrequest_krb5_tok(pdu, n);
		/* an NTLM OID in GSS framing is not a Kerberos token */
		gn = tlv(g, 0x06, OID_NTLM, sizeof(OID_NTLM));
		g[gn++] = 0x04;
		g[gn++] = 0x00;
		const size_t fakeu2u = tlv(a, 0x60, g, gn);
		n = spnego_init(tok, win, 4, a, fakeu2u);
		n = tsrequest(pdu, tok, n);
		const unsigned wrongoid = fastrdp_tsrequest_krb5_tok(pdu, n);
		if (none || ntlmtok || opaque || wrongoid)
		{
			printf("FAIL token id where there is none: %x %x %x %x\n", none, ntlmtok, opaque,
			       wrongoid);
			failures++;
		}
	}

	/* names for the log line */
	char names[96];
	fastrdp_mech_names(FASTRDP_MECH_NEGOEX | FASTRDP_MECH_NTLM, names, sizeof(names));
	if (strcmp(names, "NegoEx, NTLM") != 0)
	{
		printf("FAIL names: \"%s\"\n", names);
		failures++;
	}
	char tiny[8];
	fastrdp_mech_names(FASTRDP_MECH_NEGOEX | FASTRDP_MECH_NTLM, tiny, sizeof(tiny));
	if (strcmp(tiny, "NegoEx") != 0)
	{
		printf("FAIL names, small buffer: \"%s\"\n", tiny);
		failures++;
	}

	if (failures == 0)
		printf("test_spnego: all checks passed\n");
	return failures ? 1 : 0;
}
