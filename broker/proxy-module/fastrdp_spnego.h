/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * Which security mechanisms does a CredSSP client offer? Reads the client's first
 * TSRequest ([MS-CSSP] 2.2.1): negoTokens[0].negoToken is an SPNEGO negTokenInit
 * (RFC 4178 4.2.1, GSS framing RFC 2743 3.1) whose mechTypes list the mechanisms, or a
 * bare NTLMSSP message. Only the mechTypes list counts; the optimistic mechToken is
 * opaque. libc only, so that tests/proxy-module/test_spnego.c can test it without
 * FreeRDP.
 *
 * Used by the module to log plainly that a client tried NTLM (fastrdp offers only
 * Kerberos NLA, see fastrdp_server_session_init()).
 */
#ifndef FASTRDP_SPNEGO_H
#define FASTRDP_SPNEGO_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum
{
	FASTRDP_MECH_KRB5 = 1 << 0,    /* 1.2.840.113554.1.2.2 */
	FASTRDP_MECH_MS_KRB5 = 1 << 1, /* 1.2.840.48018.1.2.2 (Windows lists it first) */
	FASTRDP_MECH_U2U = 1 << 2,     /* 1.2.840.113554.1.2.2.3 (WinPR initiators) */
	FASTRDP_MECH_NTLM = 1 << 3,    /* 1.3.6.1.4.1.311.2.2.10, or a bare NTLMSSP message */
	FASTRDP_MECH_NEGOEX = 1 << 4,  /* 1.3.6.1.4.1.311.2.2.30 */
	FASTRDP_MECH_OTHER = 1 << 5
};
#define FASTRDP_MECH_ANY_KERBEROS (FASTRDP_MECH_KRB5 | FASTRDP_MECH_MS_KRB5 | FASTRDP_MECH_U2U)

/* One DER element at *p (< end): tag (single byte), content, advances *p past it. */
static int fastrdp_der_next(const unsigned char** p, const unsigned char* end, unsigned char* tag,
                            const unsigned char** val, size_t* len)
{
	const unsigned char* q = *p;
	if (q >= end || end - q < 2)
		return 0;
	*tag = *q++;
	if ((*tag & 0x1f) == 0x1f) /* multi-byte tags do not occur here */
		return 0;
	size_t l = *q++;
	if (l & 0x80)
	{
		const size_t n = l & 0x7f;
		if (n == 0 || n > 4 || (size_t)(end - q) < n)
			return 0;
		l = 0;
		for (size_t i = 0; i < n; i++)
			l = (l << 8) | *q++;
	}
	if (l > (size_t)(end - q))
		return 0;
	*val = q;
	*len = l;
	*p = q + l;
	return 1;
}

/* The first element with this tag in a constructed value [v, v + n). */
static int fastrdp_der_find(const unsigned char* v, size_t n, unsigned char want,
                            const unsigned char** val, size_t* len)
{
	const unsigned char* p = v;
	unsigned char tag = 0;
	while (fastrdp_der_next(&p, v + n, &tag, val, len))
		if (tag == want)
			return 1;
	return 0;
}

static unsigned fastrdp_mech_from_oid(const unsigned char* oid, size_t n)
{
	static const unsigned char krb5[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
	static const unsigned char u2u[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12,
		                                 0x01, 0x02, 0x02, 0x03 };
	static const unsigned char mskrb5[] = { 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 };
	static const unsigned char ntlm[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
	static const unsigned char negoex[] = { 0x2b, 0x06, 0x01, 0x04, 0x01,
		                                    0x82, 0x37, 0x02, 0x02, 0x1e };
#define FASTRDP_OID_IS(o) (n == sizeof(o) && memcmp(oid, o, n) == 0)
	if (FASTRDP_OID_IS(krb5))
		return FASTRDP_MECH_KRB5;
	if (FASTRDP_OID_IS(u2u))
		return FASTRDP_MECH_U2U;
	if (FASTRDP_OID_IS(mskrb5))
		return FASTRDP_MECH_MS_KRB5;
	if (FASTRDP_OID_IS(ntlm))
		return FASTRDP_MECH_NTLM;
	if (FASTRDP_OID_IS(negoex))
		return FASTRDP_MECH_NEGOEX;
#undef FASTRDP_OID_IS
	return FASTRDP_MECH_OTHER;
}

/* Mechanisms of one negoToken: SPNEGO negTokenInit, a bare mechanism token (GSS framing
 * with the mechanism's OID) or a bare NTLMSSP message. 0 if not recognised. */
static unsigned fastrdp_nego_token_mechs(const unsigned char* t, size_t n)
{
	static const unsigned char ntlmssp[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };
	static const unsigned char spnego[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
	if (n >= sizeof(ntlmssp) && memcmp(t, ntlmssp, sizeof(ntlmssp)) == 0)
		return FASTRDP_MECH_NTLM;
	const unsigned char* p = t;
	const unsigned char* v = NULL;
	size_t l = 0;
	unsigned char tag = 0;
	if (!fastrdp_der_next(&p, t + n, &tag, &v, &l) || tag != 0x60) /* [APPLICATION 0] */
		return 0;
	const unsigned char* end = v + l;
	const unsigned char* oid = NULL;
	size_t oidlen = 0;
	if (!fastrdp_der_next(&v, end, &tag, &oid, &oidlen) || tag != 0x06)
		return 0;
	if (oidlen != sizeof(spnego) || memcmp(oid, spnego, oidlen) != 0)
		return fastrdp_mech_from_oid(oid, oidlen);
	/* NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, ... } */
	const unsigned char* init = NULL;
	size_t initlen = 0;
	if (!fastrdp_der_next(&v, end, &tag, &init, &initlen) || tag != 0xa0)
		return 0;
	const unsigned char* seq = NULL;
	size_t seqlen = 0;
	const unsigned char* mt = NULL;
	size_t mtlen = 0;
	if (!fastrdp_der_find(init, initlen, 0x30, &seq, &seqlen) ||
	    !fastrdp_der_find(seq, seqlen, 0xa0, &mt, &mtlen) || /* mechTypes [0] MechTypeList */
	    !fastrdp_der_find(mt, mtlen, 0x30, &seq, &seqlen))
		return 0;
	unsigned mechs = 0;
	p = seq;
	while (fastrdp_der_next(&p, seq + seqlen, &tag, &oid, &oidlen))
		if (tag == 0x06)
			mechs |= fastrdp_mech_from_oid(oid, oidlen);
	return mechs;
}

/* Mechanisms offered in a TSRequest PDU: SEQUENCE { [0] version, [1] negoTokens
 * SEQUENCE OF SEQUENCE { [0] OCTET STRING }, ... }. 0 if the PDU is not a TSRequest
 * with a recognised negoToken. */
static unsigned fastrdp_tsrequest_mechs(const unsigned char* pdu, size_t n)
{
	const unsigned char* p = pdu;
	const unsigned char* v = NULL;
	size_t l = 0;
	unsigned char tag = 0;
	if (!fastrdp_der_next(&p, pdu + n, &tag, &v, &l) || tag != 0x30)
		return 0;
	const unsigned char* nd = NULL;
	size_t ndlen = 0;
	const unsigned char* seq = NULL;
	size_t seqlen = 0;
	const unsigned char* item = NULL;
	size_t itemlen = 0;
	const unsigned char* tok = NULL;
	size_t toklen = 0;
	const unsigned char* os = NULL;
	size_t oslen = 0;
	if (!fastrdp_der_find(v, l, 0xa1, &nd, &ndlen) ||
	    !fastrdp_der_find(nd, ndlen, 0x30, &seq, &seqlen) ||
	    !fastrdp_der_find(seq, seqlen, 0x30, &item, &itemlen) ||
	    !fastrdp_der_find(item, itemlen, 0xa0, &tok, &toklen) ||
	    !fastrdp_der_find(tok, toklen, 0x04, &os, &oslen))
		return 0;
	return fastrdp_nego_token_mechs(os, oslen);
}

/* "NegoEx, NTLM" for a log line. */
static const char* fastrdp_mech_names(unsigned mechs, char* buf, size_t size)
{
	static const struct
	{
		unsigned bit;
		const char* name;
	} names[] = { { FASTRDP_MECH_MS_KRB5, "MS-Kerberos" }, { FASTRDP_MECH_KRB5, "Kerberos" },
		          { FASTRDP_MECH_U2U, "Kerberos U2U" },   { FASTRDP_MECH_NEGOEX, "NegoEx" },
		          { FASTRDP_MECH_NTLM, "NTLM" },          { FASTRDP_MECH_OTHER, "other" } };
	size_t used = 0;
	if (size == 0)
		return buf;
	buf[0] = '\0';
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
	{
		if (!(mechs & names[i].bit))
			continue;
		const int w = snprintf(buf + used, size - used, "%s%s", used ? ", " : "", names[i].name);
		if (w < 0 || (size_t)w >= size - used)
		{
			buf[used] = '\0'; /* whole names only */
			break;
		}
		used += (size_t)w;
	}
	return buf;
}

#endif /* FASTRDP_SPNEGO_H */
