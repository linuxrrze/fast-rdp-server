/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* WinPR Negotiate (SPNEGO) initiator against an MIT GSSAPI acceptor, in one process.
 *   spnego_mic user password realm target [package-list]
 * The acceptor uses the default keytab (KRB5_KTNAME). package-list is what FreeRDP's
 * /auth-pkg-list passes, e.g. "kerberos,!u2u,!ntlm". Exit 0 = both sides complete.
 *
 * With default settings WinPR offers Kerberos U2U first; MIT picks plain Kerberos, so
 * RFC 4178 requires a mechListMIC from both sides. MIT krb5 1.21.0-1.22.1 looks for the
 * initiator's MIC under the wrong tag and rejects the last token (krb5 ticket 9183). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <winpr/sspi.h>

static void hexdump(const char *what, const void *p, size_t n)
{
    const unsigned char *b = p;
    printf("  %s (%zu bytes):", what, n);
    for (size_t i = 0; i < n; i++)
        printf("%s%02x", i % 32 ? "" : "\n    ", b[i]);
    printf("\n");
}

static void gss_status(const char *what, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 m, more = 0;
    gss_buffer_desc b;
    printf("  %s: major 0x%x minor %u\n", what, maj, min);
    if (!GSS_ERROR(maj))
        return;
    do {
        gss_display_status(&m, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &more, &b);
        printf("    major: %.*s\n", (int)b.length, (char *)b.value);
        gss_release_buffer(&m, &b);
    } while (more);
    do {
        gss_display_status(&m, min, GSS_C_MECH_CODE, GSS_C_NO_OID, &more, &b);
        printf("    minor: %.*s\n", (int)b.length, (char *)b.value);
        gss_release_buffer(&m, &b);
    } while (more);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s user password realm target [package-list]\n", argv[0]);
        return 2;
    }
    const char *user = argv[1], *pw = argv[2], *realm = argv[3], *target = argv[4];
    const char *pkgs = argc > 5 ? argv[5] : "";

    SecurityFunctionTableA *t = InitSecurityInterfaceExA(0);
    SEC_WINNT_AUTH_IDENTITY_EXA ex = { 0 };
    ex.Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
    ex.Length = sizeof(ex);
    ex.User = (unsigned char *)user;
    ex.UserLength = (ULONG)strlen(user);
    ex.Domain = (unsigned char *)realm;
    ex.DomainLength = (ULONG)strlen(realm);
    ex.Password = (unsigned char *)pw;
    ex.PasswordLength = (ULONG)strlen(pw);
    ex.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    ex.PackageList = (unsigned char *)pkgs;
    ex.PackageListLength = (ULONG)strlen(pkgs);

    CredHandle cred;
    TimeStamp exp;
    SECURITY_STATUS st = t->AcquireCredentialsHandleA(NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
                                                     NULL, &ex, NULL, NULL, &cred, &exp);
    if (st != SEC_E_OK) {
        printf("AcquireCredentialsHandle: 0x%08x\n", (unsigned)st);
        return 3;
    }

    CtxtHandle ctx;
    int have_ctx = 0;
    gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
    static BYTE inbuf[65536], outbuf[65536];
    ULONG inlen = 0;
    OM_uint32 maj = GSS_S_CONTINUE_NEEDED, min;

    for (int round = 1; round <= 6; round++) {
        SecBuffer ib = { inlen, SECBUFFER_TOKEN, inbuf };
        SecBuffer ob = { sizeof(outbuf), SECBUFFER_TOKEN, outbuf };
        SecBufferDesc idesc = { SECBUFFER_VERSION, 1, &ib };
        SecBufferDesc odesc = { SECBUFFER_VERSION, 1, &ob };
        ULONG attr;
        st = t->InitializeSecurityContextA(&cred, have_ctx ? &ctx : NULL, (char *)target,
                                           ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY, 0,
                                           SECURITY_NATIVE_DREP, have_ctx ? &idesc : NULL, 0,
                                           &ctx, &odesc, &attr, &exp);
        have_ctx = 1;
        printf("round %d: WinPR initiator status 0x%08x\n", round, (unsigned)st);
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED)
            return 4;
        if (ob.cbBuffer == 0) {
            int ok = st == SEC_E_OK && maj == GSS_S_COMPLETE;
            printf("%s\n", ok ? "RESULT: both sides complete" : "RESULT: initiator stopped early");
            return ok ? 0 : 5;
        }
        hexdump("initiator -> acceptor", outbuf, ob.cbBuffer);

        gss_buffer_desc gin = { ob.cbBuffer, outbuf }, gout = { 0, NULL };
        OM_uint32 flags = 0;
        maj = gss_accept_sec_context(&min, &gctx, GSS_C_NO_CREDENTIAL, &gin,
                                     GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &gout, &flags,
                                     NULL, NULL);
        gss_status("MIT acceptor", maj, min);
        if (gout.length)
            hexdump("acceptor -> initiator", gout.value, gout.length);
        if (GSS_ERROR(maj)) {
            printf("RESULT: MIT acceptor rejected the token\n");
            return 6;
        }
        memcpy(inbuf, gout.value, gout.length);
        inlen = (ULONG)gout.length;
        gss_release_buffer(&min, &gout);
        if (maj == GSS_S_COMPLETE && inlen == 0) {
            printf("RESULT: %s\n", st == SEC_E_OK ? "both sides complete"
                                                  : "acceptor complete, initiator not");
            return st == SEC_E_OK ? 0 : 5;
        }
    }
    return 7;
}
