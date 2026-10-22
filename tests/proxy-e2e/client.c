/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Minimal headless RDP client for the e2e tests.
 * usage: client HOST PORT USER PASSWORD SHELL
 * Default: TLS security, credentials in the Client Info PDU.
 * E2E_NLA=1: NLA with Kerberos only (E2E_DOMAIN = realm), credentials via CredSSP.
 *   E2E_AUTH_PKGS overrides the package list (default "kerberos,!ntlm"; "" = WinPR's
 *   defaults U2U, Kerberos, NTLM; "none,ntlm" = NTLM only, like a client without a ticket).
 * E2E_PKCS11=/path/module.so (with E2E_NLA=1): smartcard logon, PKINIT through the
 *   PKCS#11 token; PASSWORD is the PIN.
 * E2E_RAIL=1: request RemoteApp (INFO_RAIL). E2E_SC_PIN=1: flag the password as a smartcard
 *   PIN (INFO_PASSWORD_IS_SC_PIN). E2E_WORKDIR: Client Info WorkingDir.
 * E2E_CONNECTION_TYPE=N: connectionType 1..7 in the Client Core Data (FreeRDP default 7).
 * E2E_GIVE_UP_S=N: exit after N seconds wherever the client is (like closing mstsc while
 *   the server still waits for an MFA push); prints "client: gave up".
 * E2E_REMOTE_GUARD=1: require Remote Credential Guard (RDP_NEG_REQ flag
 *   REDIRECTED_AUTHENTICATION_MODE_REQUIRED, like mstsc /remoteGuard); with E2E_NLA=1 send
 *   TSRemoteGuardCreds (HOST/<server> ticket + forwarded TGT) instead of a password. An
 *   empty PASSWORD makes the client take a forwardable TGT from KRB5CCNAME.
 * E2E_KEEP_S=N: keep the session up to N seconds (default 4) after connecting.
 * E2E_BPP=N: color depth (FreeRDP default 32).
 * E2E_STATUS_INFO=1: announce RNS_UD_CS_SUPPORT_STATUSINFO_PDU; prints each Server Status
 *   Info PDU ("status_info=0x...").
 * E2E_DUMP=FILE, E2E_DUMP_AT_MS=N: decode the graphics (FreeRDP's GDI) and write the screen
 *   as a PPM image N ms (default 1500) after the connection started.
 * Prints the Set Error Info code the server sent before disconnecting ("errinfo=0x..."),
 * if freerdp_connect failed, the connect error ("connect_error=0x..."), and the Bitmap
 * Updates received ("bitmap_updates=N bitmap_rects=N first_bitmap_ms=N", -1: none). */
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/settings.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static struct timespec started;
static long elapsed_ms(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - started.tv_sec) * 1000 + (now.tv_nsec - started.tv_nsec) / 1000000;
}
static unsigned bitmap_updates, bitmap_rects;
static long first_bitmap_ms = -1;
static pBitmapUpdate gdi_bitmap_update; /* FreeRDP's GDI handler with E2E_DUMP */
static BOOL count_bitmap_update(rdpContext* ctx, const BITMAP_UPDATE* bitmap)
{
	if (bitmap_updates++ == 0)
		first_bitmap_ms = elapsed_ms();
	bitmap_rects += bitmap->number;
	return gdi_bitmap_update ? gdi_bitmap_update(ctx, bitmap) : TRUE;
}
static BOOL print_status_info(rdpContext* ctx, UINT32 status)
{
	(void)ctx;
	printf("client: status_info=0x%04" PRIX32 "\n", status);
	return TRUE;
}
static BOOL post_connect(freerdp* inst)
{
	if (getenv("E2E_DUMP"))
	{
		if (!gdi_init(inst, PIXEL_FORMAT_BGRX32))
			return FALSE;
		gdi_bitmap_update = inst->context->update->BitmapUpdate;
	}
	inst->context->update->BitmapUpdate = count_bitmap_update;
	inst->context->update->ServerStatusInfo = print_status_info;
	return TRUE;
}
static void dump_screen(freerdp* inst, const char* path)
{
	const rdpGdi* gdi = inst->context->gdi;
	FILE* f = gdi ? fopen(path, "wb") : NULL;
	if (!f)
		return;
	fprintf(f, "P6 %" PRIu32 " %" PRIu32 " 255\n", gdi->width, gdi->height);
	for (UINT32 y = 0; y < gdi->height; y++)
		for (UINT32 x = 0; x < gdi->width; x++)
		{
			const BYTE* px = gdi->primary_buffer + (size_t)y * gdi->stride + (size_t)x * 4;
			fputc(px[2], f);
			fputc(px[1], f);
			fputc(px[0], f);
		}
	fclose(f);
	printf("client: dumped screen at %ld ms\n", elapsed_ms());
}
static void give_up(int sig)
{
	(void)sig;
	static const char msg[] = "client: gave up\n";
	if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) < 0)
		_exit(1);
	_exit(0); /* the kernel closes the socket, as for a closed client window */
}
int main(int argc, char** argv)
{
	if (argc != 6) { fprintf(stderr, "usage: host port user pass shell\n"); return 2; }
	freerdp* inst = freerdp_new();
	if (!inst || !freerdp_context_new(inst)) return 3;
	rdpSettings* s = inst->context->settings;
	freerdp_settings_set_string(s, FreeRDP_ServerHostname, argv[1]);
	freerdp_settings_set_uint32(s, FreeRDP_ServerPort, (UINT32)atoi(argv[2]));
	freerdp_settings_set_string(s, FreeRDP_Username, argv[3]);
	if (argv[4][0])
		freerdp_settings_set_string(s, FreeRDP_Password, argv[4]);
	freerdp_settings_set_string(s, FreeRDP_AlternateShell, argv[5]);
	freerdp_settings_set_bool(s, FreeRDP_AutoLogonEnabled, TRUE);
	/* RNS_UD_CS_SUPPORT_ERRINFO_PDU like mstsc; the library default for clients is off */
	freerdp_settings_set_bool(s, FreeRDP_SupportErrorInfoPdu, TRUE);
	if (getenv("E2E_CLIENT_ADDRESS")) /* claimed address in the Client Info PDU */
		freerdp_settings_set_string(s, FreeRDP_ClientAddress, getenv("E2E_CLIENT_ADDRESS"));
	if (getenv("E2E_RAIL"))
	{
		freerdp_settings_set_bool(s, FreeRDP_RemoteApplicationMode, TRUE);
		freerdp_settings_set_string(s, FreeRDP_RemoteApplicationProgram, "||notepad");
	}
	if (getenv("E2E_SC_PIN"))
		freerdp_settings_set_bool(s, FreeRDP_PasswordIsSmartcardPin, TRUE);
	if (getenv("E2E_WORKDIR"))
		freerdp_settings_set_string(s, FreeRDP_ShellWorkingDirectory, getenv("E2E_WORKDIR"));
	if (getenv("E2E_CONNECTION_TYPE")) /* Client Core Data connectionType; default AUTODETECT */
		freerdp_settings_set_uint32(s, FreeRDP_ConnectionType,
		                            (UINT32)atoi(getenv("E2E_CONNECTION_TYPE")));
	const BOOL nla = getenv("E2E_NLA") && strcmp(getenv("E2E_NLA"), "1") == 0;
	if (getenv("E2E_REMOTE_GUARD")) /* the RDP_NEG_REQ flag is sent with TLS, too */
		freerdp_settings_set_bool(s, FreeRDP_RemoteCredentialGuard, TRUE);
	freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, nla);
	freerdp_settings_set_bool(s, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, !nla);
	if (nla)
	{
		freerdp_settings_set_string(s, FreeRDP_Domain, getenv("E2E_DOMAIN"));
		freerdp_settings_set_string(s, FreeRDP_AuthenticationPackageList,
		                            getenv("E2E_AUTH_PKGS") ? getenv("E2E_AUTH_PKGS") : "kerberos,!ntlm");
		if (getenv("E2E_PKCS11"))
		{
			freerdp_settings_set_bool(s, FreeRDP_SmartcardLogon, TRUE);
			freerdp_settings_set_string(s, FreeRDP_Pkcs11Module, getenv("E2E_PKCS11"));
		}
	}
	if (getenv("E2E_CERT_FP")) /* pin like guacd's cert-fingerprints, no ignore */
		freerdp_settings_set_string(s, FreeRDP_CertificateAcceptedFingerprints, getenv("E2E_CERT_FP"));
	else
		freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE);
	freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth, 2560);
	freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, 1440);
	if (getenv("E2E_GIVE_UP_S"))
	{
		setvbuf(stdout, NULL, _IONBF, 0);
		signal(SIGALRM, give_up);
		alarm((unsigned)atoi(getenv("E2E_GIVE_UP_S")));
	}
	if (getenv("E2E_BPP"))
		freerdp_settings_set_uint32(s, FreeRDP_ColorDepth, (UINT32)atoi(getenv("E2E_BPP")));
	if (getenv("E2E_STATUS_INFO"))
		freerdp_settings_set_bool(s, FreeRDP_SupportStatusInfoPdu, TRUE);
	inst->PostConnect = post_connect;
	const long keep_ms = 1000L * (getenv("E2E_KEEP_S") ? atoi(getenv("E2E_KEEP_S")) : 4);
	const char* dump = getenv("E2E_DUMP");
	const long dump_at = getenv("E2E_DUMP_AT_MS") ? atol(getenv("E2E_DUMP_AT_MS")) : 1500;
	clock_gettime(CLOCK_MONOTONIC, &started);
	BOOL ok = freerdp_connect(inst);
	printf("client: freerdp_connect=%d\n", ok);
	if (!ok)
		printf("client: connect_error=0x%08" PRIX32 " (%s)\n", freerdp_get_last_error(inst->context),
		       freerdp_get_last_error_name(freerdp_get_last_error(inst->context)));
	/* keep the session alive so the proxy reaches post-connect and contacts the back-end */
	const long connected_ms = elapsed_ms();
	while (ok && elapsed_ms() - connected_ms < keep_ms &&
	       !freerdp_shall_disconnect_context(inst->context))
	{
		if (dump && elapsed_ms() >= dump_at)
		{
			dump_screen(inst, dump);
			dump = NULL;
		}
		HANDLE h[64];
		DWORD n = freerdp_get_event_handles(inst->context, h, 64);
		WaitForMultipleObjects(n, h, FALSE, 100);
		if (!freerdp_check_event_handles(inst->context))
		{
			printf("client: session closed by server after %ld ms\n", elapsed_ms() - connected_ms);
			break;
		}
	}
	printf("client: errinfo=0x%08" PRIX32 "\n", freerdp_error_info(inst));
	printf("client: bitmap_updates=%u bitmap_rects=%u first_bitmap_ms=%ld\n", bitmap_updates,
	       bitmap_rects, first_bitmap_ms);
	freerdp_disconnect(inst);
	if (inst->context->gdi)
		gdi_free(inst);
	freerdp_context_free(inst);
	freerdp_free(inst);
	return 0;
}
