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
 * E2E_KEYS=LIST, E2E_INPUT_AT_MS=N: keys sent N ms (default 2500) after connecting, e.g. to
 *   the desktop picker: comma-separated tokens, each a press and a release: "1".."9" (top
 *   row), "kp1".."kp9" (numeric keypad), "up", "down", "tab", "enter", "esc", "u1".."u9"
 *   (Unicode keyboard events); "dN" / "rN" only press / only release top-row N.
 * E2E_EARLY_KEYS=LIST: the same right after connecting (typed during the MFA wait).
 * E2E_NUMLOCK=1: a Synchronize event with NumLock on before the keys.
 * E2E_CLICK=+N: at E2E_INPUT_AT_MS, a left click on the picker row N rows below the
 *   selected one (found on the decoded screen: the accent-filled row).
 * E2E_CHANNEL_DATA=N: announce the static virtual channel "e2echan" and, at
 *   E2E_INPUT_AT_MS, send N bytes on it (before the keys); prints "channel_data=N sent=0|1".
 * Prints the Set Error Info code the server sent before disconnecting ("errinfo=0x..."),
 * if freerdp_connect failed, the connect error ("connect_error=0x..."), and the Bitmap
 * Updates received ("bitmap_updates=N bitmap_rects=N first_bitmap_ms=N", -1: none). */
#include <freerdp/channels/channels.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
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
	if (getenv("E2E_DUMP") || getenv("E2E_CLICK"))
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
/* one token of E2E_KEYS (see above) */
static void send_key(rdpInput* input, const char* t)
{
	static const struct
	{
		const char* name;
		UINT16 code; /* | 0x100: extended */
	} named[] = { { "up", 0x148 }, { "down", 0x150 }, { "tab", 0x0f }, { "enter", 0x1c }, { "esc", 0x01 } };
	static const BYTE keypad[9] = { 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47, 0x48, 0x49 };
	UINT16 code = 0;
	BOOL down = TRUE, up = TRUE;
	if (t[0] == 'u' && t[1] >= '1' && t[1] <= '9' && !t[2])
	{
		(void)freerdp_input_send_unicode_keyboard_event(input, 0, (UINT16)t[1]);
		(void)freerdp_input_send_unicode_keyboard_event(input, KBD_FLAGS_RELEASE, (UINT16)t[1]);
		return;
	}
	if ((t[0] == 'd' || t[0] == 'r') && t[1] >= '1' && t[1] <= '9' && !t[2])
	{
		down = t[0] == 'd';
		up = !down;
		t++;
	}
	if (t[0] >= '1' && t[0] <= '9' && !t[1])
		code = (UINT16)(0x02 + t[0] - '1');
	else if (strncmp(t, "kp", 2) == 0 && t[2] >= '1' && t[2] <= '9' && !t[3])
		code = keypad[t[2] - '1'];
	for (size_t i = 0; i < sizeof(named) / sizeof(named[0]) && !code; i++)
		if (strcmp(t, named[i].name) == 0)
			code = named[i].code;
	if (!code)
		return;
	const UINT16 ext = (code & 0x100) ? KBD_FLAGS_EXTENDED : 0;
	if (down)
		(void)freerdp_input_send_keyboard_event(input, ext, (UINT8)code);
	if (up)
		(void)freerdp_input_send_keyboard_event(input, ext | KBD_FLAGS_RELEASE, (UINT8)code);
}
static void send_keys(freerdp* inst, const char* list)
{
	char buf[512];
	(void)snprintf(buf, sizeof(buf), "%s", list);
	if (getenv("E2E_NUMLOCK"))
		(void)freerdp_input_send_synchronize_event(inst->context->input, KBD_SYNC_NUM_LOCK);
	for (char* t = strtok(buf, ","); t; t = strtok(NULL, ","))
		send_key(inst->context->input, t);
	printf("client: sent keys %s at %ld ms\n", list, elapsed_ms());
}
/* E2E_CLICK=+N: the accent-filled (selected) picker row on the decoded screen is the
 * first run of FASTRDP_COLOR_ACCENT (fastrdp_panel.h) taller than 20 pixels (the lock icon
 * and the countdown bar are lower); click N rows below it */
static BOOL is_accent(const BYTE* px)
{
	return px[2] == 0x2b && px[1] == 0x63 && px[0] == 0xd9;
}
static void click_row(freerdp* inst, int rows_below)
{
	const rdpGdi* gdi = inst->context->gdi;
	if (!gdi)
		return;
	for (UINT32 y = 1; y < gdi->height; y++)
		for (UINT32 x = 0; x < gdi->width; x++)
		{
			const BYTE* px = gdi->primary_buffer + (size_t)y * gdi->stride + (size_t)x * 4;
			if (!is_accent(px) || is_accent(px - gdi->stride))
				continue;
			UINT32 h = 0;
			while (y + h < gdi->height && is_accent(px + (size_t)h * gdi->stride))
				h++;
			if (h <= 20)
				continue;
			const UINT16 cx = (UINT16)(x + 4);
			const UINT16 cy = (UINT16)(y + (UINT32)rows_below * h + h / 2);
			rdpInput* input = inst->context->input;
			(void)freerdp_input_send_mouse_event(input, PTR_FLAGS_MOVE, cx, cy);
			(void)freerdp_input_send_mouse_event(input, PTR_FLAGS_DOWN | PTR_FLAGS_BUTTON1, cx, cy);
			(void)freerdp_input_send_mouse_event(input, PTR_FLAGS_BUTTON1, cx, cy);
			printf("client: clicked %u,%u (selected row at %u,%u, %u high) at %ld ms\n", cx, cy, x,
			       y, h, elapsed_ms());
			return;
		}
	printf("client: no picker row on the screen\n");
}
/* E2E_CHANNEL_DATA: one static channel without a plugin, announced in the Client Network Data */
static BOOL announce_channel(rdpSettings* s)
{
	const UINT32 n = freerdp_settings_get_uint32(s, FreeRDP_ChannelCount);
	CHANNEL_DEF* def = freerdp_settings_get_pointer_array_writable(s, FreeRDP_ChannelDefArray, n);
	if (!def)
		return FALSE;
	memset(def, 0, sizeof(*def));
	memcpy(def->name, "e2echan", sizeof("e2echan"));
	def->options = CHANNEL_OPTION_INITIALIZED;
	return freerdp_settings_set_uint32(s, FreeRDP_ChannelCount, n + 1);
}
static void send_channel_data(freerdp* inst, size_t size)
{
	const UINT16 id = freerdp_channels_get_id_by_name(inst, "e2echan");
	BYTE* data = calloc(1, size);
	BOOL sent = FALSE;
	/* in pieces, as a channel plugin would send messages; each is chunked by the core */
	for (size_t off = 0; data && id && off < size; off += 64 * 1024)
	{
		sent = inst->SendChannelData(inst, id, data + off, MIN(64 * 1024, size - off));
		if (!sent)
			break;
	}
	free(data);
	printf("client: channel_data=%zu sent=%d\n", size, sent);
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
	size_t channel_data = getenv("E2E_CHANNEL_DATA") ? strtoul(getenv("E2E_CHANNEL_DATA"), NULL, 10) : 0;
	if (channel_data && !announce_channel(s))
		return 4;
	inst->PostConnect = post_connect;
	const long keep_ms = 1000L * (getenv("E2E_KEEP_S") ? atoi(getenv("E2E_KEEP_S")) : 4);
	const char* dump = getenv("E2E_DUMP");
	const long dump_at = getenv("E2E_DUMP_AT_MS") ? atol(getenv("E2E_DUMP_AT_MS")) : 1500;
	const char* keys = getenv("E2E_KEYS");
	const char* click = getenv("E2E_CLICK");
	const long input_at = getenv("E2E_INPUT_AT_MS") ? atol(getenv("E2E_INPUT_AT_MS")) : 2500;
	clock_gettime(CLOCK_MONOTONIC, &started);
	BOOL ok = freerdp_connect(inst);
	printf("client: freerdp_connect=%d\n", ok);
	if (!ok)
		printf("client: connect_error=0x%08" PRIX32 " (%s)\n", freerdp_get_last_error(inst->context),
		       freerdp_get_last_error_name(freerdp_get_last_error(inst->context)));
	/* keep the session alive so the proxy reaches post-connect and contacts the back-end */
	const long connected_ms = elapsed_ms();
	if (ok && getenv("E2E_EARLY_KEYS"))
		send_keys(inst, getenv("E2E_EARLY_KEYS"));
	while (ok && elapsed_ms() - connected_ms < keep_ms &&
	       !freerdp_shall_disconnect_context(inst->context))
	{
		if (channel_data && elapsed_ms() - connected_ms >= input_at)
		{
			send_channel_data(inst, channel_data);
			channel_data = 0;
		}
		if ((keys || click) && elapsed_ms() - connected_ms >= input_at)
		{
			if (keys)
				send_keys(inst, keys);
			if (click)
				click_row(inst, atoi(click));
			keys = click = NULL;
		}
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
