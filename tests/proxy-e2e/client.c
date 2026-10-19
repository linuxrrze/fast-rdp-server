/* Minimal headless RDP client for the e2e tests.
 * usage: client HOST PORT USER PASSWORD SHELL
 * Default: TLS security, credentials in the Client Info PDU.
 * E2E_NLA=1: NLA with Kerberos only (E2E_DOMAIN = realm), credentials via CredSSP. */
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv)
{
	if (argc != 6) { fprintf(stderr, "usage: host port user pass shell\n"); return 2; }
	freerdp* inst = freerdp_new();
	if (!inst || !freerdp_context_new(inst)) return 3;
	rdpSettings* s = inst->context->settings;
	freerdp_settings_set_string(s, FreeRDP_ServerHostname, argv[1]);
	freerdp_settings_set_uint32(s, FreeRDP_ServerPort, (UINT32)atoi(argv[2]));
	freerdp_settings_set_string(s, FreeRDP_Username, argv[3]);
	freerdp_settings_set_string(s, FreeRDP_Password, argv[4]);
	freerdp_settings_set_string(s, FreeRDP_AlternateShell, argv[5]);
	freerdp_settings_set_bool(s, FreeRDP_AutoLogonEnabled, TRUE);
	const BOOL nla = getenv("E2E_NLA") && strcmp(getenv("E2E_NLA"), "1") == 0;
	freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, nla);
	freerdp_settings_set_bool(s, FreeRDP_RdpSecurity, FALSE);
	freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, !nla);
	if (nla)
	{
		freerdp_settings_set_string(s, FreeRDP_Domain, getenv("E2E_DOMAIN"));
		freerdp_settings_set_string(s, FreeRDP_AuthenticationPackageList, "kerberos,!ntlm");
	}
	freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE);
	freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth, 2560);
	freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, 1440);
	BOOL ok = freerdp_connect(inst);
	printf("client: freerdp_connect=%d\n", ok);
	/* keep the session alive so the proxy reaches post-connect and contacts the back-end */
	for (int i = 0; ok && i < 40 && !freerdp_shall_disconnect_context(inst->context); i++)
	{
		HANDLE h[64];
		DWORD n = freerdp_get_event_handles(inst->context, h, 64);
		WaitForMultipleObjects(n, h, FALSE, 100);
		if (!freerdp_check_event_handles(inst->context))
		{
			printf("client: session closed by server after %d ms\n", i * 100);
			break;
		}
	}
	freerdp_disconnect(inst);
	freerdp_context_free(inst);
	freerdp_free(inst);
	return 0;
}
