/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Minimal headless RDP client for the e2e tests.
 * usage: client HOST PORT USER PASSWORD SHELL
 * Default: TLS security, credentials in the Client Info PDU.
 * E2E_NLA=1: NLA with Kerberos only (E2E_DOMAIN = realm), credentials via CredSSP.
 * E2E_PKCS11=/path/module.so (with E2E_NLA=1): smartcard logon, PKINIT through the
 *   PKCS#11 token; PASSWORD is the PIN.
 * E2E_RAIL=1: request RemoteApp (INFO_RAIL). E2E_SC_PIN=1: flag the password as a smartcard
 *   PIN (INFO_PASSWORD_IS_SC_PIN). E2E_WORKDIR: Client Info WorkingDir.
 * E2E_CONNECTION_TYPE=N: connectionType 1..7 in the Client Core Data (FreeRDP default 7).
 * E2E_GIVE_UP_S=N: exit after N seconds wherever the client is (like closing mstsc while
 *   the server still waits for an MFA push); prints "client: gave up".
 * Prints the Set Error Info code the server sent before disconnecting ("errinfo=0x..."). */
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
	printf("client: errinfo=0x%08" PRIX32 "\n", freerdp_error_info(inst));
	freerdp_disconnect(inst);
	freerdp_context_free(inst);
	freerdp_free(inst);
	return 0;
}
