/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * fastrdp proxy module for freerdp-proxy3.
 *
 * Flow per connection:
 *   ServerPeerLogon       capture the front identity. For NLA, bind the CredSSP
 *                         user name to the Kerberos principal that actually
 *                         authenticated (SECPKG_ATTR_AUTH_IDENTITY).
 *   ServerFetchTargetAddr ask fastrdp-brokerd (Unix socket) to authorise the
 *                         login (account, groups, MFA) and to start or reuse the
 *                         user's session. The broker returns the back-end target.
 *   ClientPreConnect      replace the credentials and security protocol the proxy
 *                         uses towards the back-end with the broker's values,
 *                         so the user's password never reaches a back-end directly.
 *   ServerSessionEnd      notify the broker and wipe secrets.
 *
 * Refusals after the RDP connection is up carry a Set Error Info PDU
 * ([MS-RDPBCGR] 2.2.5.1.1) so that clients such as mstsc can show a reason instead of a
 * bare disconnect; see errinfo_for_reply().
 *
 * Configuration (proxy ini):
 *   [FastRDP]
 *   BrokerSocket = /run/fastrdp/broker.sock
 *   Timeout      = 120        ; seconds, must exceed the MFA push timeout
 *   AllowTls     = false      ; accept non-NLA logins (password [+OTP] in client info)
 */

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include <winpr/string.h>
#include <winpr/wlog.h>
#include <winpr/sspi.h>

#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_modules_api.h>

#define TAG MODULE_TAG("fastrdp")
#define PLUGIN_NAME "fastrdp"
#define PLUGIN_DESC "fastrdp session broker integration"
#define CONFIG_SECTION "FastRDP"
#define DEFAULT_SOCKET "/run/fastrdp/broker.sock"
#define DEFAULT_TIMEOUT_S 120
#define MAX_REPLY (64 * 1024)

typedef struct
{
	BOOL nla;
	BOOL smartcard; /* TSSmartCardCreds: the "password" is the card PIN */
	char* user;
	char* domain;
	char* password;
	char* principal;
	/* broker reply */
	BOOL routed;
	char* target_user;
	char* target_password;
	char* target_domain;
	BOOL target_nla;
} fastrdpSession;

static void wipe_free(char** s)
{
	if (*s)
	{
		memset(*s, 0, strlen(*s));
		free(*s);
		*s = NULL;
	}
}

static void session_free(fastrdpSession* s)
{
	if (!s)
		return;
	wipe_free(&s->user);
	wipe_free(&s->domain);
	wipe_free(&s->password);
	wipe_free(&s->principal);
	wipe_free(&s->target_user);
	wipe_free(&s->target_password);
	wipe_free(&s->target_domain);
	free(s);
}

static fastrdpSession* get_session(proxyPlugin* plugin, proxyData* pdata)
{
	return (fastrdpSession*)plugin->mgr->GetPluginData(plugin->mgr, PLUGIN_NAME, pdata);
}

static const char* config_str(const proxyData* pdata, const char* key, const char* def)
{
	const char* v = pf_config_get(pdata->config, CONFIG_SECTION, key);
	return (v && *v) ? v : def;
}

static BOOL config_bool(const proxyData* pdata, const char* key, BOOL def)
{
	const char* v = pf_config_get(pdata->config, CONFIG_SECTION, key);
	if (!v || !*v)
		return def;
	return (_stricmp(v, "true") == 0) || (strcmp(v, "1") == 0) || (_stricmp(v, "yes") == 0);
}

static char* identity_string(const SEC_WINNT_AUTH_IDENTITY* id, const void* ptr, UINT32 len)
{
	if (!ptr || len == 0)
		return NULL;
	if (id->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
		return strndup((const char*)ptr, len);
	return ConvertWCharNToUtf8Alloc((const WCHAR*)ptr, len, NULL);
}

/* TRUE if the finished NLA exchange used Kerberos. NTLM also answers
 * SECPKG_ATTR_AUTH_IDENTITY, but with a client-chosen domain, so it must not count. */
static BOOL nla_used_kerberos(rdpContext* ps)
{
	SecPkgContext_PackageInfo info = { 0 };
	if (freerdp_nla_QueryContextAttributes(ps, SECPKG_ATTR_PACKAGE_INFO, &info) != SEC_E_OK ||
	    !info.PackageInfo || !info.PackageInfo->Name)
		return FALSE;
	/* The SSPI table may be the ANSI or the wide variant depending on the build. */
	const BYTE* name = (const BYTE*)info.PackageInfo->Name;
	char ascii[16] = { 0 };
	const BOOL wide = name[0] != 0 && name[1] == 0;
	for (size_t i = 0; i < sizeof(ascii) - 1; i++)
	{
		const BYTE c = wide ? name[2 * i] : name[i];
		if (c == 0)
			break;
		ascii[i] = (char)c;
	}
	(void)freerdp_nla_FreeContextBuffer(ps, info.PackageInfo);
	return _stricmp(ascii, "Kerberos") == 0;
}

/* --------------------------------------------------------------- broker IPC */

static BOOL write_all(int fd, const char* buf, size_t len)
{
	while (len > 0)
	{
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			return FALSE;
		}
		buf += n;
		len -= (size_t)n;
	}
	return TRUE;
}

/* Sends one JSON line, returns the parsed reply (caller frees) or NULL.
 * *timed_out (optional) tells a broker that did not answer in time from other failures. */
static cJSON* broker_call(const char* path, const cJSON* request, int timeout_s, BOOL* timed_out)
{
	cJSON* reply = NULL;
	char* text = cJSON_PrintUnformatted(request);
	char* buf = calloc(1, MAX_REPLY + 1);
	int fd = -1;

	if (!text || !buf)
		goto out;

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof(addr.sun_path))
		goto out;
	strcpy(addr.sun_path, path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		WLog_ERR(TAG, "cannot connect to broker at %s: %s", path, strerror(errno));
		goto out;
	}

	if (!write_all(fd, text, strlen(text)) || !write_all(fd, "\n", 1))
		goto out;

	size_t used = 0;
	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (used < MAX_REPLY)
	{
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		const long elapsed_ms =
		    (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
		const long left_ms = (long)timeout_s * 1000 - elapsed_ms;
		if (left_ms <= 0)
		{
			WLog_ERR(TAG, "broker did not answer within %d s", timeout_s);
			if (timed_out)
				*timed_out = TRUE;
			goto out;
		}
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		const int pr = poll(&pfd, 1, (int)left_ms);
		if (pr < 0 && errno == EINTR)
			continue;
		if (pr < 0)
		{
			WLog_ERR(TAG, "poll on broker socket failed: %s", strerror(errno));
			goto out;
		}
		if (pr == 0)
			continue;
		ssize_t n = recv(fd, buf + used, MAX_REPLY - used, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
		if (memchr(buf, '\n', used))
			break;
	}
	if (!memchr(buf, '\n', used))
	{
		WLog_ERR(TAG, "incomplete broker reply");
		goto out;
	}
	reply = cJSON_Parse(buf);

out:
	if (fd >= 0)
		close(fd);
	if (text)
	{
		memset(text, 0, strlen(text));
		free(text);
	}
	if (buf)
	{
		memset(buf, 0, MAX_REPLY);
		free(buf);
	}
	return reply;
}

static const char* json_str(const cJSON* obj, const char* key)
{
	const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
	return cJSON_IsString(item) ? item->valuestring : NULL;
}

static void add_str(cJSON* obj, const char* key, const char* value)
{
	if (value)
		cJSON_AddStringToObject(obj, key, value);
	else
		cJSON_AddNullToObject(obj, key);
}

/* ------------------------------------------------------------ error info */

/* Set Error Info code ([MS-RDPBCGR] 2.2.5.1.1) for a refused broker login. The broker
 * keeps its error text generic on purpose ("access denied"); the "reason" field
 * (broker/brokerd/fastrdp_broker/protocol.py) lets it be more specific without exposing
 * details in the text. "denied" and "mfa_failed" (a distinct code would confirm the
 * password to somebody without the second factor) and unknown reasons give 0x7. */
static UINT32 errinfo_for_reply(const cJSON* reply)
{
	const cJSON* r = cJSON_GetObjectItemCaseSensitive(reply, "reason");
	const char* reason = cJSON_IsString(r) ? r->valuestring : NULL;
	const cJSON* e = cJSON_GetObjectItemCaseSensitive(reply, "error");
	const char* error = cJSON_IsString(e) ? e->valuestring : NULL;

	if (reason && strcmp(reason, "not_allowed") == 0)
		return ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES;
	/* No logon-timeout code exists: ERRINFO_LOGON_TIMEOUT (0x4) is the active session
	 * limit. A push not approved in time cancels the connection, as a broker timeout does. */
	if (reason && strcmp(reason, "mfa_timeout") == 0)
		return ERRINFO_CB_CONNECTION_CANCELLED;
	/* the error text covers brokers from before "reason" */
	if ((reason && strcmp(reason, "backend") == 0) ||
	    (error && strcmp(error, "session could not be started") == 0))
		return ERRINFO_CB_DESTINATION_NOT_FOUND;
	return ERRINFO_SERVER_DENIED_CONNECTION;
}

/* Queue the code for the front connection. freerdp_peer_close() sends it as a Set Error
 * Info PDU before the Disconnect Provider Ultimatum (if the client announced
 * RNS_UD_CS_SUPPORT_ERRINFO_PDU). An error info already forwarded from the back-end wins. */
static void set_front_errinfo(proxyData* pdata, UINT32 code)
{
	if (!pdata || !pdata->ps)
		return;
	rdpContext* ctx = pdata->ps;
	if (freerdp_get_last_error(ctx) != FREERDP_ERROR_SUCCESS)
		return;
	freerdp_set_error_info(ctx->rdp, code);
}

/* ------------------------------------------------------------------ hooks */

static BOOL fastrdp_server_peer_logon(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const proxyServerPeerLogon* info = (const proxyServerPeerLogon*)param;
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(info);
	WINPR_ASSERT(info->identity);

	fastrdpSession* s = calloc(1, sizeof(*s));
	if (!s)
		return FALSE;

	const SEC_WINNT_AUTH_IDENTITY* id = info->identity;
	s->nla = info->automatic;
	s->user = identity_string(id, id->User, id->UserLength);
	s->domain = identity_string(id, id->Domain, id->DomainLength);
	s->password = identity_string(id, id->Password, id->PasswordLength);

	if (s->nla)
	{
		if (!nla_used_kerberos(pdata->ps))
		{
			WLog_WARN(TAG, "[%s] NLA without Kerberos refused", pdata->session_id);
			session_free(s);
			return FALSE;
		}

		/* Who did the KDC say this is? Never trust the CredSSP user name alone. */
		SecPkgContext_AuthIdentity ai = { 0 };
		const SECURITY_STATUS st =
		    freerdp_nla_QueryContextAttributes(pdata->ps, SECPKG_ATTR_AUTH_IDENTITY, &ai);
		if (st != SEC_E_OK || ai.User[0] == '\0' || ai.Domain[0] == '\0')
		{
			WLog_WARN(TAG, "[%s] NLA without Kerberos identity (status 0x%08" PRIx32 "), denied",
			          pdata->session_id, (UINT32)st);
			session_free(s);
			return FALSE;
		}
		const size_t plen = strlen(ai.User) + strlen(ai.Domain) + 2;
		s->principal = calloc(1, plen);
		if (!s->principal)
		{
			session_free(s);
			return FALSE;
		}
		(void)_snprintf(s->principal, plen, "%s@%s", ai.User, ai.Domain);

		/* The delegated TSCredentials (user, domain, password typed by the user) land in
		 * the front settings, not in the logon identity. They are client-supplied: the
		 * broker logs in the Kerberos principal's account and treats the user name as
		 * informational (a UPN or DOMAIN\user may differ from the account name); it
		 * drops the password if the name is clearly another account. */
		const rdpSettings* front = pdata->ps->settings;
		const char* tu = freerdp_settings_get_string(front, FreeRDP_Username);
		const char* td = freerdp_settings_get_string(front, FreeRDP_Domain);
		const char* tp = freerdp_settings_get_string(front, FreeRDP_Password);
		if (tu && *tu)
		{
			wipe_free(&s->user);
			s->user = _strdup(tu);
		}
		if (td && *td)
		{
			wipe_free(&s->domain);
			s->domain = _strdup(td);
		}
		/* With smartcard logon (PKINIT) the client delegates TSSmartCardCreds and FreeRDP
		 * stores the PIN as "password". Never pass a PIN on as a password: it would end up
		 * in pam_sss (failed-logon counters, lockouts) or at the MFA server. */
		s->smartcard = freerdp_settings_get_bool(front, FreeRDP_PasswordIsSmartcardPin);
		if (tp && *tp && !s->smartcard)
		{
			wipe_free(&s->password);
			s->password = _strdup(tp);
		}
		if (s->smartcard)
			wipe_free(&s->password);
		if (!s->user)
			s->user = _strdup(ai.User);
		WLog_INFO(TAG, "[%s] NLA logon: principal %s, rdp user %s%s", pdata->session_id,
		          s->principal, s->user ? s->user : "(none)", s->smartcard ? " (smartcard)" : "");
	}
	else if (!config_bool(pdata, "AllowTls", FALSE))
	{
		WLog_WARN(TAG, "[%s] non-NLA connection refused (AllowTls=false)", pdata->session_id);
		session_free(s);
		return FALSE;
	}

	if (!plugin->mgr->SetPluginData(plugin->mgr, PLUGIN_NAME, pdata, s))
	{
		session_free(s);
		return FALSE;
	}
	return TRUE;
}

static BOOL fastrdp_fetch_target(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	proxyFetchTargetEventInfo* ev = (proxyFetchTargetEventInfo*)param;
	WINPR_ASSERT(ev);

	rdpSettings* front = pdata->ps->settings;
	cJSON* reply = NULL;
	UINT32 errinfo = ERRINFO_SERVER_DENIED_CONNECTION;
	BOOL rc = FALSE;

	fastrdpSession* s = get_session(plugin, pdata);
	if (!s)
	{
		WLog_ERR(TAG, "[%s] no logon state, refusing", pdata->session_id);
		goto out;
	}

	/* INFO_RAIL ([MS-RDPBCGR] 2.2.1.11.1.1): the client wants RemoteApp. The broker only
	 * hands out full desktops and the proxy blocks the RAIL channel unless RemoteApp=true,
	 * so the client would wait forever for its application window. */
	if (freerdp_settings_get_bool(front, FreeRDP_RemoteApplicationMode) &&
	    !pdata->config->RemoteApp)
	{
		WLog_WARN(TAG, "[%s] RemoteApp (INFO_RAIL) requested but not offered, refusing",
		          pdata->session_id);
		goto out;
	}

	if (!s->nla)
	{
		/* TLS/RDP security: credentials arrive in the Client Info PDU. */
		wipe_free(&s->user);
		wipe_free(&s->domain);
		wipe_free(&s->password);
		/* INFO_PASSWORD_IS_SC_PIN: the "password" is a smartcard PIN. There is no
		 * smartcard logon without NLA here, and a PIN must never reach PAM or MFA. */
		if (freerdp_settings_get_bool(front, FreeRDP_PasswordIsSmartcardPin))
		{
			WLog_WARN(TAG, "[%s] TLS login with a smartcard PIN, refusing (use NLA)",
			          pdata->session_id);
			goto out;
		}
		const char* u = freerdp_settings_get_string(front, FreeRDP_Username);
		const char* d = freerdp_settings_get_string(front, FreeRDP_Domain);
		const char* p = freerdp_settings_get_string(front, FreeRDP_Password);
		s->user = u ? _strdup(u) : NULL;
		s->domain = d ? _strdup(d) : NULL;
		s->password = p ? _strdup(p) : NULL;
		if (!s->user || !s->password)
		{
			WLog_WARN(TAG, "[%s] TLS login without credentials, refusing (no login screen at proxy)",
			          pdata->session_id);
			goto out;
		}
	}

	cJSON* req = cJSON_CreateObject();
	if (!req)
		goto out;
	cJSON_AddStringToObject(req, "op", "login");
	cJSON_AddStringToObject(req, "session_id", pdata->session_id);
	cJSON_AddStringToObject(req, "method", s->nla ? "nla" : "tls");
	add_str(req, "user", s->user);
	add_str(req, "domain", s->domain);
	add_str(req, "password", s->password);
	add_str(req, "principal", s->principal);
	cJSON_AddBoolToObject(req, "smartcard", s->smartcard);
	add_str(req, "desktop_hint", freerdp_settings_get_string(front, FreeRDP_AlternateShell));
	/* The socket's peer address, not FreeRDP_ClientAddress: the latter comes from the
	 * client's own Client Info PDU and can be anything. */
	const freerdp_peer* peer = pdata->ps->peer;
	add_str(req, "client_address", (peer && peer->hostname[0]) ? peer->hostname : NULL);
	cJSON_AddNumberToObject(req, "width", freerdp_settings_get_uint32(front, FreeRDP_DesktopWidth));
	cJSON_AddNumberToObject(req, "height",
	                        freerdp_settings_get_uint32(front, FreeRDP_DesktopHeight));

	long timeout = strtol(config_str(pdata, "Timeout", "120"), NULL, 10);
	if (timeout <= 0 || timeout > 600)
		timeout = DEFAULT_TIMEOUT_S;
	BOOL timed_out = FALSE;
	reply = broker_call(config_str(pdata, "BrokerSocket", DEFAULT_SOCKET), req, (int)timeout,
	                    &timed_out);

	/* the request held the user's password */
	cJSON* pw = cJSON_GetObjectItemCaseSensitive(req, "password");
	if (cJSON_IsString(pw))
		memset(pw->valuestring, 0, strlen(pw->valuestring));
	cJSON_Delete(req);

	errinfo = ERRINFO_CB_DESTINATION_NOT_FOUND; /* broker down or malformed reply */
	if (!reply)
	{
		if (timed_out)
			errinfo = ERRINFO_CB_CONNECTION_CANCELLED;
		goto out;
	}
	if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(reply, "ok")))
	{
		errinfo = errinfo_for_reply(reply);
		const char* err = json_str(reply, "error");
		WLog_WARN(TAG, "[%s] broker refused %s: %s", pdata->session_id,
		          s->user ? s->user : "(none)", err ? err : "?");
		goto out;
	}

	const cJSON* target = cJSON_GetObjectItemCaseSensitive(reply, "target");
	const cJSON* port = cJSON_GetObjectItemCaseSensitive(target, "port");
	const char* host = json_str(target, "host");
	const char* tuser = json_str(target, "username");
	const char* tpass = json_str(target, "password");
	const char* tdom = json_str(target, "domain");
	const char* sec = json_str(target, "security");
	if (!host || !cJSON_IsNumber(port) || port->valueint <= 0 || port->valueint > 65535 || !tuser ||
	    !tpass || !sec)
	{
		WLog_ERR(TAG, "[%s] malformed broker reply", pdata->session_id);
		goto out;
	}

	s->target_user = _strdup(tuser);
	s->target_password = _strdup(tpass);
	s->target_domain = _strdup(tdom ? tdom : "");
	s->target_nla = strcmp(sec, "nla") == 0;
	ev->target_address = _strdup(host);
	if (!s->target_user || !s->target_password || !s->target_domain || !ev->target_address)
		goto out;
	ev->target_port = (UINT16)port->valueint;
	ev->fetch_method = PROXY_FETCH_TARGET_USE_CUSTOM_ADDR;
	s->routed = TRUE;
	WLog_INFO(TAG, "[%s] %s -> %s:%d (%s, desktop %s)", pdata->session_id,
	          json_str(reply, "user"), host, port->valueint, sec, json_str(reply, "desktop"));
	rc = TRUE;

out:
	if (!rc)
	{
		free(ev->target_address);
		ev->target_address = NULL;
		set_front_errinfo(pdata, errinfo);
	}
	if (reply)
	{
		cJSON* t = cJSON_GetObjectItemCaseSensitive(reply, "target");
		cJSON* tp = cJSON_GetObjectItemCaseSensitive(t, "password");
		if (cJSON_IsString(tp))
			memset(tp->valuestring, 0, strlen(tp->valuestring));
		cJSON_Delete(reply);
	}
	/* The front password is no longer needed once the broker has it. The back-end
	 * client context copied it too; ClientPreConnect replaces that copy. */
	if (s)
		wipe_free(&s->password);
	const char* fp = freerdp_settings_get_string(front, FreeRDP_Password);
	if (fp)
		memset((void*)fp, 0, strlen(fp));
	(void)freerdp_settings_set_string(front, FreeRDP_Password, NULL);
	return rc;
}

static BOOL fastrdp_client_pre_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	rdpContext* pc = (rdpContext*)custom;
	WINPR_ASSERT(pc);

	fastrdpSession* s = get_session(plugin, pdata);
	if (!s || !s->routed)
	{
		WLog_ERR(TAG, "[%s] back-end connect without broker routing, refusing", pdata->session_id);
		return FALSE;
	}

	rdpSettings* settings = pc->settings;
	if (!freerdp_settings_set_string(settings, FreeRDP_Username, s->target_user) ||
	    !freerdp_settings_set_string(settings, FreeRDP_Password, s->target_password) ||
	    !freerdp_settings_set_string(settings, FreeRDP_Domain, s->target_domain) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_AutoLogonEnabled, TRUE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, s->target_nla) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, !s->target_nla) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, FALSE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, FALSE) ||
	    /* the desktop is chosen by the broker; do not forward a client shell request */
	    !freerdp_settings_set_string(settings, FreeRDP_AlternateShell, NULL) ||
	    /* The back-end settings start as a copy of the front client's. Client Info and
	     * X.224 fields that are client-controlled or describe the front credentials must
	     * not reach the back-end: WorkingDir belongs to the dropped shell, INFO_RAIL and
	     * INFO_PASSWORD_IS_SC_PIN would mislabel the broker's credentials, and the
	     * routingToken is meant for the proxy, not for a loopback back-end. */
	    !freerdp_settings_set_string(settings, FreeRDP_ShellWorkingDirectory, NULL) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_RemoteApplicationMode, FALSE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_PasswordIsSmartcardPin, FALSE) ||
	    !freerdp_settings_set_bool(settings, FreeRDP_SmartcardLogon, FALSE) ||
	    !freerdp_settings_set_pointer_len(settings, FreeRDP_LoadBalanceInfo, NULL, 0))
		return FALSE;
	if (s->target_nla &&
	    !freerdp_settings_set_string(settings, FreeRDP_AuthenticationPackageList, "!kerberos"))
		return FALSE;
	return TRUE;
}

/* The back-end connection failed (TLS/NLA/Client Info rejected or unreachable). */
static BOOL fastrdp_client_login_failure(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(plugin);
	WINPR_UNUSED(custom);
	WLog_WARN(TAG, "[%s] back-end connection failed", pdata->session_id);
	set_front_errinfo(pdata, ERRINFO_CB_DESTINATION_NOT_FOUND);
	return TRUE;
}

/* A Server Redirection PDU ([MS-RDPBCGR] 2.2.13) from a back-end would make the proxy
 * reconnect elsewhere with the broker's one-time credentials. Back-ends are chosen by
 * the broker only; refuse. */
static BOOL fastrdp_client_redirect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(plugin);
	WINPR_UNUSED(custom);
	WLog_WARN(TAG, "[%s] back-end sent a Server Redirection PDU, refusing", pdata->session_id);
	set_front_errinfo(pdata, ERRINFO_SERVER_DENIED_CONNECTION);
	return FALSE;
}

/* Before the front connection sequence starts. freerdp-proxy has no RDP-UDP listener
 * ([MS-RDPEMT]/[MS-RDPEUDP]), but FreeRDP's server defaults would still advertise
 * multitransport (TS_UD_SC_MULTITRANSPORT) and send an Initiate Multitransport Request
 * ([MS-RDPBCGR] 2.2.15.1), then wait until the client gives up on UDP and answers
 * E_ABORT. Not offering it keeps the connection on TCP from the start; the back-end
 * connection inherits this setting. */
static BOOL fastrdp_server_session_init(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(plugin);
	WINPR_UNUSED(custom);
	if (!pdata || !pdata->ps)
		return FALSE;
	rdpSettings* front = pdata->ps->settings;
	return freerdp_settings_set_bool(front, FreeRDP_SupportMultitransport, FALSE) &&
	       freerdp_settings_set_uint32(front, FreeRDP_MultitransportFlags, 0);
}

static BOOL fastrdp_session_end(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(custom);
	fastrdpSession* s = get_session(plugin, pdata);
	if (s && s->routed)
	{
		cJSON* req = cJSON_CreateObject();
		if (req)
		{
			cJSON_AddStringToObject(req, "op", "end");
			cJSON_AddStringToObject(req, "session_id", pdata->session_id);
			cJSON* reply =
			    broker_call(config_str(pdata, "BrokerSocket", DEFAULT_SOCKET), req, 5, NULL);
			cJSON_Delete(reply);
			cJSON_Delete(req);
		}
	}
	(void)plugin->mgr->SetPluginData(plugin->mgr, PLUGIN_NAME, pdata, NULL);
	session_free(s);
	return TRUE;
}

static BOOL fastrdp_unload(proxyPlugin* plugin)
{
	WINPR_UNUSED(plugin);
	return TRUE;
}

FREERDP_API FREERDP_ENTRY_POINT(BOOL proxy_module_entry_point(proxyPluginsManager* mgr,
                                                             void* userdata))
{
	proxyPlugin plugin = { 0 };
	plugin.name = PLUGIN_NAME;
	plugin.description = PLUGIN_DESC;
	plugin.PluginUnload = fastrdp_unload;
	plugin.ServerPeerLogon = fastrdp_server_peer_logon;
	plugin.ServerFetchTargetAddr = fastrdp_fetch_target;
	plugin.ClientPreConnect = fastrdp_client_pre_connect;
	plugin.ClientLoginFailure = fastrdp_client_login_failure;
	plugin.ClientRedirect = fastrdp_client_redirect;
	plugin.ServerSessionInitialize = fastrdp_server_session_init;
	plugin.ServerSessionEnd = fastrdp_session_end;
	plugin.userdata = userdata;
	return mgr->RegisterPlugin(mgr, &plugin);
}
