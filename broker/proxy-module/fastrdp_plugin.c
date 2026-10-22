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
 *                         so the user's password never reaches a back-end directly;
 *                         set the connection type the broker chose (xrdp encoder
 *                         profile, see connection_type_from_target()).
 *                         Pin the back-end's TLS certificate to the SHA-256 the broker
 *                         sent with the target (CertificateAcceptedFingerprints); with
 *                         [Target] CertificatePolicy=deny (required) nothing else is
 *                         accepted, so a local user who binds a back-end port while
 *                         the back-end is down cannot pose as it.
 *   ClientX509Certificate reached only for a certificate the pin refused: log it.
 *   ServerSessionEnd      notify the broker and wipe secrets.
 *
 * The broker call can take as long as an MFA push. It is abandoned as soon as the front
 * client closes its connection or the proxy aborts the session (broker_call()), so a
 * user who gives up does not hold the proxy's thread until the timeout.
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
 *   AllowTlsFrom =            ; non-NLA logins only from these peers: comma-separated
 *                             ; addresses/CIDRs (fastrdp_addr.h); empty = any peer
 *   AcceptRemoteGuard = false ; offer Remote Credential Guard, identity only: the
 *                             ; forwarded Kerberos tickets are discarded
 *                             ; (fastrdp_remote_credentials())
 */

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include <winpr/string.h>
#include <winpr/wlog.h>
#include <winpr/sspi.h>
#include <winpr/stream.h>
#include <winpr/synch.h>

#include <freerdp/crypto/certificate.h>
#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/transport_io.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
/* pServerContext: the proxyData of a freerdp_peer in peer callbacks that have no proxy
 * hook (peer->RemoteCredentials). The module is built against exactly one FreeRDP. */
#include <freerdp/private/proxy_server.h>
/* pClientContext.remote_pem: the certificate the back-end presented (ClientX509Certificate) */
#include <freerdp/private/proxy_client.h>

#include "fastrdp_addr.h"
#include "fastrdp_spnego.h"

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
	BOOL smartcard;    /* TSSmartCardCreds: the "password" is the card PIN */
	BOOL remote_guard; /* TSRemoteGuardCreds (Remote Credential Guard), discarded */
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
	UINT32 target_connection_type; /* 0 = keep the client's */
	char target_cert_sha256[65];   /* the back-end's certificate, lower-case hex */
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

/* Set at load time; for callbacks without a proxyPlugin argument. */
static proxyPluginsManager* fastrdp_mgr = NULL;

static fastrdpSession* get_session(proxyPlugin* plugin, proxyData* pdata)
{
	return (fastrdpSession*)plugin->mgr->GetPluginData(plugin->mgr, PLUGIN_NAME, pdata);
}

/* The session state, created on first use. Normally that is ServerPeerLogon; with
 * Remote Credential Guard it is the RemoteCredentials callback during NLA, just before.
 * Once registered, ServerSessionEnd frees it. */
static fastrdpSession* session_for(proxyPluginsManager* mgr, proxyData* pdata, BOOL* created)
{
	fastrdpSession* s = (fastrdpSession*)mgr->GetPluginData(mgr, PLUGIN_NAME, pdata);
	*created = FALSE;
	if (s)
		return s;
	s = calloc(1, sizeof(*s));
	if (s)
		*created = TRUE;
	return s;
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

/* The SSPI package of the finished NLA exchange ("Kerberos", "NTLM") into ascii[size];
 * FALSE if it cannot be queried. */
static BOOL nla_package_name(rdpContext* ps, char* ascii, size_t size)
{
	SecPkgContext_PackageInfo info = { 0 };
	if (size == 0)
		return FALSE;
	memset(ascii, 0, size);
	if (freerdp_nla_QueryContextAttributes(ps, SECPKG_ATTR_PACKAGE_INFO, &info) != SEC_E_OK ||
	    !info.PackageInfo || !info.PackageInfo->Name)
		return FALSE;
	/* The SSPI table may be the ANSI or the wide variant depending on the build. */
	const BYTE* name = (const BYTE*)info.PackageInfo->Name;
	const BOOL wide = name[0] != 0 && name[1] == 0;
	for (size_t i = 0; i < size - 1; i++)
	{
		const BYTE c = wide ? name[2 * i] : name[i];
		if (c == 0)
			break;
		ascii[i] = (char)c;
	}
	(void)freerdp_nla_FreeContextBuffer(ps, info.PackageInfo);
	return TRUE;
}

/* The one hint for every "this client could not do Kerberos" log line. */
#define KERBEROS_HINT                                                                        \
	"only Kerberos NLA is accepted: check that the client can reach the KDC (DNS SRV "       \
	"_kerberos._tcp.<domain>, ksetup /addkdc or a KDC proxy), connects to the server's FQDN " \
	"(not an IP address or an alias without TERMSRV SPN) and gives the user name as UPN "   \
	"(user@domain)"

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

typedef enum
{
	BROKER_FAILED = 0, /* not reachable, I/O error, malformed or incomplete reply */
	BROKER_REPLIED,
	BROKER_TIMED_OUT,
	BROKER_ABANDONED /* the front connection went away while waiting */
} brokerCallResult;

#define MAX_ABORT_FDS 8

/* Descriptors that end the wait for the broker: the proxy's abort event (readable once
 * set) and the front client's TCP socket. The socket is found through the peer's event
 * handles (WinPR binds the transport's socket event to the socket itself); only the
 * peer's end of the stream counts (POLLRDHUP, POLLHUP, POLLERR), not pending data.
 * The descriptors stay owned by FreeRDP: polled, never read or closed here. */
static nfds_t abort_fds(proxyData* pdata, struct pollfd* fds, nfds_t max)
{
	nfds_t n = 0;
	if (!pdata)
		return 0;
	if (pdata->abort_event)
	{
		const int fd = GetEventFileDescriptor(pdata->abort_event);
		if (fd >= 0 && n < max)
			fds[n++] = (struct pollfd){ .fd = fd, .events = POLLIN };
	}
	freerdp_peer* peer = pdata->ps ? pdata->ps->peer : NULL;
	if (!peer || !peer->GetEventHandles)
		return n;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
	const DWORD count = peer->GetEventHandles(peer, handles, ARRAYSIZE(handles));
	for (DWORD i = 0; i < count && n < max; i++)
	{
		const int fd = GetEventFileDescriptor(handles[i]);
		int type = 0;
		socklen_t len = sizeof(type);
		if (fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0 &&
		    type == SOCK_STREAM)
			fds[n++] = (struct pollfd){ .fd = fd, .events = POLLRDHUP };
	}
	return n;
}

/* Sends one JSON line and waits for the one-line reply (parsed into *reply, caller frees).
 * With `abort_on`, the wait ends early when that session's front connection closes or
 * its abort event is set (abort_fds()); the broker sees its connection closed and stops
 * working on the request (MFA push wait). Without it (session end), it does not. */
static brokerCallResult broker_call(const char* path, const cJSON* request, int timeout_s,
                                    proxyData* abort_on, cJSON** reply)
{
	brokerCallResult rc = BROKER_FAILED;
	char* text = cJSON_PrintUnformatted(request);
	char* buf = calloc(1, MAX_REPLY + 1);
	int fd = -1;
	const char* sid = abort_on ? abort_on->session_id : "-";

	*reply = NULL;
	if (!text || !buf)
		goto out;

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof(addr.sun_path))
		goto out;
	strcpy(addr.sun_path, path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		WLog_ERR(TAG, "[%s] cannot connect to broker at %s: %s", sid, path, strerror(errno));
		goto out;
	}

	if (!write_all(fd, text, strlen(text)) || !write_all(fd, "\n", 1))
		goto out;

	struct pollfd fds[1 + MAX_ABORT_FDS] = { { .fd = fd, .events = POLLIN } };
	const nfds_t nfds = 1 + abort_fds(abort_on, &fds[1], MAX_ABORT_FDS);

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
			WLog_ERR(TAG, "[%s] broker did not answer within %d s", sid, timeout_s);
			rc = BROKER_TIMED_OUT;
			goto out;
		}
		const int pr = poll(fds, nfds, (int)left_ms);
		if (pr < 0 && errno == EINTR)
			continue;
		if (pr < 0)
		{
			WLog_ERR(TAG, "[%s] poll on broker socket failed: %s", sid, strerror(errno));
			goto out;
		}
		if (pr == 0)
			continue;
		for (nfds_t i = 1; i < nfds; i++)
		{
			if (fds[i].revents)
			{
				clock_gettime(CLOCK_MONOTONIC, &now);
				WLog_WARN(TAG,
				          "[%s] front connection closed while waiting for the broker "
				          "(after %ld ms), request abandoned",
				          sid,
				          (long)((now.tv_sec - start.tv_sec) * 1000 +
				                 (now.tv_nsec - start.tv_nsec) / 1000000));
				rc = BROKER_ABANDONED;
				goto out;
			}
		}
		if (!fds[0].revents)
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
		WLog_ERR(TAG, "[%s] incomplete broker reply", sid);
		goto out;
	}
	*reply = cJSON_Parse(buf);
	if (*reply)
		rc = BROKER_REPLIED;

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
	return rc;
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

/* -------------------------------------------------------- connection type */

/* connectionType values ([MS-RDPBCGR] 2.2.1.3.2) by xrdp's gfx.toml section names */
static const struct
{
	const char* name;
	UINT32 value;
} connection_types[] = { { "modem", CONNECTION_TYPE_MODEM },
	                     { "broadband_low", CONNECTION_TYPE_BROADBAND_LOW },
	                     { "satellite", CONNECTION_TYPE_SATELLITE },
	                     { "broadband_high", CONNECTION_TYPE_BROADBAND_HIGH },
	                     { "wan", CONNECTION_TYPE_WAN },
	                     { "lan", CONNECTION_TYPE_LAN } };

/* The broker's optional target "connection_type" for the back-end hop. xrdp picks its
 * encoder profile from it, and mstsc's default AUTODETECT would get the uncapped LAN
 * profile because the proxy measures nothing. The broker decides (client network,
 * explicit client choice, back-end kind); missing or unknown = 0 = keep the client's. */
static UINT32 connection_type_from_target(const proxyData* pdata, const cJSON* target)
{
	const char* name = json_str(target, "connection_type");
	if (!name)
		return 0;
	for (size_t i = 0; i < ARRAYSIZE(connection_types); i++)
	{
		if (strcmp(name, connection_types[i].name) == 0)
			return connection_types[i].value;
	}
	WLog_WARN(TAG, "[%s] unknown connection type from broker ignored", pdata->session_id);
	return 0;
}

/* Only connectionType changes. The client's performance flags and its network
 * auto-detect support (RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT) stay as they are, so this is
 * not freerdp_set_connection_type(), which would rewrite the performance flags. */
static BOOL apply_connection_type(const proxyData* pdata, const fastrdpSession* s,
                                  rdpSettings* settings)
{
	if (s->target_connection_type == 0)
		return TRUE;
	WLog_INFO(TAG, "[%s] back-end connection type %" PRIu32 " (client sent %" PRIu32 ")",
	          pdata->session_id, s->target_connection_type,
	          freerdp_settings_get_uint32(settings, FreeRDP_ConnectionType));
	return freerdp_settings_set_uint32(settings, FreeRDP_ConnectionType,
	                                   s->target_connection_type);
}

/* ------------------------------------------------------------ TLS logins */

/* [FastRDP] AllowTlsFrom: non-NLA logins only from these peers. The address is the TCP
 * peer FreeRDP took from getpeername() (freerdp_peer::hostname, also the broker's
 * client_address), never the client's own claim in the Client Info PDU. */
static BOOL tls_peer_allowed(const proxyData* pdata)
{
	const char* list = config_str(pdata, "AllowTlsFrom", "");
	const freerdp_peer* peer = pdata->ps ? pdata->ps->peer : NULL;
	const char* addr = (peer && peer->hostname[0]) ? peer->hostname : NULL;
	unsigned invalid = 0;
	const int ok = fastrdp_addr_allowed(list, addr, &invalid);
	if (invalid)
		WLog_ERR(TAG, "[%s] AllowTlsFrom: %u invalid entr%s ignored (\"%s\")", pdata->session_id,
		         invalid, invalid == 1 ? "y" : "ies", list);
	if (!ok)
		WLog_WARN(TAG, "[%s] non-NLA login from %s refused (AllowTlsFrom=%s)", pdata->session_id,
		          addr ? addr : "(unknown address)", list);
	return ok != 0;
}

/* ------------------------------------------------- Remote Credential Guard */

/* Zero the redirected credentials in place. FreeRDP owns the buffers (the tickets point
 * into the decrypted TSCredentials, suppCreds is its own allocation) and frees them
 * after this callback without reading them again (libfreerdp/core/nla.c). */
static void discard_remote_credentials(KERB_TICKET_LOGON* logon,
                                       MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL* supp)
{
	if (logon)
	{
		if (logon->ServiceTicket && logon->ServiceTicketLength)
			memset(logon->ServiceTicket, 0, logon->ServiceTicketLength);
		if (logon->TicketGrantingTicket && logon->TicketGrantingTicketLength)
			memset(logon->TicketGrantingTicket, 0, logon->TicketGrantingTicketLength);
		logon->ServiceTicketLength = logon->TicketGrantingTicketLength = 0;
	}
	if (supp)
		memset(supp, 0,
		       offsetof(MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL, EncryptedCreds) +
		           supp->EncryptedCredsSize);
}

/* peer->RemoteCredentials: the client sent TSRemoteGuardCreds ([MS-CSSP] 2.2.1.2.3)
 * instead of a password, after Kerberos NLA authenticated it. They hold a service ticket
 * for HOST/<proxy> and a forwarded TGT (KRB-CRED); a Windows client keeps the TGT's
 * session key and expects the server to send its Kerberos requests back over
 * [MS-RDPEAR], which fastrdp does not implement. So: identity only. The login goes on
 * like a Restricted Admin or SSO login without a password (no session TGT; the broker
 * gets "remote_guard": true), and the tickets are never logged, kept or forwarded.
 * Installed for every connection: with AcceptRemoteGuard=false the proxy does not
 * offer the mode, and such credentials sent anyway are refused here. */
static BOOL fastrdp_remote_credentials(freerdp_peer* peer, KERB_TICKET_LOGON* logon,
                                       MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL* supp)
{
	BOOL rc = FALSE;
	pServerContext* ps = (peer && peer->context) ? (pServerContext*)peer->context : NULL;
	proxyData* pdata = ps ? ps->pdata : NULL;
	discard_remote_credentials(logon, supp);
	if (!pdata || !fastrdp_mgr)
		return FALSE;
	if (!config_bool(pdata, "AcceptRemoteGuard", FALSE))
	{
		WLog_WARN(TAG, "[%s] Remote Credential Guard credentials refused (AcceptRemoteGuard=false)",
		          pdata->session_id);
		return FALSE;
	}
	BOOL created = FALSE;
	fastrdpSession* s = session_for(fastrdp_mgr, pdata, &created);
	if (!s)
		return FALSE;
	s->remote_guard = TRUE;
	if (created && !fastrdp_mgr->SetPluginData(fastrdp_mgr, PLUGIN_NAME, pdata, s))
		session_free(s);
	else
		rc = TRUE;
	if (rc)
		WLog_INFO(TAG,
		          "[%s] Remote Credential Guard: identity only, forwarded Kerberos credentials "
		          "discarded",
		          pdata->session_id);
	return rc;
}

/* ------------------------------------------------------------------ hooks */

static BOOL fastrdp_server_peer_logon(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const proxyServerPeerLogon* info = (const proxyServerPeerLogon*)param;
	WINPR_ASSERT(plugin);
	WINPR_ASSERT(pdata);
	WINPR_ASSERT(info);
	WINPR_ASSERT(info->identity);

	BOOL created = FALSE;
	fastrdpSession* s = session_for(plugin->mgr, pdata, &created);
	if (!s)
		return FALSE;

	const SEC_WINNT_AUTH_IDENTITY* id = info->identity;
	s->nla = info->automatic;
	wipe_free(&s->user);
	wipe_free(&s->domain);
	wipe_free(&s->password);
	s->user = identity_string(id, id->User, id->UserLength);
	s->domain = identity_string(id, id->Domain, id->DomainLength);
	s->password = identity_string(id, id->Password, id->PasswordLength);

	if (s->remote_guard && !s->nla)
	{
		WLog_WARN(TAG, "[%s] Remote Credential Guard without NLA, refusing", pdata->session_id);
		goto refuse;
	}

	if (s->nla)
	{
		/* NTLM is not offered (fastrdp_server_session_init()); kept as defence in depth.
		 * NTLM also answers SECPKG_ATTR_AUTH_IDENTITY, but with a client-chosen domain,
		 * so nothing but Kerberos may count. */
		char pkg[16] = { 0 };
		const BOOL have_pkg = nla_package_name(pdata->ps, pkg, sizeof(pkg));
		if (!have_pkg || _stricmp(pkg, "Kerberos") != 0)
		{
			WLog_WARN(TAG, "[%s] NLA without Kerberos refused (package %s); " KERBEROS_HINT,
			          pdata->session_id, have_pkg ? pkg : "unknown");
			goto refuse;
		}

		/* Who did the KDC say this is? Never trust the CredSSP user name alone. */
		SecPkgContext_AuthIdentity ai = { 0 };
		const SECURITY_STATUS st =
		    freerdp_nla_QueryContextAttributes(pdata->ps, SECPKG_ATTR_AUTH_IDENTITY, &ai);
		if (st != SEC_E_OK || ai.User[0] == '\0' || ai.Domain[0] == '\0')
		{
			WLog_WARN(TAG, "[%s] NLA without Kerberos identity (status 0x%08" PRIx32 "), denied",
			          pdata->session_id, (UINT32)st);
			goto refuse;
		}
		const size_t plen = strlen(ai.User) + strlen(ai.Domain) + 2;
		wipe_free(&s->principal);
		s->principal = calloc(1, plen);
		if (!s->principal)
			goto refuse;
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
		/* Remote Credential Guard: TSRemoteGuardCreds carry no password (and were
		 * discarded, fastrdp_remote_credentials()). Nothing else counts as one. */
		if (s->smartcard || s->remote_guard)
			wipe_free(&s->password);
		if (!s->user)
			s->user = _strdup(ai.User);
		WLog_INFO(TAG, "[%s] NLA logon: principal %s, rdp user %s%s", pdata->session_id,
		          s->principal, s->user ? s->user : "(none)",
		          s->smartcard      ? " (smartcard)"
		          : s->remote_guard ? " (Remote Credential Guard, identity only)"
		                            : "");
	}
	else if (!config_bool(pdata, "AllowTls", FALSE))
	{
		WLog_WARN(TAG, "[%s] non-NLA connection refused (AllowTls=false)", pdata->session_id);
		goto refuse;
	}

	if (created && !plugin->mgr->SetPluginData(plugin->mgr, PLUGIN_NAME, pdata, s))
		goto refuse;
	return TRUE;

refuse:
	/* A session registered earlier (fastrdp_remote_credentials()) is freed at session end. */
	if (created)
		session_free(s);
	return FALSE;
}

/* 64 lower-case hex digits: the broker's cert_sha256 (sysutil.cert_sha256) */
static BOOL is_sha256_hex(const char* s)
{
	if (!s || strlen(s) != 64)
		return FALSE;
	for (const char* c = s; *c; c++)
		if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
			return FALSE;
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

	/* The back-end certificate is pinned in fastrdp_client_pre_connect(); any policy but
	 * deny would accept a certificate the pin refused. */
	if (pdata->config->TargetCertPolicy != FREERDP_PROXY_CERT_POLICY_DENY)
	{
		WLog_ERR(TAG, "[%s] proxy.ini [Target] CertificatePolicy must be deny (fastrdp pins "
		              "the back-end certificate itself), refusing",
		         pdata->session_id);
		goto out;
	}

	if (!s->nla)
	{
		/* Checked here, not at ServerPeerLogon: for TLS that runs right after the X.224
		 * negotiation, before MCS, when no Set Error Info PDU can reach the client yet.
		 * The Client Info credentials are dropped below without reaching the broker. */
		if (!tls_peer_allowed(pdata))
			goto out;
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
	cJSON_AddBoolToObject(req, "remote_guard", s->remote_guard);
	add_str(req, "desktop_hint", freerdp_settings_get_string(front, FreeRDP_AlternateShell));
	/* The socket's peer address, not FreeRDP_ClientAddress: the latter comes from the
	 * client's own Client Info PDU and can be anything. */
	const freerdp_peer* peer = pdata->ps->peer;
	add_str(req, "client_address", (peer && peer->hostname[0]) ? peer->hostname : NULL);
	cJSON_AddNumberToObject(req, "width", freerdp_settings_get_uint32(front, FreeRDP_DesktopWidth));
	cJSON_AddNumberToObject(req, "height",
	                        freerdp_settings_get_uint32(front, FreeRDP_DesktopHeight));
	/* 0 if the client did not set RNS_UD_CS_VALID_CONNECTION_TYPE */
	cJSON_AddNumberToObject(req, "connection_type",
	                        freerdp_settings_get_uint32(front, FreeRDP_ConnectionType));

	long timeout = strtol(config_str(pdata, "Timeout", "120"), NULL, 10);
	if (timeout <= 0 || timeout > 600)
		timeout = DEFAULT_TIMEOUT_S;
	const brokerCallResult called = broker_call(
	    config_str(pdata, "BrokerSocket", DEFAULT_SOCKET), req, (int)timeout, pdata, &reply);

	/* the request held the user's password */
	cJSON* pw = cJSON_GetObjectItemCaseSensitive(req, "password");
	if (cJSON_IsString(pw))
		memset(pw->valuestring, 0, strlen(pw->valuestring));
	cJSON_Delete(req);

	errinfo = ERRINFO_CB_DESTINATION_NOT_FOUND; /* broker down or malformed reply */
	if (called != BROKER_REPLIED)
	{
		if (called == BROKER_TIMED_OUT)
			errinfo = ERRINFO_CB_CONNECTION_CANCELLED;
		else if (called == BROKER_ABANDONED)
			errinfo = 0; /* nobody left to tell */
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
	const char* fp = json_str(target, "cert_sha256");
	if (!host || !cJSON_IsNumber(port) || port->valueint <= 0 || port->valueint > 65535 || !tuser ||
	    !tpass || !sec || !is_sha256_hex(fp))
	{
		WLog_ERR(TAG, "[%s] malformed broker reply", pdata->session_id);
		goto out;
	}

	s->target_user = _strdup(tuser);
	s->target_password = _strdup(tpass);
	s->target_domain = _strdup(tdom ? tdom : "");
	s->target_nla = strcmp(sec, "nla") == 0;
	s->target_connection_type = connection_type_from_target(pdata, target);
	memcpy(s->target_cert_sha256, fp, sizeof(s->target_cert_sha256)); /* 64 + NUL, checked */
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
		if (errinfo)
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
	const char* fpw = freerdp_settings_get_string(front, FreeRDP_Password);
	if (fpw)
		memset((void*)fpw, 0, strlen(fpw));
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
	    /* AcceptRemoteGuard sets this on the front; as a client setting it would require
	     * Remote Credential Guard from the back-end */
	    !freerdp_settings_set_bool(settings, FreeRDP_RemoteCredentialGuard, FALSE) ||
	    !freerdp_settings_set_pointer_len(settings, FreeRDP_LoadBalanceInfo, NULL, 0))
		return FALSE;
	/* The back-end's certificate: only the broker's (the TLS code accepts a listed
	 * fingerprint before the proxy's verify callback, which CertificatePolicy=deny makes
	 * refuse everything else). No certificate accepted earlier counts. */
	char pin[sizeof("sha256:") + sizeof(s->target_cert_sha256)];
	(void)snprintf(pin, sizeof(pin), "sha256:%s", s->target_cert_sha256);
	if (!s->target_cert_sha256[0] ||
	    !freerdp_settings_set_string(settings, FreeRDP_CertificateAcceptedFingerprints, pin) ||
	    !freerdp_settings_set_string(settings, FreeRDP_AcceptedCert, NULL) ||
	    !freerdp_settings_set_uint32(settings, FreeRDP_AcceptedCertLength, 0))
		return FALSE;
	/* The front list ("!ntlm", fastrdp_server_session_init()) was copied as well. The
	 * back-end hop authenticates with the broker's one-time secret over NTLM (GNOME
	 * Remote Desktop, KRdp); without NLA the list is unused. */
	if (!freerdp_settings_set_string(settings, FreeRDP_AuthenticationPackageList,
	                                 s->target_nla ? "!kerberos" : NULL))
		return FALSE;
	return apply_connection_type(pdata, s, settings);
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

/* HOOK_TYPE_CLIENT_VERIFY_X509 (custom = the proxy's client context): FreeRDP's TLS code
 * calls the proxy's verify callback, and with it this hook, only for a certificate that is
 * not in CertificateAcceptedFingerprints, i.e. not the one the broker named. The proxy
 * accepts a certificate here only if every module's hook returns TRUE, and its built-in
 * "config" module has none, so the hook cannot accept anything; it says why the back-end
 * was refused and returns FALSE ([Target] CertificatePolicy=deny then refuses). */
static BOOL fastrdp_client_x509_refused(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	pClientContext* pc = (pClientContext*)custom;
	fastrdpSession* s = get_session(plugin, pdata);
	char* got = NULL;
	/* sealed with a terminating NUL by the proxy (pf_client_verify_X509_certificate) */
	const size_t len = (pc && pc->remote_pem) ? Stream_Length(pc->remote_pem) : 0;
	const char* pem = len ? (const char*)Stream_Buffer(pc->remote_pem) : NULL;
	if (pem && len >= 2 && pem[len - 1] == '\0')
	{
		rdpCertificate* cert = freerdp_certificate_new_from_pem(pem);
		if (cert)
			got = freerdp_certificate_get_fingerprint_by_hash_ex(cert, "sha256", FALSE);
		freerdp_certificate_free(cert);
	}
	WLog_ERR(TAG,
	         "[%s] back-end %s:%u presented certificate sha256 %s, the broker expects %s: "
	         "refusing (another process on the back-end port?)",
	         pdata->session_id, (pc && pc->remote_hostname) ? pc->remote_hostname : "?",
	         pc ? (unsigned)pc->remote_port : 0U, got ? got : "(unreadable)",
	         (s && s->target_cert_sha256[0]) ? s->target_cert_sha256 : "(none)");
	free(got);
	set_front_errinfo(pdata, ERRINFO_CB_DESTINATION_NOT_FOUND);
	return FALSE;
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

/* NTLM in the front acceptor. fastrdp authenticates users only with Kerberos: an NTLM
 * logon would be checked against nothing the proxy has (no SAM, no domain controller).
 * Offering NTLM anyway made a client without a Kerberos ticket (IP address, KDC not
 * reachable, not domain-joined) run the whole NTLM exchange and then fail with a generic
 * "credentials did not work", and it sent the proxy an NTLMv2 response for the user's
 * password. So the front Negotiate acceptor offers Kerberos (and U2U) only.
 *
 * WinPR's Negotiate honours FreeRDP_AuthenticationPackageList on the server side only
 * when credssp_auth_setup_server() passes auth data to AcquireCredentialsHandle, i.e.
 * when a keytab, an NTLM SAM file or an NTLM hash callback is set. The callback is the
 * one that changes nothing else: the Kerberos acceptor keeps using the default keytab
 * (KRB5_KTNAME from the proxy's environment, as before). It is never called while NTLM is
 * disabled; should NTLM ever be selected anyway, it refuses. */
static SECURITY_STATUS fastrdp_ntlm_refused(void* client, const SEC_WINNT_AUTH_IDENTITY* id,
                                            const SecBuffer* ntproof, const BYTE* randkey,
                                            const BYTE* mic, const SecBuffer* micvalue,
                                            BYTE* hash)
{
	WINPR_UNUSED(id);
	WINPR_UNUSED(ntproof);
	WINPR_UNUSED(randkey);
	WINPR_UNUSED(mic);
	WINPR_UNUSED(micvalue);
	WINPR_UNUSED(hash);
	freerdp_peer* peer = (freerdp_peer*)client;
	const pServerContext* ps = (peer && peer->context) ? (pServerContext*)peer->context : NULL;
	WLog_WARN(TAG, "[%s] client attempted NTLM; " KERBEROS_HINT,
	          (ps && ps->pdata) ? ps->pdata->session_id : "?");
	return SEC_E_LOGON_DENIED;
}

/* The transport's own ReadPdu, wrapped by fastrdp_read_pdu() until NLA starts. */
static pTransportRWFkt fastrdp_default_read_pdu = NULL;

static BOOL is_x224_connection_request(const BYTE* b, size_t n)
{
	/* TPKT version 3 ([T.123] 8), then the X.224 CR TPDU code 0xE0 ([X.224] 13.3) */
	return n >= 7 && b[0] == 0x03 && (b[5] & 0xf0) == 0xe0;
}

/* Front connection, before NLA: the client's first TSRequest names the mechanisms it
 * offers. A client that offers NTLM but no Kerberos (it has no ticket for
 * TERMSRV/<name>) is going to fail in the acceptor, which only logs
 * "AcceptSecurityContext status SEC_E_INTERNAL_ERROR"; say why here. The wrapper removes
 * itself at the first PDU after the X.224 Connection Request, so the rest of the session
 * reads PDUs unwrapped. */
static int fastrdp_read_pdu(rdpTransport* transport, wStream* s)
{
	WINPR_ASSERT(fastrdp_default_read_pdu);
	const int rc = fastrdp_default_read_pdu(transport, s);
	if (rc <= 0)
		return rc;
	const BYTE* b = Stream_Buffer(s);
	const size_t n = Stream_Length(s);
	if (is_x224_connection_request(b, n))
		return rc;

	rdpContext* ctx = transport_get_context(transport);
	if (!ctx)
		return rc;
	const pServerContext* ps = (pServerContext*)ctx;
	const char* sid = ps->pdata ? ps->pdata->session_id : "?";
	const unsigned mechs = (n > 0 && b[0] == 0x30) ? fastrdp_tsrequest_mechs(b, n) : 0;
	if ((mechs & FASTRDP_MECH_NTLM) && !(mechs & FASTRDP_MECH_ANY_KERBEROS))
	{
		char names[96] = { 0 };
		WLog_WARN(TAG, "[%s] client %s attempted NTLM (offered: %s); " KERBEROS_HINT, sid,
		          (ctx->peer && ctx->peer->hostname) ? ctx->peer->hostname : "?",
		          fastrdp_mech_names(mechs, names, sizeof(names)));
	}
	/* mstsc under CredSSP asks for the server's TGT first (Kerberos user-to-user). The
	 * acceptor answers with the TGT of the account that owns TERMSRV/<name>; with Active
	 * Directory that is the machine account, whose keys must be in the proxy's keytab
	 * (fastrdp-termsrv-keytab, patches/freerdp/0004). */
	if (fastrdp_tsrequest_krb5_tok(b, n) == FASTRDP_KRB5_TOK_TGT_REQ)
		WLog_INFO(TAG,
		          "[%s] client %s requested Kerberos user-to-user (KERB-TGT-REQUEST): the proxy "
		          "answers with the TGT of the account owning TERMSRV/<name> (AD: machine "
		          "account <NAME>$ keys in the proxy keytab)",
		          sid, (ctx->peer && ctx->peer->hostname) ? ctx->peer->hostname : "?");

	const rdpTransportIo* cur = freerdp_get_io_callbacks(ctx);
	if (cur && cur->ReadPdu == fastrdp_read_pdu)
	{
		rdpTransportIo io = *cur;
		io.ReadPdu = fastrdp_default_read_pdu;
		if (!freerdp_set_io_callbacks(ctx, &io))
			WLog_WARN(TAG, "[%s] could not restore the transport callbacks", sid);
	}
	return rc;
}

static BOOL install_read_pdu_wrapper(rdpContext* ctx)
{
	const rdpTransportIo* cur = freerdp_get_io_callbacks(ctx);
	if (!cur || !cur->ReadPdu)
		return TRUE; /* nothing to wrap; only the log line is lost */
	if (!fastrdp_default_read_pdu)
		fastrdp_default_read_pdu = cur->ReadPdu;
	if (cur->ReadPdu != fastrdp_default_read_pdu)
		return TRUE; /* someone else's transport (stream dump/replay): leave it alone */
	rdpTransportIo io = *cur;
	io.ReadPdu = fastrdp_read_pdu;
	return freerdp_set_io_callbacks(ctx, &io);
}

/* Before the front connection sequence starts. freerdp-proxy has no RDP-UDP listener
 * ([MS-RDPEMT]/[MS-RDPEUDP]), but FreeRDP's server defaults would still advertise
 * multitransport (TS_UD_SC_MULTITRANSPORT) and send an Initiate Multitransport Request
 * ([MS-RDPBCGR] 2.2.15.1), then wait until the client gives up on UDP and answers
 * E_ABORT. Not offering it keeps the connection on TCP from the start; the back-end
 * connection inherits this setting.
 * Remote Credential Guard: freerdp_peer_initialize() (client->Initialize, right after
 * this hook) passes FreeRDP_RemoteCredentialGuard to the X.224 negotiation, which then
 * answers REDIRECTED_AUTHENTICATION_MODE_SUPPORTED ([MS-RDPBCGR] 2.2.1.2.1). Without it a
 * client that requires the mode gets a negotiation response without that flag and
 * disconnects itself (patches/freerdp/0002).
 * NLA: Kerberos only, see fastrdp_ntlm_refused(). The back-end client inherits the
 * package list; fastrdp_client_pre_connect() replaces it. */
static BOOL fastrdp_server_session_init(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	WINPR_UNUSED(plugin);
	WINPR_UNUSED(custom);
	if (!pdata || !pdata->ps || !pdata->ps->peer)
		return FALSE;
	rdpSettings* front = pdata->ps->settings;
	pdata->ps->peer->RemoteCredentials = fastrdp_remote_credentials;
	pdata->ps->peer->SspiNtlmHashCallback = fastrdp_ntlm_refused;
	return freerdp_settings_set_bool(front, FreeRDP_SupportMultitransport, FALSE) &&
	       freerdp_settings_set_uint32(front, FreeRDP_MultitransportFlags, 0) &&
	       freerdp_settings_set_bool(front, FreeRDP_RemoteCredentialGuard,
	                                 config_bool(pdata, "AcceptRemoteGuard", FALSE)) &&
	       freerdp_settings_set_string(front, FreeRDP_AuthenticationPackageList, "!ntlm") &&
	       install_read_pdu_wrapper(pdata->ps);
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
			/* not abortable: the front connection is usually gone by now */
			cJSON* reply = NULL;
			(void)broker_call(config_str(pdata, "BrokerSocket", DEFAULT_SOCKET), req, 5, NULL,
			                  &reply);
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
	fastrdp_mgr = mgr;
	plugin.name = PLUGIN_NAME;
	plugin.description = PLUGIN_DESC;
	plugin.PluginUnload = fastrdp_unload;
	plugin.ServerPeerLogon = fastrdp_server_peer_logon;
	plugin.ServerFetchTargetAddr = fastrdp_fetch_target;
	plugin.ClientPreConnect = fastrdp_client_pre_connect;
	plugin.ClientLoginFailure = fastrdp_client_login_failure;
	plugin.ClientRedirect = fastrdp_client_redirect;
	plugin.ClientX509Certificate = fastrdp_client_x509_refused;
	plugin.ServerSessionInitialize = fastrdp_server_session_init;
	plugin.ServerSessionEnd = fastrdp_session_end;
	plugin.userdata = userdata;
	return mgr->RegisterPlugin(mgr, &plugin);
}
