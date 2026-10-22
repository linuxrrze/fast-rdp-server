/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/**
 * fastrdp proxy module for freerdp-proxy3.
 *
 * Flow per connection:
 *   ServerPeerLogon       capture the front identity. For NLA, bind the CredSSP
 *                         user name to the Kerberos principal that actually
 *                         authenticated (SECPKG_ATTR_AUTH_IDENTITY), and keep what
 *                         the KDC asserted in the ticket (kdc_evidence()).
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
 * user who gives up does not hold the proxy's thread until the timeout. Meanwhile the
 * client can show what the login waits for ([FastRDP] WaitingScreen, waitingScreen), and
 * with [broker] desktop_picker the user picks the desktop there (ws_picker_start()).
 *
 * Refusals after the RDP connection is up carry a Set Error Info PDU
 * ([MS-RDPBCGR] 2.2.5.1.1) so that clients such as mstsc can show a reason instead of a
 * bare disconnect; see errinfo_for_reply().
 *
 * Configuration (proxy ini):
 *   [FastRDP]
 *   BrokerSocket = /run/fastrdp/broker.sock
 *   Timeout      = 180        ; seconds (1..600): MFA push/web approval + session start
 *   AllowTls     = false      ; accept non-NLA logins (password [+OTP] in client info)
 *   AllowTlsFrom =            ; non-NLA logins only from these peers: comma-separated
 *                             ; addresses/CIDRs (fastrdp_addr.h); empty = any peer
 *   AcceptRemoteGuard = false ; offer Remote Credential Guard, identity only: the
 *                             ; forwarded Kerberos tickets are discarded
 *                             ; (fastrdp_remote_credentials())
 *   WaitingScreen = true      ; show the broker's progress (MFA push, web approval with
 *                             ; QR code, session start) while the login waits
 *                             ; (waitingScreen)
 *   StatusInfo    = false     ; also Server Status Info PDUs, to clients that ask for them
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

#include <freerdp/codec/color.h>
#include <freerdp/codec/interleaved.h>
#include <freerdp/codec/planar.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/transport_io.h>
#include <freerdp/update.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
/* pServerContext: the proxyData of a freerdp_peer in peer callbacks that have no proxy
 * hook (peer->RemoteCredentials). The module is built against exactly one FreeRDP. */
#include <freerdp/private/proxy_server.h>
/* pClientContext.remote_pem: the certificate the back-end presented (ClientX509Certificate) */
#include <freerdp/private/proxy_client.h>

#include "fastrdp_addr.h"
#include "fastrdp_panel.h"
/* patches/freerdp/0005: the acceptor keeps what the KDC asserted in the ticket */
#if defined(SECPKG_ATTR_KERBEROS_AUTH_INDICATORS) && defined(SECPKG_ATTR_KERBEROS_PAC_LOGON_INFO)
#define FASTRDP_KDC_EVIDENCE 1
#include "fastrdp_pac.h"
#endif
#include "fastrdp_spnego.h"
/* patches/freerdp/0007: PDUs read while PostConnect runs are input of the active
 * connection, not a second PostConnect; the desktop picker reads its input that way. Weak:
 * built against the patched headers but loaded with an unpatched libfreerdp3, the module
 * finds no such function and shows no picker. */
#if defined(FREERDP_PEER_IN_POST_CONNECT)
#define FASTRDP_DESKTOP_PICKER 1
#pragma weak freerdp_peer_in_post_connect
#endif

#define TAG MODULE_TAG("fastrdp")
#define PLUGIN_NAME "fastrdp"
#define PLUGIN_DESC "fastrdp session broker integration"
#define CONFIG_SECTION "FastRDP"
#define DEFAULT_SOCKET "/run/fastrdp/broker.sock"
#define DEFAULT_TIMEOUT_S 180 /* Ansible fastrdp_proxy_broker_timeout */
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
	cJSON* kdc_evidence; /* NLA: ["ind:...", "sid:..."]; NULL: FreeRDP cannot tell */
	/* broker reply */
	BOOL routed;
	char* target_user;
	char* target_password;
	char* target_domain;
	BOOL target_nla;
	UINT32 target_connection_type; /* 0 = keep the client's */
	char target_cert_sha256[65];   /* the back-end's certificate, lower-case hex */
	void* screen; /* waitingScreen during the broker call: the picker's input callbacks */
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
	cJSON_Delete(s->kdc_evidence);
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

/* ------------------------------------------------------------ KDC evidence */

#if defined(FASTRDP_KDC_EVIDENCE)
/* The broker reads one JSON line of at most 64 KiB; keep the list well below that. A
 * truncated list can only miss evidence, so the login falls back to the second factor. */
#define KDC_EVIDENCE_MAX_ITEMS 512
#define KDC_EVIDENCE_MAX_BYTES (32 * 1024)
#define KDC_EVIDENCE_BUFFER (64 * 1024) /* patches/freerdp/0005 keeps at most this much */

typedef struct
{
	cJSON* list;
	size_t bytes;
	size_t dropped;
} kdcEvidence;

static int kdc_evidence_add(kdcEvidence* e, const char* prefix, const char* value)
{
	char item[FASTRDP_PAC_SID_LEN + 32];
	(void)snprintf(item, sizeof(item), "%s%s", prefix, value);
	const size_t len = strlen(item) + 3; /* quotes and comma */
	if ((size_t)cJSON_GetArraySize(e->list) >= KDC_EVIDENCE_MAX_ITEMS ||
	    e->bytes + len > KDC_EVIDENCE_MAX_BYTES)
	{
		e->dropped++;
		return 1;
	}
	cJSON* str = cJSON_CreateString(item);
	if (!str || !cJSON_AddItemToArray(e->list, str))
	{
		cJSON_Delete(str);
		return 0;
	}
	e->bytes += len;
	return 1;
}

static int kdc_evidence_add_sid(void* ctx, const char* sid)
{
	return kdc_evidence_add(ctx, "sid:", sid);
}
#endif

/* What the KDC asserted about the client in the Kerberos service ticket the proxy
 * accepted, from patches/freerdp/0005 (verified with the service key there):
 *   "ind:<indicator>"  authentication indicators (MIT krb5, FreeIPA: pkinit, otp, passkey, ...)
 *   "sid:S-1-..."      enabled group SIDs from the PAC (Active Directory, Samba, FreeIPA):
 *                      ExtraSids first (S-1-18-x, other domains), then domain and resource
 *                      groups (fastrdp_pac.h)
 * The broker may count it as the second factor ([mfa] kdc_evidence_as_mfa). Nothing the
 * client sends ends up here: the TSSmartCardCreds flag, for one, does not count.
 * NULL if this FreeRDP cannot tell (unpatched, Heimdal): the broker then sees no field. */
static cJSON* kdc_evidence(proxyData* pdata)
{
#if defined(FASTRDP_KDC_EVIDENCE)
	kdcEvidence e = { cJSON_CreateArray(), 0, 0 };
	BYTE* buf = calloc(1, KDC_EVIDENCE_BUFFER);
	SecBuffer sb = { 0 };
	if (!e.list || !buf)
		goto fail;

	sb.cbBuffer = KDC_EVIDENCE_BUFFER;
	sb.pvBuffer = buf;
	SECURITY_STATUS st = freerdp_nla_QueryContextAttributes(
	    pdata->ps, SECPKG_ATTR_KERBEROS_AUTH_INDICATORS, &sb);
	if (st != SEC_E_OK || sb.cbBuffer > KDC_EVIDENCE_BUFFER)
	{
		WLog_WARN(TAG, "[%s] Kerberos ticket evidence not available (status 0x%08" PRIx32
		               "); [mfa] kdc_evidence_as_mfa cannot apply",
		          pdata->session_id, (UINT32)st);
		goto fail;
	}
	for (size_t off = 0; off < sb.cbBuffer;)
	{
		const char* ind = (const char*)buf + off;
		const size_t len = strnlen(ind, sb.cbBuffer - off);
		if (len == sb.cbBuffer - off) /* not NUL-terminated */
			break;
		if (len > 0 && !kdc_evidence_add(&e, "ind:", ind))
			goto fail;
		off += len + 1;
	}

	sb.cbBuffer = KDC_EVIDENCE_BUFFER;
	sb.pvBuffer = buf;
	st = freerdp_nla_QueryContextAttributes(pdata->ps, SECPKG_ATTR_KERBEROS_PAC_LOGON_INFO, &sb);
	if (st == SEC_E_OK && sb.cbBuffer > 0 && sb.cbBuffer <= KDC_EVIDENCE_BUFFER &&
	    (!fastrdp_pac_group_sids(buf, sb.cbBuffer, FASTRDP_PAC_EXTRA, kdc_evidence_add_sid, &e) ||
	     !fastrdp_pac_group_sids(buf, sb.cbBuffer, FASTRDP_PAC_GROUPS | FASTRDP_PAC_RESOURCE,
	                             kdc_evidence_add_sid, &e)))
		WLog_WARN(TAG, "[%s] PAC logon information does not parse; no group SIDs",
		          pdata->session_id);
	if (e.dropped)
		WLog_WARN(TAG, "[%s] Kerberos ticket evidence: %" PRIuz " items left out (at most %d)",
		          pdata->session_id, e.dropped, KDC_EVIDENCE_MAX_ITEMS);
	free(buf);
	return e.list;

fail:
	free(buf);
	cJSON_Delete(e.list);
	return NULL;
#else
	(void)pdata;
	return NULL;
#endif
}

/* "pkinit, hardened; 12 group SIDs" for the log */
static void kdc_evidence_summary(const cJSON* list, char* out, size_t size)
{
	size_t sids = 0, o = 0;
	out[0] = '\0';
	const cJSON* it = NULL;
	cJSON_ArrayForEach(it, list)
	{
		const char* v = cJSON_GetStringValue(it);
		if (v && strncmp(v, "ind:", 4) == 0 && o < size)
		{
			const int n = snprintf(out + o, size - o, "%s%s", o ? ", " : "", v + 4);
			o += n > 0 ? (size_t)n : 0;
		}
		else if (v && strncmp(v, "sid:", 4) == 0)
			sids++;
	}
	if (o < size)
		(void)snprintf(out + o, size - o, "%s%" PRIuz " group SIDs", o ? "; " : "", sids);
}

/* The one hint for every "this client could not do Kerberos" log line. */
#define KERBEROS_HINT                                                                        \
	"only Kerberos NLA is accepted: check that the client can reach the KDC (DNS SRV "       \
	"_kerberos._tcp.<domain>, ksetup /addkdc or a KDC proxy), connects to the server's FQDN " \
	"(not an IP address or an alias without TERMSRV SPN) and gives the user name as UPN "   \
	"(user@domain)"

/* ------------------------------------------------------------ waiting screen */

static const char* json_str(const cJSON* obj, const char* key);

/* TS_BITMAP_DATA flags ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.2); libfreerdp keeps its own private */
#define WS_BITMAP_COMPRESSION 0x0001
#define WS_NO_BITMAP_COMPRESSION_HDR 0x0400
#define WS_TILE 64          /* tile edge, as the shadow server's Bitmap Updates */
#define WS_BATCH 64         /* tiles per Bitmap Update */
#define WS_MAX_UPDATE (256 * 1024) /* bytes per Bitmap Update, at most */
#define WS_MAX_PROGRESS 32  /* progress messages per login */
#define WS_MAX_TIMEOUT 3600 /* seconds a countdown may show */
#define WS_GENERIC_TEXT "Signing you in\xe2\x80\xa6"
#define WS_PICKER_NAME 64        /* bytes of a desktop name */
#define WS_PICKER_MAX_TIMEOUT 60 /* seconds the picker may wait ([broker] desktop_picker_timeout) */
#define WS_PICKER_GRACE_S 5      /* the broker waits that much longer for the answer */
#define WS_PICKER_DRAIN_MS 500   /* at most, reading what the client sent before the picker */
/* Static channel data read during the picker, counted with WS_PICKER_CHUNK_COST per chunk
 * (the proxy's per-chunk copy): above it the login is abandoned (ws_picker_channel_data()) */
#define WS_PICKER_MAX_CHANNEL_BYTES (4 * 1024 * 1024)
#define WS_PICKER_CHUNK_COST 128

typedef enum
{
	WS_PICKER_OFF = 0, /* not offered, or answered */
	WS_PICKER_SHOWN,   /* on the screen, waiting for the user */
	WS_PICKER_ANSWER   /* answer ready for the broker */
} wsPickerState;

/* The desktop picker on the waiting screen (ws_picker_start()). */
typedef struct
{
	BOOL offered; /* the login announced "picker": 1 (ws_picker_possible()) */
	BOOL asked;   /* a prompt came (one per login) */
	wsPickerState state;
	BOOL gone;  /* the front connection failed while reading its input */
	BOOL armed; /* input from before the picker read and dropped */
	unsigned n, def, sel;
	char names[FASTRDP_PANEL_MAX_OPTIONS][WS_PICKER_NAME + 1];
	int answer; /* row, or -1: the broker's default */
	const char* how;
	BOOL moved; /* the user moved the selection */
	BOOL num_lock;
	int pressed_row;  /* button 1 went down on this row */
	BYTE keys[64];    /* scancodes (| 0x100 extended) pressed after arming */
	UINT16 unicode;   /* bit n: Unicode '1' + n (n = 9: Enter) pressed after arming */
	pSynchronizeEvent sync;
	pKeyboardEvent keyboard;
	pUnicodeKeyboardEvent unicode_keyboard;
	pMouseEvent mouse;
	pExtendedMouseEvent extended_mouse;
	psPeerReceiveChannelData receive_channel_data; /* the proxy's, while counting */
	size_t channel_bytes; /* static channel data read meanwhile (+ WS_PICKER_CHUNK_COST each) */
	BOOL channel_capped;
} wsPicker;

/* The front connection while the broker works on the login ([FastRDP] WaitingScreen):
 * a panel with the broker's progress texts (MFA push, web approval with a QR code of the
 * approval URL, session start), drawn by fastrdp_panel.h and sent as Bitmap Updates
 * ([MS-RDPBCGR] 2.2.9.1.1.3.1.2), the one graphics output every client must accept.
 * This runs in the proxy's ServerPostConnect on the peer thread: the front connection is
 * active, the proxy's back-end client does not exist yet, so the module is the only
 * writer. Nothing else is possible then: GFX (drdynvc) starts only after PostConnect, and
 * the proxy turns off drawing orders and FreeRDP's automatic bitmap fields
 * (pf_server.c), so the module fills in every field of the bitmap data itself.
 * The desktop is cut into 64x64 tiles, compressed like the shadow server does it
 * (shadow_client_send_bitmap_update()): planar at 32 bpp, interleaved RLE at 15/16/24 bpp.
 * Before the hook returns a granted login, the panel is painted over in the screen colour,
 * so nothing of it stays should the back-end not repaint the whole desktop afterwards.
 * [FastRDP] StatusInfo additionally sends Server Status Info PDUs ([MS-RDPBCGR] 2.2.5.2)
 * to clients that announced RNS_UD_CS_SUPPORT_STATUSINFO_PDU (none of FreeRDP's do).
 * Drawing errors only stop the screen; they never fail the login. */
typedef struct
{
	proxyData* pdata;
	BOOL draw;        /* WaitingScreen: Bitmap Updates */
	BOOL status_info; /* StatusInfo, and the client accepts the PDU */
	UINT32 width, height, bpp;
	BOOL no_compression_hdr; /* the client's NoBitmapCompressionHeader */
	UINT32 budget;           /* bytes per Bitmap Update */
	fastrdpPanel* panel;
	BYTE* img; /* the panel, BGRX, panel->rect.w * panel->rect.h */
	size_t img_size;
	BOOL visible;      /* the panel belongs on the screen */
	fastrdpRect shown; /* where the client has it now */
	BITMAP_PLANAR_CONTEXT* planar;
	BITMAP_INTERLEAVED_CONTEXT* interleaved;
	BYTE tile[WS_TILE * WS_TILE * 4];
	BOOL countdown;
	struct timespec deadline;
	long shown_left; /* seconds the countdown shows */
	unsigned progress;
	unsigned updates; /* Bitmap Updates sent */
	/* the Bitmap Update being filled */
	BITMAP_DATA rects[WS_BATCH];
	UINT32 nrects;
	size_t batch_bytes;
	wsPicker picker;
} waitingScreen;

static long ws_ms_until(const struct timespec* t)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (t->tv_sec - now.tv_sec) * 1000 + (t->tv_nsec - now.tv_nsec) / 1000000;
}

/* Seconds the countdown shows: rounded up, so it reaches 0:00 at the deadline. */
static long ws_seconds_left(const waitingScreen* ws)
{
	const long ms = ws_ms_until(&ws->deadline);
	return ms <= 0 ? 0 : (ms + 999) / 1000;
}

static void ws_stop(waitingScreen* ws, const char* why)
{
	if (ws->draw)
		WLog_WARN(TAG, "[%s] waiting screen stopped: %s", ws->pdata->session_id, why);
	ws->draw = FALSE;
}

static BOOL ws_flush(waitingScreen* ws)
{
	BOOL ok = TRUE;
	if (ws->nrects > 0)
	{
		rdpUpdate* update = ws->pdata->ps->update;
		BITMAP_UPDATE bu = { .number = ws->nrects, .rectangles = ws->rects, .skipCompression = FALSE };
		ok = update && update->BitmapUpdate && update->BitmapUpdate(ws->pdata->ps, &bu);
		ws->updates++;
	}
	for (UINT32 i = 0; i < ws->nrects; i++)
		free(ws->rects[i].bitmapDataStream);
	memset(ws->rects, 0, sizeof(ws->rects));
	ws->nrects = 0;
	ws->batch_bytes = 0;
	return ok;
}

/* The pixels of the desktop tile at (x, y), bw x bh (bw a multiple of 4, may reach past
 * the desktop's right edge), into ws->tile: FASTRDP_COLOR_SCREEN, and the panel where it
 * is visible. */
static void ws_compose(waitingScreen* ws, UINT32 x, UINT32 y, UINT32 bw, UINT32 bh)
{
	for (size_t i = 0; i < (size_t)bw * bh * 4; i += 4)
	{
		ws->tile[i] = FASTRDP_COLOR_SCREEN & 0xff;
		ws->tile[i + 1] = (FASTRDP_COLOR_SCREEN >> 8) & 0xff;
		ws->tile[i + 2] = (FASTRDP_COLOR_SCREEN >> 16) & 0xff;
		ws->tile[i + 3] = 0xff;
	}
	const fastrdpRect t = { (int)x, (int)y, bw, bh };
	fastrdpRect o;
	if (!ws->visible || !fastrdp_rect_intersect(t, ws->panel->rect, &o))
		return;
	const fastrdpRect p = ws->panel->rect;
	for (unsigned row = 0; row < o.h; row++)
		memcpy(ws->tile + ((size_t)(o.y - t.y + (int)row) * bw + (size_t)(o.x - t.x)) * 4,
		       ws->img + ((size_t)(o.y - p.y + (int)row) * p.w + (size_t)(o.x - p.x)) * 4,
		       (size_t)o.w * 4);
}

static BOOL ws_add_tile(waitingScreen* ws, UINT32 x, UINT32 y)
{
	const UINT32 w = MIN(WS_TILE, ws->width - x);
	const UINT32 h = MIN(WS_TILE, ws->height - y);
	const UINT32 bw = (w + 3) & ~3u; /* interleaved needs a multiple of 4; the client clips */
	const UINT32 bytes_pp = (ws->bpp + 7) / 8;
	BYTE* data = NULL;
	UINT32 size = 0;
	ws_compose(ws, x, y, bw, h);
	if (ws->bpp == 32)
		data = freerdp_bitmap_compress_planar(ws->planar, ws->tile, PIXEL_FORMAT_BGRX32, bw, h,
		                                      bw * 4, NULL, &size);
	else
	{
		size = WS_TILE * WS_TILE * 4;
		data = malloc(size);
		if (data && !interleaved_compress(ws->interleaved, data, &size, bw, h, ws->tile,
		                                  PIXEL_FORMAT_BGRX32, bw * 4, 0, 0, NULL, ws->bpp))
		{
			free(data);
			data = NULL;
		}
	}
	if (!data)
		return FALSE;
	/* TS_BITMAP_DATA header and the update's own header */
	const size_t cost = (size_t)size + 26;
	if (cost + 32 > ws->budget || cost > UINT16_MAX)
	{
		free(data);
		return FALSE;
	}
	if ((ws->nrects == WS_BATCH || ws->batch_bytes + cost + 32 > ws->budget) && !ws_flush(ws))
	{
		free(data);
		return FALSE;
	}
	BITMAP_DATA* b = &ws->rects[ws->nrects++];
	b->destLeft = x;
	b->destTop = y;
	b->destRight = x + w - 1;
	b->destBottom = y + h - 1;
	b->width = bw;
	b->height = h;
	b->bitsPerPixel = ws->bpp;
	b->compressed = TRUE;
	b->flags = WS_BITMAP_COMPRESSION | (ws->no_compression_hdr ? WS_NO_BITMAP_COMPRESSION_HDR : 0);
	b->bitmapLength = size;
	b->cbCompFirstRowSize = 0;
	b->cbCompMainBodySize = size;
	b->cbScanWidth = bw * bytes_pp;
	b->cbUncompressedSize = bw * h * bytes_pp;
	b->bitmapDataStream = data;
	ws->batch_bytes += cost;
	return TRUE;
}

/* Sends every tile that overlaps r (desktop coordinates). */
static BOOL ws_send(waitingScreen* ws, fastrdpRect r)
{
	const fastrdpRect desk = { 0, 0, ws->width, ws->height };
	fastrdpRect c;
	if (!ws->draw || !fastrdp_rect_intersect(r, desk, &c))
		return TRUE;
	for (UINT32 y = ((UINT32)c.y / WS_TILE) * WS_TILE; y < (UINT32)c.y + c.h; y += WS_TILE)
		for (UINT32 x = ((UINT32)c.x / WS_TILE) * WS_TILE; x < (UINT32)c.x + c.w; x += WS_TILE)
			if (!ws_add_tile(ws, x, y))
			{
				(void)ws_flush(ws);
				ws_stop(ws, "a tile could not be compressed or sent");
				return FALSE;
			}
	if (!ws_flush(ws))
	{
		ws_stop(ws, "Bitmap Update not sent");
		return FALSE;
	}
	return TRUE;
}

/* Lays out and draws the panel; sends what changed on the screen. */
static void ws_redraw(waitingScreen* ws, BOOL whole_desktop)
{
	if (!ws->draw)
		return;
	if (!fastrdp_panel_layout(ws->panel, ws->width, ws->height))
	{
		ws_stop(ws, "the desktop is too small");
		return;
	}
	const fastrdpRect p = ws->panel->rect;
	const size_t need = (size_t)p.w * p.h * 4;
	if (need > ws->img_size)
	{
		BYTE* img = realloc(ws->img, need);
		if (!img)
		{
			ws_stop(ws, "out of memory");
			return;
		}
		ws->img = img;
		ws->img_size = need;
	}
	ws->shown_left = ws->countdown ? ws_seconds_left(ws) : 0;
	fastrdp_panel_draw(ws->panel, ws->img, p.w * 4, ws->shown_left);
	const fastrdpRect desk = { 0, 0, ws->width, ws->height };
	if (ws_send(ws, whole_desktop ? desk : fastrdp_rect_union(ws->shown, p)))
		ws->shown = p;
}

static void waiting_screen_free(waitingScreen* ws, BOOL clear)
{
	if (!ws)
		return;
	if (clear && ws->draw && ws->shown.w > 0)
	{
		ws->visible = FALSE;
		if (ws_send(ws, ws->shown))
			WLog_DBG(TAG, "[%s] waiting screen cleared", ws->pdata->session_id);
	}
	if (ws->updates > 0)
		WLog_INFO(TAG, "[%s] waiting screen: %u Bitmap Updates sent", ws->pdata->session_id,
		          ws->updates);
	freerdp_bitmap_planar_context_free(ws->planar);
	bitmap_interleaved_context_free(ws->interleaved);
	free(ws->panel);
	free(ws->img);
	free(ws);
}

static void ws_status_info(waitingScreen* ws, UINT32 status)
{
	rdpUpdate* update = ws->pdata->ps->update;
	if (ws->status_info && update && update->ServerStatusInfo &&
	    !update->ServerStatusInfo(ws->pdata->ps, status))
		WLog_WARN(TAG, "[%s] Status Info PDU 0x%04" PRIx32 " not sent", ws->pdata->session_id,
		          status);
}

/* NULL if neither [FastRDP] WaitingScreen nor StatusInfo applies to this client. Shows
 * the generic panel at once; the broker's progress messages replace its text. */
static waitingScreen* waiting_screen_new(proxyData* pdata)
{
	const rdpSettings* front = pdata->ps->settings;
	BOOL draw = config_bool(pdata, "WaitingScreen", TRUE);
	const BOOL status_info = config_bool(pdata, "StatusInfo", FALSE) &&
	                         freerdp_settings_get_bool(front, FreeRDP_SupportStatusInfoPdu);
	const UINT32 bpp = freerdp_settings_get_uint32(front, FreeRDP_ColorDepth);
	if (draw && bpp != 15 && bpp != 16 && bpp != 24 && bpp != 32)
	{
		WLog_INFO(TAG, "[%s] no waiting screen at %" PRIu32 " bpp", pdata->session_id, bpp);
		draw = FALSE;
	}
	if (!draw && !status_info)
		return NULL;
	waitingScreen* ws = calloc(1, sizeof(*ws));
	if (!ws)
		return NULL;
	ws->pdata = pdata;
	ws->draw = draw;
	ws->status_info = status_info;
	ws->width = freerdp_settings_get_uint32(front, FreeRDP_DesktopWidth);
	ws->height = freerdp_settings_get_uint32(front, FreeRDP_DesktopHeight);
	ws->bpp = bpp;
	ws->no_compression_hdr = freerdp_settings_get_bool(front, FreeRDP_NoBitmapCompressionHeader);
	ws->budget = MIN(freerdp_settings_get_uint32(front, FreeRDP_MultifragMaxRequestSize),
	                 WS_MAX_UPDATE);
	ws->visible = TRUE;
	ws_status_info(ws, TS_STATUS_FINDING_DESTINATION);
	if (!ws->draw)
		return ws;
	ws->panel = calloc(1, sizeof(*ws->panel));
	if (bpp == 32)
		ws->planar = freerdp_bitmap_planar_context_new(
		    PLANAR_FORMAT_HEADER_NA | PLANAR_FORMAT_HEADER_RLE, WS_TILE, WS_TILE);
	else
		ws->interleaved = bitmap_interleaved_context_new(TRUE);
	if (!ws->panel || (bpp == 32 ? !ws->planar : !ws->interleaved))
	{
		ws_stop(ws, "out of memory");
		return ws;
	}
	/* a client without the multifragment capability takes 16256 bytes per update
	 * (FASTPATH_FRAGMENT_SAFE_SIZE); a compressed 64x64 tile stays below that */
	if (ws->budget < 0x3F80 || ws->width > 8192 || ws->height > 8192)
	{
		ws_stop(ws, "unusable client limits");
		return ws;
	}
	static const char* const generic[] = { WS_GENERIC_TEXT };
	fastrdp_panel_init(ws->panel);
	fastrdp_panel_set_text(ws->panel, generic, ARRAYSIZE(generic));
	ws_redraw(ws, TRUE);
	return ws;
}

static void ws_picker_start(waitingScreen* ws, const cJSON* msg);
static void ws_picker_end(waitingScreen* ws);

/* One {"progress": ...} message from the broker (protocol.py): new text, QR code and
 * countdown, or the desktop picker ("choose_desktop"). Malformed parts are left out. */
static void waiting_screen_progress(waitingScreen* ws, const cJSON* msg)
{
	const char* kind = json_str(msg, "progress");
	WLog_DBG(TAG, "[%s] broker progress: %s", ws->pdata->session_id, kind ? kind : "?");
	/* the broker moved on without the picker's answer (its wait ended) */
	if (ws->picker.state == WS_PICKER_SHOWN)
		ws_picker_end(ws);
	if (kind && strcmp(kind, "choose_desktop") == 0)
	{
		ws_picker_start(ws, msg);
		return;
	}
	if (kind && strcmp(kind, "session_start") == 0)
		ws_status_info(ws, TS_STATUS_BRINGING_SESSION_ONLINE);
	if (!ws->draw)
		return;

	const cJSON* lines = cJSON_GetObjectItemCaseSensitive(msg, "lines");
	if (cJSON_IsArray(lines))
	{
		const char* text[FASTRDP_PANEL_MAX_LINES] = { 0 };
		unsigned n = 0;
		const cJSON* line = NULL;
		cJSON_ArrayForEach(line, lines)
		{
			if (n == FASTRDP_PANEL_MAX_LINES)
				break;
			text[n++] = cJSON_GetStringValue(line); /* NULL: empty line */
		}
		fastrdp_panel_set_text(ws->panel, text, n);
	}

	/* every message names its QR code; none: the previous one goes */
	const cJSON* qr = cJSON_GetObjectItemCaseSensitive(msg, "qr");
	const char* rows[FASTRDP_QR_MAX + 1] = { 0 };
	unsigned nrows = 0;
	const cJSON* it = NULL;
	cJSON_ArrayForEach(it, qr)
	{
		rows[nrows++] = cJSON_GetStringValue(it);
		if (nrows > FASTRDP_QR_MAX)
			break;
	}
	if (!fastrdp_panel_set_qr(ws->panel, rows, nrows))
		WLog_WARN(TAG, "[%s] malformed QR code from the broker left out", ws->pdata->session_id);

	const cJSON* timeout = cJSON_GetObjectItemCaseSensitive(msg, "timeout_s");
	ws->countdown = cJSON_IsNumber(timeout) && timeout->valuedouble >= 1 &&
	                timeout->valuedouble <= WS_MAX_TIMEOUT;
	if (ws->countdown)
	{
		clock_gettime(CLOCK_MONOTONIC, &ws->deadline);
		ws->deadline.tv_sec += (time_t)timeout->valuedouble;
		const char* label = json_str(msg, "countdown");
		fastrdp_panel_set_countdown(ws->panel, label ? label : "");
		fastrdp_panel_set_countdown_total(ws->panel, (unsigned)timeout->valuedouble);
	}
	else
		fastrdp_panel_set_countdown(ws->panel, NULL);
	ws_redraw(ws, FALSE);
}

/* Milliseconds until the countdown shows the next second; -1 without a countdown. */
static int waiting_screen_next_ms(const waitingScreen* ws)
{
	if (!ws || !ws->draw || !ws->countdown)
		return -1;
	const long ms = ws_ms_until(&ws->deadline);
	if (ms <= 0)
		return -1;
	const long next = ms % 1000;
	return (int)((next == 0 ? 1000 : next) + 5);
}

/* Redraws the countdown's tiles when its second changed. */
static void waiting_screen_tick(waitingScreen* ws)
{
	if (!ws || !ws->draw || !ws->countdown)
		return;
	const long left = ws_seconds_left(ws);
	if (left == ws->shown_left)
		return;
	ws->shown_left = left;
	const fastrdpPanel* p = ws->panel;
	fastrdp_panel_draw_countdown(p, ws->img, p->rect.w * 4, left);
	const fastrdpRect r = { p->rect.x + p->countdown_rect.x, p->rect.y + p->countdown_rect.y,
		                    p->countdown_rect.w, p->countdown_rect.h };
	(void)ws_send(ws, r);
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

static nfds_t ws_picker_fds(const waitingScreen* ws, struct pollfd* fds, nfds_t max);
static BOOL ws_picker_read(waitingScreen* ws);
static void ws_picker_check_timeout(waitingScreen* ws);
static int ws_picker_next_ms(const waitingScreen* ws);
static BOOL ws_picker_answer(waitingScreen* ws, int fd);

/* Sends one JSON line and waits for the one-line reply (parsed into *reply, caller frees).
 * With `abort_on`, the wait ends early when that session's front connection closes or
 * its abort event is set (abort_fds()); the broker sees its connection closed and stops
 * working on the request (MFA push wait). Without it (session end), it does not.
 * With `screen` (the request asked for "progress"), lines with a "progress" field before
 * the reply update the waiting screen, at most WS_MAX_PROGRESS of them, each within
 * MAX_REPLY like the reply; the countdown is redrawn once a second meanwhile.
 * While the desktop picker shows (ws_picker_start()), the front connection's input is
 * read instead of only watched, the picker's answer goes to the broker as one line, and
 * the wait grows by the picker's timeout plus WS_PICKER_GRACE_S. */
static brokerCallResult broker_call(const char* path, const cJSON* request, int timeout_s,
                                    proxyData* abort_on, waitingScreen* screen, cJSON** reply)
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
		/* the picker reads the front connection; otherwise it is only watched */
		const BOOL picking = screen && screen->picker.state == WS_PICKER_SHOWN;
		const nfds_t nfds = 1 + (picking ? ws_picker_fds(screen, &fds[1], MAX_ABORT_FDS)
		                                 : abort_fds(abort_on, &fds[1], MAX_ABORT_FDS));
		int wait_ms = (int)left_ms;
		const int next_ms = waiting_screen_next_ms(screen);
		const int picker_ms = ws_picker_next_ms(screen);
		if (next_ms >= 0 && next_ms < wait_ms)
			wait_ms = next_ms;
		if (picker_ms >= 0 && picker_ms < wait_ms)
			wait_ms = picker_ms;
		const int pr = poll(fds, nfds, wait_ms);
		if (pr < 0 && errno == EINTR)
			continue;
		if (pr < 0)
		{
			WLog_ERR(TAG, "[%s] poll on broker socket failed: %s", sid, strerror(errno));
			goto out;
		}
		waiting_screen_tick(screen);
		if (picking)
		{
			BOOL input = FALSE, aborted = FALSE;
			for (nfds_t i = 1; i < nfds; i++)
			{
				if (fds[i].revents && abort_on && abort_on->abort_event &&
				    fds[i].fd == GetEventFileDescriptor(abort_on->abort_event))
					aborted = TRUE;
				else if (fds[i].revents)
					input = TRUE;
			}
			if (!aborted && input && !ws_picker_read(screen))
				aborted = TRUE;
			if (aborted)
			{
				WLog_WARN(TAG, "[%s] request abandoned during the desktop picker", sid);
				rc = BROKER_ABANDONED;
				goto out;
			}
			ws_picker_check_timeout(screen);
			if (screen->picker.state == WS_PICKER_ANSWER && !ws_picker_answer(screen, fd))
			{
				WLog_ERR(TAG, "[%s] desktop choice not sent to the broker", sid);
				goto out;
			}
			if (!fds[0].revents)
				continue;
		}
		else if (pr == 0)
			continue;
		for (nfds_t i = 1; i < nfds && !picking; i++)
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
		/* progress lines (only if asked for); the first other line is the reply */
		const char* nl = NULL;
		while (screen && (nl = memchr(buf, '\n', used)) != NULL)
		{
			const size_t len = (size_t)(nl - buf) + 1;
			cJSON* msg = cJSON_ParseWithLength(buf, len);
			const BOOL progress = cJSON_IsObject(msg) && cJSON_HasObjectItem(msg, "progress");
			if (progress && ++screen->progress <= WS_MAX_PROGRESS)
				waiting_screen_progress(screen, msg);
			cJSON_Delete(msg);
			if (screen->picker.gone)
			{
				rc = BROKER_ABANDONED;
				goto out;
			}
			if (screen->picker.state == WS_PICKER_SHOWN)
			{
				/* the broker waits for the choice: its timeout and some grace on top */
				timeout_s += (int)ws_seconds_left(screen) + WS_PICKER_GRACE_S;
			}
			else if (screen->picker.state == WS_PICKER_ANSWER && !ws_picker_answer(screen, fd))
			{
				WLog_ERR(TAG, "[%s] desktop choice not sent to the broker", sid);
				goto out;
			}
			if (!progress)
				break;
			if (screen->progress > WS_MAX_PROGRESS)
			{
				WLog_ERR(TAG, "[%s] more than %d progress messages from the broker", sid,
				         WS_MAX_PROGRESS);
				goto out;
			}
			memmove(buf, buf + len, used - len);
			used -= len;
			memset(buf + used, 0, len);
		}
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
	if (screen)
		ws_picker_end(screen); /* the proxy's input callbacks back */
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

/* ------------------------------------------------------------ desktop picker */

/* [broker] desktop_picker: after the second factor the broker sends a "choose_desktop"
 * prompt (protocol.py) and the user picks the desktop on the waiting screen: keys 1-9
 * (top row, or the numeric keypad with NumLock), Up/Down/Tab/Home/End and Enter, a click
 * (button 1 down and up on the same row; touch clients send it as one), Esc for the
 * broker's default. The answer goes back once, {"op": "choice", "desktop": name|null};
 * null (Esc, or the countdown ran out without a move) means the broker's default.
 *
 * The proxy's own input handlers drop input until its back-end connection is active
 * (pf_input.c), and module input filters do not run before that, so the module reads the
 * front connection itself: it polls the peer's event handles (socket and the transport's
 * reread event for TLS bytes already decrypted) and calls CheckFileDescriptor() with its
 * own input callbacks installed, restored afterwards (ws_picker_end()). This runs inside
 * the proxy's PostConnect; FreeRDP 3.32.2 would run PostConnect again for a PDU read
 * there, patches/freerdp/0007 handles it as input of the active connection
 * (freerdp_peer_in_post_connect()). Without that patch the login does not offer the
 * picker (ws_picker_possible()). Channel data read meanwhile goes the proxy's way (its
 * queue for the back-end, which has no limit), other PDUs as in the active state; the
 * module counts it (ws_picker_channel_data()) and abandons the login above
 * WS_PICKER_MAX_CHANNEL_BYTES. It is not dropped: the proxy's intercepted channels (rdpdr,
 * drdynvc) already talk to the client then (pf_server_setup_channels()), and a client's
 * answer there must reach the proxy; a well-behaved client sends little else before the
 * back-end's channels speak first.
 *
 * Input typed during the MFA wait is read first and dropped (ws_picker_drain()); a key
 * counts on its release, and only if it went down after that, a click only if both
 * halves came after it. Everything stays bounded: at most FASTRDP_PANEL_MAX_OPTIONS rows,
 * names of WS_PICKER_NAME bytes, WS_PICKER_MAX_TIMEOUT seconds; the module's own timeout
 * grows by the picker's (fastrdp_fetch_target()), so the choice never shortens the time
 * left for the session start. A failed read is a closed client: the login is abandoned. */

static BOOL ws_picker_possible(const waitingScreen* ws)
{
#if defined(FASTRDP_DESKTOP_PICKER)
	const proxyData* pdata = ws ? ws->pdata : NULL;
	freerdp_peer* peer = (pdata && pdata->ps) ? pdata->ps->peer : NULL;
	if (!ws || !ws->draw || !peer || !pdata->ps->input || !peer->GetEventHandles ||
	    !peer->CheckFileDescriptor)
		return FALSE;
	if (!freerdp_peer_in_post_connect || !freerdp_peer_in_post_connect(peer))
	{
		WLog_DBG(TAG, "[%s] no desktop picker: libfreerdp3 without patches/freerdp/0007",
		         pdata->session_id);
		return FALSE;
	}
	return TRUE;
#else
	(void)ws;
	return FALSE;
#endif
}

static waitingScreen* ws_of_input(rdpInput* input)
{
	const pServerContext* ps = input ? (const pServerContext*)input->context : NULL;
	proxyData* pdata = ps ? ps->pdata : NULL;
	if (!pdata || !fastrdp_mgr)
		return NULL;
	fastrdpSession* s = (fastrdpSession*)fastrdp_mgr->GetPluginData(fastrdp_mgr, PLUGIN_NAME, pdata);
	waitingScreen* ws = s ? (waitingScreen*)s->screen : NULL;
	return (ws && ws->picker.state == WS_PICKER_SHOWN) ? ws : NULL;
}

/* Sends picker row i (desktop coordinates). */
static void ws_picker_send_row(waitingScreen* ws, unsigned i)
{
	const fastrdpPanel* p = ws->panel;
	const fastrdpRect r = fastrdp_panel_option_rect(p, i);
	fastrdp_panel_draw_option(p, ws->img, p->rect.w * 4, i);
	const fastrdpRect d = { p->rect.x + r.x, p->rect.y + r.y, r.w, r.h };
	(void)ws_send(ws, d);
}

static void ws_picker_select(waitingScreen* ws, unsigned i)
{
	wsPicker* pk = &ws->picker;
	if (i >= pk->n || i == pk->sel)
		return;
	const unsigned old = pk->sel;
	pk->sel = i;
	pk->moved = TRUE;
	ws->panel->selected = i;
	ws_picker_send_row(ws, old);
	ws_picker_send_row(ws, i);
}

/* row: the chosen row, -1: the broker's default */
static void ws_picker_finish(waitingScreen* ws, int row, const char* how)
{
	wsPicker* pk = &ws->picker;
	if (pk->state != WS_PICKER_SHOWN)
		return;
	if (row >= 0)
		ws_picker_select(ws, (unsigned)row);
	pk->answer = row;
	pk->how = how;
	pk->state = WS_PICKER_ANSWER;
}

static void ws_picker_move(waitingScreen* ws, int delta)
{
	const wsPicker* pk = &ws->picker;
	ws_picker_select(ws, (unsigned)(((int)pk->sel + delta + (int)pk->n) % (int)pk->n));
}

static void ws_picker_digit(waitingScreen* ws, unsigned digit)
{
	if (digit >= 1 && digit <= ws->picker.n)
		ws_picker_finish(ws, (int)digit - 1, "key");
}

/* A key released after it went down while the picker showed: code | 0x100 if extended. */
static void ws_picker_key(waitingScreen* ws, unsigned key)
{
	/* numeric keypad 1-9 by scancode (0x47 = 7 ... 0x51 = 3), not extended */
	static const BYTE keypad[9] = { 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47, 0x48, 0x49 };
	const wsPicker* pk = &ws->picker;
	if (key >= 0x02 && key <= 0x0a) /* top row 1-9 */
	{
		ws_picker_digit(ws, key - 0x01);
		return;
	}
	if (pk->num_lock)
		for (unsigned d = 0; d < ARRAYSIZE(keypad); d++)
			if (key == keypad[d])
			{
				ws_picker_digit(ws, d + 1);
				return;
			}
	switch (key)
	{
		case 0x01: /* Esc */
			ws_picker_finish(ws, -1, "Esc");
			break;
		case 0x1c:  /* Enter */
		case 0x11c: /* keypad Enter */
			ws_picker_finish(ws, (int)pk->sel, "key");
			break;
		case 0x148: /* Up */
		case 0x48:  /* keypad 8 without NumLock */
			ws_picker_move(ws, -1);
			break;
		case 0x150: /* Down */
		case 0x50:  /* keypad 2 without NumLock */
		case 0x0f:  /* Tab */
			ws_picker_move(ws, 1);
			break;
		case 0x147: /* Home */
		case 0x47:
			ws_picker_select(ws, 0);
			break;
		case 0x14f: /* End */
		case 0x4f:
			ws_picker_select(ws, pk->n - 1);
			break;
		default:
			break;
	}
}

static BOOL ws_picker_keyboard(rdpInput* input, UINT16 flags, UINT8 code)
{
	waitingScreen* ws = ws_of_input(input);
	if (!ws || !ws->picker.armed)
		return TRUE;
	wsPicker* pk = &ws->picker;
	const unsigned key = code | ((flags & KBD_FLAGS_EXTENDED) ? 0x100u : 0u);
	const BYTE bit = (BYTE)(1u << (key % 8));
	if (!(flags & KBD_FLAGS_RELEASE))
		pk->keys[key / 8] |= bit;
	else if (pk->keys[key / 8] & bit)
	{
		pk->keys[key / 8] &= (BYTE)~bit;
		ws_picker_key(ws, key);
	}
	return TRUE;
}

/* Clients that type characters instead of scancodes: '1'-'9' and Enter */
static BOOL ws_picker_unicode(rdpInput* input, UINT16 flags, UINT16 code)
{
	waitingScreen* ws = ws_of_input(input);
	if (!ws || !ws->picker.armed)
		return TRUE;
	wsPicker* pk = &ws->picker;
	int n = -1;
	if (code >= '1' && code <= '9')
		n = code - '1';
	else if (code == '\r')
		n = 9;
	if (n < 0)
		return TRUE;
	const UINT16 bit = (UINT16)(1u << n);
	if (!(flags & KBD_FLAGS_RELEASE))
		pk->unicode |= bit;
	else if (pk->unicode & bit)
	{
		pk->unicode &= (UINT16)~bit;
		if (n == 9)
			ws_picker_finish(ws, (int)pk->sel, "key");
		else
			ws_picker_digit(ws, (unsigned)n + 1);
	}
	return TRUE;
}

static BOOL ws_picker_mouse(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	waitingScreen* ws = ws_of_input(input);
	if (!ws || !ws->picker.armed || !(flags & PTR_FLAGS_BUTTON1) || (flags & PTR_FLAGS_WHEEL))
		return TRUE;
	wsPicker* pk = &ws->picker;
	const int row = fastrdp_panel_hit(ws->panel, x, y);
	if (flags & PTR_FLAGS_DOWN)
	{
		pk->pressed_row = row;
		if (row >= 0)
			ws_picker_select(ws, (unsigned)row);
	}
	else
	{
		if (row >= 0 && row == pk->pressed_row)
			ws_picker_finish(ws, row, "click");
		pk->pressed_row = -1;
	}
	return TRUE;
}

static BOOL ws_picker_extended_mouse(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	WINPR_UNUSED(input);
	WINPR_UNUSED(flags);
	WINPR_UNUSED(x);
	WINPR_UNUSED(y);
	return TRUE; /* buttons 4 and 5 */
}

/* The keypad digits need NumLock; the proxy keeps the state for its back-end. */
static BOOL ws_picker_sync(rdpInput* input, UINT32 flags)
{
	const pServerContext* ps = input ? (const pServerContext*)input->context : NULL;
	proxyData* pdata = ps ? ps->pdata : NULL;
	fastrdpSession* s = (pdata && fastrdp_mgr)
	                        ? (fastrdpSession*)fastrdp_mgr->GetPluginData(fastrdp_mgr, PLUGIN_NAME, pdata)
	                        : NULL;
	waitingScreen* ws = s ? (waitingScreen*)s->screen : NULL;
	if (!ws)
		return TRUE;
	ws->picker.num_lock = (flags & KBD_SYNC_NUM_LOCK) != 0;
	return ws->picker.sync ? ws->picker.sync(input, flags) : TRUE;
}

/* The peer's ReceiveChannelData while the picker reads the front connection: hands the data
 * to the proxy's hook (its queue for the not yet existing back-end), counting it; FALSE
 * (the read fails, the login is abandoned) once WS_PICKER_MAX_CHANNEL_BYTES is exceeded. */
static BOOL ws_picker_channel_data(freerdp_peer* peer, UINT16 channelId, const BYTE* data,
                                   size_t size, UINT32 flags, size_t totalSize)
{
	const pServerContext* ps = peer ? (const pServerContext*)peer->context : NULL;
	proxyData* pdata = ps ? ps->pdata : NULL;
	fastrdpSession* s = (pdata && fastrdp_mgr)
	                        ? (fastrdpSession*)fastrdp_mgr->GetPluginData(fastrdp_mgr, PLUGIN_NAME, pdata)
	                        : NULL;
	waitingScreen* ws = s ? (waitingScreen*)s->screen : NULL;
	if (!ws || !ws->picker.receive_channel_data)
		return FALSE;
	wsPicker* pk = &ws->picker;
	pk->channel_bytes += size + WS_PICKER_CHUNK_COST;
	if (pk->channel_bytes > WS_PICKER_MAX_CHANNEL_BYTES)
	{
		if (!pk->channel_capped)
			WLog_WARN(TAG, "[%s] more than %d bytes of channel data during the desktop picker",
			          pdata->session_id, WS_PICKER_MAX_CHANNEL_BYTES);
		pk->channel_capped = TRUE;
		return FALSE;
	}
	return pk->receive_channel_data(peer, channelId, data, size, flags, totalSize);
}

/* Peer event handles to read (POLLIN) into fds; the proxy's abort event first. */
static nfds_t ws_picker_fds(const waitingScreen* ws, struct pollfd* fds, nfds_t max)
{
	nfds_t n = 0;
	proxyData* pdata = ws->pdata;
	if (pdata->abort_event && n < max)
	{
		const int fd = GetEventFileDescriptor(pdata->abort_event);
		if (fd >= 0)
			fds[n++] = (struct pollfd){ .fd = fd, .events = POLLIN };
	}
	freerdp_peer* peer = pdata->ps->peer;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
	const DWORD count = peer->GetEventHandles(peer, handles, ARRAYSIZE(handles));
	for (DWORD i = 0; i < count && n < max; i++)
	{
		const int fd = GetEventFileDescriptor(handles[i]);
		if (fd >= 0)
			fds[n++] = (struct pollfd){ .fd = fd, .events = POLLIN };
	}
	return n;
}

/* Reads what the front client sent (input callbacks above); FALSE if the connection failed. */
static BOOL ws_picker_read(waitingScreen* ws)
{
	freerdp_peer* peer = ws->pdata->ps->peer;
	if (peer->CheckFileDescriptor(peer))
		return TRUE;
	ws->picker.gone = TRUE;
	WLog_WARN(TAG, "[%s] front connection closed during the desktop picker",
	          ws->pdata->session_id);
	return FALSE;
}

/* Reads and drops what the client sent before the picker showed (keys typed during the
 * MFA wait), until nothing more is waiting or WS_PICKER_DRAIN_MS passed. */
static BOOL ws_picker_drain(waitingScreen* ws)
{
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	end.tv_nsec += WS_PICKER_DRAIN_MS * 1000000L;
	end.tv_sec += end.tv_nsec / 1000000000L;
	end.tv_nsec %= 1000000000L;
	while (ws_ms_until(&end) > 0)
	{
		struct pollfd fds[MAX_ABORT_FDS];
		const nfds_t n = ws_picker_fds(ws, fds, ARRAYSIZE(fds));
		const int pr = poll(fds, n, 0);
		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0)
			break;
		if (!ws_picker_read(ws))
			return FALSE;
	}
	return TRUE;
}

/* The broker's {"progress": "choose_desktop", ...}: shows the rows, installs the input
 * callbacks. A prompt the module cannot show (no picker offered, malformed, the desktop
 * too small) is answered at once with the default. */
static void ws_picker_start(waitingScreen* ws, const cJSON* msg)
{
	wsPicker* pk = &ws->picker;
	const char* sid = ws->pdata->session_id;
	if (!pk->offered || pk->asked)
	{
		WLog_WARN(TAG, "[%s] desktop picker prompt from the broker ignored (%s)", sid,
		          pk->asked ? "a second one" : "not offered");
		return;
	}
	pk->asked = TRUE;
	pk->answer = -1;
	pk->how = "not shown";
	pk->pressed_row = -1;
	pk->state = WS_PICKER_ANSWER; /* until the rows are on the screen */

	const char* labels[FASTRDP_PANEL_MAX_OPTIONS] = { 0 };
	const char* def = json_str(msg, "default");
	const cJSON* it = NULL;
	cJSON_ArrayForEach(it, cJSON_GetObjectItemCaseSensitive(msg, "options"))
	{
		const char* name = json_str(it, "name");
		const char* label = json_str(it, "label");
		if (pk->n == FASTRDP_PANEL_MAX_OPTIONS || !name || !*name || strlen(name) > WS_PICKER_NAME)
			break;
		strcpy(pk->names[pk->n], name);
		labels[pk->n] = label ? label : pk->names[pk->n];
		if (def && strcmp(def, name) == 0)
			pk->def = pk->n;
		pk->n++;
	}
	const cJSON* t = cJSON_GetObjectItemCaseSensitive(msg, "timeout_s");
	if (pk->n < 2 || !cJSON_IsNumber(t) || t->valuedouble < 1 ||
	    t->valuedouble > WS_PICKER_MAX_TIMEOUT || !ws->draw)
	{
		WLog_WARN(TAG, "[%s] desktop picker not shown (%s): default desktop", sid,
		          !ws->draw ? "no waiting screen" : "malformed prompt");
		return;
	}
	pk->sel = pk->def;

	const char* text[FASTRDP_PANEL_MAX_LINES] = { 0 };
	unsigned nlines = 0;
	cJSON_ArrayForEach(it, cJSON_GetObjectItemCaseSensitive(msg, "lines"))
	{
		if (nlines == FASTRDP_PANEL_MAX_LINES)
			break;
		text[nlines++] = cJSON_GetStringValue(it);
	}
	fastrdp_panel_set_text(ws->panel, text, nlines);
	(void)fastrdp_panel_set_qr(ws->panel, NULL, 0);
	fastrdp_panel_set_options(ws->panel, labels, pk->n, pk->sel, json_str(msg, "hint"));
	const char* label = json_str(msg, "countdown");
	fastrdp_panel_set_countdown(ws->panel, label ? label : "");
	fastrdp_panel_set_countdown_total(ws->panel, (unsigned)t->valuedouble);
	ws->countdown = TRUE;
	clock_gettime(CLOCK_MONOTONIC, &ws->deadline);
	ws->deadline.tv_sec += (time_t)t->valuedouble;
	ws_redraw(ws, FALSE);
	if (!ws->draw)
	{
		WLog_WARN(TAG, "[%s] desktop picker not shown: default desktop", sid);
		return;
	}

	/* the client's own pointer: nothing set one yet */
	rdpUpdate* update = ws->pdata->ps->update;
	const POINTER_SYSTEM_UPDATE arrow = { .type = SYSPTR_DEFAULT };
	if (update && update->pointer && update->pointer->PointerSystem &&
	    !update->pointer->PointerSystem(ws->pdata->ps, &arrow))
		WLog_DBG(TAG, "[%s] default pointer not sent", sid);

	rdpInput* input = ws->pdata->ps->input;
	pk->sync = input->SynchronizeEvent;
	pk->keyboard = input->KeyboardEvent;
	pk->unicode_keyboard = input->UnicodeKeyboardEvent;
	pk->mouse = input->MouseEvent;
	pk->extended_mouse = input->ExtendedMouseEvent;
	input->SynchronizeEvent = ws_picker_sync;
	input->KeyboardEvent = ws_picker_keyboard;
	input->UnicodeKeyboardEvent = ws_picker_unicode;
	input->MouseEvent = ws_picker_mouse;
	input->ExtendedMouseEvent = ws_picker_extended_mouse;
	freerdp_peer* peer = ws->pdata->ps->peer;
	if (peer->ReceiveChannelData)
	{
		pk->receive_channel_data = peer->ReceiveChannelData;
		peer->ReceiveChannelData = ws_picker_channel_data;
	}
	pk->state = WS_PICKER_SHOWN;
	WLog_INFO(TAG, "[%s] desktop picker: %u desktops, default %s, %d s", sid, pk->n,
	          pk->names[pk->def], (int)t->valuedouble);
	if (ws_picker_drain(ws))
		pk->armed = TRUE;
}

/* Restores the proxy's input callbacks; the panel goes back to the generic text until the
 * broker's next message. */
static void ws_picker_end(waitingScreen* ws)
{
	wsPicker* pk = &ws->picker;
	if (pk->sync || pk->keyboard)
	{
		rdpInput* input = ws->pdata->ps->input;
		if (input->SynchronizeEvent == ws_picker_sync)
			input->SynchronizeEvent = pk->sync;
		if (input->KeyboardEvent == ws_picker_keyboard)
			input->KeyboardEvent = pk->keyboard;
		if (input->UnicodeKeyboardEvent == ws_picker_unicode)
			input->UnicodeKeyboardEvent = pk->unicode_keyboard;
		if (input->MouseEvent == ws_picker_mouse)
			input->MouseEvent = pk->mouse;
		if (input->ExtendedMouseEvent == ws_picker_extended_mouse)
			input->ExtendedMouseEvent = pk->extended_mouse;
		pk->sync = NULL;
		pk->keyboard = NULL;
	}
	if (pk->receive_channel_data)
	{
		freerdp_peer* peer = ws->pdata->ps->peer;
		if (peer->ReceiveChannelData == ws_picker_channel_data)
			peer->ReceiveChannelData = pk->receive_channel_data;
		pk->receive_channel_data = NULL;
	}
	if (pk->state == WS_PICKER_OFF)
		return;
	pk->state = WS_PICKER_OFF;
	if (!ws->draw || ws->panel->nopt == 0)
		return;
	static const char* const generic[] = { WS_GENERIC_TEXT };
	fastrdp_panel_set_options(ws->panel, NULL, 0, 0, NULL);
	fastrdp_panel_set_text(ws->panel, generic, ARRAYSIZE(generic));
	fastrdp_panel_set_countdown(ws->panel, NULL);
	ws->countdown = FALSE;
	ws_redraw(ws, FALSE);
}

/* Once the countdown ran out: the selected row if the user moved it, else the default. */
static void ws_picker_check_timeout(waitingScreen* ws)
{
	if (ws && ws->picker.state == WS_PICKER_SHOWN && ws_ms_until(&ws->deadline) <= 0)
		ws_picker_finish(ws, ws->picker.moved ? (int)ws->picker.sel : -1, "timeout");
}

/* Milliseconds until the picker's countdown ends; -1 without a picker. */
static int ws_picker_next_ms(const waitingScreen* ws)
{
	if (!ws || ws->picker.state != WS_PICKER_SHOWN)
		return -1;
	const long ms = ws_ms_until(&ws->deadline);
	return ms <= 0 ? 0 : (int)MIN(ms, INT32_MAX);
}

/* {"op": "choice", "desktop": name|null} to the broker; the picker ends. */
static BOOL ws_picker_answer(waitingScreen* ws, int fd)
{
	wsPicker* pk = &ws->picker;
	const char* name = pk->answer >= 0 ? pk->names[pk->answer] : NULL;
	WLog_INFO(TAG, "[%s] desktop picker: %s (%s)", ws->pdata->session_id,
	          name ? name : "default desktop", pk->how);
	ws_picker_end(ws);
	cJSON* msg = cJSON_CreateObject();
	if (!msg)
		return FALSE;
	cJSON_AddStringToObject(msg, "op", "choice");
	add_str(msg, "desktop", name);
	char* text = cJSON_PrintUnformatted(msg);
	cJSON_Delete(msg);
	const BOOL ok = text && write_all(fd, text, strlen(text)) && write_all(fd, "\n", 1);
	free(text);
	return ok;
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
		cJSON_Delete(s->kdc_evidence);
		s->kdc_evidence = kdc_evidence(pdata);

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
		char evidence[256] = "not available";
		if (s->kdc_evidence)
			kdc_evidence_summary(s->kdc_evidence, evidence, sizeof(evidence));
		WLog_INFO(TAG, "[%s] NLA logon: principal %s, rdp user %s%s; KDC evidence: %s",
		          pdata->session_id, s->principal, s->user ? s->user : "(none)",
		          s->smartcard      ? " (smartcard)"
		          : s->remote_guard ? " (Remote Credential Guard, identity only)"
		                            : "",
		          evidence);
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
	waitingScreen* screen = NULL;
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
	/* Kerberos NLA only (s->kdc_evidence stays NULL for TLS): absent if FreeRDP cannot tell */
	if (s->nla && s->kdc_evidence)
		cJSON_AddItemToObject(req, "kdc_evidence", cJSON_Duplicate(s->kdc_evidence, 1));
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

	/* [FastRDP] WaitingScreen/StatusInfo: the broker may send progress lines first. The
	 * keyboard layout lets it pick the language of its texts. With the panel on the
	 * screen and patches/freerdp/0007, the user can also pick the desktop there
	 * ([broker] desktop_picker). */
	screen = waiting_screen_new(pdata);
	if (screen)
	{
		cJSON_AddNumberToObject(req, "progress", 1);
		cJSON_AddNumberToObject(req, "keyboard_layout",
		                        freerdp_settings_get_uint32(front, FreeRDP_KeyboardLayout));
		screen->picker.offered = ws_picker_possible(screen);
		if (screen->picker.offered)
			cJSON_AddNumberToObject(req, "picker", 1);
		s->screen = screen;
	}

	long timeout = strtol(config_str(pdata, "Timeout", "180"), NULL, 10);
	if (timeout <= 0 || timeout > 600)
		timeout = DEFAULT_TIMEOUT_S;
	const brokerCallResult called =
	    broker_call(config_str(pdata, "BrokerSocket", DEFAULT_SOCKET), req, (int)timeout, pdata,
	                screen, &reply);

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
	if (s)
		s->screen = NULL;
	/* a granted login: no trace of the panel before the back-end's first frame */
	waiting_screen_free(screen, rc);
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
			                  NULL, &reply);
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
