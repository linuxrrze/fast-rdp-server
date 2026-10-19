/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/*
 * rdpbench - headless RDP benchmark client (FreeRDP 3).
 *
 * Connects with the graphics pipeline, decodes like a real client (software GDI) and
 * reports per second: frames, codecs, GFX payload bandwidth, client decode time.
 * --no-decode skips client decoding to measure what server + network deliver.
 * Optional input-to-frame latency: sends a key press every 500 ms and measures the
 * time until the next frame that carries a surface update (pair with
 * `perfload latency`, which repaints a square on every key press).
 *
 *   rdpbench --host H [--port 3389] --user U --password P [--domain D] [--sec tls|nla]
 *            [--seconds 30] [--width 1920 --height 1080] [--shell fastrdp:gnome]
 *            [--no-h264] [--no-avc444] [--latency] [--json out.json]
 *
 * The last line of stdout is a JSON summary.
 */
#include <dirent.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <freerdp/channels/rdpgfx.h>
#include <freerdp/client.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/rdpgfx.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/gdi/gfx.h>
#include <freerdp/scancode.h>
#include <freerdp/settings.h>

#define MAX_LAT 4096

typedef struct
{
	rdpClientContext common;
	/* wrapped GFX callbacks */
	pcRdpgfxEndFrame orig_end_frame;
	pcRdpgfxSurfaceCommand orig_surface_command;
	/* counters (current second / totals) */
	unsigned long frames, frames_total;
	unsigned long long payload, payload_total;
	double decode_s, decode_total_s;
	unsigned long codec_cmds[RDPGFX_CODECID_MAX + 1];
	BOOL frame_had_surface;
	BOOL no_decode;
	/* latency */
	double key_sent_at;
	double lat[MAX_LAT];
	size_t nlat;
} benchContext;

/* One connection per process: the GFX callbacks find their state here. */
static benchContext* g_bench;

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char* codec_name(UINT32 id)
{
	switch (id)
	{
		case RDPGFX_CODECID_UNCOMPRESSED: return "uncompressed";
		case RDPGFX_CODECID_CAVIDEO: return "rfx";
		case RDPGFX_CODECID_CLEARCODEC: return "clearcodec";
		case RDPGFX_CODECID_CAPROGRESSIVE: return "progressive";
		case RDPGFX_CODECID_PLANAR: return "planar";
		case RDPGFX_CODECID_AVC420: return "avc420";
		case RDPGFX_CODECID_ALPHA: return "alpha";
		case RDPGFX_CODECID_CAPROGRESSIVE_V2: return "progressive2";
		case RDPGFX_CODECID_AVC444: return "avc444";
		case RDPGFX_CODECID_AVC444v2: return "avc444v2";
		default: return "other";
	}
}

/* Bytes received on all TCP sockets of this process (kernel counter, includes TLS). */
static unsigned long long tcp_bytes_received(void)
{
	unsigned long long total = 0;
	DIR* d = opendir("/proc/self/fd");
	if (!d)
		return 0;
	struct dirent* de;
	while ((de = readdir(d)) != NULL)
	{
		const int fd = atoi(de->d_name);
		struct tcp_info ti;
		socklen_t len = sizeof(ti);
		if (fd > 2 && getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0 &&
		    len >= offsetof(struct tcp_info, tcpi_bytes_received) + sizeof(ti.tcpi_bytes_received))
			total += ti.tcpi_bytes_received;
	}
	closedir(d);
	return total;
}

static UINT bench_surface_command(RdpgfxClientContext* gfx, const RDPGFX_SURFACE_COMMAND* cmd)
{
	benchContext* b = g_bench;
	if (b->no_decode)
	{
		if (cmd->codecId <= RDPGFX_CODECID_MAX)
			b->codec_cmds[cmd->codecId]++;
		b->payload += cmd->length;
		b->frame_had_surface = TRUE;
		return CHANNEL_RC_OK; /* frames are still acknowledged by the channel */
	}
	if (cmd->codecId <= RDPGFX_CODECID_MAX)
		b->codec_cmds[cmd->codecId]++;
	b->payload += cmd->length;
	b->frame_had_surface = TRUE;
	const double t0 = now();
	const UINT rc = b->orig_surface_command(gfx, cmd);
	b->decode_s += now() - t0;
	return rc;
}

static UINT bench_end_frame(RdpgfxClientContext* gfx, const RDPGFX_END_FRAME_PDU* end)
{
	benchContext* b = g_bench;
	b->frames++;
	if (b->key_sent_at > 0 && b->frame_had_surface && b->nlat < MAX_LAT)
	{
		b->lat[b->nlat++] = (now() - b->key_sent_at) * 1000.0;
		b->key_sent_at = 0;
	}
	b->frame_had_surface = FALSE;
	return b->orig_end_frame(gfx, end);
}

static void on_channel_connected(void* ctx, const ChannelConnectedEventArgs* e)
{
	benchContext* b = (benchContext*)ctx;
	freerdp_client_OnChannelConnectedEventHandler(ctx, e);
	if (strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME) == 0)
	{
		RdpgfxClientContext* gfx = (RdpgfxClientContext*)e->pInterface;
		b->orig_end_frame = gfx->EndFrame;
		b->orig_surface_command = gfx->SurfaceCommand;
		gfx->EndFrame = bench_end_frame;
		gfx->SurfaceCommand = bench_surface_command;
		fprintf(stderr, "rdpbench: graphics pipeline connected\n");
	}
}

static void on_channel_disconnected(void* ctx, const ChannelDisconnectedEventArgs* e)
{
	freerdp_client_OnChannelDisconnectedEventHandler(ctx, e);
}

static BOOL bench_pre_connect(freerdp* instance)
{
	rdpContext* ctx = instance->context;
	if (PubSub_SubscribeChannelConnected(ctx->pubSub, on_channel_connected) < 0 ||
	    PubSub_SubscribeChannelDisconnected(ctx->pubSub, on_channel_disconnected) < 0)
		return FALSE;
	return TRUE;
}

/* Called on GFX ResetGraphics / server resize; gdi requires a client handler. */
static BOOL bench_desktop_resize(rdpContext* ctx)
{
	return gdi_resize(ctx->gdi, freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopWidth),
	                  freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopHeight));
}

static BOOL bench_post_connect(freerdp* instance)
{
	if (!gdi_init(instance, PIXEL_FORMAT_BGRX32))
		return FALSE;
	instance->context->update->DesktopResize = bench_desktop_resize;
	return TRUE;
}

static void bench_post_disconnect(freerdp* instance)
{
	gdi_free(instance);
}

static BOOL bench_client_new(freerdp* instance, rdpContext* context)
{
	(void)context;
	instance->PreConnect = bench_pre_connect;
	instance->PostConnect = bench_post_connect;
	instance->PostDisconnect = bench_post_disconnect;
	instance->LoadChannels = freerdp_client_load_channels;
	return TRUE;
}

static int cmp_double(const void* a, const void* b)
{
	const double x = *(const double*)a, y = *(const double*)b;
	return (x > y) - (x < y);
}

static double percentile(double* v, size_t n, double p)
{
	if (n == 0)
		return -1;
	qsort(v, n, sizeof(double), cmp_double);
	size_t i = (size_t)(p * (double)(n - 1) + 0.5);
	return v[i];
}

static void usage(void)
{
	fprintf(stderr, "usage: rdpbench --host H [--port P] --user U --password P [--domain D]\n"
	                "                [--sec tls|nla] [--seconds N] [--width W --height H]\n"
	                "                [--shell S] [--no-h264] [--no-avc444] [--latency] [--json F]\n"
	                "                [--no-decode]   (count/ack frames without decoding)\n");
}

int main(int argc, char** argv)
{
	const char *host = NULL, *user = NULL, *pass = NULL, *domain = NULL, *sec = "nla",
	           *shell = NULL, *json_path = NULL;
	int port = 3389, seconds = 30, width = 1920, height = 1080;
	BOOL h264 = TRUE, avc444 = TRUE, latency = FALSE, no_decode = FALSE;
	static const struct option opts[] = {
		{ "host", 1, 0, 'H' },     { "port", 1, 0, 'P' },    { "user", 1, 0, 'u' },
		{ "password", 1, 0, 'p' }, { "domain", 1, 0, 'd' },  { "sec", 1, 0, 's' },
		{ "seconds", 1, 0, 't' },  { "width", 1, 0, 'W' },   { "height", 1, 0, 'E' },
		{ "shell", 1, 0, 'S' },    { "no-h264", 0, 0, 'n' }, { "no-avc444", 0, 0, 'a' },
		{ "latency", 0, 0, 'l' },  { "json", 1, 0, 'j' },    { "no-decode", 0, 0, 'D' },
		{ 0, 0, 0, 0 }
	};
	int c;
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1)
	{
		switch (c)
		{
			case 'H': host = optarg; break;
			case 'P': port = atoi(optarg); break;
			case 'u': user = optarg; break;
			case 'p': pass = optarg; break;
			case 'd': domain = optarg; break;
			case 's': sec = optarg; break;
			case 't': seconds = atoi(optarg); break;
			case 'W': width = atoi(optarg); break;
			case 'E': height = atoi(optarg); break;
			case 'S': shell = optarg; break;
			case 'n': h264 = FALSE; break;
			case 'a': avc444 = FALSE; break;
			case 'l': latency = TRUE; break;
			case 'j': json_path = optarg; break;
			case 'D': no_decode = TRUE; break;
			default: usage(); return 2;
		}
	}
	if (!host || !user || !pass || seconds <= 0)
	{
		usage();
		return 2;
	}

	RDP_CLIENT_ENTRY_POINTS ep = { 0 };
	ep.Version = RDP_CLIENT_INTERFACE_VERSION;
	ep.Size = sizeof(ep);
	ep.ContextSize = sizeof(benchContext);
	ep.ClientNew = bench_client_new;
	rdpContext* ctx = freerdp_client_context_new(&ep);
	if (!ctx)
		return 3;
	benchContext* b = (benchContext*)ctx;
	g_bench = b;
	b->no_decode = no_decode;
	rdpSettings* s = ctx->settings;
	const BOOL nla = strcmp(sec, "nla") == 0;
	if (!freerdp_settings_set_string(s, FreeRDP_ServerHostname, host) ||
	    !freerdp_settings_set_uint32(s, FreeRDP_ServerPort, (UINT32)port) ||
	    !freerdp_settings_set_string(s, FreeRDP_Username, user) ||
	    !freerdp_settings_set_string(s, FreeRDP_Password, pass) ||
	    (domain && !freerdp_settings_set_string(s, FreeRDP_Domain, domain)) ||
	    (shell && !freerdp_settings_set_string(s, FreeRDP_AlternateShell, shell)) ||
	    !freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, nla) ||
	    !freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, !nla) ||
	    !freerdp_settings_set_bool(s, FreeRDP_RdpSecurity, FALSE) ||
	    !freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE) ||
	    !freerdp_settings_set_bool(s, FreeRDP_AutoLogonEnabled, TRUE) ||
	    !freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth, (UINT32)width) ||
	    !freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, (UINT32)height) ||
	    !freerdp_settings_set_uint32(s, FreeRDP_ColorDepth, 32) ||
	    !freerdp_settings_set_bool(s, FreeRDP_SoftwareGdi, TRUE) ||
	    !freerdp_settings_set_bool(s, FreeRDP_SupportGraphicsPipeline, TRUE) ||
	    !freerdp_settings_set_bool(s, FreeRDP_GfxH264, h264) ||
	    !freerdp_settings_set_bool(s, FreeRDP_GfxAVC444, h264 && avc444) ||
	    !freerdp_settings_set_bool(s, FreeRDP_GfxAVC444v2, h264 && avc444) ||
	    !freerdp_settings_set_bool(s, FreeRDP_GfxProgressive, TRUE) ||
	    !freerdp_settings_set_bool(s, FreeRDP_RemoteFxCodec, TRUE) ||
	    !freerdp_set_connection_type(s, CONNECTION_TYPE_LAN))
		return 3;

	const double t_connect = now();
	if (!freerdp_connect(ctx->instance))
	{
		fprintf(stderr, "rdpbench: connect failed: %s\n",
		        freerdp_get_last_error_string(freerdp_get_last_error(ctx)));
		return 4;
	}
	const double connect_ms = (now() - t_connect) * 1000.0;
	fprintf(stderr, "rdpbench: connected in %.0f ms\n", connect_ms);

	const double t_start = now();
	double t_tick = t_start + 1.0, t_key = t_start + 1.0;
	unsigned long long wire0 = tcp_bytes_received(), wire_tick = wire0;
	unsigned long peak_fps = 0;
	printf("%5s %6s %10s %10s %12s %s\n", "t[s]", "fps", "gfx Mbit/s", "wire Mbit/s",
	       "decode ms/f", "codecs");
	while (!freerdp_shall_disconnect_context(ctx) && now() - t_start < seconds)
	{
		HANDLE h[MAXIMUM_WAIT_OBJECTS];
		DWORD n = freerdp_get_event_handles(ctx, h, ARRAYSIZE(h));
		if (n == 0)
			break;
		(void)WaitForMultipleObjects(n, h, FALSE, 20);
		if (!freerdp_check_event_handles(ctx))
			break;

		const double t = now();
		if (latency && t >= t_key && b->key_sent_at == 0)
		{
			(void)freerdp_input_send_keyboard_event_ex(ctx->input, TRUE, FALSE, RDP_SCANCODE_KEY_A);
			(void)freerdp_input_send_keyboard_event_ex(ctx->input, FALSE, FALSE, RDP_SCANCODE_KEY_A);
			b->key_sent_at = t;
			t_key = t + 0.5;
		}
		if (latency && b->key_sent_at > 0 && t - b->key_sent_at > 2.0)
			b->key_sent_at = 0; /* no visible reaction: drop the sample */
		if (t >= t_tick)
		{
			const unsigned long long rc = tcp_bytes_received();
			char codecs[256] = "";
			for (UINT32 i = 0; i <= RDPGFX_CODECID_MAX; i++)
				if (b->codec_cmds[i])
				{
					char part[48];
					(void)snprintf(part, sizeof(part), "%s%s:%lu", codecs[0] ? " " : "",
					               codec_name(i), b->codec_cmds[i]);
					strncat(codecs, part, sizeof(codecs) - strlen(codecs) - 1);
				}
			printf("%5.0f %6lu %10.2f %10.2f %12.2f %s\n", t - t_start, b->frames,
			       (double)b->payload * 8 / 1e6, (double)(rc - wire_tick) * 8 / 1e6,
			       b->frames ? b->decode_s * 1000 / (double)b->frames : 0.0, codecs);
			fflush(stdout);
			if (b->frames > peak_fps)
				peak_fps = b->frames;
			b->frames_total += b->frames;
			b->payload_total += b->payload;
			b->decode_total_s += b->decode_s;
			b->frames = 0;
			b->payload = 0;
			b->decode_s = 0;
			wire_tick = rc;
			t_tick += 1.0;
		}
	}
	const double dur = now() - t_start;
	const unsigned long long wire = tcp_bytes_received() - wire0;
	b->frames_total += b->frames;
	b->payload_total += b->payload;
	b->decode_total_s += b->decode_s;

	unsigned long main_codec_n = 0;
	UINT32 main_codec = 0;
	for (UINT32 i = 0; i <= RDPGFX_CODECID_MAX; i++)
		if (b->codec_cmds[i] > main_codec_n)
		{
			main_codec_n = b->codec_cmds[i];
			main_codec = i;
		}
	char json[1024];
	(void)snprintf(
	    json, sizeof(json),
	    "{\"host\":\"%s\",\"port\":%d,\"seconds\":%.1f,\"connect_ms\":%.0f,\"frames\":%lu,"
	    "\"fps_avg\":%.1f,\"fps_peak\":%lu,\"gfx_mbit_avg\":%.2f,\"wire_mbit_avg\":%.2f,"
	    "\"decode_ms_per_frame\":%.2f,\"main_codec\":\"%s\",\"h264_requested\":%s,\"decoded\":%s,"
	    "\"latency_samples\":%zu,\"latency_ms_p50\":%.1f,\"latency_ms_p95\":%.1f}",
	    host, port, dur, connect_ms, b->frames_total, (double)b->frames_total / dur, peak_fps,
	    (double)b->payload_total * 8 / 1e6 / dur, (double)wire * 8 / 1e6 / dur,
	    b->frames_total ? b->decode_total_s * 1000 / (double)b->frames_total : 0.0,
	    main_codec_n ? codec_name(main_codec) : "none", h264 ? "true" : "false",
	    no_decode ? "false" : "true", b->nlat,
	    percentile(b->lat, b->nlat, 0.5), percentile(b->lat, b->nlat, 0.95));
	printf("%s\n", json);
	if (json_path)
	{
		FILE* f = fopen(json_path, "w");
		if (f)
		{
			fprintf(f, "%s\n", json);
			fclose(f);
		}
	}
	freerdp_disconnect(ctx->instance);
	freerdp_client_context_free(ctx);
	return 0;
}
