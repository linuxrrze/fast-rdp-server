/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/*
 * Functional test for xrdp_encoder_ffmpeg.c (fastrdp xrdp patch).
 *
 * Feeds NV12 frames exactly as xorgxrdp delivers them (Y plane, then interleaved
 * UV, stride = twidth) through the real encoder entry points, decodes every
 * output with libavcodec's H.264 decoder and checks:
 *   - one decodable access unit per input frame (zero latency, no B-frames)
 *   - SPS + IDR at the start and after a resize (flags 1 / 3)
 *   - picture quality (Y PSNR) incl. a size that is not macroblock aligned
 *   - partial updates: only damaged rectangles change
 *   - an unavailable hardware encoder fails cleanly
 *   - MS-RDPEGFX 2.2.4.4 / MF decoder limits: no B-frames, no IDR inside the GOP,
 *     Baseline/Main profile, full-range BT.709 VUI (3.3.8.3.1), full-range black
 *   - lost output (buffer too small) is followed by SPS + IDR
 * Build/run: see run_test.sh. The encoder name comes from argv[1] (default libx264).
 */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>

#include "log.h"
#include "xrdp_encoder_ffmpeg.h"

static int g_fail = 0;
#define CHECK(cond, ...) do { if (cond) { printf("ok   "); } else { printf("FAIL "); g_fail = 1; } \
                              printf(__VA_ARGS__); printf("\n"); } while (0)

/* moving gradient + block, NV12, stride == width */
static void make_frame(unsigned char *buf, int w, int h, int t)
{
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++)
            buf[y * w + x] = (unsigned char)(16 + ((x + y + 3 * t) % 200));
    for (int y = 100; y < 180 && y < h; y++)
        for (int x = 100 + 4 * t; x < 260 + 4 * t && x < w; x++)
            buf[y * w + x] = 235;
    unsigned char *uv = buf + w * h;
    for (int y = 0; y < h / 2; y++)
        for (int x = 0; x < w; x += 2)
        {
            uv[y * w + x] = (unsigned char)(128 + ((x / 2 + t) % 40) - 20);
            uv[y * w + x + 1] = (unsigned char)(128 - ((y + t) % 40) + 20);
        }
}

static double psnr_y(const unsigned char *a, int as, const unsigned char *b, int bs,
                     int x0, int y0, int w, int h)
{
    double mse = 0;
    for (int y = y0; y < y0 + h; y++)
        for (int x = x0; x < x0 + w; x++)
        {
            double d = (double)a[y * as + x] - (double)b[y * bs + x];
            mse += d * d;
        }
    mse /= (double)w * h;
    return mse == 0 ? 99.0 : 10 * log10(255.0 * 255.0 / mse);
}

static int has_nal(const unsigned char *p, int n, int type)
{
    for (int i = 0; i + 3 < n; i++)
        if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 1 && (p[i + 3] & 0x1f) == type)
            return 1;
    return 0;
}

struct dec { AVCodecContext *ctx; AVPacket *pkt; AVFrame *frm; };

static int decode(struct dec *d, const unsigned char *data, int n)
{
    av_packet_unref(d->pkt);
    d->pkt->data = (uint8_t *)data;
    d->pkt->size = n;
    if (avcodec_send_packet(d->ctx, d->pkt) < 0)
        return -1;
    return avcodec_receive_frame(d->ctx, d->frm); /* 0 = a picture came out now */
}

int main(int argc, char **argv)
{
    const char *enc_name = argc > 1 ? argv[1] : "libx264";
    /* argv[2] == "null": create() must fail (encoder unusable, fallback disabled) */
    int expect_null = argc > 2 && strcmp(argv[2], "null") == 0;
    struct log_config *lc = log_config_init_for_console(LOG_LEVEL_WARNING, NULL);
    log_start_from_param(lc);
    log_config_free(lc);

    void *h = xrdp_encoder_ffmpeg_create();
    if (expect_null)
    {
        CHECK(h == NULL, "%s unusable and no fallback: create() returns NULL", enc_name);
        return g_fail;
    }
    CHECK(h != NULL, "encoder %s created (or its fallback)", enc_name);
    if (h == NULL)
        return 1;

    struct dec d;
    d.ctx = avcodec_alloc_context3(avcodec_find_decoder(AV_CODEC_ID_H264));
    d.ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    avcodec_open2(d.ctx, avcodec_find_decoder(AV_CODEC_ID_H264), NULL);
    d.pkt = av_packet_alloc();
    d.frm = av_frame_alloc();

    const int W = 1366, H = 768;          /* not macroblock aligned: coded 1376x768 */
    unsigned char *src = malloc((size_t)W * H * 3 / 2);
    char *out = malloc(4 << 20);
    short full[4] = { 0, 0, W, H };
    int decoded = 0, frames = 30, flags = 0, idr_first = 0, sps_first = 0;
    int b_frames = 0, idr_later = 0;
    double min_psnr = 99;

    for (int t = 0; t < frames; t++)
    {
        int n = 4 << 20;
        make_frame(src, W, H, t);
        int rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W, H, W, H, 0, (char *)src,
                                            full, 1, out, &n, 0, &flags);
        if (rv != 0) { CHECK(0, "frame %d encode rv=%d", t, rv); break; }
        if (t == 0)
        {
            CHECK(flags == 1, "first frame reports a new encoder (flags=%d)", flags);
            sps_first = has_nal((unsigned char *)out, n, 7);
            idr_first = has_nal((unsigned char *)out, n, 5);
        }
        else if (has_nal((unsigned char *)out, n, 5))
            idr_later++;
        if (decode(&d, (unsigned char *)out, n) == 0)
        {
            decoded++;
            if (d.frm->pict_type == AV_PICTURE_TYPE_B)
                b_frames++;
            double p = psnr_y(src, W, d.frm->data[0], d.frm->linesize[0], 0, 0, W, H);
            if (p < min_psnr) min_psnr = p;
        }
    }
    CHECK(sps_first && idr_first, "first access unit carries SPS and IDR");
    CHECK(decoded == frames, "every input produced a decodable picture immediately (%d/%d)",
          decoded, frames);
    CHECK(d.frm->width >= W && d.frm->height >= H && d.frm->width <= W + 15,
          "coded size %dx%d covers %dx%d", d.frm->width, d.frm->height, W, H);
    CHECK(min_psnr > 30.0, "luma PSNR >= 30 dB (min %.1f dB)", min_psnr);
    CHECK(b_frames == 0 && idr_later == 0, "no B-frames (%d), no IDR inside the GOP (%d)",
          b_frames, idr_later);
    /* Baseline (66), Constrained Baseline (66|512) or Main (77): what the patch asks for
     * (profile=main; x264 ultrafast signals Constrained Baseline) and what every RDP
     * client decoder accepts. High (100) would also work with mstsc, but is not intended. */
    const int prof = d.ctx->profile & ~AV_PROFILE_H264_CONSTRAINED;
    CHECK(prof == AV_PROFILE_H264_BASELINE || prof == AV_PROFILE_H264_MAIN,
          "profile_idc %d is Baseline or Main, level_idc %d", prof, d.ctx->level);
    CHECK(d.frm->color_range == AVCOL_RANGE_JPEG && d.frm->colorspace == AVCOL_SPC_BT709,
          "VUI signals full-range BT.709 like the xorgxrdp input (range %d, matrix %d)",
          (int)d.frm->color_range, (int)d.frm->colorspace);

    /* partial update: only a 64x64 rect at (640,320) changes */
    memcpy(src + 0, src, 0);
    for (int y = 320; y < 384; y++)
        memset(src + y * W + 640, 60, 64);
    short part[4] = { 640, 320, 64, 64 };
    int n = 4 << 20;
    xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W, H, W, H, 0, (char *)src, part, 1, out, &n, 0, &flags);
    int got = decode(&d, (unsigned char *)out, n) == 0;
    double p_rect = got ? psnr_y(src, W, d.frm->data[0], d.frm->linesize[0], 640, 320, 64, 64) : 0;
    double p_rest = got ? psnr_y(src, W, d.frm->data[0], d.frm->linesize[0], 0, 0, 600, 300) : 0;
    CHECK(got && p_rect > 30 && p_rest > 30,
          "partial update: damaged rect %.1f dB, untouched area %.1f dB", p_rect, p_rest);

    /* resize -> new encoder, flags 3 (closed + opened), new SPS/IDR */
    const int W2 = 1280, H2 = 720;
    make_frame(src, W2, H2, 99);
    short full2[4] = { 0, 0, W2, H2 };
    n = 4 << 20;
    int rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W2, H2, W2, H2, 0, (char *)src, full2, 1,
                                        out, &n, 0, &flags);
    CHECK(rv == 0 && flags == 3 && has_nal((unsigned char *)out, n, 7) &&
              has_nal((unsigned char *)out, n, 5),
          "resize to %dx%d: re-created encoder (flags=%d) with SPS+IDR", W2, H2, flags);
    avcodec_flush_buffers(d.ctx);
    CHECK(decode(&d, (unsigned char *)out, n) == 0 && d.frm->width == W2 && d.frm->height == H2,
          "decoder follows the new size");

    /* output buffer too small -> error 4, no overflow */
    int small = 16;
    make_frame(src, W2, H2, 100);
    rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W2, H2, W2, H2, 0, (char *)src, full2, 1,
                                    out, &small, 0, &flags);
    CHECK(rv == 4, "too small output buffer reported (rv=%d)", rv);

    /* the client never got that frame: the next one must restart the reference chain */
    make_frame(src, W2, H2, 101);
    n = 4 << 20;
    rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W2, H2, W2, H2, 0, (char *)src, full2, 1,
                                    out, &n, 0, &flags);
    CHECK(rv == 0 && flags == 0 && has_nal((unsigned char *)out, n, 7) &&
              has_nal((unsigned char *)out, n, 5),
          "frame after a lost output carries SPS+IDR (rv=%d flags=%d)", rv, flags);
    CHECK(decode(&d, (unsigned char *)out, n) == 0, "and decodes");
    n = 4 << 20;
    make_frame(src, W2, H2, 102);
    rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W2, H2, W2, H2, 0, (char *)src, full2, 1,
                                    out, &n, 0, &flags);
    CHECK(rv == 0 && !has_nal((unsigned char *)out, n, 5), "then P-frames again");

    /* new encoder, only a small rect damaged: the rest is the encoder's initial
     * frame, which must be black in the full-range signal (Y=0), not Y=16 grey */
    const int W3 = 640, H3 = 480;
    memset(src, 0, (size_t)W3 * H3 * 3 / 2);
    for (int y = 0; y < 64; y++)
        memset(src + y * W3, 200, 64);
    memset(src + W3 * H3, 128, (size_t)W3 * H3 / 2);
    short small_rect[4] = { 0, 0, 64, 64 };
    n = 4 << 20;
    rv = xrdp_encoder_ffmpeg_encode(h, 0, 0, 0, W3, H3, W3, H3, 0, (char *)src, small_rect, 1,
                                    out, &n, 0, &flags);
    avcodec_flush_buffers(d.ctx);
    got = rv == 0 && decode(&d, (unsigned char *)out, n) == 0;
    double ysum = 0;
    for (int y = 200; got && y < 400; y++)
        for (int x = 200; x < 600; x++)
            ysum += d.frm->data[0][y * d.frm->linesize[0] + x];
    CHECK(got && ysum / (200.0 * 400.0) < 4.0,
          "undamaged area of a new encoder decodes as full-range black (mean Y %.1f)",
          got ? ysum / (200.0 * 400.0) : -1.0);

    xrdp_encoder_ffmpeg_delete(h);
    log_end();
    return g_fail;
}
