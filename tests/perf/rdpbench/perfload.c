/*
 * perfload - deterministic X11 screen load for RDP benchmarks (run inside a session).
 *
 *   perfload video   [WxH] [fps]  full-motion region (moving bars + noise blocks)
 *   perfload scroll        [fps]  scrolling text-like stripes, like a browser/terminal
 *   perfload latency              static screen; each key press flips a 128x128 square
 *
 * Works in X11 sessions and under Xwayland. Ctrl+C to stop.
 */
#define _POSIX_C_SOURCE 200809L
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void sleep_until(double t)
{
	double d = t - now();
	if (d > 0)
	{
		struct timespec ts = { (time_t)d, (long)((d - (time_t)d) * 1e9) };
		nanosleep(&ts, NULL);
	}
}

int main(int argc, char** argv)
{
	const char* mode = argc > 1 ? argv[1] : "video";
	int vw = 1280, vh = 720, fps = 60;
	if (strcmp(mode, "video") == 0 && argc > 2 && sscanf(argv[2], "%dx%d", &vw, &vh) != 2)
		return 2;
	if (argc > (strcmp(mode, "video") == 0 ? 3 : 2))
		fps = atoi(argv[strcmp(mode, "video") == 0 ? 3 : 2]);
	if (fps <= 0 || fps > 240)
		fps = 60;

	Display* dpy = XOpenDisplay(NULL);
	if (!dpy)
	{
		fprintf(stderr, "perfload: cannot open display\n");
		return 1;
	}
	int scr = DefaultScreen(dpy);
	int sw = DisplayWidth(dpy, scr), sh = DisplayHeight(dpy, scr);
	if (vw > sw) vw = sw;
	if (vh > sh) vh = sh;
	Window win = XCreateSimpleWindow(dpy, RootWindow(dpy, scr), 0, 0, (unsigned)sw, (unsigned)sh,
	                                 0, 0, WhitePixel(dpy, scr));
	XSelectInput(dpy, win, KeyPressMask | ExposureMask);
	XStoreName(dpy, win, "perfload");
	XMapRaised(dpy, win);
	XSync(dpy, False);
	XSetInputFocus(dpy, win, RevertToParent, CurrentTime);
	GC gc = XCreateGC(dpy, win, 0, NULL);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	unsigned seed = 12345;
	const double period = 1.0 / fps;
	double next = now();
	unsigned long frame = 0;
	int flip = 0;

	while (!stop)
	{
		while (XPending(dpy))
		{
			XEvent ev;
			XNextEvent(dpy, &ev);
			if (ev.type == KeyPress && strcmp(mode, "latency") == 0)
			{
				flip = !flip;
				XSetForeground(dpy, gc, flip ? 0xd03030 : 0x3030d0);
				XFillRectangle(dpy, win, gc, 64, 64, 128, 128);
				XFlush(dpy);
			}
		}
		if (strcmp(mode, "latency") == 0)
		{
			struct timespec ts = { 0, 1000000 };
			nanosleep(&ts, NULL);
			continue;
		}
		if (strcmp(mode, "video") == 0)
		{
			const int x0 = (sw - vw) / 2, y0 = (sh - vh) / 2, bars = 16;
			for (int b = 0; b < bars; b++)
			{
				unsigned long c = ((frame * 3 + (unsigned long)b * 40) & 0xff) << 16 |
				                  ((frame * 5 + (unsigned long)b * 20) & 0xff) << 8 |
				                  ((frame * 7 + (unsigned long)b * 10) & 0xff);
				XSetForeground(dpy, gc, c);
				XFillRectangle(dpy, win, gc, x0 + (int)((frame * 4 + (unsigned long)b * (unsigned long)vw / bars) % (unsigned long)vw),
				               y0, (unsigned)(vw / bars), (unsigned)vh);
			}
			for (int i = 0; i < 200; i++) /* noise blocks: defeat trivial inter-frame prediction */
			{
				seed = seed * 1103515245u + 12345u;
				XSetForeground(dpy, gc, seed & 0xffffff);
				XFillRectangle(dpy, win, gc, x0 + (int)((seed >> 8) % (unsigned)(vw - 16)),
				               y0 + (int)((seed >> 3) % (unsigned)(vh - 16)), 16, 16);
			}
		}
		else /* scroll */
		{
			const int step = 8;
			XCopyArea(dpy, win, win, gc, 0, step, (unsigned)sw, (unsigned)(sh - step), 0, 0);
			XSetForeground(dpy, gc, 0xffffff);
			XFillRectangle(dpy, win, gc, 0, sh - step, (unsigned)sw, step);
			XSetForeground(dpy, gc, 0x202020);
			for (int x = 20; x < sw - 40; x += 9)
			{
				seed = seed * 1103515245u + 12345u;
				if ((seed >> 16) % 7 && (frame % 3) != 0)
					XFillRectangle(dpy, win, gc, x, sh - step, 6, (unsigned)step - 2);
			}
		}
		XFlush(dpy);
		frame++;
		next += period;
		sleep_until(next);
	}
	XCloseDisplay(dpy);
	return 0;
}
