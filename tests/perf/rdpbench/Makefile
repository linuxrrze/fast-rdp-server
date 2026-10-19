# Needs: freerdp3-dev libwinpr3-dev libx11-dev pkgconf, or fastrdp's FreeRDP build:
#   make FREERDP_PREFIX=/opt/fastrdp   (H.264/AVC444 decoding; the Ubuntu 26.04
#   freerdp3 is built without it)
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-deprecated-declarations
ifdef FREERDP_PREFIX
FREERDP = $(shell PKG_CONFIG_PATH=$(FREERDP_PREFIX)/lib/pkgconfig pkg-config --cflags --libs \
	freerdp-client3 freerdp3 winpr3) -Wl,--disable-new-dtags -Wl,-rpath,$(FREERDP_PREFIX)/lib
else
FREERDP = $(shell pkg-config --cflags --libs freerdp-client3 freerdp3 winpr3)
endif

all: rdpbench perfload

rdpbench: rdpbench.c
	$(CC) $(CFLAGS) -o $@ $< $(FREERDP) -lm

perfload: perfload.c
	$(CC) $(CFLAGS) -o $@ $< $(shell pkg-config --cflags --libs x11)

clean:
	rm -f rdpbench perfload

.PHONY: all clean
