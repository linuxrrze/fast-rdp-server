# Needs: freerdp3-dev libwinpr3-dev libx11-dev pkgconf
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-deprecated-declarations
FREERDP = $(shell pkg-config --cflags --libs freerdp-client3 freerdp3 winpr3)

all: rdpbench perfload

rdpbench: rdpbench.c
	$(CC) $(CFLAGS) -o $@ $< $(FREERDP) -lm

perfload: perfload.c
	$(CC) $(CFLAGS) -o $@ $< $(shell pkg-config --cflags --libs x11)

clean:
	rm -f rdpbench perfload

.PHONY: all clean
