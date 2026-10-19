# Build: make            Install: make install DESTDIR=...
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -fPIC -Wall -Wextra -Werror $(shell pkg-config --cflags libcjson)
LDLIBS += -lpam $(shell pkg-config --libs libcjson)
PAMDIR ?= $(shell pkg-config --variable=libdir pam 2>/dev/null || echo /usr/lib)/security

pam_fastrdp_token.so: pam_fastrdp_token.c
	$(CC) $(CFLAGS) -shared -Wl,--no-undefined -o $@ $< $(LDFLAGS) $(LDLIBS)

test/harness: test/harness.c
	$(CC) -Wall -Werror -o $@ $< -lpam

# Functional test against a fake broker; needs only python3 and pam_exec/pam_permit.
check: pam_fastrdp_token.so test/harness
	test/run_test.sh ./pam_fastrdp_token.so test/harness

install: pam_fastrdp_token.so
	install -D -m 0644 $< $(DESTDIR)$(PAMDIR)/pam_fastrdp_token.so

clean:
	rm -f pam_fastrdp_token.so test/harness

.PHONY: check install clean
