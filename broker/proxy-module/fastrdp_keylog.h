/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* [FastRDP] TlsKeyLogFile (lab only, off by default; backlog A5): FreeRDP's TLS code appends
 * the TLS secrets of every front connection to this file (FreeRDP_TlsSecretsFile, NSS key
 * log format), so Wireshark can decrypt a capture of the client's traffic. Whoever has the
 * file and a capture reads everything in it: the code typed into the waiting screen, and
 * the password of a TLS login. OpenSSL's callback opens the file with fopen("a+"), which
 * would create it with the process umask; fastrdp_keylog_prepare() creates it first, mode
 * 0600, and refuses anything but a regular file of the proxy's own user, a symbolic link
 * included. libc only (tests/proxy-module/test_keylog.c). */
#ifndef FASTRDP_KEYLOG_H
#define FASTRDP_KEYLOG_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* 0: the file exists, is a regular file of this user with mode 0600. -1: err names why. */
static int fastrdp_keylog_prepare(const char* path, char* err, size_t errlen)
{
	if (!path || path[0] != '/')
	{
		(void)snprintf(err, errlen, "not an absolute path");
		return -1;
	}
	const int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY, 0600);
	if (fd < 0)
	{
		(void)snprintf(err, errlen, "%s", strerror(errno));
		return -1;
	}
	struct stat st;
	int rc = -1;
	if (fstat(fd, &st) != 0)
		(void)snprintf(err, errlen, "%s", strerror(errno));
	else if (!S_ISREG(st.st_mode))
		(void)snprintf(err, errlen, "not a regular file");
	else if (st.st_uid != geteuid())
		(void)snprintf(err, errlen, "owned by uid %u, not by the proxy's user", (unsigned)st.st_uid);
	else if ((st.st_mode & 07777) != 0600 && fchmod(fd, 0600) != 0)
		(void)snprintf(err, errlen, "chmod 600: %s", strerror(errno));
	else
		rc = 0;
	(void)close(fd);
	return rc;
}

#endif
