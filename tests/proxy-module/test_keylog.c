/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* The TLS key log file (broker/proxy-module/fastrdp_keylog.h): created with mode 0600
 * whatever the umask, a wider mode narrowed, its content kept; a relative path, a symbolic
 * link, a directory and a missing directory refused. libc only.
 * Build and run: make test-proxy-module */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../broker/proxy-module/fastrdp_keylog.h"

static int failures;

#define CHECK(cond, ...)                \
	do                                  \
	{                                   \
		if (!(cond))                    \
		{                               \
			printf("FAIL %s: ", #cond); \
			printf(__VA_ARGS__);        \
			printf("\n");               \
			failures++;                 \
		}                               \
	} while (0)

static unsigned mode_of(const char* path)
{
	struct stat st;
	return lstat(path, &st) == 0 ? (unsigned)(st.st_mode & 07777) : 0;
}

int main(void)
{
	char dir[] = "/tmp/fastrdp-keylog.XXXXXX";
	if (!mkdtemp(dir))
	{
		perror("mkdtemp");
		return 1;
	}
	char path[256], link[256], sub[256], missing[256], err[128];
	(void)snprintf(path, sizeof(path), "%s/keys.txt", dir);
	(void)snprintf(link, sizeof(link), "%s/link.txt", dir);
	(void)snprintf(sub, sizeof(sub), "%s/sub", dir);
	(void)snprintf(missing, sizeof(missing), "%s/none/keys.txt", dir);

	/* created 0600 although the umask would allow 0644 */
	(void)umask(022);
	CHECK(fastrdp_keylog_prepare(path, err, sizeof(err)) == 0, "%s", err);
	CHECK(mode_of(path) == 0600, "%o", mode_of(path));

	/* an existing file: content kept, mode narrowed */
	FILE* f = fopen(path, "a");
	if (f)
	{
		(void)fputs("CLIENT_RANDOM 00 11\n", f);
		(void)fclose(f);
	}
	(void)chmod(path, 0644);
	CHECK(fastrdp_keylog_prepare(path, err, sizeof(err)) == 0, "%s", err);
	CHECK(mode_of(path) == 0600, "%o", mode_of(path));
	struct stat st;
	CHECK(stat(path, &st) == 0 && st.st_size == 20, "size %lld", (long long)st.st_size);

	/* refused: relative, NULL, symbolic link (even to the right file), directory, missing dir */
	CHECK(fastrdp_keylog_prepare("keys.txt", err, sizeof(err)) != 0, "relative accepted");
	CHECK(strcmp(err, "not an absolute path") == 0, "%s", err);
	CHECK(fastrdp_keylog_prepare(NULL, err, sizeof(err)) != 0, "NULL accepted");
	CHECK(symlink(path, link) == 0, "symlink");
	CHECK(fastrdp_keylog_prepare(link, err, sizeof(err)) != 0, "symbolic link accepted");
	CHECK(mkdir(sub, 0700) == 0, "mkdir");
	CHECK(fastrdp_keylog_prepare(sub, err, sizeof(err)) != 0, "directory accepted");
	CHECK(fastrdp_keylog_prepare(missing, err, sizeof(err)) != 0, "missing directory accepted");
	CHECK(strstr(err, "No such file") != NULL, "%s", err);

	(void)unlink(link);
	(void)unlink(path);
	(void)rmdir(sub);
	(void)rmdir(dir);
	if (failures)
		return 1;
	printf("test_keylog: ok\n");
	return 0;
}
