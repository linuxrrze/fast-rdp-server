/*
 * pam_fastrdp_token - accept one-time login tokens issued by fastrdp-brokerd.
 *
 * Used in the xrdp-sesman PAM stack. The proxy logs in to xrdp with the
 * user name and a token ("fastrdp1:...") as password. This module redeems the
 * token over the broker's root-only socket. If the broker knew the user's real
 * password, the module stores it as PAM_AUTHTOK, so a following
 * "pam_sss.so use_first_pass" can still fetch a Kerberos TGT and unlock keyrings.
 *
 * Recommended stack (xrdp-sesman):
 *
 *   auth [success=ok ignore=1 default=die] pam_fastrdp_token.so [socket=...] [timeout=10] [debug]
 *   auth optional                          pam_sss.so use_first_pass
 *   auth required                          pam_permit.so
 *
 * Return values:
 *   PAM_SUCCESS   valid token, real password now in PAM_AUTHTOK
 *   PAM_IGNORE    valid token, but no password known (pure Kerberos SSO): the
 *                 stack jumps over pam_sss, so nothing ever sends the spent
 *                 token to the KDC (no bad-password counts in AD)
 *   PAM_AUTH_ERR  anything else - not a token, unknown, expired, reused, or
 *                 for another user - so xrdp cannot bypass the proxy's MFA
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#define PAM_SM_AUTH
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define TOKEN_PREFIX "fastrdp1:"
#define DEFAULT_SOCKET "/run/fastrdp/token.sock"
#define MAX_REPLY 8192

struct options
{
	const char* socket;
	int timeout_ms;
	int debug;
};

static void parse_args(pam_handle_t* pamh, int argc, const char** argv, struct options* o)
{
	o->socket = DEFAULT_SOCKET;
	o->timeout_ms = 10000;
	o->debug = 0;
	for (int i = 0; i < argc; i++)
	{
		if (strncmp(argv[i], "socket=", 7) == 0)
			o->socket = argv[i] + 7;
		else if (strncmp(argv[i], "timeout=", 8) == 0)
			o->timeout_ms = atoi(argv[i] + 8) * 1000;
		else if (strcmp(argv[i], "debug") == 0)
			o->debug = 1;
		else
			pam_syslog(pamh, LOG_WARNING, "unknown option: %s", argv[i]);
	}
	if (o->timeout_ms <= 0)
		o->timeout_ms = 10000;
}

static void wipe(char* s, size_t n)
{
	if (s)
		explicit_bzero(s, n);
}

/* Returns 1 and sets *password (may stay NULL) when the broker accepted the token. */
static int redeem(pam_handle_t* pamh, const struct options* o, const char* user, const char* token,
                  char** password)
{
	int ok = 0;
	int fd = -1;
	char* text = NULL;
	char buf[MAX_REPLY + 1] = { 0 };
	cJSON* reply = NULL;
	cJSON* req = cJSON_CreateObject();

	*password = NULL;
	if (!req)
		goto out;
	cJSON_AddStringToObject(req, "op", "redeem");
	cJSON_AddStringToObject(req, "user", user);
	cJSON_AddStringToObject(req, "token", token);
	text = cJSON_PrintUnformatted(req);
	if (!text)
		goto out;

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	if (strlen(o->socket) >= sizeof(addr.sun_path))
		goto out;
	strcpy(addr.sun_path, o->socket);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		pam_syslog(pamh, LOG_ERR, "cannot reach broker at %s: %s", o->socket, strerror(errno));
		goto out;
	}

	size_t len = strlen(text);
	if (send(fd, text, len, MSG_NOSIGNAL) != (ssize_t)len || send(fd, "\n", 1, MSG_NOSIGNAL) != 1)
		goto out;

	size_t used = 0;
	while (used < MAX_REPLY && !memchr(buf, '\n', used))
	{
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int pr = poll(&pfd, 1, o->timeout_ms);
		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0)
		{
			pam_syslog(pamh, LOG_ERR, "broker timeout");
			goto out;
		}
		ssize_t n = recv(fd, buf + used, MAX_REPLY - used, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		used += (size_t)n;
	}

	reply = cJSON_Parse(buf);
	if (!reply || !cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(reply, "ok")))
		goto out;
	const cJSON* pw = cJSON_GetObjectItemCaseSensitive(reply, "password");
	if (cJSON_IsString(pw) && pw->valuestring[0] != '\0')
	{
		*password = strdup(pw->valuestring);
		if (!*password)
			goto out;
	}
	ok = 1;

out:
	if (reply)
	{
		cJSON* pw = cJSON_GetObjectItemCaseSensitive(reply, "password");
		if (cJSON_IsString(pw))
			wipe(pw->valuestring, strlen(pw->valuestring));
		cJSON_Delete(reply);
	}
	if (text)
	{
		wipe(text, strlen(text));
		free(text);
	}
	cJSON_Delete(req);
	wipe(buf, sizeof(buf));
	if (fd >= 0)
		close(fd);
	return ok;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	struct options o;
	const char* user = NULL;
	const char* token = NULL;
	char* password = NULL;

	(void)flags;
	parse_args(pamh, argc, argv, &o);

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user)
		return PAM_USER_UNKNOWN;
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL) != PAM_SUCCESS || !token)
		return PAM_AUTH_ERR;
	if (strncmp(token, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) != 0)
	{
		pam_syslog(pamh, LOG_NOTICE, "login for %s without broker token refused", user);
		return PAM_AUTH_ERR;
	}

	if (!redeem(pamh, &o, user, token, &password))
	{
		pam_syslog(pamh, LOG_NOTICE, "invalid or expired broker token for %s", user);
		return PAM_AUTH_ERR;
	}

	/* Never leave the spent token in PAM_AUTHTOK for the modules that follow. */
	int rc = pam_set_item(pamh, PAM_AUTHTOK, password);
	if (password)
	{
		wipe(password, strlen(password));
		free(password);
		if (rc != PAM_SUCCESS)
			return PAM_AUTH_ERR;
		if (o.debug)
			pam_syslog(pamh, LOG_DEBUG, "broker token accepted for %s (password known)", user);
		return PAM_SUCCESS;
	}
	if (rc != PAM_SUCCESS)
		return PAM_AUTH_ERR;
	if (o.debug)
		pam_syslog(pamh, LOG_DEBUG, "broker token accepted for %s (no password)", user);
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}
