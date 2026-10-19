/* Drives pam_fastrdp_token through libpam with a private config dir (no root needed).
 * usage: harness CONFDIR USER SECRET  -> prints "rc=<n> authtok=<value|(null)>" */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* secret;

static int conv(int n, const struct pam_message** msg, struct pam_response** resp, void* data)
{
	(void)data;
	*resp = calloc((size_t)n, sizeof(**resp));
	for (int i = 0; i < n; i++)
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
			(*resp)[i].resp = strdup(secret);
	return PAM_SUCCESS;
}

int main(int argc, char** argv)
{
	if (argc != 4)
		return 2;
	secret = argv[3];
	struct pam_conv c = { conv, NULL };
	pam_handle_t* h = NULL;
	if (pam_start_confdir("fastrdp-test", argv[2], &c, argv[1], &h) != PAM_SUCCESS)
		return 3;
	int rc = pam_authenticate(h, 0);
	const void* tok = NULL;
	pam_get_item(h, PAM_AUTHTOK, &tok);
	printf("rc=%d authtok=%s\n", rc, tok ? (const char*)tok : "(null)");
	pam_end(h, rc);
	return 0;
}
