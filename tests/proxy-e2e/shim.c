/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* Test-only build of the plugin: freerdp-proxy loads "static" modules by looking up
 * <name>_proxy_module_entry_point in the process, so LD_PRELOAD works without
 * installing into the system plugin directory. */
#include "../../broker/proxy-module/fastrdp_plugin.c"

__attribute__((visibility("default"))) BOOL
fastrdp_proxy_module_entry_point(proxyPluginsManager* mgr, void* userdata)
{
	return proxy_module_entry_point(mgr, userdata);
}

/* WLog writes INFO and below to stdout, which is fully buffered when redirected to a log
 * file: the checks would read the log while lines still sit in the proxy's buffer. */
__attribute__((constructor)) static void fastrdp_test_line_buffered_stdout(void)
{
	(void)setvbuf(stdout, NULL, _IOLBF, 0);
}
