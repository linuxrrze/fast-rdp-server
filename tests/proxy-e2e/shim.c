/* Test-only build of the plugin: freerdp-proxy loads "static" modules by looking up
 * <name>_proxy_module_entry_point in the process, so LD_PRELOAD works without
 * installing into the system plugin directory. */
#include "../../broker/proxy-module/fastrdp_plugin.c"

__attribute__((visibility("default"))) BOOL
fastrdp_proxy_module_entry_point(proxyPluginsManager* mgr, void* userdata)
{
	return proxy_module_entry_point(mgr, userdata);
}
