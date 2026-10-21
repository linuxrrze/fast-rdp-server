/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de> */
/* MIT KDC policy module for run_nla.sh ("kdcpolicy" plugin interface, krb5 >= 1.16).
 * Makes the throwaway KDC refuse a service principal name (more than one name
 * component, e.g. TERMSRV/localhost) as the client of an AS request, as Active
 * Directory does: there TERMSRV/<host> is only a name of the machine account <NAME>$,
 * and an AS-REQ for it fails with KDC_ERR_C_PRINCIPAL_UNKNOWN ("Client not found in
 * Kerberos database"). With the file named by FASTRDP_TEST_KDC_SPN_AS present (checked
 * per request), the KDC behaves like plain MIT or FreeIPA again, where a service
 * principal may get a TGT with its keytab. */
#include <stdlib.h>
#include <unistd.h>
#include <krb5/kdcpolicy_plugin.h>
#include <krb5/plugin.h>

static krb5_error_code adlike_check_as(krb5_context context, krb5_kdcpolicy_moddata moddata,
                                       const krb5_kdc_req* request,
                                       const struct _krb5_db_entry_new* client,
                                       const struct _krb5_db_entry_new* server,
                                       const char* const* auth_indicators, const char** status,
                                       krb5_deltat* lifetime_out, krb5_deltat* renew_lifetime_out)
{
	(void)context;
	(void)moddata;
	(void)client;
	(void)server;
	(void)auth_indicators;
	(void)lifetime_out;
	(void)renew_lifetime_out;
	const char* allow = getenv("FASTRDP_TEST_KDC_SPN_AS");
	if (allow && access(allow, F_OK) == 0)
		return 0;
	if (request->client && request->client->length > 1)
	{
		*status = "SPN_AS_CLIENT (AD-like test KDC)";
		return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	}
	return 0;
}

krb5_error_code kdcpolicy_adlike_initvt(krb5_context context, int maj_ver, int min_ver,
                                        krb5_plugin_vtable vtable);

krb5_error_code kdcpolicy_adlike_initvt(krb5_context context, int maj_ver, int min_ver,
                                        krb5_plugin_vtable vtable)
{
	(void)context;
	(void)min_ver;
	if (maj_ver != 1)
		return KRB5_PLUGIN_VER_NOTSUPP;
	krb5_kdcpolicy_vtable vt = (krb5_kdcpolicy_vtable)vtable;
	vt->name = "adlike";
	vt->check_as = adlike_check_as;
	return 0;
}
