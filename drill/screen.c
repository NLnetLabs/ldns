/*
 * screen.c
 * Secure tracing requires some fancy screen updates
 * 
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>


void
resolver_print_nameservers(ldns_resolver *r) 
{
	uint8_t i;
	ldns_rdf **n;
	n = ldns_resolver_nameservers(r);

        for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		printf(" | @"); ldns_rdf_print(stdout, n[i]);
        }
}

/* 
 * print the key in abbr. form
 * owner_name TYPE ; { id = id (ksk), size = b}
 */
void
print_dnskey(ldns_rr_list *key_list) 
{
	uint16_t key_size;
	uint16_t key_id;
	uint16_t ksk;
	ldns_rr *dnskey;
	size_t i;

	for (i = 0; i < ldns_rr_list_rr_count(key_list); i++) {
		dnskey = ldns_rr_list_rr(key_list, i);
		
		printf(" | ");
		ldns_rdf_print(stdout, ldns_rr_owner(dnskey));
		printf(" DNSKEY ");
		key_size = ldns_rr_dnskey_key_size(dnskey);
		key_id = ldns_calc_keytag(dnskey);
		ksk = ldns_rdf2native_int16(ldns_rr_rdf(dnskey, 0));

		switch (ksk) {
			case 257:
				printf("; { id = %d (ksk), size = %db }\n",
						(int)key_id, (int)key_size);
				break;
			case 256:
				printf("; { id = %d (zsk), size = %db }\n",
						(int)key_id, (int)key_size);
				break;
			default:
				printf("; { id = %d, size = %db }\n",
						(int)key_id, (int)key_size);
				break;
		}
	}
}

void
print_ds(ldns_rr_list *ds_list) 
{
	ldns_rr *ds;
	uint16_t key_id;
	size_t i;

	for (i = 0; i < ldns_rr_list_rr_count(ds_list); i++) {
		ds = ldns_rr_list_rr(ds_list, i);
		
		printf(" | ");
		ldns_rdf_print(stdout, ldns_rr_owner(ds));
		printf(" DS ");
		key_id = ldns_rdf2native_int16(ldns_rr_rdf(ds, 0));

		printf("; { id = %d }\n", (int)key_id);
	}
}
