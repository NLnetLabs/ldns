/**
 * An example ldns program
 *
 * transform a key into a ds
 */

#include <config.h>
#include <ldns/dns.h>

int
main(void)
{
	ldns_rr *key;
	ldns_rr *ds;
	ldns_rdf *ch;

	key = ldns_rr_new_frm_str("nlnetlabs.nl.   86400   IN      DNSKEY  257 3 RSASHA1 AQPzzTWMz8qSWIQlfRnPckx2BiVmkVN6LPupO3mbz7FhLSnm26n6iG9NLby97Ji453aWZY3M5/xJBSOS2vWtco2t8C0+xeO1bc/d6ZTy32DHchpW6rDH1vp86Ll+ha0tmwyy9QP7y2bVw5zSbFCrefk8qCUBgfHm9bHzMG1UBYtEIQ==");

	ldns_rr_print(stdout, key);
	printf("keytag %d\n", ldns_keytag(key));
	
	printf("\n");

	ds = ldns_key_rr2ds(key);

	printf("\nand now the DS\n");
	printf("rdata count %d\n", ldns_rr_rd_count(ds));
	ldns_rr_print(stdout, ds);
	printf("\n");

	ch = ldns_dname_left_chop(ldns_rr_owner(ds));
	ldns_rdf_print(stdout, ch);
	printf("\n");

	return 0;
}
