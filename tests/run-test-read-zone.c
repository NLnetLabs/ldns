/*
 * read a zone file from disk
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#include <stdint.h>

#include <ldns/dns.h>


int
main(int argc, char **argv)
{
	ldns_rr *rr;
	char *filename = "db.miek.nl";
	FILE *fp;
	ldns_zone *z;

	fp = fopen(filename, "r");
	if (!fp) {
		exit(EXIT_FAILURE);
	}
	
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	rr = ldns_rr_new_frm_fp(fp);
	ldns_rr_print(stdout, rr);
	printf("\n");
	fclose(fp);

	printf("ldns_zone_new_frm_fp\n");
	fp = fopen(filename, "r");
	if (!fp) {
		exit(EXIT_FAILURE);
	}

	z = ldns_zone_new_frm_fp(fp, NULL, 0, LDNS_RR_CLASS_IN);

	if (z) {
		ldns_zone_print(stdout, z);
	}
	fclose(fp);
	
        exit(EXIT_SUCCESS);
}
