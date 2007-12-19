/*
 * special zone file structures and functions for better dnssec handling
 *
 * A zone contains a SOA dnssec_zone_rrset, and an AVL tree of 'normal'
 * dnssec_zone_rrsets, indexed by name and type
 */

#ifndef LDNS_DNSSEC_ZONE_H
#define LDNS_DNSSEC_ZONE_H
 
#include <ldns/ldns.h>

/* collection of rrs belonging to one rrset */
typedef struct ldns_struct_dnssec_rrs ldns_dnssec_rrs;
struct ldns_struct_dnssec_rrs
{
	ldns_rr *rr;
	ldns_dnssec_rrs *next;
};

/* collection of rrsets belonging to one dname */
typedef struct ldns_struct_dnssec_rrsets ldns_dnssec_rrsets;
struct ldns_struct_dnssec_rrsets
{
	ldns_dnssec_rrs *rrs;
	ldns_rr_type type;
	ldns_dnssec_rrs *signatures;
	ldns_dnssec_rrsets *next;
};

/* AVL tree of names */
typedef struct ldns_struct_dnssec_name ldns_dnssec_name;
struct ldns_struct_dnssec_name
{
	/* AVL tree components */
	int balance;
	ldns_dnssec_name *left;
	ldns_dnssec_name *right;
	ldns_dnssec_name *up;

	/* rrset and dnssec data */
	ldns_rdf *name;
	ldns_dnssec_rrsets *rrsets;
	ldns_rr *nsec;
	ldns_dnssec_rrs *nsec_signatures;
};

struct ldns_struct_dnssec_zone {
	ldns_dnssec_name *soa;
	ldns_dnssec_name *names;
};
typedef struct ldns_struct_dnssec_zone ldns_dnssec_zone;

ldns_dnssec_rrs *
ldns_dnssec_rrs_new();

void
ldns_dnssec_rrs_free(ldns_dnssec_rrs *rrs);

ldns_status
ldns_dnssec_rrs_add_rr(ldns_dnssec_rrs *rrs, ldns_rr *rr);

void
ldns_dnssec_rrs_print(FILE *out, ldns_dnssec_rrs *rrs);

ldns_dnssec_rrsets *
ldns_dnssec_rrsets_new();

void
ldns_dnssec_rrsets_free(ldns_dnssec_rrsets *rrsets);

ldns_rr_type
ldns_dnssec_rrsets_type(ldns_dnssec_rrsets *rrsets);

ldns_status
ldns_dnssec_rrsets_set_type(ldns_dnssec_rrsets *rrsets,
					   ldns_rr_type type);

ldns_status
ldns_dnssec_rrsets_add_rr(ldns_dnssec_rrsets *rrsets, ldns_rr *rr);

void
ldns_dnssec_rrsets_print(FILE *out, ldns_dnssec_rrsets *rrsets);

ldns_dnssec_name *
ldns_dnssec_name_new();

ldns_dnssec_name *
ldns_dnssec_name_new_frm_rr(ldns_rr *rr);

void
ldns_dnssec_name_free(ldns_dnssec_name *rrset);

ldns_rdf *
ldns_dnssec_name_name(ldns_dnssec_name *rrset);

void
ldns_dnssec_name_set_name(ldns_dnssec_name *rrset,
						  ldns_rdf *dname);

ldns_status
ldns_dnssec_name_set_nsec(ldns_dnssec_name *rrset, ldns_rr *nsec);

ldns_dnssec_name *
ldns_dnssec_name_next(ldns_dnssec_name *name);

ldns_status
ldns_dnssec_name_add_rr_to_current(ldns_dnssec_name *rrset,
								 ldns_rr *rr);

ldns_status
ldns_dnssec_name_add_rr(ldns_dnssec_name *rrset,
						ldns_rr *rr);

void
ldns_dnssec_name_print(FILE *out, ldns_dnssec_name *name, bool single);

ldns_dnssec_zone *
ldns_dnssec_zone_new();

void
ldns_dnssec_zone_free(ldns_dnssec_zone *zone);

ldns_status
ldns_dnssec_zone_add_rr(ldns_dnssec_zone *zone, ldns_rr *rr);

void
ldns_dnssec_zone_print(FILE *out, ldns_dnssec_zone *zone);

#endif
