/*
 * rr.c
 *
 * access function for ldns_rr
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <limits.h>

#include <ldns/rr.h>

#include "util.h"

/**
 * create a new rr structure.
 */
ldns_rr *
ldns_rr_new(void)
{
	ldns_rr *rr;
	rr = MALLOC(ldns_rr);
        if (!rr) {
                return NULL;
	}
	
	ldns_rr_set_rd_count(rr, 0);
	rr->_rdata_fields = NULL; /* XXX */
        return rr;
}

/**
 * Frees the rr structure TODO
 */
void
ldns_rr_free(ldns_rr *rr)
{
	uint16_t i;
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		ldns_rdf_free(ldns_rr_rdf(rr, i));
	}
	/*
	FREE(ldns_rr_owner(rr));
	*/
	FREE(rr);
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_owner(ldns_rr *rr, ldns_rdf *owner)
{
	rr->_owner = owner;
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_ttl(ldns_rr *rr, uint16_t ttl)
{
	rr->_ttl = ttl;
}

/**
 * set the rd_count in the rr
 */
void
ldns_rr_set_rd_count(ldns_rr *rr, uint16_t count)
{
	rr->_rd_count = count;
}

/**
 * set the type in the rr
 */
void
ldns_rr_set_type(ldns_rr *rr, ldns_rr_type rr_type)
{
	rr->_rr_type = rr_type;
}

/**
 * set the class in the rr
 */
void
ldns_rr_set_class(ldns_rr *rr, ldns_rr_class rr_class)
{
	rr->_rr_class = rr_class;
}

/**
 * set rd_field member in the rr, it will be 
 * placed in the next available spot
 */
bool
ldns_rr_push_rdf(ldns_rr *rr, ldns_rdf *f)
{
	uint16_t rd_count;
	ldns_rdf **rdata_fields;
	
	rd_count = ldns_rr_rd_count(rr);
	
	/* grow the array */
	rdata_fields = XREALLOC(
		rr->_rdata_fields, ldns_rdf *, rd_count + 1);
	if (!rdata_fields) {
		return false;
	}
	
	/* add the new member */
	rr->_rdata_fields = rdata_fields;
	rr->_rdata_fields[rd_count] = f;

	ldns_rr_set_rd_count(rr, rd_count + 1);
	return true;
}

/**
 *
 */
ldns_rdf *
ldns_rr_rdf(ldns_rr *rr, uint16_t nr)
{
	if (nr < ldns_rr_rd_count(rr)) {
		return rr->_rdata_fields[nr];
	} else {
		return NULL;
	}
}

/**
 * return the owner name of an rr structure
 */
ldns_rdf *
ldns_rr_owner(ldns_rr *rr)
{
	return rr->_owner;
}

/**
 * return the owner name of an rr structure
 */
uint8_t
ldns_rr_ttl(ldns_rr *rr)
{
	return rr->_ttl;
}

/**
 * return the rd_count of an rr structure
 */
uint16_t
ldns_rr_rd_count(ldns_rr *rr)
{
	return rr->_rd_count;
}

/**
 * Returns the type of the rr
 */
ldns_rr_type
ldns_rr_get_type(ldns_rr *rr)
{
        return rr->_rr_type;
}

/**
 * Returns the class of the rr
 */
ldns_rr_class
ldns_rr_get_class(ldns_rr *rr)
{
        return rr->_rr_class;
}

/* rrsets */

uint16_t
ldns_rrset_rr_count(ldns_rrset *rrset)
{
	return rrset->_rr_count;
}

void
ldns_rrset_set_rr_count(ldns_rrset *rrset, uint16_t count)
{
	rrset->_rr_count = count;
}

ldns_rr *
ldns_rrset_rr(ldns_rrset *rrset, uint16_t nr)
{
	if (nr < ldns_rrset_rr_count(rrset)) {
		return rrset->_rrs[nr];
	} else {
		return NULL;
	}
}

ldns_rrset *
ldns_rrset_new()
{
	ldns_rrset *rrset = MALLOC(ldns_rrset);
	rrset->_rr_count = 0;
	rrset->_rrs = NULL;
	
	return rrset;
}

void
ldns_rrset_free(ldns_rrset *rrset)
{
	uint16_t i;
	
	for (i=0; i < ldns_rrset_rr_count(rrset); i++) {
		ldns_rr_free(ldns_rrset_rr(rrset, i));
	}
	
	FREE(rrset);
}

bool
ldns_rrset_push_rr(ldns_rrset *rrset, ldns_rr *rr)
{
	uint16_t rr_count;
	ldns_rr **rrs;
	
	rr_count = ldns_rrset_rr_count(rrset);
	
	/* grow the array */
	rrs = XREALLOC(
		rrset->_rrs, ldns_rr *, rr_count + 1);
	if (!rrs) {
		return false;
	}
	
	/* add the new member */
	rrset->_rrs = rrs;
	rrset->_rrs[rr_count] = rr;

	ldns_rrset_set_rr_count(rrset, rr_count + 1);
	return true;

}

static const ldns_rdf_type type_0_wireformat[] = { LDNS_RDF_TYPE_UNKNOWN };
static const ldns_rdf_type type_a_wireformat[] = { LDNS_RDF_TYPE_A };
static const ldns_rdf_type type_ns_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_md_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mf_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_cname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_soa_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_INT32, 
	LDNS_RDF_TYPE_TIME, LDNS_RDF_TYPE_TIME, LDNS_RDF_TYPE_TIME,
	LDNS_RDF_TYPE_TIME
};
static const ldns_rdf_type type_mb_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mg_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_wks_wireformat[] = {
	LDNS_RDF_TYPE_A, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_SERVICE
};
static const ldns_rdf_type type_ptr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_hinfo_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_minfo_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_mx_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_rp_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_afsdb_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_x25_wireformat[] = { LDNS_RDF_TYPE_STR };
static const ldns_rdf_type type_isdn_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_rt_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_sig_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_TIME,
	LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_key_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_px_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_aaaa_wireformat[] = { LDNS_RDF_TYPE_AAAA };
static const ldns_rdf_type type_loc_wireformat[] = { LDNS_RDF_TYPE_LOC };
static const ldns_rdf_type type_nxt_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_UNKNOWN
};
static const ldns_rdf_type type_srv_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_naptr_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_kx_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_cert_wireformat[] = {
	 LDNS_RDF_TYPE_CERT, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_dname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_ds_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_sshfp_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_rrsig_wireformat[] = {
	LDNS_RDF_TYPE_TYPE, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT32,
	LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_nsec_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_NSEC
};
static const ldns_rdf_type type_dnskey_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_B64
};

static ldns_rr_descriptor rdata_field_descriptors[] = {
	/* 0 */
	{ 0, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 1 */
	{LDNS_RR_TYPE_A, "A", 1, 1, type_a_wireformat, LDNS_RDF_TYPE_NONE },
	/* 2 */
	{LDNS_RR_TYPE_NS, "NS", 1, 1, type_ns_wireformat, LDNS_RDF_TYPE_NONE },
	/* 3 */
	{LDNS_RR_TYPE_MD, "MD", 1, 1, type_md_wireformat, LDNS_RDF_TYPE_NONE },
	/* 4 */ 
	{LDNS_RR_TYPE_MF, "MF", 1, 1, type_mf_wireformat, LDNS_RDF_TYPE_NONE },
	/* 5 */
	{LDNS_RR_TYPE_CNAME, "CNAME", 1, 1, type_cname_wireformat, LDNS_RDF_TYPE_NONE },
	/* 6 */
	{LDNS_RR_TYPE_SOA, "SOA", 7, 7, type_soa_wireformat, LDNS_RDF_TYPE_NONE },
	/* 7 */
	{LDNS_RR_TYPE_MB, "MB", 1, 1, type_mb_wireformat, LDNS_RDF_TYPE_NONE },
	/* 8 */
	{LDNS_RR_TYPE_MG, "MG", 1, 1, type_mg_wireformat, LDNS_RDF_TYPE_NONE },
	/* 9 */
	{LDNS_RR_TYPE_MR, "MR", 1, 1, type_mr_wireformat, LDNS_RDF_TYPE_NONE },
	/* 10 */
	{LDNS_RR_TYPE_NULL, "NULL", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 11 */
	{LDNS_RR_TYPE_WKS, "WKS", 2, 2, type_wks_wireformat, LDNS_RDF_TYPE_NONE },
	/* 12 */
	{LDNS_RR_TYPE_PTR, "PTR", 1, 1, type_ptr_wireformat, LDNS_RDF_TYPE_NONE },
	/* 13 */
	{LDNS_RR_TYPE_HINFO, "HINFO", 2, 2, type_hinfo_wireformat, LDNS_RDF_TYPE_NONE },
	/* 14 */
	{LDNS_RR_TYPE_MINFO, "MINFO", 2, 2, type_minfo_wireformat, LDNS_RDF_TYPE_NONE },
	/* 15 */
	{LDNS_RR_TYPE_MX, "MX", 2, 2, type_mx_wireformat, LDNS_RDF_TYPE_NONE },
	/* 16 */
	{LDNS_RR_TYPE_TXT, "TXT", 1, 0, NULL, LDNS_RDF_TYPE_STR },
	/* 17 */
	{LDNS_RR_TYPE_RP, "RP", 2, 2, type_rp_wireformat, LDNS_RDF_TYPE_NONE },
	/* 18 */
	{LDNS_RR_TYPE_AFSDB, "AFSDB", 2, 2, type_afsdb_wireformat, LDNS_RDF_TYPE_NONE },
	/* 19 */
	{LDNS_RR_TYPE_X25, "X25", 1, 1, type_x25_wireformat, LDNS_RDF_TYPE_NONE },
	/* 20 */
	{LDNS_RR_TYPE_ISDN, "ISDN", 1, 2, type_isdn_wireformat, LDNS_RDF_TYPE_NONE },
	/* 21 */
	{LDNS_RR_TYPE_RT, "RT", 2, 2, type_rt_wireformat, LDNS_RDF_TYPE_NONE },
	/* 22 */
	{LDNS_RR_TYPE_NSAP, "NSAP", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 23 */
	{ 23, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 24 */
	{LDNS_RR_TYPE_SIG, "SIG", 9, 9, type_sig_wireformat, LDNS_RDF_TYPE_NONE },
	/* 25 */
	{LDNS_RR_TYPE_KEY, "KEY", 4, 4, type_key_wireformat, LDNS_RDF_TYPE_NONE },
	/* 26 */
	{LDNS_RR_TYPE_PX, "PX", 3, 3, type_px_wireformat, LDNS_RDF_TYPE_NONE },
	/* 27 */
	{ 27, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 28 */
	{LDNS_RR_TYPE_AAAA, "AAAA", 1, 1, type_aaaa_wireformat, LDNS_RDF_TYPE_NONE },
	/* 29 */
	{LDNS_RR_TYPE_LOC, "LOC", 1, 1, type_loc_wireformat, LDNS_RDF_TYPE_NONE },
	/* 30 */
	{LDNS_RR_TYPE_NXT, "NXT", 2, 2, type_nxt_wireformat, LDNS_RDF_TYPE_NONE },
	/* 31 */
	{ 31, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 32 */
	{ 32, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 33 */
	{LDNS_RR_TYPE_SRV, "SRV", 4, 4, type_srv_wireformat, LDNS_RDF_TYPE_NONE },
	/* 34 */
	{ 34, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 35 */
	{LDNS_RR_TYPE_NAPTR, "NAPTR", 6, 6, type_naptr_wireformat, LDNS_RDF_TYPE_NONE },
	/* 36 */
	{LDNS_RR_TYPE_KX, "KX", 2, 2, type_kx_wireformat, LDNS_RDF_TYPE_NONE },
	/* 37 */
	{LDNS_RR_TYPE_CERT, "CERT", 4, 4, type_cert_wireformat, LDNS_RDF_TYPE_NONE },
	/* 38 */
	{ 38, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 39 */
	{LDNS_RR_TYPE_DNAME, "DNAME", 1, 1, type_dname_wireformat, LDNS_RDF_TYPE_NONE },
	/* 40 */
	{ 40, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 41 */
	{LDNS_RR_TYPE_OPT, "OPT", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 42 */
	{LDNS_RR_TYPE_APL, "APL", 0, 0, NULL, LDNS_RDF_TYPE_APL },
	/* 43 */
	{LDNS_RR_TYPE_DS, "DS", 4, 4, type_ds_wireformat, LDNS_RDF_TYPE_NONE },
	/* 44 */
	{LDNS_RR_TYPE_SSHFP, "SSHFP", 3, 3, type_sshfp_wireformat, LDNS_RDF_TYPE_NONE },
	/* 45 */
	{ 45, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE },
	/* 46 */
	{LDNS_RR_TYPE_RRSIG, "RRSIG", 9, 9, type_rrsig_wireformat, LDNS_RDF_TYPE_NONE },
	/* 47 */
	{LDNS_RR_TYPE_NSEC, "NSEC", 2, 2, type_nsec_wireformat, LDNS_RDF_TYPE_NONE },
	/* 48 */
	{LDNS_RR_TYPE_DNSKEY, "DNSKEY", 4, 4, type_dnskey_wireformat, LDNS_RDF_TYPE_NONE }
};

#define RDATA_FIELD_DESCRIPTORS_COUNT \
	(sizeof(rdata_field_descriptors)/sizeof(rdata_field_descriptors[0]))

const ldns_rr_descriptor *
ldns_rr_descript(uint16_t type)
{
	if (type < RDATA_FIELD_DESCRIPTORS_COUNT) {
		return &rdata_field_descriptors[type];
	} else {
		return &rdata_field_descriptors[0];
	}
}

size_t
ldns_rr_descriptor_minimum(const ldns_rr_descriptor *descriptor)
{
	return descriptor->_minimum;
}

size_t
ldns_rr_descriptor_maximum(const ldns_rr_descriptor *descriptor)
{
	if (descriptor->_variable != LDNS_RDF_TYPE_NONE) {
		/* XXX: Should really be SIZE_MAX... bad FreeBSD.  */
		return UINT_MAX;
	} else {
		return descriptor->_maximum;
	}
}

ldns_rdf_type
ldns_rr_descriptor_field_type(const ldns_rr_descriptor *descriptor,
                              size_t index)
{
	assert(descriptor != NULL);
	assert(index < descriptor->_maximum
	       || descriptor->_variable != LDNS_RDF_TYPE_NONE);
	if (index < descriptor->_maximum) {
		return descriptor->_wireformat[index];
	} else {
		return descriptor->_variable;
	}
}

