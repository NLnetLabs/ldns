/*
 * rr.c
 *
 * access function for t_rr
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include <ldns/rr.h>

#include "util.h"

/**
 * create a new rr structure.
 */
t_rr *
ldns_rr_new(void)
{
	t_rr *rr;
	rr = MALLOC(t_rr);
        if (!rr) {
                return NULL;
	}
	
	ldns_rr_set_rd_count(rr, 0);
	rr->_rdata_fields = NULL; /* XXX */
        return rr;
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_owner(t_rr *rr, uint8_t *owner)
{
	rr->_owner = owner;
}

/**
 * set the owner in the rr structure
 */
void
ldns_rr_set_ttl(t_rr *rr, uint16_t ttl)
{
	rr->_ttl = ttl;
}

/**
 * set the rd_count in the rr
 */
void
ldns_rr_set_rd_count(t_rr *rr, uint16_t count)
{
	rr->_rd_count = count;
}

/**
 * set the class in the rr
 */
void
ldns_rr_set_class(t_rr *rr, t_class klass)
{
	rr->_klass = klass;
}

/**
 * set rd_field member in the rr, it will be 
 * placed in the next available spot
 */
bool
ldns_rr_push_rd_field(t_rr *rr, t_rdata_field *f)
{
	uint16_t rd_count;
	t_rdata_field **rdata_fields;
	
	rd_count = ldns_rr_rd_count(rr);
	
	/* grow the array */
	rdata_fields = XREALLOC(
		rr->_rdata_fields, t_rdata_field *, rd_count + 1);
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
 * return the owner name of an rr structure
 */
uint8_t *
ldns_rr_owner(t_rr *rr)
{
	return rr->_owner;
}

/**
 * return the owner name of an rr structure
 */
uint8_t
ldns_rr_ttl(t_rr *rr)
{
	return rr->_ttl;
}

/**
 * return the rd_count of an rr structure
 */
uint16_t
ldns_rr_rd_count(t_rr *rr)
{
	return rr->_rd_count;
}

static const ldns_rdata_field_type type_0_wireformat[] = { RD_UNKNOWN_T };
static const ldns_rdata_field_type type_a_wireformat[] = { RD_A_T };
static const ldns_rdata_field_type type_ns_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_md_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_mf_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_cname_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_soa_wireformat[] = {
	RD_DNAME_T, RD_DNAME_T, RD_INT32_T, RD_INT32_T,
	RD_INT32_T, RD_INT32_T, RD_INT32_T
};
static const ldns_rdata_field_type type_mb_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_mg_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_mr_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_wks_wireformat[] = {
	RD_A_T, RD_SERVICE_T
};
static const ldns_rdata_field_type type_ptr_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_hinfo_wireformat[] = {
	RD_STR_T, RD_STR_T
};
static const ldns_rdata_field_type type_minfo_wireformat[] = {
	RD_DNAME_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_mx_wireformat[] = {
	RD_INT8_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_rp_wireformat[] = {
	RD_DNAME_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_afsdb_wireformat[] = {
	RD_INT8_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_x25_wireformat[] = { RD_STR_T };
static const ldns_rdata_field_type type_isdn_wireformat[] = {
	RD_STR_T, RD_STR_T
};
static const ldns_rdata_field_type type_rt_wireformat[] = {
	RD_INT8_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_sig_wireformat[] = {
	RD_INT8_T, RD_INT8_T, RD_INT8_T, RD_INT32_T,
	RD_INT32_T, RD_INT32_T, RD_INT16_T,
	RD_DNAME_T, RD_B64_T
};
static const ldns_rdata_field_type type_key_wireformat[] = {
	RD_INT16_T, RD_INT8_T, RD_INT8_T, RD_B64_T
};
static const ldns_rdata_field_type type_px_wireformat[] = {
	RD_INT16_T, RD_DNAME_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_aaaa_wireformat[] = { RD_AAAA_T };
static const ldns_rdata_field_type type_loc_wireformat[] = { RD_LOC_T };
static const ldns_rdata_field_type type_nxt_wireformat[] = {
	RD_DNAME_T, RD_UNKNOWN_T
};
static const ldns_rdata_field_type type_srv_wireformat[] = {
	RD_INT16_T, RD_INT16_T, RD_INT16_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_naptr_wireformat[] = {
	RD_INT16_T, RD_INT16_T, RD_STR_T, RD_STR_T, RD_STR_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_kx_wireformat[] = {
	RD_INT16_T, RD_DNAME_T
};
static const ldns_rdata_field_type type_cert_wireformat[] = {
	 RD_CERT_T, RD_INT16_T, RD_ALG_T, RD_B64_T
};
static const ldns_rdata_field_type type_dname_wireformat[] = { RD_DNAME_T };
static const ldns_rdata_field_type type_ds_wireformat[] = {
	RD_INT16_T, RD_INT8_T, RD_INT8_T, RD_HEX_T
};
static const ldns_rdata_field_type type_sshfp_wireformat[] = {
	RD_INT8_T, RD_INT8_T, RD_HEX_T
};
static const ldns_rdata_field_type type_rrsig_wireformat[] = {
	RD_TYPE_T, RD_INT8_T, RD_INT8_T, RD_INT32_T,
	RD_INT32_T, RD_INT32_T, RD_INT16_T, RD_DNAME_T, RD_B64_T
};
static const ldns_rdata_field_type type_nsec_wireformat[] = {
	RD_DNAME_T, RD_NSEC_T
};
static const ldns_rdata_field_type type_dnskey_wireformat[] = {
	RD_INT16_T, RD_INT8_T, RD_ALG_T, RD_B64_T
};

static ldns_rr_descriptor_type rdata_field_descriptors[] = {
	/* 0 */
	{ 0, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 1 */
	{ TYPE_A, "A", 1, 1, type_a_wireformat, RD_NONE_T },
	/* 2 */
	{ TYPE_NS, "NS", 1, 1, type_ns_wireformat, RD_NONE_T },
	/* 3 */
	{ TYPE_MD, "MD", 1, 1, type_md_wireformat, RD_NONE_T },
	/* 4 */ 
	{ TYPE_MF, "MF", 1, 1, type_mf_wireformat, RD_NONE_T },
	/* 5 */
	{ TYPE_CNAME, "CNAME", 1, 1, type_cname_wireformat, RD_NONE_T },
	/* 6 */
	{ TYPE_SOA, "SOA", 7, 7, type_soa_wireformat, RD_NONE_T },
	/* 7 */
	{ TYPE_MB, "MB", 1, 1, type_mb_wireformat, RD_NONE_T },
	/* 8 */
	{ TYPE_MG, "MG", 1, 1, type_mg_wireformat, RD_NONE_T },
	/* 9 */
	{ TYPE_MR, "MR", 1, 1, type_mr_wireformat, RD_NONE_T },
	/* 10 */
	{ TYPE_NULL, "NULL", 1, 1, type_0_wireformat, RD_NONE_T },
	/* 11 */
	{ TYPE_WKS, "WKS", 2, 2, type_wks_wireformat, RD_NONE_T },
	/* 12 */
	{ TYPE_PTR, "PTR", 1, 1, type_ptr_wireformat, RD_NONE_T },
	/* 13 */
	{ TYPE_HINFO, "HINFO", 2, 2, type_hinfo_wireformat, RD_NONE_T },
	/* 14 */
	{ TYPE_MINFO, "MINFO", 2, 2, type_minfo_wireformat, RD_NONE_T },
	/* 15 */
	{ TYPE_MX, "MX", 2, 2, type_mx_wireformat, RD_NONE_T },
	/* 16 */
	{ TYPE_TXT, "TXT", 1, 0, NULL, RD_STR_T },
	/* 17 */
	{ TYPE_RP, "RP", 2, 2, type_rp_wireformat, RD_NONE_T },
	/* 18 */
	{ TYPE_AFSDB, "AFSDB", 2, 2, type_afsdb_wireformat, RD_NONE_T },
	/* 19 */
	{ TYPE_X25, "X25", 1, 1, type_x25_wireformat, RD_NONE_T },
	/* 20 */
	{ TYPE_ISDN, "ISDN", 1, 2, type_isdn_wireformat, RD_NONE_T },
	/* 21 */
	{ TYPE_RT, "RT", 2, 2, type_rt_wireformat, RD_NONE_T },
	/* 22 */
	{ TYPE_NSAP, "NSAP", 1, 1, type_0_wireformat, RD_NONE_T },
	/* 23 */
	{ 23, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 24 */
	{ TYPE_SIG, "SIG", 9, 9, type_sig_wireformat, RD_NONE_T },
	/* 25 */
	{ TYPE_KEY, "KEY", 4, 4, type_key_wireformat, RD_NONE_T },
	/* 26 */
	{ TYPE_PX, "PX", 3, 3, type_px_wireformat, RD_NONE_T },
	/* 27 */
	{ 27, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 28 */
	{ TYPE_AAAA, "AAAA", 1, 1, type_aaaa_wireformat, RD_NONE_T },
	/* 29 */
	{ TYPE_LOC, "LOC", 1, 1, type_loc_wireformat, RD_NONE_T },
	/* 30 */
	{ TYPE_NXT, "NXT", 2, 2, type_nxt_wireformat, RD_NONE_T },
	/* 31 */
	{ 31, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 32 */
	{ 32, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 33 */
	{ TYPE_SRV, "SRV", 4, 4, type_srv_wireformat, RD_NONE_T },
	/* 34 */
	{ 34, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 35 */
	{ TYPE_NAPTR, "NAPTR", 6, 6, type_naptr_wireformat, RD_NONE_T },
	/* 36 */
	{ TYPE_KX, "KX", 2, 2, type_kx_wireformat, RD_NONE_T },
	/* 37 */
	{ TYPE_CERT, "CERT", 4, 4, type_cert_wireformat, RD_NONE_T },
	/* 38 */
	{ 38, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 39 */
	{ TYPE_DNAME, "DNAME", 1, 1, type_dname_wireformat, RD_NONE_T },
	/* 40 */
	{ 40, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 41 */
	{ TYPE_OPT, "OPT", 1, 1, type_0_wireformat, RD_NONE_T },
	/* 42 */
	{ TYPE_APL, "APL", 0, 0, NULL, RD_APL_T },
	/* 43 */
	{ TYPE_DS, "DS", 4, 4, type_ds_wireformat, RD_NONE_T },
	/* 44 */
	{ TYPE_SSHFP, "SSHFP", 3, 3, type_sshfp_wireformat, RD_NONE_T },
	/* 45 */
	{ 45, NULL, 1, 1, type_0_wireformat, RD_NONE_T },
	/* 46 */
	{ TYPE_RRSIG, "RRSIG", 9, 9, type_rrsig_wireformat, RD_NONE_T },
	/* 47 */
	{ TYPE_NSEC, "NSEC", 2, 2, type_nsec_wireformat, RD_NONE_T },
	/* 48 */
	{ TYPE_DNSKEY, "DNSKEY", 4, 4, type_dnskey_wireformat, RD_NONE_T }
};

#define RDATA_FIELD_DESCRIPTORS_COUNT \
	(sizeof(rdata_field_descriptors)/sizeof(rdata_field_descriptors[0]))

const ldns_rr_descriptor_type *
ldns_rr_descriptor(uint16_t type)
{
	if (type < RDATA_FIELD_DESCRIPTORS_COUNT) {
		return &rdata_field_descriptors[type];
	} else {
		return &rdata_field_descriptors[0];
	}
}

size_t
ldns_rr_descriptor_minimum(ldns_rr_descriptor_type *descriptor)
{
	return descriptor->_minimum;
}

size_t
ldns_rr_descriptor_maximum(ldns_rr_descriptor_type *descriptor)
{
	if (descriptor->_variable != RD_NONE_T) {
		return SIZE_MAX;
	} else {
		return descriptor->_maximum;
	}
}

ldns_rdata_field_type
ldns_rr_descriptor_field_type(ldns_rr_descriptor_type *descriptor, size_t index)
{
	assert(descriptor);
	assert(index < descriptor->_maximum
	       || descriptor->_variable != RD_NONE_T);
	if (index < descriptor->_maximum) {
		return descriptor->_wireformat[index];
	} else {
		return descriptor->_variable;
	}
}
