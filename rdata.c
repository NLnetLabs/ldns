/*
 * rdata.c
 *
 * rdata implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004
 *
 * See the file LICENSE for the license
 */

#include <config.h>

#include "rdata.h"
#include "rr.h"
#include "util.h"
#include "prototype.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
_ldns_rd_field_size(t_rdata_field *rd)
{
	return rd->_size;
}

t_rd_type
_ldns_rd_field_type(t_rdata_field *rd)
{
	return rd->_type;
}

uint8_t *
_ldns_rd_field_data(t_rdata_field *rd)
{
	return rd->_data;
}

/* write */
void
_ldns_rd_field_set_size(t_rdata_field *rd, uint16_t s)
{
	rd->_size = s;
}

void
_ldns_rd_field_set_type(t_rdata_field *rd, t_rd_type t)
{
	rd->_type = t;
}

void
_ldns_rd_field_set_data(t_rdata_field *rd, uint8_t *d)
{
	/* only copy the pointer */
	rd->_data = d;
}

/**
 * Allocate a new t_rdata_field structure 
 * and return it
 */
t_rdata_field *
_ldns_rd_field_new(uint16_t s, t_rd_type t, uint8_t *d)
{
	t_rdata_field *rd;
	MALLOC(rd, t_rdata_field);
	if (!rd)
		return NULL;

	_ldns_rd_field_set_size(rd, s);
	_ldns_rd_field_set_type(rd, t);
	_ldns_rd_field_set_data(rd, d);

	return(rd);
}

/**
 * Allocate a new t_rdata_field from
 * a NULL terminated string
 * and return it
 */
t_rdata_field *
_ldns_rd_field_new_frm_string(t_rd_type t, char *s)
{
	return NULL;
}

void 
_ldns_rd_field_destroy(t_rdata_field *rd)
{
	rd = NULL; /* kuch */
	/* empty */
}


t_rdata_field_descriptor rdata_field_descriptors[] = {
	/* 0 */
	{ 0, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 1 */
	{ TYPE_A, "A", 1, 1, { RD_A_T } },
	/* 2 */
	{ TYPE_NS, "NS", 1, 1, { RD_DNAME_T } },
	/* 3 */
	{ TYPE_MD, "MD", 1, 1, { RD_DNAME_T } },
	/* 4 */ 
	{ TYPE_MF, "MF", 1, 1, { RD_DNAME_T } },
	/* 5 */
	{ TYPE_CNAME, "CNAME", 1, 1, { RD_DNAME_T } },
	/* 6 */
	{ TYPE_SOA, "SOA", 7, 7,
	  { RD_DNAME_T, RD_DNAME_T, RD_INT32_T, 
	    RD_INT32_T, RD_INT32_T, RD_INT32_T, RD_INT32_T } },
	/* 7 */
	{ TYPE_MB, "MB", 1, 1, { RD_DNAME_T } },
	/* 8 */
	{ TYPE_MG, "MG", 1, 1, { RD_DNAME_T } },
	/* 9 */
	{ TYPE_MR, "MR", 1, 1, { RD_DNAME_T } },
	/* 10 */
	{ TYPE_NULL, "NULL", 1, 1, { RD_UNKNOWN_T } },
	/* 11 */
	{ TYPE_WKS, "WKS", 2, 2, { RD_A_T, RD_SERVICE_T } },
	/* 12 */
	{ TYPE_PTR, "PTR", 1, 1, { RD_DNAME_T } },
	/* 13 */
	{ TYPE_HINFO, "HINFO", 2, 2, { RD_STR_T, RD_STR_T } },
	/* 14 */
	{ TYPE_MINFO, "MINFO", 2, 2, { RD_DNAME_T, RD_DNAME_T } },
	/* 15 */
	{ TYPE_MX, "MX", 2, 2, { RD_INT8_T, RD_DNAME_T } },
	/* 16 */
	{ TYPE_TXT, "TXT", 1, MAXRDATALEN,
	  { RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T,
	    RD_STR_T, RD_STR_T, RD_STR_T, RD_STR_T } },
	/* 17 */
	{ TYPE_RP, "RP", 2, 2, { RD_DNAME_T, RD_DNAME_T } },
	/* 18 */
	{ TYPE_AFSDB, "AFSDB", 2, 2, { RD_INT8_T, RD_DNAME_T } },
	/* 19 */
	{ TYPE_X25, "X25", 1, 1, { RD_STR_T } },
	/* 20 */
	{ TYPE_ISDN, "ISDN", 1, 2, { RD_STR_T, RD_STR_T } },
	/* 21 */
	{ TYPE_RT, "RT", 2, 2, { RD_INT8_T, RD_DNAME_T } },
	/* 22 */
	{ TYPE_NSAP, "NSAP", 1, 1, { RD_UNKNOWN_T } },
	/* 23 */
	{ 23, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 24 */
	{ TYPE_SIG, "SIG", 9, 9,
	  { RD_INT8_T, RD_INT8_T, RD_INT8_T, RD_INT32_T,
	    RD_INT32_T, RD_INT32_T, RD_INT16_T,
	    RD_DNAME_T, RD_B64_T } },
	/* 25 */
	{ TYPE_KEY, "KEY", 4, 4,
	  { RD_INT16_T, RD_INT8_T, RD_INT8_T, RD_B64_T } },
	/* 26 */
	{ TYPE_PX, "PX", 3, 3,
	  { RD_INT16_T, RD_DNAME_T, RD_DNAME_T } },
	/* 27 */
	{ 27, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 28 */
	{ TYPE_AAAA, "AAAA", 1, 1, { RD_AAAA_T } },
	/* 29 */
	{ TYPE_LOC, "LOC", 1, 1, { RD_LOC_T } },
	/* 30 */
	{ TYPE_NXT, "NXT", 2, 2, { RD_DNAME_T, RD_UNKNOWN_T } },
	/* 31 */
	{ 31, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 32 */
	{ 32, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 33 */
	{ TYPE_SRV, "SRV", 4, 4,
	  { RD_INT16_T, RD_INT16_T, RD_INT16_T, RD_DNAME_T } },
	/* 34 */
	{ 34, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 35 */
	{ TYPE_NAPTR, "NAPTR", 6, 6,
	  { RD_INT16_T, RD_INT16_T, RD_STR_T, RD_STR_T, RD_STR_T, RD_DNAME_T } },
	/* 36 */
	{ TYPE_KX, "KX", 2, 2,
	  { RD_INT16_T, RD_DNAME_T } },
	/* 37 */
	{ TYPE_CERT, "CERT", 4, 4,
	  { RD_CERT_T, RD_INT16_T, RD_ALG_T, RD_B64_T } },
	/* 38 */
	{ 38, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 39 */
	{ TYPE_DNAME, "DNAME", 1, 1, { RD_DNAME_T } },
	/* 40 */
	{ 40, NULL, 1, 1, { RD_UNKNOWN_T } },
	/* 41 */
	{ TYPE_OPT, "OPT", 1, 1, { RD_UNKNOWN_T } },
	/* 42 */
	{ TYPE_APL, "APL", 0, MAXRDATALEN,
	  { RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T,
	    RD_APL_T, RD_APL_T, RD_APL_T, RD_APL_T } },
	/* 43 */
	{ TYPE_DS, "DS", 4, 4,
	  { RD_INT16_T, RD_INT8_T, RD_INT8_T, RD_HEX_T } },
	/* 44 */
	{ TYPE_SSHFP, "SSHFP", 3, 3, { RD_INT8_T, RD_INT8_T, RD_HEX_T } },
	/* 45 */
	{ 45, NULL, 1, 1, {  RD_UNKNOWN_T } },
	/* 46 */
	{ TYPE_RRSIG, "RRSIG", 9, 9,
	  { RD_TYPE_T, RD_INT8_T, RD_INT8_T, RD_INT32_T,
	    RD_INT32_T, RD_INT32_T, RD_INT16_T, RD_DNAME_T, RD_B64_T } },
	/* 47 */
	{ TYPE_NSEC, "NSEC", 2, 2,
	  { RD_DNAME_T, RD_NSEC_T } },
	/* 48 */
	{ TYPE_DNSKEY, "DNSKEY", 4, 4,
	  { RD_INT16_T, RD_INT8_T, RD_ALG_T, RD_B64_T } },
};
