/** \file rr.c
 *
 * \brief access functions for ldns_rr - 
 * \brief a Net::DNS like library for C
 * \author LibDNS Team @ NLnet Labs
 * \version 0.01
 */

/*
 * (c) NLnet Labs, 2004
 * See the file LICENSE for the license
 */

#include <config.h>
#include <limits.h>
#include <ldns/rr.h>
#include <strings.h>

#include "util.h"
#include <ldns/dns.h>

/**
 * \brief create a new rr structure.
 * \return ldns_rr *
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
 * \brief free a RR structure
 * \param[in] *rr the RR to be freed 
 * \return void
 */
void
ldns_rr_free(ldns_rr *rr)
{
	uint16_t i;
	if (ldns_rr_owner(rr)) {
		ldns_rdf_free(ldns_rr_owner(rr));
	}
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		ldns_rdf_free(ldns_rr_rdf(rr, i));
	}
	/*
	FREE(ldns_rr_owner(rr));
	*/
	FREE(rr);
}

/** 
 * normalize a RR string; kill newlines and parentheses
 * and put the whole rr on 1 line
 * \param[in] rr the rr to normalize
 * \return the normalized rr
 */
/* no need to export this */
static char *
ldns_rr_str_normalize(const char *rr)
{
	char *p;
	char *s;
	char *orig_s;

	s = XMALLOC(char, strlen(rr)); /* for the newly created string */
	orig_s = s;

	/* walk through the rr and fix it. Whitespace is handled in
	 * ldns_rr_new_frm_str(), so don't worry about that here
	 * - remove (, ) and \n
	 * - everything after ; is discard
	 * - allow for simple escaping, with \??? TODO Miek
	 */
	for(p = (char*)rr; *p; p++) {
		if (*p == '(' || *p == ')' || *p == '\n') {
			continue;
		}
		if (*p == ';') {
			/* comment seen, bail out */
			break;
		}
	 	*s++ = *p;
	}
	*s = '\0';
	return orig_s;
}

/**
 * \brief create a rr from a string
 * string should be a fully filled in rr, like
 * ownername <space> TTL <space> CLASS <space> TYPE <space> RDATA
 * \param[in] str the string to convert
 * \return the new rr
 */
/* we expect 3 spaces, everything there after is rdata
 * So the RR should look like. e.g.
 * miek.nl. 3600 IN MX 10 elektron.atoom.net
 * Everything should be on 1 line, parentheses are not
 * handled. We may need a normalize function.
 *
 * We cannot(!) handle extranous spaces in the rdata (for instace b64
 * stuff)
 */
ldns_rr *
ldns_rr_new_frm_str(const char *str)
{
	ldns_rr *new;
	const ldns_rr_descriptor *desc;
	ldns_rr_type rr_type;
	char  *str_normalized;
	char  *owner; 
	char  *ttl; 
	char  *clas;
	char  *type;
	char  *rdata;
	char  *rd;
	
	ldns_rdf *r;
	uint16_t r_cnt;
	uint16_t r_min;
	uint16_t r_max;

	new = ldns_rr_new();

	owner = XMALLOC(char, 256);
	ttl = XMALLOC(char, 20);
	clas = XMALLOC(char, 8);
	type = XMALLOC(char, 10);
	rdata = XMALLOC(char, MAX_PACKETLEN);
	str_normalized = ldns_rr_str_normalize(str);
	
	  /* numbers are bogus XXX Miek */
	sscanf(str_normalized, "%256s%20s%8s%10s%65535c", owner, ttl, clas, type, rdata);

#if 0
	printf("owner [%s]\n", owner);
	printf("ttl [%s]\n", ttl);
	printf("clas [%s]\n", clas);
	printf("type [%s]\n", type);
	printf("rdata [%s]\n", rdata);
#endif 

	ldns_rr_set_owner(new, ldns_dname_new_frm_str(owner));
	/* ttl might be more complicated, like 2h, or 3d5h */
	ldns_rr_set_ttl(new, (uint32_t) atoi(ttl));
	ldns_rr_set_class(new, ldns_rr_get_class_by_name(clas));

	rr_type = ldns_rr_get_type_by_name(type);
	desc = ldns_rr_descript((uint16_t)rr_type);
	ldns_rr_set_type(new, rr_type);

	/* only the rdata remains */
	r_max = ldns_rr_descriptor_maximum(desc);
	r_min = ldns_rr_descriptor_minimum(desc);

	/* rdata (rdf's) */
	printf("tot rd [%s]\n", rdata);
	for(rd = strtok(rdata, "\t \0"), r_cnt =0; rd; rd = strtok(NULL, "\t \0"), r_cnt++) {
		r = ldns_rdf_new_frm_str(rd,
				ldns_rr_descriptor_field_type(desc, r_cnt));
		printf("rd str [%s] %d\n", rd, r_cnt);
		if (!r) {
			printf("rdf conversion mismatch\n");
			return NULL;
		}
		ldns_rr_push_rdf(new, r);
		if (r_cnt > r_max) {
			printf("rdf data overflow");
			return NULL;
		}
	}
	return new;
}



/**
 * \brief set the owner in the rr structure
 * \param[in] *rr rr to operate on
 * \param[in] *owner set to this owner
 * \return void
 */
void
ldns_rr_set_owner(ldns_rr *rr, ldns_rdf *owner)
{
	rr->_owner = owner;
}

/**
 * \brief set the ttl in the rr structure
 * \param[in] *rr rr to operate on
 * \param[in] ttl set to this ttl
 * \return void
 */
void
ldns_rr_set_ttl(ldns_rr *rr, uint32_t ttl)
{
	rr->_ttl = ttl;
}

/**
 * \brief set the rd_count in the rr
 * \param[in] *rr rr to operate on
 * \param[in] count set to this count
 * \return void
 */
void
ldns_rr_set_rd_count(ldns_rr *rr, uint16_t count)
{
	rr->_rd_count = count;
}

/**
 * \brief set the type in the rr
 * \param[in] *rr rr to operate on
 * \param[in] rr_type set to this type
 * \return void
 */
void
ldns_rr_set_type(ldns_rr *rr, ldns_rr_type rr_type)
{
	rr->_rr_type = rr_type;
}

/**
 * \brief set the class in the rr
 * \param[in] *rr rr to operate on
 * \param[in] rr_class set to this class
 * \return void
 */
void
ldns_rr_set_class(ldns_rr *rr, ldns_rr_class rr_class)
{
	rr->_rr_class = rr_class;
}

/**
 * set rd_field member, it will be 
 * placed in the next available spot
 * \param[in] *rr rr to operate on
 * \param[in] *f the data field member to set
 * \return bool
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
 * remove a rd_field member, it will be 
 * popped from the last place
 * \param[in] *rr rr to operate on
 * \return rdf which was popped (null if nothing)
 */
ldns_rdf *
ldns_rr_pop_rdf(ldns_rr *rr)
{
	uint16_t rd_count;
	ldns_rdf *pop;
	
	rd_count = ldns_rr_rd_count(rr);

	if (rd_count == 0) {
		return NULL;
	}

	pop = rr->_rdata_fields[rd_count];
	
	/* shrink the array */
	rr->_rdata_fields = XREALLOC(
		rr->_rdata_fields, ldns_rdf *, rd_count - 1);

	ldns_rr_set_rd_count(rr, rd_count - 1);
	return pop;
}

/**
 * set the rdata field member counter
 * \param[in] *rr rr to operate on
 * \param[in] nr the number to set
 * \return ldns_rdf *
 */
ldns_rdf *
ldns_rr_rdf(const ldns_rr *rr, uint16_t nr)
{
	if (nr < ldns_rr_rd_count(rr)) {
		return rr->_rdata_fields[nr];
	} else {
		return NULL;
	}
}

/**
 * return the owner name of an rr structure
 * \param[in] *rr rr to operate on
 * \return ldns_rdf * 
 */
ldns_rdf *
ldns_rr_owner(const ldns_rr *rr)
{
	return rr->_owner;
}

/**
 * return the owner name of an rr structure
 */
uint32_t
ldns_rr_ttl(const ldns_rr *rr)
{
	return rr->_ttl;
}

/**
 * return the rd_count of an rr structure
 */
uint16_t
ldns_rr_rd_count(const ldns_rr *rr)
{
	return rr->_rd_count;
}

/**
 * Returns the type of the rr
 */
ldns_rr_type
ldns_rr_get_type(const ldns_rr *rr)
{
        return rr->_rr_type;
}

/**
 * Returns the class of the rr
 */
ldns_rr_class
ldns_rr_get_class(const ldns_rr *rr)
{
        return rr->_rr_class;
}

/* rr_lists */

uint16_t
ldns_rr_list_rr_count(ldns_rr_list *rr_list)
{
	return rr_list->_rr_count;
}

void
ldns_rr_list_set_rr_count(ldns_rr_list *rr_list, uint16_t count)
{
	rr_list->_rr_count = count;
}

ldns_rr *
ldns_rr_list_rr(ldns_rr_list *rr_list, uint16_t nr)
{
	if (nr < ldns_rr_list_rr_count(rr_list)) {
		return rr_list->_rrs[nr];
	} else {
		return NULL;
	}
}

ldns_rr_list *
ldns_rr_list_new()
{
	ldns_rr_list *rr_list = MALLOC(ldns_rr_list);
	rr_list->_rr_count = 0;
	rr_list->_rrs = NULL;
	
	return rr_list;
}

void
ldns_rr_list_free(ldns_rr_list *rr_list)
{
	uint16_t i;
	
	for (i=0; i < ldns_rr_list_rr_count(rr_list); i++) {
		ldns_rr_free(ldns_rr_list_rr(rr_list, i));
	}
	
	FREE(rr_list);
}


/**
 * concatenate two ldns_rr_lists together
 * \param[in] left the leftside
 * \param[in] right the rightside
 * \return a new rr_list with leftside/rightside concatenated
 */
ldns_rr_list *
ldns_rr_list_cat(ldns_rr_list *left, ldns_rr_list *right)
{
	uint16_t l_rr_count;
	uint16_t r_rr_count;
	uint16_t i;
	ldns_rr_list *cat;

	l_rr_count = ldns_rr_list_rr_count(left);
	r_rr_count = ldns_rr_list_rr_count(right);

	/* check it not exceeding uint16_t size XXX XXX MIEK TODO */
	cat = ldns_rr_list_new();

	if (!cat) {
		return NULL;
	}

	/* left */
	for(i = 0; i < l_rr_count; i++) {
		ldns_rr_list_push_rr(cat, 
				ldns_rr_list_rr(left, i));
	}
	/* right */
	for(i = 0; i < r_rr_count; i++) {
		ldns_rr_list_push_rr(cat, 
				ldns_rr_list_rr(right, i));
	}
	return cat;
}

/**
 * push an  rr to a rrlist
 * \param[in] rr_list the rr_list to push to 
 * \param[in] rr the rr to push 
 * \return NULL on error, otherwise true
 */
bool
ldns_rr_list_push_rr(ldns_rr_list *rr_list, ldns_rr *rr)
{
	uint16_t rr_count;
	ldns_rr **rrs;
	
	rr_count = ldns_rr_list_rr_count(rr_list);
	
	/* grow the array */
	rrs = XREALLOC(
		rr_list->_rrs, ldns_rr *, rr_count + 1);
	if (!rrs) {
		return false;
	}
	
	/* add the new member */
	rr_list->_rrs = rrs;
	rr_list->_rrs[rr_count] = rr;

	ldns_rr_list_set_rr_count(rr_list, rr_count + 1);
	return true;
}

/**
 * pop the last rr from a rrlist
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 */
ldns_rr *
ldns_rr_list_pop_rr(ldns_rr_list *rr_list)
{
	uint16_t rr_count;
	ldns_rr *pop;
	
	rr_count = ldns_rr_list_rr_count(rr_list);

	if (rr_count == 0) {
		return NULL;
	}

	pop = ldns_rr_list_rr(rr_list, rr_count);
	
	/* shrink the array */
	rr_list->_rrs = XREALLOC(
		rr_list->_rrs, ldns_rr *, rr_count - 1);

	ldns_rr_list_set_rr_count(rr_list, rr_count - 1);

	return pop;
}

/* rrset stuff 
 * rrset is a rr_list with the following properties
 * 1. owner is equal
 * 2. class is equal
 * 3. type is equal
 * 4. ttl is equal - although not for RRSIG
 */

/**
 * check if an rr_list is a rrset
 * \param[in] rr_list the rr_list to check
 */
bool
ldns_is_rrset(ldns_rr_list *rr_list)
{
	ldns_rr_list_print(stdout, rr_list);
	return false;
}

/**
 * Push an rr to an rrset (which really are rr_list's)
 * \param[in] *rr_list the rrset to push the rr to
 * \param[in] *rr the rr to push
 * \return true or false
 */
bool
ldns_rr_set_push_rr(ldns_rr_list *rr_list, ldns_rr *rr)
{
	uint16_t rr_count;
	uint16_t i;
	ldns_rr *last;

	assert(rr != NULL);

	rr_count = ldns_rr_list_rr_count(rr_list);


	if (rr_count == 0) {
		/* nothing there, so checking it is 
		 * not needed */
		return ldns_rr_list_push_rr(rr_list, rr);
	} else {
		/* check with the final rr in the rr_list */
		last = ldns_rr_list_rr(rr_list, rr_count);

		if (ldns_rr_get_class(last) != ldns_rr_get_class(rr)) {
			return false;
		}
		if (ldns_rr_get_type(last) != ldns_rr_get_type(rr)) {
			return false;
		}
		/* only check if not equal to RRSIG */
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
			if (ldns_rr_ttl(last) != ldns_rr_ttl(rr)) {
				return false;
			}
		}
		if (ldns_rdf_compare(ldns_rr_owner(last),
					ldns_rr_owner(rr)) != 0) {
			return false;
		}
		/* ok, still alive - check if the rr already
		 * exists - if so, dont' add it */
		for(i = 0; i < rr_count; i++) {
			if(ldns_rr_compare(
					ldns_rr_list_rr(rr_list, i), rr) == 0) {
				return false;
			}
		}
		/* it's safe, push it */
		return ldns_rr_list_push_rr(rr_list, rr);
	}
}

/**
 * pop the last rr from a rrset. This function is there only
 * for the symmetry.
 * \param[in] rr_list the rr_list to pop from
 * \return NULL if nothing to pop. Otherwise the popped RR
 *
 */
ldns_rr *
ldns_rr_set_pop_rr(ldns_rr_list *rr_list)
{
	return ldns_rr_list_pop_rr(rr_list);
}

/** \cond */
static const ldns_rdf_type type_0_wireformat[] = { LDNS_RDF_TYPE_UNKNOWN };
static const ldns_rdf_type type_a_wireformat[] = { LDNS_RDF_TYPE_A };
static const ldns_rdf_type type_ns_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_md_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mf_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_cname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_soa_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_INT32, 
	LDNS_RDF_TYPE_PERIOD, LDNS_RDF_TYPE_PERIOD, LDNS_RDF_TYPE_PERIOD,
	LDNS_RDF_TYPE_PERIOD
};
static const ldns_rdf_type type_mb_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mg_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_wks_wireformat[] = {
	LDNS_RDF_TYPE_A, LDNS_RDF_TYPE_WKS
};
static const ldns_rdf_type type_ptr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_hinfo_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_minfo_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_mx_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_rp_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_afsdb_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_x25_wireformat[] = { LDNS_RDF_TYPE_STR };
static const ldns_rdf_type type_isdn_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_rt_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_nsap_wireformat[] = {
	LDNS_RDF_TYPE_NSAP
};
static const ldns_rdf_type type_nsap_ptr_wireformat[] = {
	LDNS_RDF_TYPE_STR
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
static const ldns_rdf_type type_gpos_wireformat[] = {
	LDNS_RDF_TYPE_STR,
	LDNS_RDF_TYPE_STR,
	LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_aaaa_wireformat[] = { LDNS_RDF_TYPE_AAAA };
static const ldns_rdf_type type_loc_wireformat[] = { LDNS_RDF_TYPE_LOC };
static const ldns_rdf_type type_nxt_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_UNKNOWN
};
static const ldns_rdf_type type_eid_wireformat[] = {
	LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_nimloc_wireformat[] = {
	LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_srv_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_atma_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
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
static const ldns_rdf_type type_a6_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_dname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_sink_wireformat[] = { LDNS_RDF_TYPE_INT8,
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_apl_wireformat[] = {
	LDNS_RDF_TYPE_APL
};
static const ldns_rdf_type type_ds_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_sshfp_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_ipseckey_wireformat[] = {
	LDNS_RDF_TYPE_IPSECKEY
};
static const ldns_rdf_type type_rrsig_wireformat[] = {
	LDNS_RDF_TYPE_TYPE, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT32,
	LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_nsec_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_NSEC
};
static const ldns_rdf_type type_dnskey_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_B64
};
/** \endcond */

/** \cond */
/* All RR's defined in 1035 are well known and can thus
 * be compressed. See RFC3597. These RR's are:
 * CNAME HINFO MB MD MF MG MINFO MR MX NULL NS PTR SOA TXT
 */
static ldns_rr_descriptor rdata_field_descriptors[] = {
	/* 0 */
	{ 0, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 1 */
	{LDNS_RR_TYPE_A, "A", 1, 1, type_a_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 2 */
	{LDNS_RR_TYPE_NS, "NS", 1, 1, type_ns_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 3 */
	{LDNS_RR_TYPE_MD, "MD", 1, 1, type_md_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 4 */ 
	{LDNS_RR_TYPE_MF, "MF", 1, 1, type_mf_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 5 */
	{LDNS_RR_TYPE_CNAME, "CNAME", 1, 1, type_cname_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 6 */
	{LDNS_RR_TYPE_SOA, "SOA", 7, 7, type_soa_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 7 */
	{LDNS_RR_TYPE_MB, "MB", 1, 1, type_mb_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 8 */
	{LDNS_RR_TYPE_MG, "MG", 1, 1, type_mg_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 9 */
	{LDNS_RR_TYPE_MR, "MR", 1, 1, type_mr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 10 */
	{LDNS_RR_TYPE_NULL, "NULL", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 11 */
	{LDNS_RR_TYPE_WKS, "WKS", 2, 2, type_wks_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 12 */
	{LDNS_RR_TYPE_PTR, "PTR", 1, 1, type_ptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 13 */
	{LDNS_RR_TYPE_HINFO, "HINFO", 2, 2, type_hinfo_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 14 */
	{LDNS_RR_TYPE_MINFO, "MINFO", 2, 2, type_minfo_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 15 */
	{LDNS_RR_TYPE_MX, "MX", 2, 2, type_mx_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS },
	/* 16 */
	{LDNS_RR_TYPE_TXT, "TXT", 1, 0, NULL, LDNS_RDF_TYPE_STR, LDNS_RR_COMPRESS },
	/* 17 */
	{LDNS_RR_TYPE_RP, "RP", 2, 2, type_rp_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 18 */
	{LDNS_RR_TYPE_AFSDB, "AFSDB", 2, 2, type_afsdb_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 19 */
	{LDNS_RR_TYPE_X25, "X25", 1, 1, type_x25_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 20 */
	{LDNS_RR_TYPE_ISDN, "ISDN", 1, 2, type_isdn_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 21 */
	{LDNS_RR_TYPE_RT, "RT", 2, 2, type_rt_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 22 */
	{LDNS_RR_TYPE_NSAP, "NSAP", 1, 1, type_nsap_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 23 */
	{LDNS_RR_TYPE_NSAP_PTR, "NSAP-PTR", 1, 1, type_nsap_ptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 24 */
	{LDNS_RR_TYPE_SIG, "SIG", 9, 9, type_sig_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 25 */
	{LDNS_RR_TYPE_KEY, "KEY", 4, 4, type_key_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 26 */
	{LDNS_RR_TYPE_PX, "PX", 3, 3, type_px_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 27 */
	{LDNS_RR_TYPE_GPOS, "GPOS", 1, 1, type_gpos_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 28 */
	{LDNS_RR_TYPE_AAAA, "AAAA", 1, 1, type_aaaa_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 29 */
	{LDNS_RR_TYPE_LOC, "LOC", 1, 1, type_loc_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 30 */
	{LDNS_RR_TYPE_NXT, "NXT", 2, 2, type_nxt_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 31 */
	{LDNS_RR_TYPE_EID, "EID", 1, 1, type_eid_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 32 */
	{LDNS_RR_TYPE_NIMLOC, "NIMLOC", 1, 1, type_nimloc_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 33 */
	{LDNS_RR_TYPE_SRV, "SRV", 4, 4, type_srv_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 34 */
	{LDNS_RR_TYPE_ATMA, "ATMA", 1, 1, type_atma_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 35 */
	{LDNS_RR_TYPE_NAPTR, "NAPTR", 6, 6, type_naptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 36 */
	{LDNS_RR_TYPE_KX, "KX", 2, 2, type_kx_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 37 */
	{LDNS_RR_TYPE_CERT, "CERT", 4, 4, type_cert_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 38 */
	{LDNS_RR_TYPE_A6, "A6", 1, 1, type_a6_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 39 */
	{LDNS_RR_TYPE_DNAME, "DNAME", 1, 1, type_dname_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 40 */
	{LDNS_RR_TYPE_SINK, "SINK", 1, 1, type_sink_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 41 */
	{LDNS_RR_TYPE_OPT, "OPT", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 42 */
	{LDNS_RR_TYPE_APL, "APL", 0, 0, type_apl_wireformat, LDNS_RDF_TYPE_APL, LDNS_RR_NO_COMPRESS },
	/* 43 */
	{LDNS_RR_TYPE_DS, "DS", 4, 4, type_ds_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 44 */
	{LDNS_RR_TYPE_SSHFP, "SSHFP", 3, 3, type_sshfp_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 45 */
	{LDNS_RR_TYPE_IPSECKEY, "IPSECKEY", 1, 1, type_ipseckey_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 46 */
	{LDNS_RR_TYPE_RRSIG, "RRSIG", 9, 9, type_rrsig_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS },
	/* 47 */
	{LDNS_RR_TYPE_NSEC, "NSEC", 2, 2, type_nsec_wireformat, LDNS_RDF_TYPE_NSEC, LDNS_RR_NO_COMPRESS },
	/* 48 */
	{LDNS_RR_TYPE_DNSKEY, "DNSKEY", 4, 4, type_dnskey_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS }
};
/** \endcond */

/** 
 * \def RDATA_FIELD_DESCRIPTORS_COUNT
 * computes the number of rdata fields
 */
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

ldns_rr_type
ldns_rr_get_type_by_name(const char *name)
{
	unsigned int i;
	const char *desc_name;
	const ldns_rr_descriptor *desc;
	
	/* TYPEXX representation */
	if (strlen(name) > 4 && strncasecmp(name, "TYPE", 4) == 0) {
		return atoi(name + 4);
	}
	
	/* Normal types */
	for (i = 0; i < (unsigned int) RDATA_FIELD_DESCRIPTORS_COUNT; i++) {
		desc = ldns_rr_descript(i);
		desc_name = desc->_name;
		if(desc_name &&
		   strlen(name) == strlen(desc_name) &&
		   strncasecmp(name, desc_name, strlen(desc_name)) == 0
		) {
			return i;
		}
	}
	
	/* special cases for query types */
	/* TODO: generalize? */
	if (strlen(name) == 4 && strncasecmp(name, "IXFR", 4) == 0) {
		return 251;
	} else if (strlen(name) == 4 && strncasecmp(name, "AXFR", 4) == 0) {
		return 252;
	} else if (strlen(name) == 5 && strncasecmp(name, "MAILB", 5) == 0) {
		return 253;
	} else if (strlen(name) == 5 && strncasecmp(name, "MAILA", 5) == 0) {
		return 254;
	} else if (strlen(name) == 3 && strncasecmp(name, "ANY", 3) == 0) {
		return 255;
	}
	
	return 0;
}

ldns_rr_class
ldns_rr_get_class_by_name(const char *name)
{
	ldns_lookup_table *lt;
	
	/* CLASSXX representation */
	if (strlen(name) > 5 && strncasecmp(name, "CLASS", 5) == 0) {
		return atoi(name + 5);
	}
	
	/* Normal types */
	lt = ldns_lookup_by_name(ldns_rr_classes, name);

	if (lt) {
		return lt->id;
	}
	return 0;
}

ldns_rr *
ldns_rr_clone(ldns_rr *rr)
{
	uint16_t i;
	
	ldns_rr *new_rr = ldns_rr_new();
	ldns_rr_set_owner(new_rr, ldns_rdf_clone(ldns_rr_owner(rr)));
	ldns_rr_set_ttl(new_rr, ldns_rr_ttl(rr));
	ldns_rr_set_type(new_rr, ldns_rr_get_type(rr));
	ldns_rr_set_class(new_rr, ldns_rr_get_class(rr));
	
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		ldns_rr_push_rdf(new_rr, ldns_rdf_clone(ldns_rr_rdf(rr, i)));
	}

	return new_rr;
}

static int
qsort_rr_compare(const void *a, const void *b)
{
	const ldns_rr *rr1 = * (const ldns_rr **) a;
	const ldns_rr *rr2 = * (const ldns_rr **) b;
	return ldns_rr_compare(rr1, rr2);
}

/**
 * sort an rr_list. the sorting is done inband
 * \param[in] unsorted the rr_list to be sorted
 */
void
ldns_rr_list_sort(ldns_rr_list *unsorted)
{
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare);
}


/**
 * Compare two rr
 * \param[in] rr1 the first one
 * \parma[in] rr2 the second one
 * \return 0 if equal
 *         -1 if rr1 comes before rr2
 *         +1 if rr2 comes before rr1
 */
int
ldns_rr_compare(const ldns_rr *rr1, const ldns_rr *rr2)
{
	ldns_buffer *rr1_buf;
	ldns_buffer *rr2_buf;
	size_t rr1_len;
	size_t rr2_len;
	size_t i;

	rr1_len = ldns_rr_uncompressed_size(rr1);
	rr2_len = ldns_rr_uncompressed_size(rr2);

	if (rr1_len < rr2_len) {
		return -1;
	} else if (rr1_len > rr2_len) {
		return +1;
	} else {
		/* equal length */
	
		rr1_buf = ldns_buffer_new(rr1_len);
		rr2_buf = ldns_buffer_new(rr2_len);

		if (ldns_rr2buffer_wire(rr1_buf, rr1, LDNS_SECTION_ANY) != LDNS_STATUS_OK) {
			return 0; /* XXX uhm, tja */
		}
		if (ldns_rr2buffer_wire(rr2_buf, rr2, LDNS_SECTION_ANY) != LDNS_STATUS_OK) {
			return 0;
		}
		/* now compare the buffer's byte for byte */
		/* < or <= ??? XXX */
		for(i = 0; i < rr1_len; i++) {
			if (ldns_buffer_at(rr1_buf, i) < 
				ldns_buffer_at(rr2_buf, i)) {
				return -1;
			} else if (ldns_buffer_at(rr1_buf, i) >
					ldns_buffer_at(rr2_buf, i)) {
				return +1;
			}
		}
	return 0;
	}
}


/** 
 * calculate the uncompressed size of an RR
 * \param[in] rr the rr to operate on
 * \return size of the rr
 */
size_t
ldns_rr_uncompressed_size(const ldns_rr *r)
{
	size_t rrsize;
	uint16_t i;

	rrsize = 0;
	/* add all the rdf sizes */
	for(i = 0; i < ldns_rr_rd_count(r); i++) {
		rrsize += ldns_rdf_size(ldns_rr_rdf(r, i));
	}
	/* ownername */
	rrsize += ldns_rdf_size(ldns_rr_owner(r));
	rrsize += RR_OVERHEAD;
	return rrsize;
}
