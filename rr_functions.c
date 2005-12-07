/*
 * rr_function.c
 *
 * function that operate on specific rr types
 *
 * (c) NLnet Labs, 2004, 2005
 * See the file LICENSE for the license
 */

/*
 * These come strait from perldoc Net::DNS::RR::xxx
 * first the read variant, then the write. This is
 * not complete.
 */

#include <ldns/config.h>

#include <ldns/dns.h>

#include <limits.h>
#include <strings.h>

/**
 * return a specific rdf
 * \param[in] type type of RR
 * \param[in] rr   the rr itself
 * \param[in] pos  at which postion to get it
 * \return the rdf sought
 */
static ldns_rdf *
ldns_rr_function(ldns_rr_type type, const ldns_rr *rr, size_t pos)
{
        if (!rr || ldns_rr_get_type(rr) != type) {
                return NULL;
        }
        return ldns_rr_rdf(rr, pos);
}

/**
 * set a specific rdf
 * \param[in] type type of RR
 * \param[in] rr   the rr itself
 * \param[in] rdf  the rdf to set
 * \param[in] pos  at which postion to set it
 * \return true or false
 */
static bool
ldns_rr_set_function(ldns_rr_type type, ldns_rr *rr, ldns_rdf *rdf, size_t pos)
{
        ldns_rdf *pop;
        if (!rr || ldns_rr_get_type(rr) != type) {
                return false;
        }
        pop = ldns_rr_set_rdf(rr, rdf, pos);
        if (pop) {
 		LDNS_FREE(pop);
                return true;
        } else {
                return true;
        }
}

/* A/AAAA records */
ldns_rdf *
ldns_rr_a_address(const ldns_rr *r)
{
	/* 2 types to check, cannot use the macro */
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

bool
ldns_rr_a_set_address(ldns_rr *r, ldns_rdf *f)
{
	/* 2 types to check, cannot use the macro... */
	ldns_rdf *pop;
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return false;
	}
	pop = ldns_rr_set_rdf(r, f, 0);
	if (pop) {
		LDNS_FREE(pop);
		return true;
	} else {
		return false;
	}
}
/* / A-AAAA records */

/* NS record */
ldns_rdf *
ldns_rr_ns_nsdname(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_NS, r, 0);
}
/* /NS record */

/* MX record */
ldns_rdf *
ldns_rr_mx_preference(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_MX, r, 0);
}

ldns_rdf *
ldns_rr_mx_exchange(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_MX, r, 1);
}
/* /MX record */

/* RRSIG record */
ldns_rdf *
ldns_rr_rrsig_typecovered(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 0);
}

bool
ldns_rr_rrsig_set_typecovered(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 0);
}

ldns_rdf *
ldns_rr_rrsig_algorithm(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 1);
}

bool
ldns_rr_rrsig_set_algorithm(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 1);
}

ldns_rdf *
ldns_rr_rrsig_labels(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 2);
}
bool
ldns_rr_rrsig_set_labels(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 2);
}

ldns_rdf *
ldns_rr_rrsig_origttl(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 3);
}
bool
ldns_rr_rrsig_set_origttl(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 3);
}

ldns_rdf *
ldns_rr_rrsig_expiration(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 4);
}
bool
ldns_rr_rrsig_set_expiration(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 4);
}

ldns_rdf *
ldns_rr_rrsig_inception(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 5);
}
bool
ldns_rr_rrsig_set_inception(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 5);
}

ldns_rdf *
ldns_rr_rrsig_keytag(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 6);
}

bool
ldns_rr_rrsig_set_keytag(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 6);
}
ldns_rdf *
ldns_rr_rrsig_signame(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 7);
}
bool
ldns_rr_rrsig_set_signame(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 7);
}

ldns_rdf *
ldns_rr_rrsig_sig(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 8);
}

bool
ldns_rr_rrsig_set_sig(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 8);
}
/* /RRSIG record */

/* DNSKEY record */
ldns_rdf *
ldns_rr_dnskey_flags(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 0);
}

bool
ldns_rr_dnskey_set_flags(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 0);
}

ldns_rdf *
ldns_rr_dnskey_protocol(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 1);
}

bool
ldns_rr_dnskey_set_protocol(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 1);
}
ldns_rdf *
ldns_rr_dnskey_algorithm(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 2);
}

bool
ldns_rr_dnskey_set_algorithm(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 2);
}
ldns_rdf *
ldns_rr_dnskey_key(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 3);
}

bool
ldns_rr_dnskey_set_key(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 3);
}

uint16_t 
ldns_rr_dnskey_key_size(const ldns_rr *key) {
	
	ldns_rdf *keydata;
	uint16_t length;
	
	keydata = ldns_rr_dnskey_key(key);

	length = ldns_rdf_size(keydata);
	/* calc back to the bit size */
	length = (length - 2) * 8;

	return length;
}

/* /DNSKEY record */
