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

#include <ldns/rdata.h>
#include <ldns/error.h>

#include "util.h"

/* Access functions 
 * do this as functions to get type checking
 */

/* read */
uint16_t
_ldns_rdf_size(ldns_rdf *rd)
{
	return rd->_size;
}

ldns_rdf_type
_ldns_rdf_type(ldns_rdf *rd)
{
	return rd->_type;
}

uint8_t *
_ldns_rdf_data(ldns_rdf *rd)
{
	return rd->_data;
}

/* write */
void
_ldns_rdf_set_size(ldns_rdf *rd, uint16_t s)
{
	rd->_size = s;
}

void
_ldns_rdf_set_type(ldns_rdf *rd, ldns_rdf_type t)
{
	rd->_type = t;
}

void
_ldns_rdf_set_data(ldns_rdf *rd, uint8_t *d)
{
	/* only copy the pointer */
	rd->_data = d;
}

/**
 * Allocate a new ldns_rdf structure 
 * fill it and return it
 */
ldns_rdf *
ldns_rdf_new(uint16_t s, ldns_rdf_type t, uint8_t *d)
{
	ldns_rdf *rd;
	rd = MALLOC(ldns_rdf);
	if (!rd) {
		return NULL;
	}

	_ldns_rdf_set_size(rd, s);
	_ldns_rdf_set_type(rd, t);
	_ldns_rdf_set_data(rd, d);
	return rd;
}

void 
_ldns_rdf_destroy(ldns_rdf *rd)
{
	rd = NULL; /* kuch */
	/* empty */
}

/**
 * remove \\DDD, \\[space] and other escapes from the input
 * See RFC 1035, section 5.1
 * Return the length of the string or a negative error
 * code
 */
ldns_status
_ldns_octet(char *word, size_t *length)
{
    char *s; char *p;
    *length = 0;

    for (s = p = word; *s != '\0'; s++,p++) {
        switch (*s) {
            case '.':
                if (s[1] == '.') {
                    fprintf(stderr,"Empty label");
		    return LDNS_STATUS_EMPTY_LABEL;
                }
                *p = *s;
                *length++;
                break;
            case '\\':
                if ('0' <= s[1] && s[1] <= '9' &&
                    '0' <= s[2] && s[2] <= '9' &&
                    '0' <= s[3] && s[3] <= '9')
                {
                    /* \DDD seen */
                    int val = ((s[1] - '0') * 100 +
                           (s[2] - '0') * 10 + (s[3] - '0'));

                    if (0 <= val && val <= 255) {
                        /* this also handles \0 */
                        s += 3;
                        *p = val;
                        *length++;
                    } else {
                        return LDNS_STATUS_DDD_OVERFLOW;
                    }
                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    *p = *++s;
                    *length++;
                }
                break;
            case '\"':
                /* non quoted " Is either first or the last character in
                 * the string */

                *p = *++s; /* skip it */
                *length++;
		/* I'm not sure if this is needed in libdns... MG */
                if ( *s == '\0' ) {
                    /* ok, it was the last one */
                    *p  = '\0'; 
		    return LDNS_STATUS_OK;
                }
                break;
            default:
                *p = *s;
                *length++;
                break;
        }
    }
    *p = '\0';
    return LDNS_STATUS_OK;
}
