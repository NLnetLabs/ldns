/*
 * rr_functions.h
 *
 * the .h file with defs for the per rr
 * functions
 *
 * a Net::DNS like library for C
 * 
 * (c) NLnet Labs, 2004
 * 
 * See the file LICENSE for the license
 */
#ifndef _RR_FUNCTIONS_H
#define _RR_FUNCTIONS_H

#define _LDNS_RR_FUNCTION(RR, POS, TYPE)		\
        if (!(RR) || (ldns_rr_get_type((RR)) != (TYPE))) {	\
                return false;				\
        } 						\
        return ldns_rr_rdf((RR), (POS));		

#define _LDNS_RR_SET_FUNCTION(RR, RDF, POS, TYPE)	\
        ldns_rdf *pop;					\
        if (!(RR) || (ldns_rr_get_type((RR)) != (TYPE))) {	\
                return false;				\
        } 						\
        pop = ldns_rr_set_rdf((RR), (RDF), (POS));	\
        if (pop) {					\
                FREE(pop);				\
                return true;				\
        } else {					\
                return false;				\
        }						

#endif /* _RR_FUNCTIONS_H */
