/*
 * edns.c
 *
 * edns implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2022
 *
 * See the file LICENSE for the license
 */

#include <ldns/ldns.h>

/*
 * Access functions 
 * functions to get and set type checking
 */

/* read */
size_t
ldns_edns_get_size(const ldns_edns_option *edns)
{
    assert(edns != NULL);
    return edns->_size;
}

ldns_edns_option_code
ldns_edns_get_code(const ldns_edns_option *edns)
{
    assert(edns != NULL);
    return edns->_code;
}

uint8_t *
ldns_edns_get_data(const ldns_edns_option *edns)
{
    assert(edns != NULL);
    return edns->_data;
}


/* write */
void
ldns_edns_set_size(ldns_edns_option *edns, size_t size)
{
    assert(edns != NULL);
    edns->_size = size;
}

void
ldns_edns_set_code(ldns_edns_option *edns, ldns_edns_option_code code)
{
    assert(edns != NULL);
    edns->_code = code;
}

void
ldns_edns_set_data(ldns_edns_option *edns, void *data)
{
    /* only copy the pointer */
    assert(edns != NULL); 
    edns->_data = data;
}

/* note: data must be allocated memory */
ldns_edns_option *
ldns_edns_new(ldns_edns_option_code code, size_t size, void *data)
{
    ldns_edns_option *edns;
    edns = LDNS_MALLOC(ldns_edns_option);
    if (!edns) {
        return NULL;
    }
    ldns_edns_set_size(edns, size);
    ldns_edns_set_code(edns, code);
    ldns_edns_set_data(edns, data);
    return edns;
}

void
ldns_edns_deep_free(ldns_edns_option *edns)
{
    if (edns) {
        if (edns->_data) {
            LDNS_FREE(edns->_data);
        }
        LDNS_FREE(edns);
    }
}

void 
ldns_edns_free(ldns_edns_option *edns)
{
    if (edns) {
        LDNS_FREE(edns);
    }
}
