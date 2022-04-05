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

ldns_edns_option_list*
ldns_edns_option_list_new()
{
    ldns_edns_option_list *options_list = LDNS_MALLOC(ldns_edns_option_list);
    if(!options_list) {
        return NULL;
    }

    options_list->_option_count = 0;
    options_list->_options = NULL;
    return options_list;
}

void
ldns_edns_option_list_free(ldns_edns_option_list *options_list)
{
    if (options_list) {
        LDNS_FREE(options_list->_options);
        LDNS_FREE(options_list);
    }
}

void
ldns_edns_option_list_deep_free(ldns_edns_option_list *options_list)
{
    size_t i;

    if (options_list) {
        for (i=0; i < ldns_edns_option_list_get_count(options_list); i++) {
            ldns_edns_deep_free(ldns_edns_option_list_get_option(options_list, i));
        }
        ldns_edns_option_list_free(options_list);
    }
}


size_t
ldns_edns_option_list_get_count(const ldns_edns_option_list *options_list)
{
    if (options_list) {
        return options_list->_option_count;
    } else {
        return 0;
    }
}

void
ldns_edns_option_list_set_count(ldns_edns_option_list *options_list, size_t count)
{
    assert(options_list); // @TODO does this check need to check more?
    options_list->_option_count = count;
}

ldns_edns_option *
ldns_edns_option_list_get_option(const ldns_edns_option_list *options_list, size_t index)
{
    if (index < ldns_edns_option_list_get_count(options_list)) {
        return options_list->_options[index];
    } else {
        return NULL;
    }
}

ldns_edns_option *
ldns_edns_option_list_set_option(ldns_edns_option_list *options_list,
    const ldns_edns_option *option, size_t index)
{
    ldns_edns_option* old;

    assert(options_list != NULL);

    if (index < ldns_edns_option_list_get_count(options_list)) {
        return NULL;
    }

    if (option == NULL) {
        return NULL;
    }

    old = ldns_edns_option_list_get_option(options_list, index);

    /* overwrite the pointer of "old" */
    options_list->_options[index] = (ldns_edns_option*)option;
    return old;
}

bool
ldns_edns_option_list_push(ldns_edns_option_list *options_list,
    const ldns_edns_option *option)
{
    assert(options_list != NULL);

    if (option != NULL) {

        // @TODO rethink reallocing per push

        options_list->_options = LDNS_XREALLOC(options_list->_options, ldns_edns_option *,
            options_list->_option_count + 1);
        if (!options_list) {
            return false;
        }
        ldns_edns_option_list_set_option(options_list, option,
            options_list->_option_count);
        options_list->_option_count += 1;

        return true;
    }
    return false;
}

ldns_edns_option *
ldns_edns_option_list_pop(ldns_edns_option_list *options_list)
{
    ldns_edns_option ** new_list;
    ldns_edns_option* pop;
    size_t count;

    assert(options_list != NULL);

    count = ldns_edns_option_list_get_count(options_list);

    if (count == 0){
        return NULL;
    }
    /* get the last option from the list */
    pop = ldns_edns_option_list_get_option(options_list, count-1);

    // @TODO rethink reallocing per pop

    /* shrink the array */
    new_list = LDNS_XREALLOC(options_list->_options, ldns_edns_option *, count -1);
    if (new_list){
        options_list->_options = new_list;
    }

    ldns_edns_option_list_set_count(options_list, count - 1);

    return pop;
}

