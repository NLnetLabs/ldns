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
	ldns_edns_option_list *option_list = LDNS_MALLOC(ldns_edns_option_list);
	if(!option_list) {
		return NULL;
	}

	option_list->_option_count = 0;
	option_list->_options_size = 0;
	option_list->_options = NULL;
	return option_list;
}

void
ldns_edns_option_list_free(ldns_edns_option_list *option_list)
{
	if (option_list) {
		LDNS_FREE(option_list->_options);
		LDNS_FREE(option_list);
	}
}

void
ldns_edns_option_list_deep_free(ldns_edns_option_list *option_list)
{
	size_t i;

	if (option_list) {
		for (i=0; i < ldns_edns_option_list_get_count(option_list); i++) {
			ldns_edns_deep_free(ldns_edns_option_list_get_option(option_list, i));
		}
		ldns_edns_option_list_free(option_list);
	}
}


size_t
ldns_edns_option_list_get_count(const ldns_edns_option_list *option_list)
{
	if (option_list) {
		return option_list->_option_count;
	} else {
		return 0;
	}
}

void
ldns_edns_option_list_set_count(ldns_edns_option_list *option_list, size_t count)
{
	assert(option_list); // @TODO does this check need to check more?
	option_list->_option_count = count;
}

ldns_edns_option *
ldns_edns_option_list_get_option(const ldns_edns_option_list *option_list, size_t index)
{
	if (option_list && index < ldns_edns_option_list_get_count(option_list)) {
		return option_list->_options[index];
	} else {
		return NULL;
	}
}

size_t
ldns_edns_option_list_get_options_size(const ldns_edns_option_list *option_list)
{
	if (option_list) {
		return option_list->_options_size;
	} else {
		return 0;
	}
}


ldns_edns_option *
ldns_edns_option_list_set_option(ldns_edns_option_list *option_list,
	const ldns_edns_option *option, size_t index)
{
	ldns_edns_option* old;

	assert(option_list != NULL);

	if (index < ldns_edns_option_list_get_count(option_list)) {
		return NULL;
	}

	if (option == NULL) {
		return NULL;
	}

	old = ldns_edns_option_list_get_option(option_list, index);

	/* shrink the total EDNS size if the old EDNS option exists */
	if (old != NULL) {
		option_list->_options_size -= (ldns_edns_get_size(old) + 4);
	}

	option_list->_options_size += (ldns_edns_get_size(option) + 4);

	/* overwrite the pointer of "old" */
	option_list->_options[index] = (ldns_edns_option*)option;
	return old;
}

bool
ldns_edns_option_list_push(ldns_edns_option_list *option_list,
	const ldns_edns_option *option)
{
	assert(option_list != NULL);

	if (option != NULL) {

		// @TODO rethink reallocing per push

		option_list->_options = LDNS_XREALLOC(option_list->_options,
			ldns_edns_option *, option_list->_option_count + 1);
		if (!option_list) {
			return false;
		}
		ldns_edns_option_list_set_option(option_list, option,
			option_list->_option_count);
		option_list->_option_count += 1;

		return true;
	}
	return false;
}

ldns_edns_option *
ldns_edns_option_list_pop(ldns_edns_option_list *option_list)
{
	ldns_edns_option ** new_list;
	ldns_edns_option* pop;
	size_t count;

	assert(option_list != NULL);

	count = ldns_edns_option_list_get_count(option_list);

	if (count == 0){
		return NULL;
	}
	/* get the last option from the list */
	pop = ldns_edns_option_list_get_option(option_list, count-1);

	// @TODO rethink reallocing per pop

	/* shrink the array */
	new_list = LDNS_XREALLOC(option_list->_options, ldns_edns_option *, count -1);
	if (new_list){
		option_list->_options = new_list;
	}

	/* shrink the total EDNS size if the popped EDNS option exists */
	if (pop != NULL) {
		option_list->_options_size -= (ldns_edns_get_size(pop) + 4);
	}

	ldns_edns_option_list_set_count(option_list, count - 1);

	return pop;
}

