

#include "config.h"
#include <ldns/ldns.h>

static int
check_option_entries(ldns_edns_option *edns, ldns_edns_option_code code,
	size_t size, uint8_t *hex_data)
{
	size_t i;
	uint8_t *edns_data;
	ldns_buffer *buf;

	if (ldns_edns_get_size(edns) != size) {
		printf("Error: EDNS size is incorrect\n");
		return 0;
	}
	if (ldns_edns_get_code(edns) != code) {
		printf("Error: EDNS code is incorrect\n");
		return 0;
	}

	edns_data = ldns_edns_get_data(edns);
	if (!(edns_data)) {
		printf("Error: EDNS data is not returned\n");
		return 0;
	}
	for (i = 0; i < size; i++) {
		if (edns_data[i] != hex_data[i]) {
			printf("Error: EDNS data is incorrect\n");
			return 0;
		}
	}

	buf = ldns_edns_get_wireformat_buffer(edns);
	if (ldns_buffer_read_u16(buf) != code) {
		printf("Error: EDNS type is incorrect\n");
		return 0;
	}
	if (ldns_buffer_read_u16(buf) != size) {
		printf("Error: EDNS length is incorrect\n");
		return 0;	
	}

	for (i = 0; i < size; i++) {
		if (ldns_buffer_read_u8_at(buf, i+4) != hex_data[i]) {
			printf("Error: EDNS data is incorrect: %d, %d\n",
				ldns_buffer_read_u8_at(buf, i+4), hex_data[i]);
			return 0;
		}
	}

	return 1;
}

static int
check_option()
{
	ldns_edns_option *edns;
	ldns_edns_option *clone;
	uint8_t *data = LDNS_XMALLOC(uint8_t, 4);
	
	uint8_t hex_data[] = {74, 65, 73, 74};

	/* Fill the data with "test" in hex */
	data[0] = hex_data[0];
	data[1] = hex_data[1];
	data[2] = hex_data[2];
	data[3] = hex_data[3];

	edns = ldns_edns_new(LDNS_EDNS_EDE, 4, data);

	if (!(check_option_entries(edns, LDNS_EDNS_EDE, 4, hex_data))) {
		return 0;
	}

	ldns_edns_free(edns);

	edns = ldns_edns_new_from_data(LDNS_EDNS_EDE, 4, hex_data);

	if (!(check_option_entries(edns, LDNS_EDNS_EDE, 4, hex_data))) {
		return 0;
	}

	clone = ldns_edns_clone(edns);

	if (!(check_option_entries(clone, LDNS_EDNS_EDE, 4, hex_data))) {
		return 0;
	}

	ldns_edns_deep_free(edns);
	ldns_edns_deep_free(clone);

	return 1;
}

static int check_option_list_entries(ldns_edns_option_list *list,
	ldns_edns_option *option, size_t count, ldns_edns_option_code code, size_t size,
	uint8_t *hex_data)
{
	size_t c = ldns_edns_option_list_get_count(list);

	if (c != count) {
		printf("Error: EDNS list count is incorrect\n");
		return 0;
	}

	if (!(option)) {
		printf("Error: EDNS list option setter doesn't return option\n");
		return 0;
	}

	if (!(check_option_entries(option, code, size, hex_data))) {
		printf("Error: EDNS list option is incorrect\n");
		return 0;
	}

	return 1;
}

static int
check_option_list()
{
	size_t size, i;
	ldns_edns_option_list* list;
	ldns_edns_option_list* clone;
	ldns_edns_option *option;
	ldns_edns_option *copy;
	ldns_edns_option *pop;
	ldns_buffer *buf;
	uint8_t hex_data[] = {74, 65, 73, 74};
	uint8_t hex_data2[] = {74, 65, 73, 74, 74};

	list = ldns_edns_option_list_new(); // don't verify, this function asserts

	/* Add first option */
	option = ldns_edns_new_from_data(LDNS_EDNS_EDE, 4, hex_data);

	if (ldns_edns_option_list_get_count(list)) {
		printf("Error: EDNS list count is incorrect after init\n");
		return 0;
	}

	ldns_edns_option_list_push(list, option);

	copy = ldns_edns_option_list_get_option(list, 0);

	if (!(check_option_list_entries(list, copy, 1, LDNS_EDNS_EDE, 4, hex_data))) {
		printf("Error: EDNS list entries are incorrect\n");
		return 0;
	}

	size = ldns_edns_option_list_get_options_size(list);

	if (size != 8) { // size of the data + 4 for the code and size
		printf("Error: EDNS list total option size is incorrect\n");
		return 0;
	}

	/* Add second option */
	option = ldns_edns_new_from_data(LDNS_EDNS_PADDING, 5, hex_data2);

	ldns_edns_option_list_push(list, option);

	if (!(check_option_list_entries(list, option, 2, LDNS_EDNS_PADDING, 5, hex_data2))) {
		printf("Error: EDNS list entries are incorrect\n");
		return 0;
	}

	buf = ldns_edns_option_list2wireformat_buffer(list);

	if (!(buf)) {
		printf("Error: EDNS list entries list2wireformat buffer is NULL\n");
		return 0;
	}

	/* Verify the wireformat options with the hex data */
	ldns_buffer_skip(buf, 4);

	for (i = 0; i < 4; i++) {
		if (ldns_buffer_read_u8(buf) != hex_data[i]) {
			printf("Error: EDNS data is incorrect: %d, %d\n",
				ldns_buffer_read_u8_at(buf, i), hex_data[i]);
			return 0;
		}
	}

	ldns_buffer_skip(buf, 4);

	for (i = 0; i < 5; i++) {
		if (ldns_buffer_read_u8(buf) != hex_data2[i]) {
			printf("Error: EDNS data is incorrect: %d, %d\n",
				ldns_buffer_read_u8_at(buf, i), hex_data2[i]);
			return 0;
		}
	}

	/* Replace the first option with a copy of the second */
	option = ldns_edns_new_from_data(LDNS_EDNS_PADDING, 5, hex_data2);

	pop = ldns_edns_option_list_set_option(list, option, 0);

	if (!(check_option_list_entries(list, pop, 2, LDNS_EDNS_EDE, 4, hex_data))) {
		printf("Error: EDNS list entries are incorrect\n");
		return 0;
	}

	ldns_edns_deep_free(pop);

	/* Remove one option from the list */

	pop = ldns_edns_option_list_pop(list);

	if (!(check_option_list_entries(list, option, 1, LDNS_EDNS_PADDING, 5, hex_data2))) {
		printf("Error: EDNS list entries are incorrect\n");
		return 0;
	}

	ldns_edns_deep_free(pop);

	/* Clone the list */
	clone = ldns_edns_option_list_clone(list);

	if (!(clone)) {
		printf("Error: EDNS list clone does not exist\n");
		return 0;
	}

	if (!(check_option_list_entries(clone, option, 1, LDNS_EDNS_PADDING, 5, hex_data2))) {
		printf("Error: EDNS list entries are incorrect\n");
		return 0;
	}

	/* Remove final entry from cloned list */
	pop = ldns_edns_option_list_pop(list);

	ldns_edns_deep_free(pop);

	if (ldns_edns_option_list_get_count(clone) == 0) {
		printf("Error: EDNS list entries are incorrect at zero\n");
		return 0;
	}

	ldns_edns_option_list_free(clone);

	ldns_edns_option_list_deep_free(list);

	return 1;
}

int main(void)
{
	int result = EXIT_SUCCESS;
	
	if (!check_option()) {
		printf("check_option() failed.\n");
		result = EXIT_FAILURE;
	}
	if (!check_option_list()) {
		printf("check_option_list() failed.\n");
		result = EXIT_FAILURE;
	}

	exit(result);
}
