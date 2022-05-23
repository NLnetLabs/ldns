

#include "config.h"

#include <ldns/ldns.h>

static int
check_option()
{
	ldns_edns_option *edns;
	uint8_t *data = LDNS_XMALLOC(uint8_t, 4);
	data[0] = 74;
	data[1] = 65;
	data[2] = 73;
	data[3] = 74;

	edns = ldns_edns_new(LDNS_EDNS_EDE, 4, data);

	if (ldns_edns_get_size(edns) != 4) {
		printf("Error: EDNS size is incorrect\n");
		return 1;
	}
	if (ldns_edns_get_code(edns) != LDNS_EDNS_EDE) {
		printf("Error: EDNS code is incorrect\n");
		return 1;
	}
	// if (ldns_edns_get_data(edns)) {}
	// if (ldns_edns_get_wireformat_buffer(edns)) {}



	// ldns_edns_option *edns2 = ldns_edns_new_from_data(LDNS_EDNS_EDE, size_t size, const void *data);

	return 0;
}

int main(void)
{
	int result = EXIT_SUCCESS;
	
	if (!check_option()) {
		printf("check_option() failed.\n");
		result = EXIT_FAILURE;
	}

	exit(result);
}
