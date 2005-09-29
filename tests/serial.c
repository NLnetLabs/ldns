#include "config.h"

#include <ldns/dns.h>

void 
test_serial(uint32_t a, uint32_t b)
{
	printf("%d : %d\n", a, b);

	printf("%d\n",
			ldns_serial(a,b));
}

int 
main(void)
{
	/* serial tests */
	test_serial(1, 1);
	test_serial(1, 2);
	test_serial(2, 1);
	test_serial(0, 0);

	
}

