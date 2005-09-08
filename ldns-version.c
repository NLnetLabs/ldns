/*
 * version. Show ldns's version 
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * Licensed under the GPL version 2
 */

#include <ldns/config.h>
#include <ldns/dns.h>

int
main(void)
{
	printf("%s\n", ldns_version());
        return 0;
}
