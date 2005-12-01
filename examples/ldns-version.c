/*
 * version. Show ldns's version 
 * for a particulary domain
 * (c) NLnet Labs, 2005
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/dns.h>

int
main(void)
{
	printf("%s\n", ldns_version());
        return 0;
}
