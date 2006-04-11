/* $Id: ldns-update.c,v 1.1 2005/09/13 09:37:05 ho Exp $ */
/*
 * Example of the update functionality
 *
 * See the file LICENSE for the license
 */


#include "config.h"

#include <strings.h>
#include <ldns/dns.h>


void
usage(FILE *fp, char *prog) {
        fprintf(fp, "%s domain [zone] ip tsig_name tsig_alg tsig_hmac\n", prog);
        fprintf(fp, "  send a dynamic update packet to <ip>\n\n");
        fprintf(fp, "  Use 'none' instead of ip to remove any previous address\n");
        fprintf(fp, "  If 'zone'  is not specified, try to figure it out from the zone's SOA\n");
        fprintf(fp, "  Example: %s my.example.org 1.2.3.4\n", prog);
}


int
main(int argc, char **argv)
{
	char		*fqdn, *ipaddr, *zone, *prog;
	ldns_status	ret;
	ldns_tsig_credentials	tsig_cr, *tsig_cred;
	int		c = 2;
	uint16_t	defttl = 300;
	uint16_t 	port = 53;
	
	prog = strdup(argv[0]);

	switch (argc) {
	case 3:
	case 4:
	case 6:
	case 7:
		break;
	default:
		usage(stderr, prog);
		exit(EXIT_FAILURE);
	}

	fqdn = argv[1]; 
	c = 2;
	if (argc == 4 || argc == 7) {
		zone = argv[c++];
	} else {
		zone = NULL;
	}
	
	if (strcmp(argv[c], "none") == 0) {
		ipaddr = NULL;
	} else {
		ipaddr = argv[c];
	}
	c++;
	if (argc == 6 || argc == 7) {
		tsig_cr.keyname = argv[c++];
		if (strncasecmp(argv[c], "hmac-sha1", 9) == 0) {
			tsig_cr.algorithm = (char*)"hmac-sha1.";
		} else if (strncasecmp(argv[c], "hmac-md5", 8) == 0) {
			tsig_cr.algorithm = (char*)"hmac-md5.sig-alg.reg.int.";
		} else {
			fprintf(stderr, "Unknown algorithm, try \"hmac-md5\" "
			    "or \"hmac-sha1\".\n");
			exit(EXIT_FAILURE);
		}
		tsig_cr.keydata = argv[++c];
		tsig_cred = &tsig_cr;
	} else {
		tsig_cred = NULL;
	}

	printf(";; trying UPDATE with FQDN \"%s\" and IP \"%s\"\n",
	    fqdn, ipaddr ? ipaddr : "<none>");
	printf(";; tsig: \"%s\" \"%s\" \"%s\"\n", tsig_cr.keyname,
	    tsig_cr.algorithm, tsig_cr.keydata);

	ret = ldns_update_send_simple_addr(fqdn, zone, ipaddr, port, defttl, tsig_cred);
	exit(ret);
}
