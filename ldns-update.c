/* $Id: ldns-update.c,v 1.1 2005/09/13 09:37:05 ho Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <ldns/config.h>

#include <ldns/dns.h>

int
main(int argc, char **argv)
{
	char		*fqdn, *ipaddr, *zone;
	u_int16_t	defttl = 300;
	ldns_status	ret;
	ldns_tsig_credentials	tsig_cr, *tsig_cred;
	int		c = 2;
	
	switch (argc) {
	case 3:
	case 4:
	case 6:
	case 7:
		break;
	default:
		fprintf(stderr, "usage: %s FQDN [zone] IP "
		    "[tsig_name tsig_alg tsig_hmac]\n", argv[0]);
		fprintf(stderr, "Example: %s my.host.org 1.2.3.4\n", argv[0]);
		fprintf(stderr, "Use 'none' instead of IP to remove any "
		    "previous address.\n");
		fprintf(stderr, "If 'zone' is not specified, "
		    "try to figure it from SOA.\n");
		exit(1);
	}

	fqdn = argv[1]; 
	c = 2;
	if (argc == 4 || argc == 7)
		zone = argv[c++];
	else
		zone = NULL;
	
	if (strcmp(argv[c], "none") == 0)
		ipaddr = NULL;
	else
		ipaddr = argv[c];
	c++;
	if (argc == 6 || argc == 7) {
		tsig_cr.keyname = argv[c++];
		if (strncasecmp(argv[c], "hmac-sha1", 9) == 0)
			tsig_cr.algorithm = "hmac-sha1.";
		else if (strncasecmp(argv[c], "hmac-md5", 8) == 0)
			tsig_cr.algorithm = "hmac-md5.sig-alg.reg.int.";
		else {
			fprintf(stderr, "Unknown algorithm, try \"hmac-md5\" "
			    "or \"hmac-sha1\".\n");
			exit(1);
		}
		tsig_cr.keydata = argv[++c];
		tsig_cred = &tsig_cr;
	} else
		tsig_cred = NULL;

	printf(";; trying UPDATE with FQDN \"%s\" and IP \"%s\"\n",
	    fqdn, ipaddr ? ipaddr : "<none>");
	printf(";; tsig: \"%s\" \"%s\" \"%s\"\n", tsig_cr.keyname,
	    tsig_cr.algorithm, tsig_cr.keydata);

	ret = ldns_update_send_simple_A(fqdn, zone, ipaddr, defttl, tsig_cred);
	exit(ret);
}
