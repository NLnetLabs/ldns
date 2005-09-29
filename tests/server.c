/*
 * Small server implementation 
 * that prints out everything it receives
 */

#include "config.h"

#include <ldns/dns.h>

int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s\n", prog);
	fprintf(fp, "  run a small mirroring server\n");
	return 0;
}

int
main(void)
{
	/* setup a socket, listen for incomings, print them out */
	int sockfd;



		

	
}
