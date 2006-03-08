/* print output of ldns-pcat-diff in DNS packet form
 * is at all possible*/

#define _GNU_SOURCE

#include "config.h"

#include <ldns/dns.h>

#define SEQUENCE 1
#define QUERY    2
#define ANSWER1  3
#define ANSWER2  0

void
usage(FILE *fp)
{
        fprintf(fp, "pcat-print [-h] FILE\n\n");
        fprintf(fp, "Read the output if pcat-diff and try to convert the\n");
        fprintf(fp, "hex dump back in the DNS packets. Then print those packets\n");
	fprintf(fp, "to standard output or print the error in case the conversion failed \n");
        fprintf(fp, "There are no options, is FILE is not given, standard input is read\n");
        fprintf(fp, "\nOUTPUT FORMAT:\n");
        fprintf(fp, "  Each record consists of an index and then three packets.\n");
        fprintf(fp, "  Each packet is seperated by a line of '='s.\n");
        fprintf(fp, "    Index: xxx:xxx\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    query packet\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    first answer/qeury packet\n");
        fprintf(fp, "    ==============\n");
        fprintf(fp, "    second answer/qeury packet\n");
        fprintf(fp, "    ==============\n");
}

void
printf_bar(void)
{
	fprintf(stdout, "===================================================================\n");
}

int
main(int argc, char **argv)
{
	ssize_t read;
	char *line;
	size_t i, j, k, len;
	u_char pkt_buf[LDNS_MAX_PACKETLEN];
	ldns_pkt *p;
	ldns_status s;

	i = 1;
	len = 0;

	while((read = getline(&line, &len, stdin)) != -1) {
		/* sequence stuff 
		 * query
		 * adata1
		 * adata2
		 */
		line[read - 1] = '\0';
		switch(i % 4) {
			case SEQUENCE:
				printf("Index: %s\n", line);
				printf_bar();
				break;
			case QUERY:
			case ANSWER1:
			case ANSWER2:
				k = 0;
				for(j = 0; j < read - 1; j += 2) {
					pkt_buf[k] = 
						ldns_hexdigit_to_int(line[j]) * 16 +
						ldns_hexdigit_to_int(line[j + 1]);
					k++;
				}
				s = ldns_wire2pkt(&p, pkt_buf, k);
				if (s != LDNS_STATUS_OK) {
					fprintf(stderr, "%s\n", ldns_get_errorstr_by_id(s));
				} else {
					ldns_pkt_print(stdout, p);
				}
				printf_bar();
				break;
		}
		i++;
		len = 0;
	}
	return 0;
}
