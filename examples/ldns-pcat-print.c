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
	size_t seq;
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
