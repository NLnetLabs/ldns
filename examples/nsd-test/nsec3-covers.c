/*
 * nsec3-covers. Parses NSEC3s from drill and shows what is covered.
 *
 * Pipe the output of the dig/drill query with NSEC3s to the tool.
 * It will print which domain names are covered by NSEC3s.
 *
 * (c) NLnet Labs, 2005, 2006
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/dns.h>
#include <errno.h>

void usage(FILE *output)
{
	fprintf(output, "Usage: nsec3-covers\n");
}

void abort_ldns_error(const char* str, ldns_status err)
{
	fprintf(stderr, "error: %s: %s\n", str, ldns_get_errorstr_by_id(err));
	exit(1);
}

int
skip_comments_and_query(FILE* in, ldns_rdf ** qname)
{
	char buf[10240];
	fpos_t start;
	/* read comment lines */
	while(1) {
		/* remember start of this line in case it is an RR */
		if(fgetpos(in, &start) == -1) {
			fprintf(stderr, "could not fgetpos: %s", strerror(errno));
			exit(1);
		}
		if(!fgets(buf, sizeof(buf), in))
			return 0; /* EOF */
		printf("%s", buf); /* echo */
		if(strcmp(buf, "") == 0 || strcmp(buf, "\n") == 0)
			continue;
		if(buf[0] != ';')
			break;
		if(strncmp(buf, ";; QUESTION SECTION:", 20) == 0)
		{
			char *q_rr = buf;
			/* read question on next line, ;;s before */
			if(!fgets(buf, sizeof(buf), in)) return 0;
			while(*q_rr == ';' || *q_rr == ' ' || *q_rr == '\t')
				++q_rr;
			printf("Question: %s", q_rr);
			*strchr(q_rr, '\t') = 0;
			*qname = ldns_dname_new_frm_str(q_rr);
		}
	}
	if(fsetpos(in, &start) == -1) {
		fprintf(stderr, "could not fsetpos: %s", strerror(errno));
		exit(1);
	}
	return 1;
}

void
read_in(ldns_rr_list* list, ldns_rdf** qname, FILE *in)
{
	while(skip_comments_and_query(in, qname))
	{
		/* add rr */
		ldns_rr *rr=0;
		ldns_rdf *origin=0, *prev=0;
		ldns_status err;
		if((err=ldns_rr_new_frm_fp(&rr, in, NULL, &origin, &prev)) != 
			LDNS_STATUS_OK)
			abort_ldns_error("read rr", err);
		ldns_rr_list_push_rr(list, rr);
	}
	printf("nsec3-covers: read %d rrs\n", ldns_rr_list_rr_count(list));
	if(!qname) {
		printf("Could not read question name\n");
		exit(1);
	}
	printf("nsec3-covers: qname is ");
	ldns_rdf_print(stdout, *qname);
	printf("\n");
}

void
check_cover(ldns_rr_list *list, ldns_rdf *qname)
{
	size_t i;
	for(i=0; i<ldns_rr_list_rr_count(list); ++i)
	{
		ldns_rr* nsec3 = ldns_rr_list_rr(list, i);
		if(ldns_rr_get_type(nsec3) != LDNS_RR_TYPE_NSEC3) {
			/* skip non nsec3 */
			continue;
		}
		ldns_rdf* hashed = ldns_nsec3_hash_name_frm_nsec3(
			nsec3, qname);
		printf("qname ");
		ldns_rdf_print(stdout, qname);
		printf(" with nsec3 ");
		ldns_rr_print(stdout, nsec3);
		printf(" hashes to ");
		ldns_rdf_print(stdout, hashed);
		printf("\n");
		if(ldns_dname_compare(hashed, ldns_rr_owner(nsec3)) == 0) {
			ldns_rdf_print(stdout, qname);
			printf(" is validated by ");
			ldns_rdf_print(stdout, ldns_rr_owner(nsec3));
			printf("\n");
		}
		else if(ldns_nsec_covers_name(nsec3, hashed)) {
			ldns_rdf_print(stdout, qname);
			printf(" is covered by ");
			ldns_rdf_print(stdout, ldns_rr_owner(nsec3));
			printf("\n");
		}
		ldns_rdf_free(hashed);
	}
}

void
covertests(ldns_rr_list *list, ldns_rdf *qname)
{
	check_cover(list, qname);
}

int
main(int argc, char **argv)
{
	if(argc != 1) {
		usage(stderr);
		return 0;
	}
	
	/* read in */
	ldns_rr_list *list = ldns_rr_list_new();
	ldns_rdf *qname = 0;
	read_in(list, &qname, stdin);

	/* check covers */
	covertests(list, qname);

	ldns_rr_list_deep_free(list);
	return 0;
}
