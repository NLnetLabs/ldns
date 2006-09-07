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
#include <ldns/ldns.h>
#include <errno.h>

void usage(FILE *output)
{
	fprintf(output, "Usage: dig +dnssec <query> | nsec3-covers or\n"
		"drill -D <query> | nsec3-covers\n");
}

void abort_ldns_error(const char* str, ldns_status err)
{
	fprintf(stderr, "error: %s: %s\n", str, ldns_get_errorstr_by_id(err));
	exit(1);
}

char*
skip_comments_and_query(FILE* in, ldns_rdf ** qname)
{
	static char buf[10240];
	/* read comment lines */
	while(1) {
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
	return buf;
}

void
read_in(ldns_rr_list* list, ldns_rdf** qname, FILE *in)
{
	char* buf;
	while((buf=skip_comments_and_query(in, qname)))
	{
		/* add rr */
		ldns_rr *rr=0;
		ldns_rdf *origin=0, *prev=0;
		ldns_status err;
		uint16_t ttl = 3600;
		if((err=ldns_rr_new_frm_str(&rr, buf, ttl, origin, &prev)) != 
			LDNS_STATUS_OK)
			abort_ldns_error("read rr", err);
		ldns_rr_list_push_rr(list, rr);
	}
	printf("nsec3-covers: read %d rrs\n", (int)ldns_rr_list_rr_count(list));
	if(!qname) {
		printf("Could not read question name\n");
		exit(1);
	}
	printf("nsec3-covers: qname is ");
	ldns_rdf_print(stdout, *qname);
	printf("\n");
}

struct donelist {
	ldns_rdf* name;
	struct donelist* next;
};
static struct donelist *done = 0;

/* this is a linear speed test (slow for large numbers).
   but the dig response will be small anyway. */
int check_done(ldns_rdf *qname)
{
	struct donelist* p = done;
	while(p) {
		if(ldns_dname_compare(qname, p->name)==0)
			return 1;
		p = p->next;
	}
	/* not done yet add to list */
	p = (struct donelist*)malloc(sizeof(struct donelist));
	p->name = qname;
	p->next = done;
	done = p;
	return 0;
}

void
check_cover(ldns_rr_list *list, ldns_rdf *qname)
{
	ldns_status status;
	size_t i;
	if(check_done(qname))
		return;
	for(i=0; i<ldns_rr_list_rr_count(list); ++i)
	{
		ldns_rr* nsec3 = ldns_rr_list_rr(list, i);
		if(ldns_rr_get_type(nsec3) != LDNS_RR_TYPE_NSEC3) {
			/* skip non nsec3 */
			continue;
		}
		ldns_rdf* hashed = ldns_nsec3_hash_name_frm_nsec3(
			nsec3, qname);
		status = ldns_dname_cat(hashed, ldns_dname_left_chop(
			ldns_rr_owner(nsec3)));
		if(status != LDNS_STATUS_OK)
			abort_ldns_error("ldns_dname_cat", status);

		if(ldns_dname_compare(hashed, ldns_rr_owner(nsec3)) == 0) {
			ldns_rdf_print(stdout, ldns_rr_owner(nsec3));
			printf(" proves ");
			ldns_rdf_print(stdout, qname);
			printf(" exists.\n");
		}
		else if(ldns_nsec_covers_name(nsec3, hashed)) {
			ldns_rdf_print(stdout, ldns_rr_owner(nsec3));
			printf(" proves ");
			ldns_rdf_print(stdout, qname);
			printf(" does not exist.\n");
		}
		ldns_rdf_free(hashed);
	}
}

void
covertests(ldns_rr_list *list, ldns_rdf *qname)
{
	size_t i;
	ldns_rdf *smaller = qname;
	ldns_rdf *wcard = ldns_dname_new_frm_str("*");
	for(i=0; i<ldns_dname_label_count(qname)+1; ++i)
	{
		check_cover(list, smaller);
		ldns_rdf* wcardchild = ldns_dname_cat_clone(wcard, smaller);
		check_cover(list, wcardchild);
		smaller = ldns_dname_left_chop(smaller);
	}
	/* check covers by weird names */
	if(0) {
		check_cover(list, ldns_dname_new_frm_str("x.bar.example."));
		check_cover(list, ldns_dname_new_frm_str("bar.example."));
	}
}

int
main(int argc, char **argv)
{
	size_t i;
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
	for(i=0; i<ldns_rr_list_rr_count(list); ++i)
	{
		ldns_rr* rr = ldns_rr_list_rr(list, i);
		if(!ldns_dname_is_subdomain(qname, ldns_rr_owner(rr))) {
			covertests(list, ldns_rr_owner(rr));
		}
	}

	ldns_rr_list_deep_free(list);
	return 0;
}
