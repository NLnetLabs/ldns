#include "config.h"
#include "backtext.h"
#include "store.h"

#define THIS ((struct backtext_data_t*)store->store_data)

/*** public ***/

int back_text_init(struct store_t* store, const char* config_string)
{
	if(!store->store_data) {
		store->store_data = malloc(sizeof(struct backtext_data_t));
		memset(store->store_data, 0, sizeof(struct backtext_data_t));
	}
	if(THIS->zonelist_filename) 
		free(THIS->zonelist_filename);
	THIS->zonelist_filename = strdup(config_string);
	back_text_free_list(store);
	return back_text_read_list(store);
}

uint32_t back_text_get_latest_serial(struct store_t* store)
{
	if(THIS->last) {
		return THIS->last->serial;
	}
	return 0;
}

void back_text_get_zone_full(struct store_t* store, uint32_t serial,
	ldns_zone** zone)
{
	ldns_status status;
	FILE* in;
	struct backtext_version_t *vs;
	int line_nr = 0;
	ldns_rdf* my_origin = ldns_dname_new_frm_str(store->zone_name);

	if(!store || !zone || !THIS->last || !my_origin) {
		if(my_origin)
			ldns_rdf_deep_free(my_origin);
		if(zone)
			*zone = 0;
		return;
	}
	vs = back_text_version_find(store, serial);
 	in = fopen(vs->filename, "r");
	if(!in) {
		printf("Could not open zone file %s: %s\n",
			vs->filename, strerror(errno));
		ldns_rdf_deep_free(my_origin);
		*zone = 0;
		return;
	}
	status = ldns_zone_new_frm_fp_l(zone, in, my_origin,
		LDNS_DEFAULT_TTL, LDNS_RR_CLASS_IN, &line_nr);
	fclose(in);
	ldns_rdf_deep_free(my_origin);
	if(status != LDNS_STATUS_OK) {
		printf("Error %s:%d: %s\n", vs->filename, line_nr,
			ldns_get_errorstr_by_id(status));
		*zone = 0;
		return;
	}
}

void back_text_get_zone_diff(struct store_t* store, uint32_t serialfrom,
	uint32_t serialto, ldns_rr_list** rr_remove, ldns_rr_list** rr_add,
	ldns_rr** rr_soa_from, ldns_rr** rr_soa_to)
{
	struct backtext_version_t *vs1, *vs2;
	FILE *in1, *in2;
	uint32_t my_ttl1 = LDNS_DEFAULT_TTL, my_ttl2 = LDNS_DEFAULT_TTL;
	ldns_rdf* my_origin1 = 0, 	*my_origin2 = 0;
	ldns_rdf *my_prev1 = 0, 	*my_prev2 = 0;
	ldns_rr *rr1= 0, 		*rr2 = 0;
	int line_nr1 = 0, 		line_nr2 = 0;
	int advance1 = 0, 		advance2 = 0;
	ldns_rr *rr1old = 0,		*rr2old = 0;

	const int check_sorted = 1;

	vs1 = back_text_version_find(store, serialfrom);
	vs2 = back_text_version_find(store, serialto);
	*rr_remove = 0;
	*rr_add = 0;
	if(!vs1 || !vs2) {
		printf("No diff %s from %u to %u\n", store->zone_name,
			serialfrom, serialto);
		return;
	}

	/* open both files, step through them both. 
	   Add differing RRs to one of the lists */
	if(!(in1 = fopen(vs1->filename, "r"))) {
		printf("Could not open zone file %s: %s\n", vs1->filename, strerror(errno));
		return;
	}
	if(!(in2 = fopen(vs2->filename, "r"))) {
		printf("Could not open zone file %s: %s\n", vs2->filename, strerror(errno));
		return;
	}
	*rr_remove = ldns_rr_list_new();
	*rr_add = ldns_rr_list_new();
	my_origin1 = ldns_dname_new_frm_str(store->zone_name);
	my_origin2 = ldns_dname_new_frm_str(store->zone_name);
	*rr_soa_from = 0;
	*rr_soa_to = 0;
	if(!rr_remove || !rr_add || !my_origin1 || !my_origin2) {
		printf("out of memory\n");
	error_exit:
		if(*rr_add) ldns_rr_list_free(*rr_add);
		if(*rr_remove) ldns_rr_list_free(*rr_remove);
		if(*rr_soa_from) ldns_rr_free(*rr_soa_from);
		if(*rr_soa_to) ldns_rr_free(*rr_soa_to);
		*rr_add = 0;
		*rr_remove = 0;
		*rr_soa_from = 0;
		*rr_soa_to = 0;
		goto close_exit;
	}

	/* read SOA from both files */
	*rr_soa_from = back_text_read_soa(in1, store->zone_name, &my_ttl1, &my_origin1,
		&my_prev1, &line_nr1);
	*rr_soa_to = back_text_read_soa(in2, store->zone_name, &my_ttl2, &my_origin2,
		&my_prev2, &line_nr2);
	if(!*rr_soa_from || !*rr_soa_to) {
		printf("Error: no diff, could not read soa\n");
		goto error_exit;
	}

	/* both files are sorted, read a line from each and compare entries.
	   same entries are skipped, otherwise the smallest entry is removed/added */
	advance1 = 1; advance2 = 1;
	while(!feof(in1) && !feof(in2)) {
		if(advance1 && !feof(in1))
			if(!back_text_next_rr(&rr1, in1, store->zone_name, &my_ttl1, 
				&my_origin1, &my_prev1, &line_nr1)) {
				printf("diff: Error reading zone file1\n");
				goto error_exit;
			}
		if(advance2 && !feof(in2))
			if(!back_text_next_rr(&rr2, in2, store->zone_name, &my_ttl2, 
				&my_origin2, &my_prev2, &line_nr2)) {
				printf("diff: Error reading zone file1\n");
				goto error_exit;
			}

		if(check_sorted) {
			if(rr1old && rr1 && rr1old != rr1) {
				if(ldns_rr_compare(rr1old, rr1) >= 0) {
					printf("diff: zone file %s is not sorted!\n",
						vs1->filename);
					goto error_exit;
				}
			}
			if(rr2old && rr2 && rr2old != rr2) {
				if(ldns_rr_compare(rr2old, rr2) >= 0) {
					printf("diff: zone file %s is not sorted!\n",
						vs2->filename);
					goto error_exit;
				}
			}
			if(rr1old) ldns_rr_free(rr1old);
			if(rr2old) ldns_rr_free(rr2old);
			rr1old = ldns_rr_clone(rr1);
			rr2old = ldns_rr_clone(rr2);
		}
		/* if rr=NULL that is EOF, otherwise compare */
		if(!rr1 && !rr2)
			break; /* simultaneous eof */
		else if(!rr1 && rr2) {
			/* only file 2 has content, add all */
			advance1 = 0;
			advance2 = 1;
			ldns_rr_list_push_rr(*rr_add, rr2);
			rr2 = 0;
		} else if(!rr2 && rr1) {
			/* only file 1 has content, remove them */
			advance1 = 1;
			advance2 = 0;
			ldns_rr_list_push_rr(*rr_remove, rr1);
			rr1 = 0;
		} else {
			/* both files have content */
			int cmp = ldns_rr_compare(rr1, rr2);
			if(cmp == 0) {
				/* equal, ignore for IXFR */
				ldns_rr_free(rr1);
				ldns_rr_free(rr2);
				rr1 = 0;
				rr2 = 0;
				advance1 = 1;
				advance2 = 1;
			} else if(cmp < 0) {
				/* rr1 is earlier, thus not in in2 */
				ldns_rr_list_push_rr(*rr_remove, rr1);
				rr1 = 0;
				advance1 = 1; /* read only in1, not in2 */
				advance2 = 0;
			} else { /* cmp > 0 */
				/* rr2 is earlier, thus not in in1 */
				ldns_rr_list_push_rr(*rr_add, rr2);
				rr2 = 0;
				advance1 = 0; /* read only in2, not in1 */
				advance2 = 1;
			}
		}
	}
	
close_exit:
	if(my_prev1)
		ldns_rdf_deep_free(my_prev1);
	if(my_prev2)
		ldns_rdf_deep_free(my_prev2);
	ldns_rdf_deep_free(my_origin1);
	ldns_rdf_deep_free(my_origin2);
	fclose(in1);
	fclose(in2);
}

void back_text_get_latest_SOA(struct store_t* store, ldns_rr** soa_rr)
{
	if(!store || !soa_rr)
		return;
	if(THIS->last) {
		*soa_rr = back_text_get_soa(THIS->last->filename, 
			store->zone_name);
	} else {
		*soa_rr = NULL;
	}
}

void back_text_store_free(struct store_t* store)
{
	if(!store)
		return;
	if(store->zone_name)
		free(store->zone_name);
	if(store->backend)
		free(store->backend);
	if(store->store_data) {
		back_text_free_list(store);
		if(THIS->zonelist_filename)
			free(THIS->zonelist_filename);
		free(store->store_data);
		store->store_data = NULL;
	}
	free(store);
}

/*** private ***/
void back_text_free_list(struct store_t* store)
{
	struct backtext_version_t *p=NULL, *np=NULL;
	p = THIS->first;
	THIS->first = NULL;
	THIS->last = NULL;
	while(p) {
		np = p->next; /* store next ptr before freed */
		if(p->filename)
			free(p->filename);
		free(p);
		p = np;
	}
}

int back_text_read_list(struct store_t* store)
{
	FILE *listf = fopen(THIS->zonelist_filename, "r");
	char buf[4096];
	struct backtext_version_t* entry = 0;

	if(!listf) {
		perror(THIS->zonelist_filename);
		return 0;
	}
	/* read line by line for zone files */
	while(fgets(buf, sizeof(buf), listf))
	{
		if(buf[0] == 0 || buf[0]=='#' || buf[0]=='\n')
			continue; /* skip comments and empty lines */
		buf[strlen(buf)-1] = 0; /* strip ending newline */
		/* add entry at end */
		entry = back_text_version_create(buf, store->zone_name);
		if(!entry) {
			printf("Error creating back_text version for zone %s\n",
				store->zone_name);
			fclose(listf);
			return 0;
		}
		printf("zone version: %s: %u\n", buf, entry->serial);
		/* slow, but sure */
		if(back_text_version_find(store, entry->serial)) {
			printf("zone version already exists: %s %u."
				" in %s and %s\n", store->zone_name, 
				entry->serial, buf, back_text_version_find(
				store, entry->serial)->filename);
			fclose(listf);
			return 0;
		}

		/* add at end of version list */
		if(THIS->last)
			THIS->last->next = entry;
		else
			THIS->first = entry;
		THIS->last = entry;
	}
	fclose(listf);
	return 1;
}


int 
back_text_next_rr(ldns_rr** rr, FILE *in, const char* zonefile, uint32_t* my_ttl, 
	ldns_rdf** my_origin, ldns_rdf** my_prev, int* line_nr)
{
	ldns_status status;
	*rr = 0;

	while(!feof(in)) {
		status = ldns_rr_new_frm_fp_l(rr, in, my_ttl, my_origin,
			my_prev, line_nr);
		if(0) printf("loop stat=%s\n", ldns_get_errorstr_by_id(status));
		if(status == LDNS_STATUS_OK) {
			return 1;
		}
		if(status == LDNS_STATUS_SYNTAX_EMPTY
			|| status == LDNS_STATUS_SYNTAX_TTL
			|| status == LDNS_STATUS_SYNTAX_ORIGIN)
			continue;
		else {
			printf("zone file %s:%d: %s\n", zonefile, *line_nr, 
				ldns_get_errorstr_by_id(status));
			return 0;
		}
	}

	return 1;
}



ldns_rr* 
back_text_read_soa(FILE *in, const char* zonefile, uint32_t* my_ttl, 
	ldns_rdf** my_origin, ldns_rdf** my_prev, int* line_nr)
{
	ldns_rr* rr = 0;
	ldns_status status;

	while(!rr && !feof(in)) {
		status = ldns_rr_new_frm_fp_l(&rr, in, my_ttl, my_origin,
			my_prev, line_nr);
		if(0) printf("loop stat=%s\n", ldns_get_errorstr_by_id(status));
		if(status == LDNS_STATUS_OK) {
			if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
				printf("zone file %s:%d: no SOA at start.\n", 
					zonefile, *line_nr);
				if(rr) ldns_rr_free(rr);
				rr = 0;
			}
			break;
		}
		if(status == LDNS_STATUS_SYNTAX_EMPTY
			|| status == LDNS_STATUS_SYNTAX_TTL
			|| status == LDNS_STATUS_SYNTAX_ORIGIN)
			continue;
		else {
			printf("zone file %s:%d: %s\n", zonefile, *line_nr, 
				ldns_get_errorstr_by_id(status));
			if(rr) ldns_rr_free(rr);
			rr = 0;
			break;
		}
	}

	return rr;
}

ldns_rr* 
back_text_get_soa(const char* zonefile, const char* zone_name)
{
	FILE *in;
	uint32_t my_ttl = LDNS_DEFAULT_TTL;
	ldns_rdf* my_origin = 0;
	ldns_rdf* my_prev = 0;
	ldns_rr* rr = 0;
	int line_nr = 0;

	in = fopen(zonefile, "r");
	if(!in) {
		printf("error for zone file %s: %s\n",
			zonefile, strerror(errno));
		return NULL;
	}
	if(zone_name)
		my_origin = ldns_dname_new_frm_str(zone_name);
	else
		my_origin = ldns_dname_new_frm_str(".");
	if(!my_origin) {
		printf("error parsing name for zone '%s'\n", zonefile);
		fclose(in);
		return NULL;
	}

	rr = back_text_read_soa(in, zonefile, &my_ttl, &my_origin, &my_prev, &line_nr);
	ldns_rdf_deep_free(my_origin);
	if(my_prev)
		ldns_rdf_deep_free(my_prev);
	fclose(in);
	return rr;
}

struct backtext_version_t* 
back_text_version_create(const char* zonefile, const char* zone_name)
{
	ldns_rr* soa = 0;
	struct backtext_version_t* version = (struct backtext_version_t*)
		malloc(sizeof(struct backtext_version_t));
	memset(version, 0, sizeof(struct backtext_version_t));
	version->filename = strdup(zonefile);

	/* get serial from zone file */
	soa = back_text_get_soa(version->filename, zone_name);
	if(!soa) {
		printf("Could not read SOA from %s\n",
			version->filename);
		free(version->filename);
		free(version);
		return 0;
	}
	version->serial = ldns_rdf2native_int32(ldns_rr_rdf(soa, 2));
	ldns_rr_free(soa);

	return version;
}

struct backtext_version_t* back_text_version_find(struct store_t* store,
        uint32_t serial)
{
	struct backtext_version_t *p = THIS->first;
	if(!THIS->first || !THIS->last)
		return NULL;
	if(serial == THIS->last->serial)
		return THIS->last;
	while(p) {
		if(serial == p->serial)
			return p;
		p = p->next;
	}
	return NULL;
}
