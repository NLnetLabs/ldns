/*
 */

#include "config.h"

#include <ldns/ldns.h>

static int
err(const ldns_rr_descriptor* desc, const char* why)
{
	printf("Type %d %s: %s\n", desc->_type, desc->_name, why);
	return 0;
}

static int
check_desc(const ldns_rr_descriptor* desc, ldns_rr_type type)
{
	int i;
	int dcount = 0;
	if(!desc) {
		printf("Null!\n");
		return 0;
	}
	if(ldns_minimum_rdata_fields(desc) != desc->_minimum)
		return err(desc, "minimum wrong");
	if(desc->_variable == LDNS_RDF_TYPE_NONE &&
		ldns_maximum_rdata_fields(desc) != desc->_maximum)
			return err(desc, "maximum wrong");
	if(desc->_type != type && !(desc->_type == LDNS_RR_TYPE_NULL
		&& strncmp(desc->_name, "TYPE", 4)==0))
		return err(desc, "type wrong");
	
	/* check wireformat desc */
	for(i=0; i<desc->_maximum; i++) {
		if(desc->_wireformat[i] != 
			ldns_rr_descriptor_field_type(desc, i))
			return err(desc, "descriptor field bad");
		if(desc->_wireformat[i] == LDNS_RDF_TYPE_DNAME)
			dcount++;
	}
	if(desc->_dname_count != dcount) {
		printf("%s counted %d, stored %d\n", 
			desc->_name, dcount, desc->_dname_count);
		return 0;
	}
	if(dcount == 0 && desc->_compress != LDNS_RR_NO_COMPRESS)
		return err(desc, "compression set but no dnames in format");
	return 1;
}

static int
check_descriptors(void)
{
	ldns_rr_type start = LDNS_RR_TYPE_FIRST;
	ldns_rr_type end = LDNS_RDATA_FIELD_DESCRIPTORS_COMMON /* 250 */;
	ldns_rr_type i;
	for(i=start; i<end; i++) {
		if(!check_desc(ldns_rr_descript(i), i)) {
			printf("Type %d failed\n", (int)i);
			return 0;
		}
	}
	return 1;
}


/* RFC 1035 section 5.1 permits the TTL before or after the class. */
static int
check_rr_ttl_class_order(void)
{
	static const struct {
		const char *text;
		uint32_t ttl;
		ldns_rr_class clas;
	} cases[] = {
		{"example.com. IN 1111 A 192.0.2.1", 1111, LDNS_RR_CLASS_IN},
		{"example.com. IN 1h30m A 192.0.2.1", 5400, LDNS_RR_CLASS_IN},
		{"example.com. IN 0 A 192.0.2.1", 0, LDNS_RR_CLASS_IN},
		{"example.com. in 1H30M A 192.0.2.1", 5400, LDNS_RR_CLASS_IN},
		{"example.com.\tIN\t1111\tA\t192.0.2.1", 1111, LDNS_RR_CLASS_IN},
		{"example.com. IN 4294967295 A 192.0.2.1", 4294967295U, LDNS_RR_CLASS_IN},
		{"example.com. CH 2222 TXT \"test\"", 2222, LDNS_RR_CLASS_CH},
		{"example.com. CLASS123 3333 TYPE1234 \\# 1 ff", 3333, 123},
		{"example.com. 1111 IN A 192.0.2.1", 1111, LDNS_RR_CLASS_IN},
		{"example.com. 1h30m IN A 192.0.2.1", 5400, LDNS_RR_CLASS_IN},
		{"example.com. 1111 A 192.0.2.1", 1111, LDNS_RR_CLASS_IN},
		{"example.com. IN A 192.0.2.1", 777, LDNS_RR_CLASS_IN},
		{"example.com. A 192.0.2.1", 777, LDNS_RR_CLASS_IN}
	};
	static const char *invalid[] = {
		"example.com. IN 1111",
		"example.com. IN 1111 IN A 192.0.2.1",
		"example.com. IN 1111 2222 A 192.0.2.1",
		"example.com. IN 1111 BOGUS 192.0.2.1",
		"example.com. IN 1111 A",
		"example.com. IN 1x A 192.0.2.1",
		"example.com. IN -1 A 192.0.2.1"
	};
	ldns_rr *rr = NULL;
	ldns_status status;
	size_t i;
	int result = 1;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		status = ldns_rr_new_frm_str(&rr, cases[i].text, 777, NULL, NULL);
		if (status != LDNS_STATUS_OK) {
			printf("Could not parse %s: %s\n", cases[i].text,
				ldns_get_errorstr_by_id(status));
			result = 0;
			continue;
		}
		if (ldns_rr_ttl(rr) != cases[i].ttl ||
			ldns_rr_get_class(rr) != cases[i].clas) {
			printf("Wrong TTL or class for %s\n", cases[i].text);
			result = 0;
		}
		ldns_rr_free(rr);
		rr = NULL;
	}
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		status = ldns_rr_new_frm_str(&rr, invalid[i], 777, NULL, NULL);
		if (status == LDNS_STATUS_OK) {
			printf("Accepted invalid record: %s\n", invalid[i]);
			ldns_rr_free(rr);
			rr = NULL;
			result = 0;
		}
	}
	return result;
}

/* The explicit TTL must also become the default for following records,
 * unless a $TTL directive supplied a default (RFC 2308 section 4).
 */
static int
check_zone_ttl_class_order(void)
{
	const char *records =
		"example.com. IN 1111 SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5\n"
		"a.example.com. IN 2222 A 192.0.2.1\n"
		"b.example.com. IN A 192.0.2.2\n";
	ldns_zone *zone = NULL;
	ldns_status status;
	FILE *fp;
	int directive, result = 1;

	for (directive = 0; directive < 2; directive++) {
		if (!(fp = tmpfile())) return 0;
		if (directive) fputs("$TTL 3333\n", fp);
		fputs(records, fp);
		rewind(fp);
		status = ldns_zone_new_frm_fp(&zone, fp, NULL, 777, LDNS_RR_CLASS_IN);
		fclose(fp);
		if (status != LDNS_STATUS_OK) {
			printf("Could not parse class-first zone: %s\n",
				ldns_get_errorstr_by_id(status));
			result = 0;
			continue;
		}
		if (ldns_rr_ttl(ldns_zone_soa(zone)) != 1111 ||
			ldns_rr_list_rr_count(ldns_zone_rrs(zone)) != 2 ||
			ldns_rr_ttl(ldns_rr_list_rr(ldns_zone_rrs(zone), 0)) != 2222 ||
			ldns_rr_ttl(ldns_rr_list_rr(ldns_zone_rrs(zone), 1)) !=
				(uint32_t)(directive ? 3333 : 2222)) {
			printf("Wrong TTLs for class-first zone ($TTL: %d)\n", directive);
			result = 0;
		}
		ldns_zone_deep_free(zone);
		zone = NULL;
	}
	return result;
}

int main(void)
{
	int result = EXIT_SUCCESS;
	
	if (!check_rr_ttl_class_order()) {
		result = EXIT_FAILURE;
	}
	if (!check_zone_ttl_class_order()) {
		result = EXIT_FAILURE;
	}

	if (!check_descriptors()) {
		printf("check_dname_count() failed.\n");
		result = EXIT_FAILURE;
	}

	exit(result);
}
