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
	if(ldns_rr_descriptor_minimum(desc) != desc->_minimum)
		return err(desc, "minimum wrong");
	if(desc->_variable == LDNS_RDF_TYPE_NONE &&
		ldns_rr_descriptor_maximum(desc) != desc->_maximum)
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

int main(void)
{
	int result = EXIT_SUCCESS;
	
	if (!check_descriptors()) {
		printf("check_dname_count() failed.\n");
		result = EXIT_FAILURE;
	}

	exit(result);
}
