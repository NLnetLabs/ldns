/* 
 * test1 for other stuff
 *
 */

#include <config.h>
#include <ldns/ldns.h>
#include <ldns/str2host.h>
#include <ldns/host2str.h>
#include <ldns/buffer.h>
#include <ldns/dname.h>

#include "util.h"

#if 0
static const uint8_t wire[] = {
	0xd0, 0x0e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00,
	0x02, 0x03, 0x77, 0x77, 0x77, 0x0b, 0x6b, 0x61, 0x6e, 0x61, 0x72,
	0x69, 0x65, 0x70, 0x69, 0x65, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00,
	0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x01, 0x45, 0xf2, 0x00, 0x04, 0xd5, 0x85, 0x27, 0xcf, 0xc0, 0x10,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x45, 0xf2, 0x00, 0x11, 0x03,
	0x6e, 0x73, 0x32, 0x08, 0x68, 0x65, 0x78, 0x6f, 0x6e, 0x2d, 0x69,
	0x73, 0x02, 0x6e, 0x6c, 0x00, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01,
	0x00, 0x01, 0x45, 0xf2, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0,
	0x45, 0xc0, 0x5e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfb, 0x2e,
	0x00, 0x04, 0xd5, 0x85, 0x27, 0xcb, 0xc0, 0x41, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0xfb, 0x2c, 0x00, 0x04, 0xd4, 0xcc, 0xdb, 0x5b
};
#endif 

void
doit(void)
{
	ldns_buffer *buf;
	ldns_rdf *rdata;
	ldns_rdf *cnt_test;
	ldns_rdf *cat_test1;
	ldns_rdf *cat_test2;
	ldns_rdf *concat;
	char *str;
	
	buf = ldns_buffer_new(10); /* alloc away! */
	if (!buf) {
		printf("Nooooo\n");
	}

	printf("Setting 15242\n");
	
	if (ldns_str2rdf_int16(&rdata, "15242") != LDNS_STATUS_OK) {
		printf("_short: ah man, shit hit the fan\n");
	}
	
	(void) ldns_rdf2buffer_str_int16(buf, rdata); 
	str = buffer2str(buf);
	fprintf(stderr, "%s\n", str);

	FREE(str);
	ldns_buffer_free(buf);
	ldns_rdf_free(rdata);

	/* test the label counter */
 	cnt_test = ldns_dname_new_frm_str("miek.nl.");
	printf("Labels miek.nl. %d\n", ldns_rdf_dname_label_count(cnt_test));
	ldns_rdf_free(cnt_test);

 	cnt_test = ldns_dname_new_frm_str("miek.nl");
	printf("Labels miek.nl %d\n", ldns_rdf_dname_label_count(cnt_test));
	ldns_rdf_free(cnt_test);
	
 	cnt_test = ldns_dname_new_frm_str("miek");
	printf("Labels miek %d\n", ldns_rdf_dname_label_count(cnt_test));
	ldns_rdf_free(cnt_test);
	
/* this errors
 	cnt_test = ldns_dname_new_frm_str(".");
printf("counting: %s\n", ldns_rdf2str(cnt_test));
	printf("Labels . %d\n", ldns_rdf_dname_label_count(cnt_test));
	
 	cnt_test = ldns_dname_new_frm_str(".www.miek.nl.");
	printf("Labels .www.miek.nl. %d\n", ldns_rdf_dname_label_count(cnt_test));

 	cnt_test = ldns_dname_new_frm_str("www.miek.nl.");
	printf("Labels www.miek.nl. %d\n", ldns_rdf_dname_label_count(cnt_test));
*/

 	cnt_test = ldns_dname_new_frm_str("nl");
	printf("Labels nl %d\n", ldns_rdf_dname_label_count(cnt_test));
	ldns_rdf_free(cnt_test);


	/* concat tests */
	cat_test1 = ldns_dname_new_frm_str("www");
	cat_test2 = ldns_dname_new_frm_str("miek.nl.");
	concat = ldns_dname_concat(cat_test1, cat_test2);

	ldns_rdf_print(stdout, concat);

	printf(" [%d]\n", ldns_rdf_size(concat));
	printf("Labels nl %d\n", ldns_rdf_dname_label_count(concat));

	ldns_rdf_free(cat_test1);
	ldns_rdf_free(cat_test2);
	ldns_rdf_free(concat);
}


int
main(void)
{
	ldns_rdf *bla;
	if (ldns_str2rdf_int16(&bla, "15242") != LDNS_STATUS_OK) {
		printf("_int16: ah man, shit hit the fan\n");
	}
	ldns_rdf_free(bla);
	
	/* %Y%m%d%H%M%S */
	if (ldns_str2rdf_time(&bla, "20041222134100") != LDNS_STATUS_OK) {
		printf("_time: ah man, shit hit the fan\n");
	}
	ldns_rdf_free(bla);

	printf("succes\n");
	doit();
	return 0;
}

