
#include "ldns/config.h"
#include <ldns/ldns.h>

void dotest(void)
{
	ldns_rr* rr = 0;
	ldns_status s;
	const char* str = "r._dns-sd._udp.\\200\\015\\246\\0018\\;\\169. IN PTR";
	str = "dr._dns-sd._udp.\\(\\242\\202. IN PTR";
	str = "\\(blurb\\)\\;\\012\\010\\.\\.zaza.jelte.nlnetlabs.nl. IN PTR";
	// \(blurb\)\;\012\010\.\.zaza.jelte.nlnetlabs.nl.
	// str = "abc\\.zaza\\\\. IN PTR";
	//s = ldns_rr_new_frm_str(&rr, str, LDNS_DEFAULT_TTL, 0, 0);
	printf("%s\n", str);
	s = ldns_rr_new_question_frm_str(&rr, str, NULL, NULL);
	if(s != LDNS_STATUS_OK)
		printf("error %s\n", ldns_get_errorstr_by_id(s));
	else	ldns_rr_print(stdout, rr);
	ldns_rr_free(rr);
}

int 
main(void) 
{
  ldns_rr *rr = ldns_rr_new();
  dotest();

  ldns_rr_free(rr);
  return 0;
}

