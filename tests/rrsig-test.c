/*
 */

#include "config.h"

#include <ldns/dns.h>

int main(void)
{
	ldns_rr *sig;
	ldns_rdf *incep, *expir;

	time_t t_incep, t_expir, t_now;
	uint32_t tweemacht = 1;

	tweemacht = tweemacht << 31;
	tweemacht = tweemacht * 2 - 1;

	printf("tweemacht %u\n", tweemacht);

	sig = ldns_rr_new_frm_str("jelte.nlnetlabs.nl.     18000   IN      RRSIG   NSEC RSASHA1 3 18000 20050913235001 20050814235001 43791 nlnetlabs.nl. epWGR0WkhWQ1h0eXvU89W57xwI0xuUlWtvvUnABQVmUfZ2nGllIy2KLR5cfgpB5UH7beASrAo78AlPddPCnH50OYNjllesDy9HLderQtjQoi47SPPluLC6v3Fwqq64Zv0wf2fPzJqDSnOOrQPVzIuB3IDv5XD4M5t8Vze8QZ8lA=", 0, NULL);

	ldns_rr_print(stdout, sig);

	t_now = time(NULL);
	incep = ldns_rr_rrsig_inception(sig);
	t_incep = ldns_rdf2native_time_t(incep);
	expir = ldns_rr_rrsig_expiration(sig);
	t_expir = ldns_rdf2native_time_t(expir);

	printf("inception: [now %d] %d\n", t_now, t_incep);
	ldns_rdf_print(stdout, incep);
	printf("\n");
	printf("expiration: %d\n", t_expir);
	ldns_rdf_print(stdout, expir);
	printf("\n");

	if (t_expir - t_incep < 0) {
		printf("bad sig, expiration before inception?? Tsssg\n");
	}
	if (t_now - t_incep < 0) {
		printf("bad sig, inception date has passed\n");
	}
	if (t_expir - t_now < 0) {
		printf("bad sig, expiration date has passed\n");
	}
	printf("Sig dates are all correct\n");
}
