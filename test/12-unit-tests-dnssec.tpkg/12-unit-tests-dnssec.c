/*
 */

#include "config.h"

#include <ldns/ldns.h>


ldns_status
check_ldns_calc_keytag_part(const char *key_str, uint16_t expected_keytag)
{
	ldns_rr *key_rr = NULL;
	uint16_t keytag;

	ldns_status result = LDNS_STATUS_OK;

	if (ldns_rr_new_frm_str(&key_rr, key_str, 0, NULL, NULL) !=
			LDNS_STATUS_OK) {
		printf("Key creation failed.");
		printf("Key: %s\n", key_str);
		result = LDNS_STATUS_ERR;
	} else {
		keytag = ldns_calc_keytag(key_rr);
		if (keytag == expected_keytag) {
			printf("Keytag 1 correct.");
		} else {
			printf("Bad keytag, should be %u (got %u)for:\n", expected_keytag, keytag);
			printf("%s\n", key_str);
			result = LDNS_STATUS_ERR;
		}
	}

	if (key_rr)
		ldns_rr_free(key_rr);

	return result;
}

ldns_status
check_ldns_calc_keytag(void)
{
	const char *key_str;
	uint16_t expected_keytag;

	ldns_status result = LDNS_STATUS_OK;

	key_str = "jelte.nlnetlabs.nl. IN DNSKEY 256 3 5 AQOraLfzarHAlFskVGwAGnX0LRjlcOiO6y5WM4Kz+QvZ9vX28h4lOvnf d5tkxnZm7ERLTAJoFq+1w/wl7VXs2Isz75BSZ7LQh3OT2xXnS6VT5ZxX ko/UCOdoGiKZZ63jHZ0jNSTCYy8+5rfvwRD8s3gGuErp5KcHg3V8VLUK SDNNEQ==";
	expected_keytag = 42860;
	if (check_ldns_calc_keytag_part(key_str, expected_keytag) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	}

	key_str = "sub.jelte.nlnetlabs.nl. IN DNSKEY 256 3 3 CI4CujZjrw4hjpAP8zMyntKEQJBV96M0OhZ5HCeZ5K46eGHEJUG6RglQ M2OVYY/qRqALDs/Ptzk+Hdb0oV3RF0+fUA5+R5gX1avgbhsEPhvIInYB OPsNaXWKMJarpH2b8xHkF4XQT4TdqAf8maQcKk/RujeKR6VnXbadZUNK +SZsNWSbaDuCHbT0rWpO9nVbfoQUnNWpk1hmOh4oIlFdBtBTPck3ND+g dQrj5eJcSx0zwqjJBJIC+JxWt2rFtIEztfHxmmjbeddC2TL41O/AFPJM vUh85dnd3b1gZRc5UvA7Z2I2+ZD16FjNrmuNkNEjnlet7oiJAC0fezzX sZYCjwHfEyeaS2YXGzzZCeQpMBzeBRh3eq8pVn8r4AaRcNt1gnXbVdjd TQvp5deIGoaAHMl3yy4n0QmXgRscSIsyfK9Gn7NrlGRlCxs9rfVwcWCD Nj2MuIComXGIUYJW+ck0Rhk9Sq6M3onhSjITY9/y/SpwBna6SLpFdpEm bLYKES4gShTxjtmhJSytH0pooq9qxJ8kyH+I";
	expected_keytag = 13026;
	if (check_ldns_calc_keytag_part(key_str, expected_keytag) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	}

	key_str = "sub.sub.jelte.nlnetlabs.nl. IN DNSKEY 256 3 1 AQPIQ2SNclMqdHu8afxVdbIVR/20vlDp2ZcEK5xFxDKVTunuq8BLAPr4 FvnbBQ4AkNYchecNcmQvKi/jJ7xwWqyqMAU1l+d6mZUTF6sC0ug9WQ/Q zG93nOBVLwGbmGTTXhrE/pRhS/o16Ab20zsbcdAb7PChQXSgByJKvT8W XumJ3FdOLhwmqQAnFuMnZC71/HAc4WjA+2zG1SNXnbTnC8Q/4/Fg/ygh 2GjT9Cj0hhFR+A2Hf+RXvkKsDwhdxWwJfW+IhAHUtwNKydsEvZM5UR2I PSytfzZ/fWKEx5BlxLZZNKzoeBtFHjHSeZU5Lb5DFnQJx5lcsd5MP2e8 +ppjVlg3";
	expected_keytag = 22104;
	if (check_ldns_calc_keytag_part(key_str, expected_keytag) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	}

	key_str = "jelte.nlnetlabs.nl. IN CDNSKEY 256 3 5 AQOraLfzarHAlFskVGwAGnX0LRjlcOiO6y5WM4Kz+QvZ9vX28h4lOvnf d5tkxnZm7ERLTAJoFq+1w/wl7VXs2Isz75BSZ7LQh3OT2xXnS6VT5ZxX ko/UCOdoGiKZZ63jHZ0jNSTCYy8+5rfvwRD8s3gGuErp5KcHg3V8VLUK SDNNEQ==";
	expected_keytag = 42860;
	if (check_ldns_calc_keytag_part(key_str, expected_keytag) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	}

/* template for adding extra keys
	key_str = "";
	expected_keytag = ;
	if (check_ldns_calc_keytag_part(key_str, expected_keytag) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	}
*/

	return result;
}

ldns_status
check_ldns_canonicalization(void)
{
	const char rr_str1[] = "bla.nl. 1000 IN NS ns1.bla.nl.";
	const char rr_str2[] = "BLA.NL. 1000 IN NS NS1.BlA.Nl.";

	ldns_rr *rr1 = NULL, *rr2 = NULL;
	ldns_status status = LDNS_STATUS_ERR;
	int diff;

	status = ldns_rr_new_frm_str(&rr1, rr_str1, 0, NULL, NULL);

	if (status != LDNS_STATUS_OK) {
		fprintf(stdout, "Error constructing rr: %s\n", rr_str1);
	}

	status = ldns_rr_new_frm_str(&rr2, rr_str2, 0, NULL, NULL);

	if (status != LDNS_STATUS_OK) {
		fprintf(stdout, "Error constructing rr: %s\n", rr_str2);
	}

	ldns_rr2canonical(rr1);
	ldns_rr2canonical(rr2);

	diff = ldns_rr_compare(rr1, rr2);
	if (diff != 0) {
		printf("Error, canonicalization does not work\n");
		status = LDNS_STATUS_ERR;
	} else {
		status = LDNS_STATUS_OK;
	}

	if (rr1)
		ldns_rr_free(rr1);

	if (rr2)
		ldns_rr_free(rr2);

	return status;
}


/* An outside-apex name must not enter the denial chain, even when it
 * sorts before the apex or has fewer labels than the apex.
 */
static int
check_out_of_zone_names(void)
{
	static const struct {
		const char *rr;
		int occluded;
	} records[] = {
		{"example.com. 240 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5", 0},
		{"example.com. 240 IN NS ns.example.com.", 0},
		{"ns.example.com. 240 IN A 192.0.2.1", 0},
		{"a.b.example.com. 240 IN A 192.0.2.2", 0},
		{"*.example.com. 240 IN A 192.0.2.3", 0},
		{"before. 240 IN A 192.0.2.4", 1},
		{"after.org. 240 IN A 192.0.2.5", 1},
		{"notexample.com. 240 IN A 192.0.2.6", 1},
		{"com. 240 IN A 192.0.2.7", 1},
		{"child.example.com. 240 IN NS ns.child.example.com.", 0},
		{"ns.child.example.com. 240 IN A 192.0.2.8", 1},
		{"alias.example.com. 240 IN DNAME target.example.net.", 0},
		{"under.alias.example.com. 240 IN A 192.0.2.9", 1}
	};
	ldns_dnssec_zone *zone = ldns_dnssec_zone_new();
	ldns_rr_list *glue = ldns_rr_list_new();
	ldns_rr *rr = NULL;
	ldns_rdf *name;
	ldns_rbnode_t *node;
	size_t i;
	int result = 1;

	if (!zone || !glue) {
		ldns_dnssec_zone_deep_free(zone);
		ldns_rr_list_free(glue);
		return 0;
	}
	for (i = 0; i < sizeof(records) / sizeof(records[0]); i++) {
		if (ldns_rr_new_frm_str(&rr, records[i].rr, 0, NULL, NULL)
			!= LDNS_STATUS_OK) {
			result = 0;
			goto done;
		}
		if (ldns_dnssec_zone_add_rr(zone, rr) != LDNS_STATUS_OK) {
			ldns_rr_free(rr);
			result = 0;
			goto done;
		}
	}
	if (ldns_dnssec_zone_mark_and_get_glue(zone, glue) != LDNS_STATUS_OK) {
		result = 0;
		goto done;
	}
	for (i = 0; i < sizeof(records) / sizeof(records[0]); i++) {
		if (ldns_rr_new_frm_str(&rr, records[i].rr, 0, NULL, NULL)
			!= LDNS_STATUS_OK) {
			result = 0;
			goto done;
		}
		node = ldns_rbtree_search(zone->names, ldns_rr_owner(rr));
		if (!node || ((ldns_dnssec_name *)node->data)->is_glue !=
			(bool)records[i].occluded) {
			printf("Wrong authority for %s\n", records[i].rr);
			result = 0;
		}
		ldns_rr_free(rr);
	}
	/* Only delegation glue belongs in this list, not outside-apex A RRs. */
	if (ldns_rr_list_rr_count(glue) != 1) result = 0;
	if (ldns_dnssec_zone_add_empty_nonterminals(zone) != LDNS_STATUS_OK) {
		result = 0;
		goto done;
	}
	name = ldns_dname_new_frm_str("b.example.com.");
	node = ldns_rbtree_search(zone->names, name);
	if (!node || ((ldns_dnssec_name *)node->data)->is_glue) result = 0;
	ldns_rdf_deep_free(name);
done:
	ldns_rr_list_free(glue);
	ldns_dnssec_zone_deep_free(zone);
	return result;
}


static int
check_root_and_missing_apex(void)
{
	ldns_dnssec_zone *zone = ldns_dnssec_zone_new();
	ldns_rr *rr;
	ldns_rbnode_t *node;
	int result = 1, root;
	if (!zone) return 0;
	if (ldns_rr_new_frm_str(&rr, "a.b.example.com. 240 IN A 192.0.2.1",
		0, NULL, NULL) != LDNS_STATUS_OK) {
		ldns_dnssec_zone_deep_free(zone);
		return 0;
	}
	if (ldns_dnssec_zone_add_rr(zone, rr) != LDNS_STATUS_OK) {
		ldns_rr_free(rr);
		ldns_dnssec_zone_deep_free(zone);
		return 0;
	}
	for (root = 0; root < 2; root++) {
		if (root) {
			if (ldns_rr_new_frm_str(&rr,
				". 240 IN SOA ns. hostmaster. 1 2 3 4 5",
				0, NULL, NULL) != LDNS_STATUS_OK) {
				result = 0;
				break;
			}
			if (ldns_dnssec_zone_add_rr(zone, rr) != LDNS_STATUS_OK) {
				ldns_rr_free(rr);
				result = 0;
				break;
			}
		}
		if (ldns_dnssec_zone_mark_glue(zone) != LDNS_STATUS_OK ||
			ldns_dnssec_zone_add_empty_nonterminals(zone) != LDNS_STATUS_OK) {
			result = 0;
			break;
		}
		for (node = ldns_rbtree_first(zone->names);
			node != LDNS_RBTREE_NULL; node = ldns_rbtree_next(node)) {
			if (((ldns_dnssec_name *)node->data)->is_glue) result = 0;
		}
	}
	ldns_dnssec_zone_deep_free(zone);
	return result;
}

int main(void)
{
	int result = EXIT_SUCCESS;

	if (!check_root_and_missing_apex()) {
		printf("check_root_and_missing_apex() failed.\n");
		result = EXIT_FAILURE;
	}

	if (!check_out_of_zone_names()) {
		printf("check_out_of_zone_names() failed.\n");
		result = EXIT_FAILURE;
	}

	if (check_ldns_calc_keytag() != LDNS_STATUS_OK) {
		printf("ldns_calc_keytag() failed.\n");
		result = EXIT_FAILURE;
	}

	if (check_ldns_canonicalization() != LDNS_STATUS_OK) {
		printf("ldns_rr2canonical() failed.\n");
		result = EXIT_FAILURE;
	}

	exit(result);
}
