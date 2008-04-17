/*
 * backtext.h: text backend for masterdont
 */

#ifndef BACKTEXT_H
#define BACKTEXT_H

struct store_t;

/* exported routines from store */
int back_text_init(struct store_t* store, const char* config_string);
uint32_t back_text_get_latest_serial(struct store_t* store);
void back_text_get_zone_full(struct store_t* store, uint32_t serial,
	ldns_zone** zone);
void back_text_get_zone_diff(struct store_t* store, uint32_t serialfrom,
	uint32_t serialto, ldns_rr_list** rr_remove, ldns_rr_list** rr_add,
	ldns_rr** rr_soa_from, ldns_rr** rr_soa_to);
void back_text_get_latest_SOA(struct store_t* store, ldns_rr** soa_rr);
void back_text_store_free(struct store_t* store);

/** data for one version of a zone */
struct backtext_version_t {
	/** file containing full zone data */
	char* filename;
	/** serial number from file */
	uint32_t serial;

	/** next element in list */
	struct backtext_version_t* next;
};

/** the opaque data type that backend backtext uses. */
struct backtext_data_t {
	/** name of file containing list of zone files */
	char* zonelist_filename;

	/** linked list of zone versions */
	struct backtext_version_t *first, *last;
};

/* private routines */

/**
 * Read the zone list, store in order in the list.
 * Read zone file to get SOA.
 * returns 0 on error.
 */
int back_text_read_list(struct store_t* store);

/**
 * Delete all entries in the list
 */
void back_text_free_list(struct store_t* store);

/**
 * Create new version entry from filename.
*/
struct backtext_version_t* back_text_version_create(const char* zonefile,
	const char* zone_name);

/**
 * Open de file and read the SOA at the start of the file.
 * can return NULL on file error / no SOA record.
 */
ldns_rr* back_text_get_soa(const char* zonefile, const char* zone_name);

/**
 * Read RRs from FILE and return the SOA (if any)
 * Or NULL on error.
 */
ldns_rr* back_text_read_soa(FILE *in, const char* zonefile, uint32_t* my_ttl,
	ldns_rdf** my_origin, ldns_rdf** my_prev, int* line_nr);

/**
 * find version by serial number
 * returns NULL if not found.
*/
struct backtext_version_t* back_text_version_find(struct store_t* store,
	uint32_t serial);

/* read next RR from a file.
   Returns 0 on error, and *rr=NULL on eof (feof(in) is true). */
int back_text_next_rr(ldns_rr** rr, FILE *in, const char* zonefile, 
	uint32_t* my_ttl, ldns_rdf** my_origin, ldns_rdf** my_prev, 
	int* line_nr);

#endif /* BACKTEXT_H */
