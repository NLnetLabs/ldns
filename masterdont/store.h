/*
 * store.h
 *
 * Data store for masterdont
 */

#ifndef STORE_H
#define STORE_H

/**
 * Data type for a backend store.
 * contains callbacks and opaque data.
 * The returned objects are allocated dynamically by the routine,
 * NULL ptr can be returned on an error. User must deallocate objects.
 */
struct store_t {
	/* init the store object.
	   returns 0 on failure to init. */
	int (*init)(struct store_t* store, const char* config_string);

	/* returns latest serial number for zone */
	uint32_t (*get_latest_serial)(struct store_t* store);

	/* return full zone. */
	void (*get_zone_full)(struct store_t* store, uint32_t serial, 
		ldns_zone** zone);

	/* return zone diff */
	void (*get_zone_diff)(struct store_t* store, uint32_t serialfrom, 
		uint32_t serialto, ldns_rr_list** rr_remove, 
		ldns_rr_list** rr_add, ldns_rr** rr_soa_from, 
		ldns_rr** rr_soa_to);

	/* return latest SOA */
	void (*get_latest_SOA)(struct store_t* store, ldns_rr** soa_rr);

	/* deallocate entire store_t */
	void (*store_free)(struct store_t* store);

	/* name of the zone, malloced. */
	char* zone_name;

	/* backend type, malloced. */
	char* backend;

	/* object data */
	void* store_data;
};

/**
 * Factory for store objects, creates store_t based on type string.
 * 'text' for text based backend.
 */
struct store_t* store_create(const char* zone_name, const char* backend);

#endif /* STORE_H */
