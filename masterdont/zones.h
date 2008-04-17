/*
	zones.h		keep list of zones to handle with backend info.
*/

#ifndef ZONES_H
#define ZONES_H

struct store_t;

/**
 * zone entry information
 */
struct zone_entry_t {
	/** store (backend) zone info */
	struct store_t* store;
	
	/** next in linked list */
	struct zone_entry_t* next;
};

/**
 * Keep zones list information.
*/
struct zones_t {
	/** number of zones in list */
	int num_zones;
	/** linked list of zone entries */
	struct zone_entry_t* first;
};

/**
 * create new empty zones struct
*/
struct zones_t* zones_create();

/**
 * Initialize the zones structure by reading from config file
 * Returns 0 on a failure.
*/
int zones_init(struct zones_t* zones, const char* config);


/**
 * Find zone entry given the name
 * or NULL if doesn't exist
*/
struct zone_entry_t* zones_find(struct zones_t* zones, const char* name);

/**
 * find a zone based on rdf 
 */
struct zone_entry_t* zones_find_rdf(struct zones_t* zones, ldns_rdf* name);

/**
 * Insert new entry for zone name, returns new entry.
 * or NULL if out of memory or bad backend spec.
*/
struct zone_entry_t* zones_insert(struct zones_t* zones, const char* name,
	const char* backend);

/**
 * free zones data structure
*/
void zones_free(struct zones_t* zones);

#endif /* ZONES_H */
