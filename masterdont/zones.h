/*
	zones.h		keep list of zones to handle with backend info.
*/

#ifndef ZONES_H
#define ZONES_H
struct zinfo_t;

/**
 * zone entry information
 */
struct zone_entry_t {
	/** rbtree node info */
	ldns_rbnode_t node;
	/** zone name */
	ldns_rdf* zname;
	/** zone name in text */
	char* zstr;
	/** zone class */
	uint16_t zclass;
	/** zone info */
	struct zinfo_t* zinfo;
	
	/** next in linked list */
	struct zone_entry_t* next;
};

/**
 * Keep zones information.
*/
struct zones_t {
	/** tree of zone_entry, sorted by zname, zclass */
	ldns_rbtree_t* ztree;
};

/**
 * create new empty zones struct
*/
struct zones_t* zones_create(void);

/**
 * Read all the zone entry storage
 */
void zones_read(struct zones_t* zones);

/**
 * Find zone entry given the name
 * or NULL if doesn't exist
*/
struct zone_entry_t* zones_find(struct zones_t* zones, const char* name,
	uint16_t fclass);

/**
 * find a zone based on rdf 
 */
struct zone_entry_t* zones_find_rdf(struct zones_t* zones, ldns_rdf* name,
	uint16_t fclass);

/**
 * Insert new entry for zone name, returns new entry.
 * or NULL if out of memory.
*/
struct zone_entry_t* zones_insert(struct zones_t* zones, const char* name,
	uint16_t nclass);

/**
 * free a zone entry
 */
void zone_entry_free(struct zone_entry_t* entry);

/**
 * free zones data structure
*/
void zones_free(struct zones_t* zones);

#endif /* ZONES_H */
