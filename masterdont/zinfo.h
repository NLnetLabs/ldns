/* zinfo.h - zone info */

#ifndef ZINFO_H
#define ZINFO_H
struct zone_entry_t;

/**
 * Store zone content information
 * zone identity is stored in zone_entry_t.
 */
struct zinfo_t {
	/** 
	 * directory to use for disk storage 
	 *	o zone.<name>.index  --  oldest SOA number in dir
	 *	o zone.<name>.ixfr.<soa>  --  text format ixfr to next version.
	 *	o zone.<name>.full.<soa>  --  text format full zone file.
	 * The full file may be omitted for many versions. At least one.
	 */
	char* dir;

	/** is the zone present at all (or empty, no data) */
	int is_present;
	/** latest serial number */
	uint32_t last_serial;
	/** latest SOA (also present in complete zone) plus rrsigs */
	ldns_rr_list* last_soa;

	/** tree of versions, sorted by serial and contains IXFRs.
	 * the last serial number is not in here, but kept as complete zone. */
	ldns_rbtree_t vs;

	/** for last version, the complete zone. zdomain_t sorted by name */
	ldns_rbtree_t zone;
};

/**
 * A zone version
 */
struct zversion_t {
	/** rbtree node, sorted by serial */
	ldns_rbnode_t node;
	/** serial number */
	uint32_t serial;
	/** next serial number */
	uint32_t next_serial;
	/** ixfr contents */
	ldns_rr_list* ixfr;
};

/**
 * A domain name in the complete zone tree
 */
struct zdomain_t {
	/** rbtree node */
	ldns_rbnode_t node;
	/** rdf name */
	ldns_rdf* name;
	/** the rrsets present, sorted by type */
	ldns_rbtree_t rrsets;
};

/**
 * An rrset at a name in the complete zone tree
 */
struct zrrset_t {
	/** rbtree node */
	ldns_rbnode_t node;
	/** rr set */
	ldns_rr_list* list;
};

/**
 * Create a zinfo. No data, empty.
 */
struct zinfo_t* zinfo_create(void);

/**
 * Delete a zinfo
 */
void zinfo_delete(struct zinfo_t* zinfo);

/**
 * Read zone info from stable storage (disk)
 */
int zinfo_read(struct zone_entry_t* entry);

/** Get a pointer to a static buffer with filename */
const char* zinfo_index_name(struct zone_entry_t* entry);
/** Get a pointer to a static buffer with filename */
const char* zinfo_ixfr_name(struct zone_entry_t* entry, uint32_t soa);
/** Get a pointer to a static buffer with filename */
const char* zinfo_full_name(struct zone_entry_t* entry, uint32_t soa);

int zinfo_get_zone_diff(struct zone_entry_t* entry, uint32_t serial_from, 
	uint32_t serial_to, ldns_rr_list** rr_remove, ldns_rr_list** rr_add, 
	ldns_rr** soa_from, ldns_rr** soa_to);

void zinfo_get_zone_full(struct zone_entry_t* entry, uint32_t serial,
	ldns_zone** z);

/* ----------------------- zversion ---------------------- */
void zversion_delete(struct zversion_t* v);
struct zversion_t* zversion_read(struct zone_entry_t* entry, uint32_t serial);

/* ----------------------- zdomain ---------------------- */
void zdomain_delete(struct zdomain_t* d);
int zfull_read(struct zone_entry_t* entry, uint32_t serial);

/* ----------------------- zrrset ---------------------- */
void zrrset_delete(struct zrrset_t* r);

#endif
