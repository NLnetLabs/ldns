#include "config.h"
#include "zones.h"
#include "zinfo.h"

/** compare two zone_entry */
static int zones_cmp(const void* a, const void* b)
{
	struct zone_entry_t* x = (struct zone_entry_t*)a;
	struct zone_entry_t* y = (struct zone_entry_t*)b;
	if(x->zclass != y->zclass) {
		if(x->zclass < y->zclass)
			return -1;
		return 1;
	}
	return ldns_rdf_compare(x->zname, y->zname);
}

struct zones_t* zones_create()
{
	struct zones_t* zones = (struct zones_t*)malloc(
		sizeof(struct zones_t));
	if(!zones) 
		return NULL;
	zones->ztree = ldns_rbtree_create(zones_cmp);
	if(!zones->ztree) {
		free(zones);
		return NULL;
	}
	return zones;
}

void zones_read(struct zones_t* zones)
{
	struct zone_entry_t* entry;
	LDNS_RBTREE_FOR(entry, struct zone_entry_t*, zones->ztree) {
		if(!zinfo_read(entry)) {
			fprintf(stderr, "could not read zone %s\n", 
				entry->zstr);
			exit(1);
		}
	}
}

struct zone_entry_t* zones_find(struct zones_t* zones, const char* name,
	uint16_t fclass)
{
	ldns_rdf* rd = ldns_dname_new_frm_str(name);
	struct zone_entry_t* found;
	if(!rd) {
		printf("out of memory\n");
		return NULL;
	}
	found = zones_find_rdf(zones, rd, fclass);
	ldns_rdf_deep_free(rd);
	return found;
}

struct zone_entry_t* zones_find_rdf(struct zones_t* zones, ldns_rdf* name,
	uint16_t fclass)
{
	struct zone_entry_t z;
	ldns_rbnode_t* found;
	z.node.key = &z;
	z.zname = name;
	z.zclass = fclass;
	found = ldns_rbtree_search(zones->ztree, &z);
	return (struct zone_entry_t*)found;
}

struct zone_entry_t* zones_insert(struct zones_t* zones, const char* name,
        uint16_t nclass)
{
	struct zone_entry_t* entry = zones_find(zones, name, nclass);
	if(entry)
		return entry;
	entry = (struct zone_entry_t*)malloc(sizeof(struct zone_entry_t));
	memset(entry, 0, sizeof(struct zone_entry_t));
	entry->node.key = entry;
	entry->zstr = strdup(name);
	if(!entry->zstr) {
		free(entry);
		return NULL;
	}
	entry->zclass = nclass;
	entry->zname = ldns_dname_new_frm_str(name);
	if(!entry->zname) {
		free(entry);
		free(entry->zstr);
		return NULL;
	}
	entry->zinfo = zinfo_create();
	if(!entry->zinfo) {
		free(entry);
		free(entry->zstr);
		ldns_rdf_deep_free(entry->zname);
		return NULL;
	}

	/* insert entry into data structure */
	ldns_rbtree_insert(zones->ztree, &entry->node);
	return entry;
}

void zone_entry_free(struct zone_entry_t* entry)
{
	if(!entry) return;
	zinfo_delete(entry->zinfo);
	free(entry->zstr);
	ldns_rdf_deep_free(entry->zname);
	free(entry);
}

static void z_free(ldns_rbnode_t* n, void* arg)
{
	(void)arg;
	zone_entry_free((struct zone_entry_t*)n);
}

void zones_free(struct zones_t* zones)
{
	if(!zones)
		return;
	ldns_traverse_postorder(zones->ztree, z_free, NULL);
	ldns_rbtree_free(zones->ztree);
	free(zones);
}
