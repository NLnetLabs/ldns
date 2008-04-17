#include "config.h"
#include "zones.h"
#include "store.h"

struct zones_t* zones_create()
{
	struct zones_t* zones = (struct zones_t*)malloc(
		sizeof(struct zones_t));
	if(!zones) 
		return NULL;
	memset(zones, 0, sizeof(struct zones_t));
	return zones;
}

int zones_init(struct zones_t* zones, const char* config)
{
	/* (re)read the config file */
	FILE *in = fopen(config, "r");
	char buf[4096], zone_name[4096], backend[4096], arg[4096];
	int lineno = 0;
	struct zone_entry_t* entry = 0;

	if(!in) {
		perror(config);
		return 0;
	}
	while(fgets(buf, sizeof(buf), in)) {
		lineno++;
		printf("reading masterdontconf: %s", buf);
		if(buf[0] == '#' || buf[0] == '\n')
			continue; /* skip comments and empty lines */
		if(sscanf(buf, " %s %s %s", zone_name, backend, arg) != 3) {
			printf("Could not parse %s:%d %s\n",
				config, lineno, buf);
			fclose(in);
			return 0;
		}
		entry = zones_find(zones, zone_name);
		if(!entry) { /* new entry */
			entry = zones_insert(zones, zone_name, backend);
			if(!entry) {
				printf("Could not add entry for %s\n",
					zone_name);
				fclose(in);
				return 0;
			}
		}
		/* re-init */
		if(! entry->store->init(entry->store, arg) ) {
			printf("Could not init zone %s\n", zone_name);
			fclose(in);
			return 0;
		}
	}

	fclose(in);
	return 1;
}

struct zone_entry_t* zones_find(struct zones_t* zones, const char* name)
{
	struct zone_entry_t *p = zones->first;
	while(p) {
		if(strcmp(name, p->store->zone_name) == 0)
			return p;
		p = p->next;
	}
	return NULL;
}

struct zone_entry_t* zones_find_rdf(struct zones_t* zones, ldns_rdf* name)
{
	char* str = ldns_rdf2str(name);
	struct zone_entry_t* entry = 0;
	if(str) {
		entry = zones_find(zones, str);
		free(str);
	}
	return entry;
}

struct zone_entry_t* zones_insert(struct zones_t* zones, const char* name,
        const char* backend)
{
	struct zone_entry_t* entry = zones_find(zones, name);
	if(entry)
		return entry;
	entry = (struct zone_entry_t*)malloc(sizeof(struct zone_entry_t));
	memset(entry, 0, sizeof(struct zone_entry_t));
	entry->store = store_create(name, backend);
	if(!entry->store) {
		free(entry);
		return NULL;
	}
	/* insert entry into data structure */
	zones->num_zones ++;
	entry->next = zones->first;
	zones->first = entry;
	return entry;
}

void zones_free(struct zones_t* zones)
{
	struct zone_entry_t* p = zones->first, *np = 0;
	while(p) {
		np = p->next;
		p->store->store_free(p->store);
		free(p);
		p = np;
	};
	zones->first = 0;
	free(zones);
}
