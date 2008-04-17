#include "config.h"
#include "store.h"
#include "backtext.h"

struct store_t*
store_create(const char* zone_name, const char* backend)
{
	struct store_t* store = NULL;

	store = (struct store_t*)malloc(sizeof(struct store_t));
	if(!store) {
		printf("out of memory\n");
		return NULL;
	}
	memset(store, 0, sizeof(struct store_t));
	store->zone_name = strdup(zone_name);
	store->backend = strdup(backend);
	store->store_data = NULL;

	if(strcmp(backend, "text") == 0) {
		store->init = back_text_init;
		store->get_latest_serial = back_text_get_latest_serial;
		store->get_zone_full = back_text_get_zone_full;
		store->get_zone_diff = back_text_get_zone_diff;
		store->get_latest_SOA = back_text_get_latest_SOA;
		store->store_free = back_text_store_free;
	} else {
		printf("Error: zone %s unknown backend type: '%s'\n", 
			zone_name, backend);
		return NULL;
	}

	return store;
}
