/* zinfo.c - zone information */
#include "config.h"
#include "zinfo.h"
#include "zones.h"

static int cmp_version(const void* a, const void* b)
{
	struct zversion_t* x = (struct zversion_t*)a;
	struct zversion_t* y = (struct zversion_t*)b;
	if(x->serial < y->serial)
		return -1;
	if(x->serial > y->serial)
		return -1;
	return 0;
}

static int cmp_domain(const void* a, const void* b)
{
	struct zdomain_t* x = (struct zdomain_t*)a;
	struct zdomain_t* y = (struct zdomain_t*)b;
	return ldns_rdf_compare(x->name, y->name);
}

struct zinfo_t* zinfo_create(void)
{
	struct zinfo_t* zinfo = (struct zinfo_t*)calloc(1, sizeof(*zinfo));
	zinfo->is_present = 0;
	ldns_rbtree_init(&zinfo->vs, cmp_version);
	ldns_rbtree_init(&zinfo->zone, cmp_domain);
	return zinfo;
}

static void del_vs(ldns_rbnode_t* node, void* arg)
{
	(void)arg;
	zversion_delete((struct zversion_t*)node);
}

static void del_domain(ldns_rbnode_t* node, void* arg)
{
	(void)arg;
	zdomain_delete((struct zdomain_t*)node);
}

void zinfo_delete(struct zinfo_t* zinfo)
{
	if(!zinfo) return;
	free(zinfo->dir);
	ldns_rr_list_deep_free(zinfo->last_soa);
	ldns_traverse_postorder(&zinfo->vs, del_vs, NULL);
	ldns_traverse_postorder(&zinfo->zone, del_domain, NULL);
	free(zinfo);
}

/** Get a pointer to a static buffer with filename */
const char* zinfo_index_name(struct zone_entry_t* entry)
{
	static char buf[1024];
	snprintf(buf, sizeof(buf), "%s/zone.%s.index", 
		entry->zinfo->dir, entry->zstr);
	return buf;
}
/** Get a pointer to a static buffer with filename */
const char* zinfo_ixfr_name(struct zone_entry_t* entry, uint32_t soa)
{
	static char buf[1024];
	snprintf(buf, sizeof(buf), "%s/zone.%s.ixfr.%u", 
		entry->zinfo->dir, entry->zstr, soa);
	return buf;
}
/** Get a pointer to a static buffer with filename */
const char* zinfo_full_name(struct zone_entry_t* entry, uint32_t soa)
{
	static char buf[1024];
	snprintf(buf, sizeof(buf), "%s/zone.%s.full.%u", 
		entry->zinfo->dir, entry->zstr, soa);
	return buf;
}
/** see if file exists */
static int file_exists(const char* path)
{
	struct stat buf;
	if(stat(path, &buf) < 0) {
		if(errno == ENOENT)
			return 0;
		printf("stat(%s): %s\n", path, strerror(errno));
		return 0;
	}
	return 1;
}

int zinfo_read(struct zone_entry_t* entry)
{
	const char* iname = zinfo_index_name(entry);
	FILE* index = fopen(iname, "ra");
	uint32_t serial = 0;
	uint32_t last_full = 0;
	int have_last_full;
	if(!index) {
		if(errno == ENOENT) {
			printf("zone %s is empty\n", entry->zstr);
			return 1;
		}
		perror(iname);
		return 0;
	}
	if(fscanf(index, " %u", &serial) != 1) {
		fclose(index);
		printf("error reading %s\n", iname);
		return 0;
	}
	fclose(index);

	/* read versions */
	while(file_exists(zinfo_ixfr_name(entry, serial))) {
		struct zversion_t* v = zversion_read(entry, serial);
		if(!v) return 0;
		if(file_exists(zinfo_full_name(entry, serial))) {
			have_last_full = 1;
			last_full = serial;
		}
		serial = v->next_serial;
	}
	if(file_exists(zinfo_full_name(entry, serial))) {
		have_last_full = 1;
		last_full = serial;
	}

	/* read full zone */
	if(!have_last_full) {
		printf("No full zone file available for zone %s\n", 
			entry->zstr);
		return 0;
	}
	entry->zinfo->last_serial = serial;
	entry->zinfo->is_present = 1;
	if(!zfull_read(entry, last_full))
		return 0;
	return 1;
}

int zinfo_get_zone_diff(struct zone_entry_t* entry, uint32_t serial_from, 
	uint32_t serial_to, ldns_rr_list** rr_remove, ldns_rr_list** rr_add, 
	ldns_rr** soa_from, ldns_rr** soa_to)
{
	/* DIFFs stored in memory and served from memory without copy */
	/* TODO */
}

void zinfo_get_zone_full(struct zone_entry_t* entry, uint32_t serial,
	ldns_zone** z)
{
	/* full zone kept in memory, served from memory after a fork 
	 * (and close of other sockets after fork) */
	/* TODO */
}

void zversion_delete(struct zversion_t* v)
{
	if(!v) return;
	ldns_rr_list_deep_free(v->ixfr);
	free(v);
}

struct zversion_t* zversion_read(struct zone_entry_t* entry, uint32_t serial)
{
	const char* fn = zinfo_ixfr_name(entry, serial);
	struct zversion_t* v;
	FILE* in = fopen(fn, "ra");
	ldns_status status;
	ldns_rr* rr = 0;
	uint32_t dttl = 3600;
	ldns_rdf* origin = 0, *prev = 0;
	int line_nr = 1;
	if(!in) {
		perror(fn);
		return NULL;
	}
	v = (struct zversion_t*)calloc(1, sizeof(*v));
	if(!v) {
		fclose(in);
		printf("out of memory\n");
		return NULL;
	}
	v->serial = serial;
	v->ixfr = ldns_rr_list_new();
	while(!feof(in)) {
		status = ldns_rr_new_frm_fp_l(&rr, in, &dttl, &origin, 
			&prev, &line_nr);
		if(status == LDNS_STATUS_SYNTAX_TTL || 
			status == LDNS_STATUS_SYNTAX_ORIGIN ||
			status == LDNS_STATUS_SYNTAX_EMPTY)
			continue;
		if(status != LDNS_STATUS_OK) {
			printf("error %s:%d: %s\n", fn, line_nr, 
				ldns_get_errorstr_by_id(status));
			fclose(in);
			ldns_rdf_deep_free(origin);
			ldns_rdf_deep_free(prev);
			ldns_rr_list_deep_free(v->ixfr);
			free(v);
			return NULL;
		}
		ldns_rr_list_push_rr(v->ixfr, rr);
	}
	ldns_rdf_deep_free(origin);
	ldns_rdf_deep_free(prev);
	fclose(in);
	if(ldns_rr_list_rr_count(v->ixfr) < 1 || 
		ldns_rr_get_type(ldns_rr_list_rr(v->ixfr, 0)) 
			!= LDNS_RR_TYPE_SOA) {
		printf("invalid IXFR format in %s\n", fn);
		ldns_rr_list_deep_free(v->ixfr);
		free(v);
		return NULL;
	}
	v->next_serial = ldns_rdf2native_int32(ldns_rr_rdf(
		ldns_rr_list_rr(v->ixfr, 0), 2));
	return v;
}

static void del_rrset(ldns_rbnode_t* node, void* arg)
{
	(void)arg;
	zrrset_delete((struct zrrset_t*)node);
}

void zdomain_delete(struct zdomain_t* d)
{
	if(!d) return;
	ldns_traverse_postorder(&d->rrsets, del_rrset, NULL);
	ldns_rdf_deep_free(d->name);
	free(d);
}

int zfull_read(struct zone_entry_t* entry, uint32_t serial)
{
}

void zrrset_delete(struct zrrset_t* r)
{
	if(!r) return;
	ldns_rr_list_deep_free(r->list);
	free(r);
}
