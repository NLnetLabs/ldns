/* config_file.c - masterdont config file reading */
#include "config.h"
#include "config_file.h"
#include "zones.h"
#include "zinfo.h"

/* used during config file reading */
static struct config_read cread;

/* config syntax error */
static void config_err(char* str)
{
	if(cread.include_depth == 0) 
		fprintf(stderr, "error: %s\n", str);
	else fprintf(stderr, "error in %s %d: %s\n", 
		cread.fnames[cread.include_depth-1],
		cread.lineno[cread.include_depth-1], str);
	exit(1);
}

/* skip to end of line */
static void skip_to_eol(FILE* in)
{
	int c;
	while( (c=fgetc(in)) != EOF) {
		if(c == '\n') {
			cread.lineno[cread.include_depth-1]++;
			return;
		}
	}
	/* EOF is end of line too for ending a comment */
}

/* fill quoted string, remove ending quote */
static void fillup_quoted(FILE* in, char* buf, size_t sz, char q)
{
	size_t pos = strlen(buf);
	int c;
	if(pos>0 && buf[pos-1] == q) {
		buf[pos-1] = 0;
		return;
	}
	while( (c=fgetc(in)) != EOF ) {
		if(c == q) {
			buf[pos] = 0;
			return;
		}
		buf[pos++] = c;
		if(pos >= sz) config_err("string too long");
	}
	config_err("no ending quote for string");
}

/* skip whitespace */
static char skip_white(FILE* in)
{
	int c;
	while( (c=fgetc(in)) != EOF ) {
		if(c == ' ' || c == '\t' || c == '\r')
			continue;
		else if(c == '\n') {
			cread.lineno[cread.include_depth-1]++;
			continue;
		}
		return c;
	}
	return 0;
}

/* mini lexer and parser; grab one word from the input file, skip
 * whitespace and comments. return 0 on EOF */
static char* read_token(FILE* in)
{
	static char buf[10240];
	buf[sizeof(buf)-1] = 0;
	while(!feof(in)) {
		buf[0] = skip_white(in);
		if(feof(in)) return 0;
		if(fscanf(in, "%10230s", buf+1) != 1) {
			return 0;
		}
		if(buf[0] == '#') {
			skip_to_eol(in);
			continue;
		} else if(buf[0] == '\"' || buf[0] == '\'') {
			fillup_quoted(in, buf, sizeof(buf), buf[0]);
			return buf+1;
		}
		return buf;
	}
	return 0;
}

struct config_file* config_file_create()
{
	struct config_file* cfg = (struct config_file*)calloc(1, sizeof(*cfg));
	if(!cfg) {
		printf("out of memory\n");
		exit(1);
	}
	cfg->port = DEFAULT_PORT;
	return cfg;
}

void config_file_delete(struct config_file* cfg)
{
	if(!cfg) return;
	free(cfg);
}

/* open new include file */
static void config_open_include(const char* fname)
{
	if(cread.include_depth >= MAX_INCLUDES)
		config_err("too many include files");
	cread.fnames[cread.include_depth] = strdup(fname);
	if(!cread.fnames[cread.include_depth])
		config_err("out of memory");
	cread.fstack[cread.include_depth] = fopen(fname, "ra");
	if(!cread.fstack[cread.include_depth]) {
		perror(fname);
		config_err("could not open config file");
	}
	cread.lineno[cread.include_depth] = 1;
	cread.include_depth ++;
}

/* close include file */
static void config_close_include(void)
{
	if(cread.include_depth == 0) config_err("unexpected end of file");
	free(cread.fnames[cread.include_depth-1]);
	fclose(cread.fstack[cread.include_depth-1]);
	cread.fstack[cread.include_depth-1] = NULL;
	cread.include_depth--;
}

void config_file_read(struct config_file* cfg, const char* fname, 
	struct zones_t* zones)
{
	char* p;
	char key[1024];
	cread.cfg = cfg;
	cread.zones = zones;
	cread.include_depth = 0;
	cread.zone_read = 0;

	config_open_include(fname);
	while(cread.include_depth > 0) {
		p = read_token(cread.fstack[cread.include_depth-1]);
		if(p == 0) {
			config_close_include();
			continue;
		}
		if(strcmp(p, "server:") == 0)
			continue;
		else if(strcmp(p, "zone:") == 0) {
			if(cread.zone_read) config_file_add_zone(&cread);
			cread.zone_read = 1;
			cread.zone_linenr = cread.lineno[cread.include_depth-1];
			cread.zone_name = NULL;
			cread.zone_dir = NULL;
			continue;
		}
		key[sizeof(key)-1]=0;
		strncpy(key, p, sizeof(key)-1);
		while((p=read_token(cread.fstack[cread.include_depth-1]))==0){
			config_close_include();
			if(cread.include_depth == 0) 
				config_err("unexpected end of file");
		}
		
		if(strcmp(key, "include:") == 0) {
			config_open_include(p);
		} else if(strcmp(key, "port:") == 0) {
			cfg->port = atoi(p);
			if(cfg->port == 0) config_err("invalid port number");
		} else if(strcmp(key, "name:") == 0) {
			free(cread.zone_name);
			cread.zone_name = strdup(p);
			if(!cread.zone_name) config_err("out of memory");
		} else if(strcmp(key, "dir:") == 0) {
			free(cread.zone_dir);
			cread.zone_dir = strdup(p);
			if(!cread.zone_dir) config_err("out of memory");
		}
	}
	if(cread.zone_read) config_file_add_zone(&cread);
}

void config_file_add_zone(struct config_read* cr)
{
	struct zone_entry_t* entry;
	if(cr->zone_name == NULL) {
		fprintf(stderr, "in zone declared on line %d\n", 
			cr->zone_linenr);
		config_err("zone has no name");
	}
	if(cr->zone_dir == NULL) {
		fprintf(stderr, "in zone declared on line %d\n", 
			cr->zone_linenr);
		config_err("zone has no dir");
	}
	entry = zones_insert(cr->zones, cr->zone_name, LDNS_RR_CLASS_IN);
	if(!entry) {
		config_err("out of memory adding zone");
	}
	entry->zinfo->dir = cr->zone_dir;
	free(cr->zone_name);
}
