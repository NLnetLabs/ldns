/* confile_file.h - masterdont config file reading */

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H
struct zones_t;

#define DEFAULT_PORT    53 /* default is to use the DNS port */
#define MAX_TCP         200 /* max number concurrent tcp queries */
#define SERVER_BUFFER_SIZE 65535 /* bytes */
#define TCP_LISTEN_BACKLOG 15 /* max number of waiting connections */
#define TCP_PKT_SIZE    16384 /* bytes size max tcp packet */

/** a config file that has been read in */
struct config_file {
	/** port number to use */
	int port;
};

/** max number of nested include files */
#define MAX_INCLUDES 100

/** during config read */
struct config_read {
	/** the cfg file */
	struct config_file* cfg;
	/** zone tree */
	struct zones_t* zones;

	/** current include depth */
	int include_depth;
	/** stack of include files */
	FILE* fstack[MAX_INCLUDES];
	/** name of include files */
	char* fnames[MAX_INCLUDES];
	/** line number */
	int lineno[MAX_INCLUDES];

	/** is the temp zone entry filled out? */
	int zone_read;
	/** line number where we started reading this zone */
	int zone_linenr;
	/** zone entry we are reading */
	char* zone_name;
	/** zone dir */
	char* zone_dir;
};

/** create structure with defaults */
struct config_file* config_file_create(void);

/** delete structure */
void config_file_delete(struct config_file* cfg);

/** read in a config file */
void config_file_read(struct config_file* cfg, const char* fname,
	struct zones_t* zones);

/** during config read, add another zone */
void config_file_add_zone(struct config_read* cr);

#endif
