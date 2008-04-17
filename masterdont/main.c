#include "config.h"
#include "zones.h"
#include "server.h"

static void
usage(const char* me)
{
	printf("usage: %s [options]\n", me);
	printf("Hidden master stealth server: serves AXFR, IXFR.\n");
	printf("-h		print this information.\n");
	printf("-p <port>	set port number of server.\n");
	printf("-c <file>	set config file to use.\n");
	printf("\n");
}

int main(int argc, char* argv[])
{
	struct zones_t* zones = zones_create();
	char* config = strdup(DEFAULT_CONFIG);
	int port = DEFAULT_PORT;
	int c;

	while((c=getopt(argc, argv, "c:hp:")) != -1)
	{
		switch(c) {
		case 'p':
			port = atoi(optarg);
			if(!port) {
				printf("Bad port number: %s\n", optarg);
				return 1;
			}
			break;
		case 'c':
			if(config) free(config);
			config = strdup(optarg);
			break;
		default:
			printf("Unknown option '-%c' (%x).\n", c, c);
		case 'h':
			usage(argv[0]);
			return 1;
		}
	}
	argc -= optind;
	argv += optind;
	if(argc > 0) {
		printf("Too many arguments.\n");
		usage(argv[0]);
		return 1;
	}
	
	if(!zones_init(zones, config)) {
		printf("Error reading configuration.\n");
		return 1;
	}

	/* start server */
	server_start(zones, config, port);

	/* exit cleanup */
	zones_free(zones); zones = 0;
	free(config); config=0;
	return 0;
}
