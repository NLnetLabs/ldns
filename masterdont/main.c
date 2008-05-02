#include "config.h"
#include "config_file.h"
#include "zones.h"
#include "server.h"

static void
usage(const char* me)
{
	printf("usage: %s [options]\n", me);
	printf("Hidden master stealth server: serves AXFR, IXFR.\n");
	printf("-h		print this information.\n");
	printf("-c <file>	set config file to use.\n");
	printf("\n");
}

int main(int argc, char* argv[])
{
	const char* config = DEFAULT_CONFIG;
	int c;

	while((c=getopt(argc, argv, "c:h")) != -1)
	{
		switch(c) {
		case 'c':
			config = optarg;
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
	
	/* start server */
	while(server_start(config)) {
		printf("Masterdont reload\n");
	}
	printf("Masterdont stopped\n");
	return 0;
}
