/**
 * An example ldns program
 *
 *
 * Get a name
 * Setup a resolver
 * trace the result from the root down to the name
 * Print the result along the way
 */

#include <config.h>
#include <ldns/resolver.h>
        
void
print_usage(char *file)
{
	printf("Usage: %s <name> [initial NS]\n", file);
	printf("  if [initial NS] is not given 127.0.0.1 is used\n");
	exit(0);
}

int     
main(int argc, char **argv)
{       
        ldns_resolver *res;
        ldns_rdf *qname;
        ldns_rdf *nameserver;
        ldns_pkt *pkt;
        char *name;
	char *init_ns;
        
        if (argc < 2) {
        	print_usage(argv[0]);
	} else if (argc == 2) {
		name = argv[1];
		init_ns = "127.0.0.1";
	} else {
		name = argv[1];
		init_ns = argv[2];
	}
                
        /* init */
        res = ldns_resolver_new(); 
        if (!res)
                return 1;

}
