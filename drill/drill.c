/*
 * drill.c
 * the main file of drill
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

#define IP6_ARPA_MAX_LEN 65

/* query debug, 2 hex dumps */
int8_t		qdebug; /* -1, be quiet, 1 show question, 2 show hex */

static void
usage(FILE *stream, const char *progname)
{
	fprintf(stream, "  Usage: %s name [@server] [type] [class]\n", progname);
	fprintf(stream, "\t<name>  can be a domain name or an IP address (-x lookups)\n");
	fprintf(stream, "\t<type>  defaults to A\n");
	fprintf(stream, "\t<class> defaults to IN\n");
	fprintf(stream, "\n\targuments may be placed in random order\n");
	fprintf(stream, "\n  Options:\n");
	fprintf(stream, "\t-D\t\tenable DNSSEC (DO bit)\n");
	fprintf(stream, "\t-T\t\ttrace from the root down to <name>\n");
	fprintf(stream, "\t-S\t\tchase signature(s) from <name> to a know key [*]\n");
	fprintf(stream, "\t-V\t\tverbose mode (once shows question, twice for hexdumps)\n");
	fprintf(stream, "\t-Q\t\tquiet mode (overrules -V)\n");
	fprintf(stream, "\n");
	fprintf(stream, "\t-f file\t\tread packet from file and send it\n");
	fprintf(stream, "\t-i file\t\tread packet from file and print it\n");
	fprintf(stream, "\t-w file\t\twrite answer packet to file\n");
	fprintf(stream, "\t-q file\t\twrite query packet to file\n");
	fprintf(stream, "\t-h\t\tshow this help\n");
	fprintf(stream, "\t-v\t\tshow version\n");
	fprintf(stream, "\n  Query options:\n");
	fprintf(stream, "\t-4\t\tstay on ip4\n");
	fprintf(stream, "\t-6\t\tstay on ip6\n");
	fprintf(stream, "\t-a\t\tonly query the first nameserver (default is to try all)\n");
	fprintf(stream, "\t-b <bufsize>\tuse <bufsize> as the buffer size (defaults to 512 b)\n");
	fprintf(stream, "\t-c\t\tsend the query with tcp (connected)\n");
	fprintf(stream, "\t-k <file>\tspecify a file that contains a trusted DNSSEC key [**]\n");
	fprintf(stream, "\t\t\tused to verify any signatures in the current answer\n");
	fprintf(stream, "\t-o <mnemonic>\tset flags to: [QR|qr][AA|aa][TC|tc][RD|rd][CD|cd][RA|ra][AD|ad]\n");
	fprintf(stream, "\t\t\tlowercase: unset bit, uppercase: set bit\n");
#if 0
	fprintf(stream, "\t-O <opcode>\tset the opcode to: [query, iquery, status, notify, update]]\n");
#endif
	fprintf(stream, "\t-p <port>\tuse <port> as remote port number\n");
	fprintf(stream, "\t-s\t\tshow the DS RR for each key in a packet\n");
	fprintf(stream, "\t-u\t\tsend the query with udp (the default)\n");
	fprintf(stream, "\t-x\t\tdo a reverse lookup\n");
        fprintf(stream, "\t-y <name:key[:algo]>\tspecify named base64 tsig key, and optional an\n\t\t\talgorithm (defaults to hmac-md5.sig-alg.reg.int)\n");
	fprintf(stream, "\t-z\t\tdon't randomize the nameservers before use\n");
	fprintf(stream, "\n  [*] = enables/implies DNSSEC\n");
	fprintf(stream, "  [**] = can be given more than once\n");
	fprintf(stream, "\n  drill@nlnetlabs.nl | www.nlnetlabs.nl/dnssec/drill.html\n");
}

/**
 * Prints the drill version to stderr
 */
static void
version(FILE *stream, const char *progname)
{
        fprintf(stream, "%s version %s (ldns version %s)\n", progname, DRILL_VERSION, ldns_version());
        fprintf(stream, "Written by NLnet Labs.\n");
        fprintf(stream, "\nCopyright (c) 2004, 2005 NLnet Labs.\n");
        fprintf(stream, "Licensed under the revised BSD license.\n");
        fprintf(stream, "There is NO warranty; not even for MERCHANTABILITY or FITNESS\n");
        fprintf(stream, "FOR A PARTICULAR PURPOSE.\n");
}


/**
 * Main function of drill
 * parse the arguments and prepare a query
 */
int
main(int argc, char *argv[])
{
        ldns_resolver	*res = NULL;
        ldns_resolver   *cmdline_res = NULL; /* only used to resolv @name names */
	ldns_rr_list	*cmdline_rr_list = NULL;
	ldns_rdf	*cmdline_dname = NULL;
        ldns_rdf 	*qname, *qname_tmp;
        ldns_pkt	*pkt;
        ldns_pkt	*qpkt;
        char 		*serv;
        char 		*name;
        char 		*name2;
	char		*progname;
	char 		*query_file = NULL;
	char		*answer_file = NULL;
	ldns_rdf 	*serv_rdf;
        ldns_rr_type 	type;
        ldns_rr_class	clas;
#if 0
	ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
#endif
	int 		i, c;
	int 		int_type;
	int		int_clas;
	int		PURPOSE;
	char		*tsig_name = NULL;
	char		*tsig_data = NULL;
	char 		*tsig_algorithm = NULL;
	ldns_rr		*dnssec_key;
	size_t		tsig_separator;
	size_t		tsig_separator2;
	ldns_rr		*axfr_rr;
	ldns_status	status;
	
	/* list of keys used in dnssec operations */
	ldns_rr_list	*key_list = ldns_rr_list_new(); 
	/* what key verify the current answer */
	ldns_rr_list 	*key_verified;

	/* resolver options */
	uint16_t	qflags;
	uint16_t 	qbuf;
	uint16_t	qport;
	uint8_t		qfamily;
	bool		qdnssec;
	bool		qfail;
	bool		qds;
	bool		qusevc;
	bool 		qrandom;

	int		result = 0;
	
	int_type = -1; serv = NULL; type = 0; 
	int_clas = -1; name = NULL; clas = 0;
	qname = NULL; 
	progname = strdup(argv[0]);
	
	PURPOSE = DRILL_QUERY;
	qflags = LDNS_RD;
	qport = LDNS_PORT;
	qdebug = 0;
	qdnssec = false;
	qfamily = LDNS_RESOLV_INETANY;
	qfail = false;
	qds = false;
	qbuf = 0;
	qusevc = false;
	qrandom = true;
	key_verified = NULL;

	if (argc == 0) {
		usage(stdout, progname);
		result = EXIT_FAILURE;
		goto exit;
	}

	/* string from orig drill: "i:w:I46Sk:TNp:b:DsvhVcuaq:f:xr" */
	/* global first, query opt next, option with parm's last
	 * and sorted */
	while ((c = getopt(argc, argv, "46DITSVQf:i:w:q:achuvxzy:so:p:b:k:")) != -1) {
		switch(c) {
			/* global options */
			case '4':
				qfamily = LDNS_RESOLV_INET;
				break;
			case '6':
				qfamily = LDNS_RESOLV_INET6;
				break;
			case 'D':
				qdnssec = true;
				break;
			case 'I':
				/* reserved for backward compatibility */
				break;
			case 'T':
				warning("%s", "Trace enabled, ignoring any <type> arguments");
				PURPOSE = DRILL_TRACE;
				break;
			case 'S':
				PURPOSE = DRILL_CHASE;
				break;
			case 'V':
				if (qdebug != -1) {
					qdebug++;
				}
				break;
			case 'Q':
				qdebug = -1;
			case 'f':
				query_file = optarg;
				break;
			case 'i':
				answer_file = optarg;
				PURPOSE = DRILL_AFROMFILE;
				break;
			case 'w':
				answer_file = optarg;
				break;
			case 'q':
				query_file = optarg;
				PURPOSE = DRILL_QTOFILE;
			/* query options */
			case 'a':
				qfail = true;
				break;
			case 'b':
				qbuf = (uint16_t)atoi(optarg);
				if (qbuf == 0) {
					error("%s", "<bufsize> could not be converted");
				}
				break;
			case 'c':
				qusevc = true;
				break;
			case 'k':
				dnssec_key = read_key_file(optarg);
				if (!dnssec_key) {
					error("Could not parse the key file: %s", optarg);
				}
				ldns_rr_list_push_rr(key_list, dnssec_key);
				qdnssec = true; /* enable that too */
				break;
			case 'o':
				/* only looks at the first hit: capital=ON, lowercase=OFF*/
				if (strstr(optarg, "QR")) {
					DRILL_ON(qflags, LDNS_QR);
				}
				if (strstr(optarg, "qr")) {
					DRILL_OFF(qflags, LDNS_QR);
				}
				if (strstr(optarg, "AA")) {
					DRILL_ON(qflags, LDNS_AA);
				}
				if (strstr(optarg, "aa")) {
					DRILL_OFF(qflags, LDNS_AA);
				}
				if (strstr(optarg, "TC")) {
					DRILL_ON(qflags, LDNS_TC);
				}
				if (strstr(optarg, "tc")) {
					DRILL_OFF(qflags, LDNS_TC);
				}
				if (strstr(optarg, "RD")) {
					DRILL_ON(qflags, LDNS_RD);
				}
				if (strstr(optarg, "rd")) {
					DRILL_OFF(qflags, LDNS_RD);
				}
				if (strstr(optarg, "CD")) {
					DRILL_ON(qflags, LDNS_CD);
				}
				if (strstr(optarg, "cd")) {
					DRILL_OFF(qflags, LDNS_CD);
				}
				if (strstr(optarg, "RA")) {
					DRILL_ON(qflags, LDNS_RA);
				}
				if (strstr(optarg, "ra")) {
					DRILL_OFF(qflags, LDNS_RA);
				}
				if (strstr(optarg, "AD")) {
					DRILL_ON(qflags, LDNS_AD);
				}
				if (strstr(optarg, "ad")) {
					DRILL_OFF(qflags, LDNS_AD);
				}
				break;
#if 0
			case 'O':
				if (strstr(optarg, "query")) {
					opcode = LDNS_PACKET_QUERY;
					break;
				}
				if (strstr(optarg, "iquery")) {
					opcode = LDNS_PACKET_IQUERY;
					break;
				}
				if (strstr(optarg, "status")) {
					opcode = LDNS_PACKET_STATUS;
					break;
				}
				if (strstr(optarg, "notify")) {
					opcode = LDNS_PACKET_NOTIFY;
					break;
				}
				if (strstr(optarg, "update")) {
					opcode = LDNS_PACKET_UPDATE;
					break;
				}
				break;
#endif
			case 'p':
				qport = (uint16_t)atoi(optarg);
				if (qport == 0) {
					error("%s", "<port> could not be converted");
				}
				break;
			case 's':
				qds = true;
				break;
			case 'u':
				qusevc = false;
				break;
			case 'v':
				version(stdout, progname);
				result = EXIT_SUCCESS;
				goto exit;
			case 'x':
				PURPOSE = DRILL_REVERSE;
				break;
			case 'y':
				if (strchr(optarg, ':')) {
					tsig_separator = (size_t) (strchr(optarg, ':') - optarg);
					if (strchr(optarg + tsig_separator + 1, ':')) {
						tsig_separator2 = (size_t) (strchr(optarg + tsig_separator + 1, ':') - optarg);
						tsig_algorithm = xmalloc(strlen(optarg) - tsig_separator2);
						strncpy(tsig_algorithm, optarg + tsig_separator2 + 1, strlen(optarg) - tsig_separator2);
						tsig_algorithm[strlen(optarg) - tsig_separator2 - 1] = '\0';
					} else {
						tsig_separator2 = strlen(optarg);
						tsig_algorithm = xmalloc(26);
						strncpy(tsig_algorithm, "hmac-md5.sig-alg.reg.int.", 25);
						tsig_algorithm[25] = '\0';
					}
					tsig_name = xmalloc(tsig_separator + 1);
					tsig_data = xmalloc(tsig_separator2 - tsig_separator);
					strncpy(tsig_name, optarg, tsig_separator);
					strncpy(tsig_data, optarg + tsig_separator + 1, tsig_separator2 - tsig_separator - 1);
					/* strncpy does not append \0 if source is longer than n */
					tsig_name[tsig_separator] = '\0';
					tsig_data[ tsig_separator2 - tsig_separator - 1] = '\0';
				}
				break;
			case 'z':
				qrandom = false;
				break;
			case 'h':
			default:
				usage(stdout, progname);
				result = EXIT_SUCCESS;
				goto exit;
		}
	}
	argc -= optind;
	argv += optind;

	/* do a secure trace when requested */
	if (PURPOSE == DRILL_TRACE && qdnssec) {
		if (ldns_rr_list_rr_count(key_list) == 0) {
			warning("%s", "No trusted keys were given. Will not be able to verify authenticity!");
		}
		PURPOSE = DRILL_SECTRACE;
	}

	/* parse the arguments, with multiple arguments, the last argument
	 * found is used */
	for(i = 0; i < argc; i++) {

		/* if ^@ then it's a server */
		if (argv[i][0] == '@') {
			if (strlen(argv[i]) == 1) {
				warning("%s", "No nameserver given");
				exit(EXIT_FAILURE);
			}
			serv = argv[i] + 1;
			continue;
		}
		/* if has a dot, it's a name */
		if (strchr(argv[i], '.')) {
			name = argv[i];
			continue;
		}
		/* if it matches a type, it's a type */
		if (int_type == -1) {
			type = ldns_get_rr_type_by_name(argv[i]);
			if (type != 0) {
				int_type = 0;
				continue;
			}
		}
		/* if it matches a class, it's a class */
		if (int_clas == -1) {
			clas = ldns_get_rr_class_by_name(argv[i]);
			if (clas != 0) {
				int_clas = 0;
				continue;
			}
		}
		/* it all fails assume it's a name */
		name = argv[i];
	}
	/* act like dig and use for . NS */
	if (!name) {
		name = ".";
		int_type = 0;
		type = LDNS_RR_TYPE_NS;
	}
	
	/* defaults if not given */
	if (int_clas == -1) {
		clas = LDNS_RR_CLASS_IN;
	}
	if (int_type == -1) {
		if (PURPOSE != DRILL_REVERSE) {
			type = LDNS_RR_TYPE_A;
		} else {
			type = LDNS_RR_TYPE_PTR;
		}
	}

	/* set the nameserver to use */
	if (!serv) {
		/* no server given make a resolver from /etc/resolv.conf */
		status = ldns_resolver_new_frm_file(&res, NULL);
		if (status != LDNS_STATUS_OK) {
			warning("Could not create a resolver structure");
			result = EXIT_FAILURE;
			goto exit;
		}
	} else {
		res = ldns_resolver_new();
		if (!res || strlen(serv) <= 0) {
			warning("Could not create a resolver structure");
			result = EXIT_FAILURE;
			goto exit;
		}
		/* add the nameserver */
		serv_rdf = ldns_rdf_new_addr_frm_str(serv);
		if (!serv_rdf) {
			/* try to resolv the name if possible */
			status = ldns_resolver_new_frm_file(&cmdline_res, NULL);
			
			if (status != LDNS_STATUS_OK) {
				error("%s", "@server ip could not be converted");
			}
			ldns_resolver_set_dnssec(cmdline_res, qdnssec);
			ldns_resolver_set_ip6(cmdline_res, qfamily);
			ldns_resolver_set_fail(cmdline_res, qfail);
			ldns_resolver_set_usevc(cmdline_res, qusevc);

			cmdline_dname = ldns_dname_new_frm_str(serv);

			cmdline_rr_list = ldns_get_rr_list_addr_by_name(
						cmdline_res, 
						cmdline_dname,
						LDNS_RR_CLASS_IN,
						qflags);
			ldns_rdf_deep_free(cmdline_dname);
			if (!cmdline_rr_list) {
				/* This error msg is not always accurate */
				error("%s `%s\'", "could not find any address for the name:", serv);
			} else {
				if (ldns_resolver_push_nameserver_rr_list(
						res, 
						cmdline_rr_list
					) != LDNS_STATUS_OK) {
					error("%s", "pushing nameserver");
				}
			}
		} else {
			if (ldns_resolver_push_nameserver(res, serv_rdf) != LDNS_STATUS_OK) {
				error("%s", "pushing nameserver");
			} else {
				ldns_rdf_deep_free(serv_rdf);
			}
		}
	}
	/* set the resolver options */
	ldns_resolver_set_port(res, qport);
	if (qdebug > 0 && qdebug != -1) {
		ldns_resolver_set_debug(res, true);
	} else {
		ldns_resolver_set_debug(res, false);
	}
	ldns_resolver_set_dnssec(res, qdnssec);
	ldns_resolver_set_dnssec_cd(res, qdnssec);
	ldns_resolver_set_ip6(res, qfamily);
	ldns_resolver_set_fail(res, qfail);
	ldns_resolver_set_usevc(res, qusevc);
	ldns_resolver_set_random(res, qrandom);
	if (qbuf != 0) {
		ldns_resolver_set_edns_udp_size(res, qbuf);
	}

	if (!name && 
	    PURPOSE != DRILL_AFROMFILE &&
	    !query_file
	   ) {
		usage(stdout, progname);
		result = EXIT_FAILURE;
		goto exit;
	}

	if (tsig_name && tsig_data) {
		ldns_resolver_set_tsig_keyname(res, tsig_name);
		ldns_resolver_set_tsig_keydata(res, tsig_data);
		ldns_resolver_set_tsig_algorithm(res, tsig_algorithm);
	}
	
	/* main switching part of drill */
	switch(PURPOSE) {
		case DRILL_TRACE:
			/* do a trace from the root down */
			init_root();
			qname = ldns_dname_new_frm_str(name);
			/* don't care about return packet */
			(void)do_trace(res, qname, type, clas);
			break;
		case DRILL_SECTRACE:
			/* do a secure trace from the root down */
			init_root();
			qname = ldns_dname_new_frm_str(name);
			/* don't care about return packet */
			(void)do_secure_trace(res, qname, type, clas, key_list);
			break;
		case DRILL_CHASE:
			qname = ldns_dname_new_frm_str(name);
			
			ldns_resolver_set_dnssec(res, true);
			ldns_resolver_set_dnssec_cd(res, true);
			/* set dnssec implies udp_size of 4096 */
			ldns_resolver_set_edns_udp_size(res, 4096);
			if (!qname) {
				error("%s", "making qname");
			}
			pkt = ldns_resolver_query(res, qname, type, clas, qflags);
			
			if (!pkt) {
				error("%s", "error pkt sending");
				result = EXIT_FAILURE;
			} else {
				if (qdebug != -1) {
					ldns_pkt_print(stdout, pkt);
				}
				
				if (!ldns_pkt_answer(pkt)) {
					mesg("No answer in packet");
				} else {
					result = do_chase(res, qname, type,
					                  clas, key_list, 
					                  pkt, qflags);
					if (result == LDNS_STATUS_OK) {
						if (qdebug != -1) {
							mesg("Chase successful");
						}
						result = 0;
					} else {
						if (qdebug != -1) {
							mesg("Chase failed: %s", ldns_get_errorstr_by_id(result));
						}
						/*result = EXIT_FAILURE;*/
					}
				}
				ldns_pkt_free(pkt);
			}
			break;
		case DRILL_AFROMFILE:
			pkt = read_hex_pkt(answer_file);
			if (pkt) {
				if (qdebug != -1) {
					ldns_pkt_print(stdout, pkt);
				}
				ldns_pkt_free(pkt);
			}
			
			break;
		case DRILL_QTOFILE:
			qname = ldns_dname_new_frm_str(name);
			if (!qname) {
				error("%s", "making qname");
			}

			status = ldns_resolver_prepare_query_pkt(&qpkt, res, qname, type, clas, qflags);
			dump_hex(qpkt, query_file);
			ldns_pkt_free(qpkt);
			break;
		case DRILL_NSEC:
			break;
		case DRILL_REVERSE:
			/* ipv4 or ipv6 addr? */
			if (strchr(name, ':')) {
				name2 = malloc(IP6_ARPA_MAX_LEN + 20);
				c = 0;
				for (i=0; i<(int)strlen(name); i++) {
					if (i >= IP6_ARPA_MAX_LEN) {
						error("%s", "reverse argument to long");
					}
					if (name[i] == ':') {
						if (i < (int) strlen(name) && name[i + 1] == ':') {
							error("%s", ":: not supported (yet)");
						} else {
							if (i + 2 == (int) strlen(name) || name[i + 2] == ':') {
								name2[c++] = '0';
								name2[c++] = '.';
								name2[c++] = '0';
								name2[c++] = '.';
								name2[c++] = '0';
								name2[c++] = '.';
							} else if (i + 3 == (int) strlen(name) || name[i + 3] == ':') {
								name2[c++] = '0';
								name2[c++] = '.';
								name2[c++] = '0';
								name2[c++] = '.';
							} else if (i + 4 == (int) strlen(name) || name[i + 4] == ':') {
								name2[c++] = '0';
								name2[c++] = '.';
							}
						}
					} else {
						name2[c++] = name[i];
						name2[c++] = '.';
					}
				}
				name2[c++] = '\0';

				qname = ldns_dname_new_frm_str(name2);
				qname_tmp = ldns_dname_reverse(qname);
				ldns_rdf_deep_free(qname);
				qname = qname_tmp;
				qname_tmp = ldns_dname_new_frm_str("ip6.arpa.");
				status = ldns_dname_cat(qname, qname_tmp);
				if (status != LDNS_STATUS_OK) {
					error("%s", "could not create reverse address for ip6: %s\n", ldns_get_errorstr_by_id(status));
				}
				ldns_rdf_deep_free(qname_tmp);

				free(name2);
			} else {
				qname = ldns_dname_new_frm_str(name);
				qname_tmp = ldns_dname_reverse(qname);
				ldns_rdf_deep_free(qname);
				qname = qname_tmp;
				qname_tmp = ldns_dname_new_frm_str("in-addr.arpa.");
				status = ldns_dname_cat(qname, qname_tmp);
				if (status != LDNS_STATUS_OK) {
					error("%s", "could not create reverse address for ip4: %s\n", ldns_get_errorstr_by_id(status));
				}
				ldns_rdf_deep_free(qname_tmp);
			}
			if (!qname) {
				error("%s", "-x implies an ip address");
			}
			
			/* create a packet and set the RD flag on it */
			pkt = ldns_resolver_query(res, qname, type, clas, qflags);
			if (!pkt)  {
				error("%s", "pkt sending");
				result = EXIT_FAILURE;
			} else {
				if (qdebug != -1) {
					ldns_pkt_print(stdout, pkt);
				}
				ldns_pkt_free(pkt);
			}
			break;
		case DRILL_QUERY:
		default:
			if (query_file) {
				qpkt = read_hex_pkt(query_file);
				if (qpkt) {
					(void)ldns_resolver_send_pkt(&pkt, res, qpkt);
				} else {
					/* qpkt was bogus, reset pkt */
					pkt = NULL;
				}
			} else {
				qname = ldns_dname_new_frm_str(name);
				if (!qname) {
					error("%s", "error in making qname");
				}

				if (type == LDNS_RR_TYPE_AXFR) {
					(void) ldns_axfr_start(res, qname, clas);

					axfr_rr = ldns_axfr_next(res);
					while (axfr_rr) {
						if (qdebug != -1) {
							ldns_rr_print(stdout, axfr_rr);
							printf("\n");
						}
						ldns_rr_free(axfr_rr);
						axfr_rr = ldns_axfr_next(res);
					}

					goto exit;
				} else {
					/* create a packet and set the RD flag on it */
					pkt = ldns_resolver_query(res, qname, type, clas, qflags);
				}
			}
			
			if (!pkt)  {
				mesg("No packet received");
				result = EXIT_FAILURE;
			} else {
				if (qdebug != -1) {
					ldns_pkt_print(stdout, pkt);
				}
				if (qds) {
					if (qdebug != -1) {
						print_ds_of_keys(pkt);
						printf("\n");
					}
				}
			
				if (ldns_rr_list_rr_count(key_list) > 0) {
					/* -k's were given on the cmd line */
					ldns_rr_list *rrset_verified;
					uint16_t key_count;

					rrset_verified = ldns_pkt_rr_list_by_name_and_type(
							pkt, qname, type, 
							LDNS_SECTION_ANY_NOQUESTION);

					if (type == LDNS_RR_TYPE_ANY) {
						/* don't verify this */
						break;
					}

					if (qdebug != -1) {
						printf("; ");
						ldns_rr_list_print(stdout, rrset_verified);
					}

					/* verify */
					result = ldns_pkt_verify(pkt, type, qname, key_list, NULL, NULL);

					if (result == LDNS_STATUS_OK) {
						for(key_count = 0; key_count < ldns_rr_list_rr_count(key_verified);
								key_count++) {
							if (qdebug != -1) {
								printf("VALIDATED by id = %d, owner = ",
										(int)ldns_calc_keytag(
												      ldns_rr_list_rr(key_verified, key_count)));
								ldns_rdf_print(stdout, ldns_rr_owner(
											ldns_rr_list_rr(key_list, key_count)));
								printf("\n");
							}
						}
					} else {
						for(key_count = 0; key_count < ldns_rr_list_rr_count(key_list);
								key_count++) {
							if (qdebug != -1) {
								printf("BOGUS by id = %d, owner = ",
										(int)ldns_calc_keytag(
												      ldns_rr_list_rr(key_list, key_count)));
								ldns_rdf_print(stdout, ldns_rr_owner(

								ldns_rr_list_rr(key_list,
								key_count)));
								printf("\n");
							}
						}

					}

				}
				if (answer_file) {
					dump_hex(pkt, answer_file);
				}
				ldns_pkt_free(pkt); 
			}
			
			break;
	}

	exit:
	ldns_rdf_deep_free(qname);
	ldns_resolver_deep_free(res);
	ldns_resolver_deep_free(cmdline_res);
	ldns_rr_list_deep_free(key_list);
	ldns_rr_list_deep_free(cmdline_rr_list);
	xfree(progname);
/*
	xfree(tsig_name);
*/
	xfree(tsig_data);
	xfree(tsig_algorithm);
	return result;
}
