/*
 * ldns-testns. Light-weight DNS daemon, gives canned replies.
 *
 * Tiny dns server, that responds with specially crafted replies
 * to requests. For testing dns software.
 *
 * (c) NLnet Labs, 2005, 2006
 * See the file LICENSE for the license
 */

/*
	The data file format is as follows:
	
	; comment.
	; a number of entries, these are processed first to last.
	; a line based format.

	$ORIGIN origin
	$TTL default_ttl

	ENTRY_BEGIN
	; first give MATCH lines, that say what queries are matched
	; by this entry.
	; 'opcode' makes the query match the opcode from the reply
	; if you leave it out, any opcode matches this entry.
	; 'qtype' makes the query match the qtype from the reply
	; 'qname' makes the query match the qname from the reply
	; 'serial=1023' makes the query match if ixfr serial is 1023. 
	MATCH [opcode] [qtype] [qname] [serial=<value>]
	MATCH ...
	; Then the REPLY header is specified.
	REPLY opcode, rcode or flags.
	REPLY ...
	; any additional actions to do.
	; 'copy_id' copies the ID from the query to the answer.
	ADJUST copy_id
	SECTION QUESTION
	<RRs, one per line>    ; the RRcount is determined automatically.
	SECTION ANSWER
	<RRs, one per line>
	SECTION AUTHORITY
	<RRs, one per line>
	SECTION ADDITIONAL
	<RRs, one per line>
	ENTRY_END
*/

#include "config.h"
#include <ldns/ldns.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <errno.h>

#define INBUF_SIZE 4096 	/* max size for incoming queries */
#define MAX_LINE   10240	/* max line length */
#define DEFAULT_PORT 53		/* default if no -p port is specified */
static const char* prog_name = "ldns-testns";

/* data structure to keep the canned queries in */
/* format is the 'matching query' and the 'canned answer' */
struct entry {
	/* match */
	/* How to match an incoming query with this canned reply */
	bool match_opcode; /* match query opcode with answer opcode */
	bool match_qtype;  /* match qtype with answer qtype */
	bool match_qname;  /* match qname with answer qname */
	bool match_serial; /* match SOA serial number, from auth section */
	uint32_t ixfr_soa_serial; /* match query serial with this value. */

	/* pre canned reply */
	ldns_pkt *reply;

	/* how to adjust the reply packet */
	bool copy_id; /* copy over the ID from the query into the answer */

	/* next in list */
	struct entry* next;
};

static void usage()
{
	printf("Usage: %s [-p port] <datafile>\n", prog_name);
	printf("  -p	listens on the specified port, default %d.\n", DEFAULT_PORT);
	printf("The program answers queries with canned replies from the datafile.\n");
	exit(EXIT_FAILURE);
}

static void error(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	printf("%s error: ", prog_name);
	vprintf(msg, args);
	printf("\n");
	va_end(args);
	exit(EXIT_FAILURE);
}

static int udp_bind(int sock, int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = (in_port_t)htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;
    return bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr));
}

static bool isendline(char c)
{
	if(c == ';' || c == '#' 
		|| c == '\n' || c == 0)
		return true;
	return false;
}

/* true if the string starts with the keyword given. Moves the str ahead. */
static bool str_keyword(const char** str, const char* keyword)
{
	size_t len = strlen(keyword);
	assert(str && keyword);
	if(strncmp(*str, keyword, len) != 0)
		return false;
	*str += len;
	while(isspace(**str))
		(*str)++;
	return true;
}

static void matchline(const char* line, struct entry* e)
{
	const char* parse = line;
	while(*parse) {
		if(isendline(*parse)) 
			return;
		if(str_keyword(&parse, "opcode")) {
			e->match_opcode = true;
		} else if(str_keyword(&parse, "qtype")) {
			e->match_qtype = true;
		} else if(str_keyword(&parse, "qname")) {
			e->match_qname = true;
		} else if(str_keyword(&parse, "serial")) {
			e->match_serial = true;
			if(*parse != '=' && *parse != ':')
				error("expected = or : in MATCH: %s", line);
			parse++;
			e->ixfr_soa_serial = (uint32_t)strtol(parse, (char**)&parse, 10);
			while(isspace(*parse)) parse++;
		} else {
			error("could not parse MATCH: '%s'", parse);
		}
	}
}

static void replyline(const char* line, struct entry* e)
{
	const char* parse = line;
	while(*parse) {
		if(isendline(*parse)) 
			return;
			/* opcodes */
		if(str_keyword(&parse, "QUERY")) {
			ldns_pkt_set_opcode(e->reply, LDNS_PACKET_QUERY);
		} else if(str_keyword(&parse, "IQUERY")) {
			ldns_pkt_set_opcode(e->reply, LDNS_PACKET_IQUERY);
		} else if(str_keyword(&parse, "STATUS")) {
			ldns_pkt_set_opcode(e->reply, LDNS_PACKET_STATUS);
		} else if(str_keyword(&parse, "NOTIFY")) {
			ldns_pkt_set_opcode(e->reply, LDNS_PACKET_NOTIFY);
		} else if(str_keyword(&parse, "UPDATE")) {
			ldns_pkt_set_opcode(e->reply, LDNS_PACKET_UPDATE);
			/* rcodes */
		} else if(str_keyword(&parse, "NOERROR")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NOERROR);
		} else if(str_keyword(&parse, "FORMERR")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_FORMERR);
		} else if(str_keyword(&parse, "SERVFAIL")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_SERVFAIL);
		} else if(str_keyword(&parse, "NXDOMAIN")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NXDOMAIN);
		} else if(str_keyword(&parse, "NOTIMPL")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NOTIMPL);
		} else if(str_keyword(&parse, "YXDOMAIN")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_YXDOMAIN);
		} else if(str_keyword(&parse, "YXRRSET")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_YXRRSET);
		} else if(str_keyword(&parse, "NXRRSET")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NXRRSET);
		} else if(str_keyword(&parse, "NOTAUTH")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NOTAUTH);
		} else if(str_keyword(&parse, "NOTZONE")) {
			ldns_pkt_set_rcode(e->reply, LDNS_RCODE_NOTZONE);
			/* flags */
		} else if(str_keyword(&parse, "QR")) {
			ldns_pkt_set_qr(e->reply, true);
		} else if(str_keyword(&parse, "AA")) {
			ldns_pkt_set_aa(e->reply, true);
		} else if(str_keyword(&parse, "TC")) {
			ldns_pkt_set_tc(e->reply, true);
		} else if(str_keyword(&parse, "RD")) {
			ldns_pkt_set_rd(e->reply, true);
		} else if(str_keyword(&parse, "CD")) {
			ldns_pkt_set_cd(e->reply, true);
		} else if(str_keyword(&parse, "RA")) {
			ldns_pkt_set_ra(e->reply, true);
		} else if(str_keyword(&parse, "AD")) {
			ldns_pkt_set_ad(e->reply, true);
		} else {
			error("could not parse REPLY: '%s'", parse);
		}
	}
}

static void adjustline(const char* line, struct entry* e)
{
	const char* parse = line;
	while(*parse) {
		if(isendline(*parse)) 
			return;
		if(str_keyword(&parse, "copy_id")) {
			e->copy_id = true;
		} else {
			error("could not parse ADJUST: '%s'", parse);
		}
	}
}

static struct entry* new_entry()
{
	struct entry* e = LDNS_MALLOC(struct entry);
	memset(e, 0, sizeof(e));
	e->match_opcode = false;
	e->match_qtype = false;
	e->match_qname = false;
	e->match_serial = false;
	e->ixfr_soa_serial = 0;
	e->reply = ldns_pkt_new();
	e->copy_id = false;
	e->next = NULL;
	return e;
}

static void get_origin(const char* name, int lineno, ldns_rdf** origin, char* parse)
{
	/* snip off rest of the text so as to make the parse work in ldns */
	char* end;
	char store;
	ldns_status status;

	ldns_rdf_free(*origin);
	*origin = NULL;

	end=parse;
	while(!isspace(*end) && !isendline(*end))
		end++;
	store = *end;
	*end = 0;
	printf("parsing '%s'\n", parse);
	status = ldns_str2rdf_dname(origin, parse);
	*end = store;
	if (status != LDNS_STATUS_OK)
		error("%s line %d:\n\t%s: %s", name, lineno,
		ldns_get_errorstr_by_id(status), parse);
}

/* reads the canned reply file and returns a list of structs */
static struct entry* read_datafile(const char* name)
{
	struct entry* list = NULL;
	struct entry* last = NULL;
	struct entry* current = NULL;
	FILE *in;
	int lineno = 0;
	char line[MAX_LINE];
	const char* parse;
	ldns_pkt_section add_section = LDNS_SECTION_QUESTION;
	uint16_t default_ttl = 0;
	ldns_rdf* origin = NULL;
	ldns_rdf* prev_rr = NULL;
	int entry_num = 0;

	if((in=fopen(name, "r")) == NULL) {
		error("could not open file %s: %s", name, strerror(errno));
	}

	while(fgets(line, (int)sizeof(line), in) != NULL) {
		line[MAX_LINE-1] = 0;
		parse = line;
		lineno ++;
		
		while(isspace(*parse))
			parse++;
		/* test for keywords */
		if(isendline(*parse))
			continue; /* skip comment and empty lines */
		if(str_keyword(&parse, "ENTRY_BEGIN")) {
			if(current) {
				error("%s line %d: previous entry does not ENTRY_END", 
					name, lineno);
			}
			current = new_entry();
			if(last)
				last->next = current;
			else	list = current;
			last = current;
			continue;
		} else if(str_keyword(&parse, "$ORIGIN")) {
			get_origin(name, lineno, &origin, (char*)parse);
			continue;
		} else if(str_keyword(&parse, "$TTL")) {
			default_ttl = (uint16_t)atoi(parse);
			continue;
		}

		/* working inside an entry */
		if(!current) {
			error("%s line %d: expected ENTRY_BEGIN but got %s", 
				name, lineno, line);
		}
		if(str_keyword(&parse, "MATCH")) {
			matchline(parse, current);
		} else if(str_keyword(&parse, "REPLY")) {
			replyline(parse, current);
		} else if(str_keyword(&parse, "ADJUST")) {
			adjustline(parse, current);
		} else if(str_keyword(&parse, "SECTION")) {
			if(str_keyword(&parse, "QUESTION"))
				add_section = LDNS_SECTION_QUESTION;
			else if(str_keyword(&parse, "ANSWER"))
				add_section = LDNS_SECTION_ANSWER;
			else if(str_keyword(&parse, "AUTHORITY"))
				add_section = LDNS_SECTION_AUTHORITY;
			else if(str_keyword(&parse, "ADDITIONAL"))
				add_section = LDNS_SECTION_ADDITIONAL;
			else error("%s line %d: bad section %s", name, lineno, parse);
		} else if(str_keyword(&parse, "ENTRY_END")) {
			current = 0;
			entry_num ++;
		} else {
			/* it must be a RR, parse and add to packet. */
			ldns_rr* n = NULL;
			ldns_status status;
			status = ldns_rr_new_frm_str(&n, parse, default_ttl, origin, &prev_rr);
			if (status != LDNS_STATUS_OK)
				error("%s line %d:\n\t%s: %s", name, lineno,
					ldns_get_errorstr_by_id(status), parse);
			ldns_pkt_push_rr(current->reply, add_section, n);
		}


	}
	printf("Read %d entries\n", entry_num);

	fclose(in);
	return list;
}

static ldns_rr_type get_qtype(ldns_pkt* p)
{
	if(!ldns_rr_list_rr(ldns_pkt_question(p), 0))
		return 0;
	return ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(p), 0));
}

static ldns_rdf* get_owner(ldns_pkt* p)
{
	if(!ldns_rr_list_rr(ldns_pkt_question(p), 0))
		return NULL;
	return ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(p), 0));
}

static uint32_t get_serial(ldns_pkt* p)
{
	/* get authority section SOA serial value */
	ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_authority(p), 0);
	ldns_rdf *rdf;
	uint32_t val;
	if(!rr) return 0;
	rdf = ldns_rr_rdf(rr, 2);
	if(!rdf) return 0;
	val = ldns_rdf2native_int32(rdf);
	printf("found serial %d in msg\n", val);
	return val;
}

/* finds entry in list, or returns NULL */
static struct entry* find_match(struct entry* entries, ldns_pkt* query_pkt)
{
	struct entry* p = entries;
	for(p=entries; p; p=p->next) {
		if(p->match_opcode && ldns_pkt_get_opcode(query_pkt) != 
			ldns_pkt_get_opcode(p->reply)) {
			continue;
		}
		if(p->match_qtype && get_qtype(query_pkt) != get_qtype(p->reply)) {
			continue;
		}
		if(p->match_qname) {
			if(!get_owner(query_pkt) || !get_owner(p->reply) ||
				ldns_dname_compare(
				get_owner(query_pkt), get_owner(p->reply)) != 0) {
				continue;
			}
		}
		if(p->match_serial && get_serial(p->reply) != p->ixfr_soa_serial) {
				continue;
		}
		return p;
	}
	return NULL;
}

static ldns_pkt* get_answer(struct entry* entries, ldns_pkt* query_pkt)
{
	ldns_pkt* answer_pkt = NULL;
	struct entry* match = find_match(entries, query_pkt);
	if(!match) 
		return NULL;
	/* copy & adjust packet */
	answer_pkt = ldns_pkt_clone(match->reply);
	if(match->copy_id)
		ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));
	return answer_pkt;
}

int
main(int argc, char **argv)
{
	/* arguments */
	int c;
	int port = DEFAULT_PORT;
	const char* datafile;
	int count;

	/* network */
	int sock;
	ssize_t nb;
	struct sockaddr_storage addr_him;
	socklen_t hislen;
	uint8_t inbuf[INBUF_SIZE];
	uint8_t *outbuf = NULL;

	/* dns */
	struct entry* entries;
	ldns_status status;
	ldns_pkt *query_pkt = NULL;
	ldns_pkt *answer_pkt = NULL;
	size_t answer_size;
	ldns_rr *query_rr = NULL;
	
	/* parse arguments */
	prog_name = argv[0];
	while((c = getopt(argc, argv, "p:")) != -1) {
		switch(c) {
		case 'p':
			port = atoi(optarg);
			if (port < 1) {
				error("Invalid port %s, use a number.", optarg);
			}
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if(argc == 0 || argc > 1)
		usage();
	
	datafile = argv[0];
	printf("Reading datafile %s\n", datafile);
	entries = read_datafile(datafile);
	
	printf("Listening on port %d\n", port);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		error("socket(): %s\n", strerror(errno));
	}

	/* bind ip4, udp */
	if (udp_bind(sock, port)) {
		error("cannot bind(): %s\n", strerror(errno));
	}

	/* service */
	count = 0;
	while (1) {
		hislen = (socklen_t)sizeof(addr_him);
		nb = recvfrom(sock, inbuf, INBUF_SIZE, 0, 
			(struct sockaddr*)&addr_him, &hislen);
		if (nb < 1) {
			printf("recvfrom(): %s\n", strerror(errno));
			continue;
		}
		
		printf("Got query of %d bytes\n", (int)nb);
		status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)nb);
		if (status != LDNS_STATUS_OK) {
			printf("Got bad packet: %s\n", ldns_get_errorstr_by_id(status));
			continue;
		}
		
		query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
		printf("query %d: id %d: ", ++count, (int)ldns_pkt_id(query_pkt));
		ldns_rr_print(stdout, query_rr);
		
		/* fill up answer packet */
		answer_pkt = get_answer(entries, query_pkt);

		status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
		printf("Answer packet size: %u bytes.\n", (unsigned int) answer_size);
		if (status != LDNS_STATUS_OK) {
			printf("Error creating answer: %s\n", ldns_get_errorstr_by_id(status));
		} else {
			nb = sendto(sock, outbuf, answer_size, 0, 
				(struct sockaddr*)&addr_him, hislen);
			if(nb == -1)
				printf("sendto(): %s\n", strerror(errno));
			else if((size_t)nb != answer_size)
				printf("sendto(): only sent %d of %d octets.\n", 
					(int)nb, (int)answer_size);
		}
		ldns_pkt_free(query_pkt); query_pkt = NULL;
		ldns_pkt_free(answer_pkt); answer_pkt = NULL;
		LDNS_FREE(outbuf); outbuf = NULL;
	}
        return 0;
}
