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
 * This program is a debugging aid. It can is not efficient, especially
 * with a long config file, but it can give any reply to any query.
 * This can help the developer pre-script replies for queries.
 *
 * It listens to IP4 UDP and TCP by default.
 * You can specify a packet RR by RR with header flags to return.
 *
 * Missing features:
 * 		- hexdump support, for 'formerr' packets.
 *		- cannot mess up the header at present.
 *		- matching content different from reply content.
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
	MATCH [UDP|TCP]
	MATCH ...
	; Then the REPLY header is specified.
	REPLY opcode, rcode or flags.
		(opcode)  QUERY IQUERY STATUS NOTIFY UPDATE
		(rcode)   NOERROR FORMERR SERVFAIL NXDOMAIN NOTIMPL YXDOMAIN
		 		YXRRSET NXRRSET NOTAUTH NOTZONE
		(flags)   QR AA TC RD CD RA AD
	REPLY ...
	; any additional actions to do.
	; 'copy_id' copies the ID from the query to the answer.
	ADJUST copy_id
	; 'sleep=10' sleeps for 10 seconds before giving the answer (TCP is open)
	ADJUST [sleep=<num>]    ; sleep before giving any reply
	ADJUST [packet_sleep=<num>]  ; sleep before this packet in sequence
	SECTION QUESTION
	<RRs, one per line>    ; the RRcount is determined automatically.
	SECTION ANSWER
	<RRs, one per line>
	SECTION AUTHORITY
	<RRs, one per line>
	SECTION ADDITIONAL
	<RRs, one per line>
	EXTRA_PACKET		; follow with SECTION, REPLY for more packets.
	ENTRY_END
*/

#include "config.h"
#include <ldns/ldns.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <errno.h>

#define INBUF_SIZE 4096 	/* max size for incoming queries */
#define MAX_LINE   10240	/* max line length */
#define DEFAULT_PORT 53		/* default if no -p port is specified */
#define CONN_BACKLOG 5		/* 5 connections queued up for tcp */
static const char* prog_name = "ldns-testns";
static FILE* logfile = 0;
static int verbose = 0;

enum transport_type {transport_any = 0, transport_udp, transport_tcp };

/* struct to keep a linked list of reply packets for a query */
struct reply_packet {
	struct reply_packet* next;
	ldns_pkt* reply;
	int packet_sleep; /* seconds to sleep before giving packet */
};

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
	enum transport_type match_transport; /* match on UDP/TCP */

	/* pre canned reply */
	struct reply_packet *reply_list;

	/* how to adjust the reply packet */
	bool copy_id; /* copy over the ID from the query into the answer */
	int sleeptime; /* in seconds */

	/* next in list */
	struct entry* next;
};

static void usage()
{
	printf("Usage: %s [options] <datafile>\n", prog_name);
	printf("  -p	listens on the specified port, default %d.\n", DEFAULT_PORT);
	printf("  -v	more verbose, prints queries, answers and matching.\n");
	printf("The program answers queries with canned replies from the datafile.\n");
	exit(EXIT_FAILURE);
}

static void log_msg(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(logfile, msg, args);
	fflush(logfile);
	va_end(args);
}

static void error(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	fprintf(logfile, "%s error: ", prog_name);
	vfprintf(logfile, msg, args);
	fprintf(logfile, "\n");
	fflush(stdout);
	va_end(args);
	exit(EXIT_FAILURE);
}

static int bind_port(int sock, int port)
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
	while(isspace((unsigned char)**str))
		(*str)++;
	return true;
}

static struct reply_packet*
entry_add_reply(struct entry* entry) 
{
	struct reply_packet* pkt = (struct reply_packet*)malloc(
		sizeof(struct reply_packet));
	struct reply_packet ** p = &entry->reply_list;
	pkt->next = NULL;
	pkt->packet_sleep = 0;
	pkt->reply = ldns_pkt_new();
	/* link at end */
	while(*p)
		p = &((*p)->next);
	*p = pkt;
	return pkt;
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
		} else if(str_keyword(&parse, "UDP")) {
			e->match_transport = transport_udp;
		} else if(str_keyword(&parse, "TCP")) {
			e->match_transport = transport_tcp;
		} else if(str_keyword(&parse, "serial")) {
			e->match_serial = true;
			if(*parse != '=' && *parse != ':')
				error("expected = or : in MATCH: %s", line);
			parse++;
			e->ixfr_soa_serial = (uint32_t)strtol(parse, (char**)&parse, 10);
			while(isspace((unsigned char)*parse)) 
				parse++;
		} else {
			error("could not parse MATCH: '%s'", parse);
		}
	}
}

static void replyline(const char* line, ldns_pkt *reply)
{
	const char* parse = line;
	while(*parse) {
		if(isendline(*parse)) 
			return;
			/* opcodes */
		if(str_keyword(&parse, "QUERY")) {
			ldns_pkt_set_opcode(reply, LDNS_PACKET_QUERY);
		} else if(str_keyword(&parse, "IQUERY")) {
			ldns_pkt_set_opcode(reply, LDNS_PACKET_IQUERY);
		} else if(str_keyword(&parse, "STATUS")) {
			ldns_pkt_set_opcode(reply, LDNS_PACKET_STATUS);
		} else if(str_keyword(&parse, "NOTIFY")) {
			ldns_pkt_set_opcode(reply, LDNS_PACKET_NOTIFY);
		} else if(str_keyword(&parse, "UPDATE")) {
			ldns_pkt_set_opcode(reply, LDNS_PACKET_UPDATE);
			/* rcodes */
		} else if(str_keyword(&parse, "NOERROR")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NOERROR);
		} else if(str_keyword(&parse, "FORMERR")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_FORMERR);
		} else if(str_keyword(&parse, "SERVFAIL")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_SERVFAIL);
		} else if(str_keyword(&parse, "NXDOMAIN")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NXDOMAIN);
		} else if(str_keyword(&parse, "NOTIMPL")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NOTIMPL);
		} else if(str_keyword(&parse, "YXDOMAIN")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_YXDOMAIN);
		} else if(str_keyword(&parse, "YXRRSET")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_YXRRSET);
		} else if(str_keyword(&parse, "NXRRSET")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NXRRSET);
		} else if(str_keyword(&parse, "NOTAUTH")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NOTAUTH);
		} else if(str_keyword(&parse, "NOTZONE")) {
			ldns_pkt_set_rcode(reply, LDNS_RCODE_NOTZONE);
			/* flags */
		} else if(str_keyword(&parse, "QR")) {
			ldns_pkt_set_qr(reply, true);
		} else if(str_keyword(&parse, "AA")) {
			ldns_pkt_set_aa(reply, true);
		} else if(str_keyword(&parse, "TC")) {
			ldns_pkt_set_tc(reply, true);
		} else if(str_keyword(&parse, "RD")) {
			ldns_pkt_set_rd(reply, true);
		} else if(str_keyword(&parse, "CD")) {
			ldns_pkt_set_cd(reply, true);
		} else if(str_keyword(&parse, "RA")) {
			ldns_pkt_set_ra(reply, true);
		} else if(str_keyword(&parse, "AD")) {
			ldns_pkt_set_ad(reply, true);
		} else {
			error("could not parse REPLY: '%s'", parse);
		}
	}
}

static void adjustline(const char* line, struct entry* e, 
	struct reply_packet* pkt)
{
	const char* parse = line;
	while(*parse) {
		if(isendline(*parse)) 
			return;
		if(str_keyword(&parse, "copy_id")) {
			e->copy_id = true;
		} else if(str_keyword(&parse, "sleep=")) {
			e->sleeptime = strtol(parse, (char**)&parse, 10);
			while(isspace((unsigned char)*parse)) 
				parse++;
		} else if(str_keyword(&parse, "packet_sleep=")) {
			pkt->packet_sleep = strtol(parse, (char**)&parse, 10);
			while(isspace((unsigned char)*parse)) 
				parse++;
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
	e->match_transport = transport_any;
	e->reply_list = NULL;
	e->copy_id = false;
	e->sleeptime = 0;
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
	while(!isspace((unsigned char)*end) && !isendline(*end))
		end++;
	store = *end;
	*end = 0;
	log_msg("parsing '%s'\n", parse);
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
	struct reply_packet *cur_reply = NULL;

	if((in=fopen(name, "r")) == NULL) {
		error("could not open file %s: %s", name, strerror(errno));
	}

	while(fgets(line, (int)sizeof(line), in) != NULL) {
		line[MAX_LINE-1] = 0;
		parse = line;
		lineno ++;
		
		while(isspace((unsigned char)*parse))
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
			cur_reply = entry_add_reply(current);
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
			replyline(parse, cur_reply->reply);
		} else if(str_keyword(&parse, "ADJUST")) {
			adjustline(parse, current, cur_reply);
		} else if(str_keyword(&parse, "EXTRA_PACKET")) {
			cur_reply = entry_add_reply(current);
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
			ldns_pkt_push_rr(cur_reply->reply, add_section, n);
		}

	}
	log_msg("Read %d entries\n", entry_num);

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
	if(verbose) log_msg("found serial %u in msg. ", (int)val);
	return val;
}

/* finds entry in list, or returns NULL */
static struct entry* find_match(struct entry* entries, ldns_pkt* query_pkt,
	enum transport_type transport)
{
	struct entry* p = entries;
	ldns_pkt* reply = NULL;
	for(p=entries; p; p=p->next) {
		if(verbose) log_msg("comparepkt: ");
		reply = p->reply_list->reply;
		if(p->match_opcode && ldns_pkt_get_opcode(query_pkt) != 
			ldns_pkt_get_opcode(reply)) {
			if(verbose) log_msg("bad opcode\n");
			continue;
		}
		if(p->match_qtype && get_qtype(query_pkt) != get_qtype(reply)) {
			if(verbose) log_msg("bad qtype\n");
			continue;
		}
		if(p->match_qname) {
			if(!get_owner(query_pkt) || !get_owner(reply) ||
				ldns_dname_compare(
				get_owner(query_pkt), get_owner(reply)) != 0) {
				if(verbose) log_msg("bad qname\n");
				continue;
			}
		}
		if(p->match_serial && get_serial(query_pkt) != p->ixfr_soa_serial) {
				if(verbose) log_msg("bad serial\n");
				continue;
		}
		if(p->match_transport != transport_any && p->match_transport != transport) {
			if(verbose) log_msg("bad transport\n");
			continue;
		}
		if(verbose) log_msg("match!\n");
		return p;
	}
	return NULL;
}

static void
adjust_packet(struct entry* match, ldns_pkt* answer_pkt, ldns_pkt* query_pkt)
{
	/* copy & adjust packet */
	if(match->copy_id)
		ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));
	if(match->sleeptime > 0) {
		if(verbose) log_msg("sleeping for %d seconds\n", match->sleeptime);
		sleep(match->sleeptime);
	}
}

/*
 * Parses data buffer to a query, finds the correct answer 
 * and calls the given function for every packet to send.
 */
static void
handle_query(uint8_t* inbuf, ssize_t inlen, struct entry* entries, int* count,
	enum transport_type transport, void (*sendfunc)(uint8_t*, size_t, void*),
	void* userdata)
{
	ldns_status status;
	ldns_pkt *query_pkt = NULL;
	ldns_pkt *answer_pkt = NULL;
	struct reply_packet *p;
	ldns_rr *query_rr = NULL;
	uint8_t *outbuf = NULL;
	size_t answer_size = 0;
	struct entry* entry = NULL;

	status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)inlen);
	if (status != LDNS_STATUS_OK) {
		log_msg("Got bad packet: %s\n", ldns_get_errorstr_by_id(status));
		return;
	}
	
	query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
	log_msg("query %d: id %d: %s %d bytes: ", ++(*count), (int)ldns_pkt_id(query_pkt), 
		(transport==transport_tcp)?"TCP":"UDP", inlen);
	ldns_rr_print(logfile, query_rr);
	if(verbose) ldns_pkt_print(logfile, query_pkt);
	
	/* fill up answer packet */
	entry = find_match(entries, query_pkt, transport);
	if(!entry || !entry->reply_list) {
		log_msg("no answer packet for this query, no reply.\n");
		ldns_pkt_free(query_pkt);
		return;
	}
	for(p = entry->reply_list; p; p = p->next)
	{
		if(verbose) log_msg("Answer pkt:\n");
		answer_pkt = ldns_pkt_clone(p->reply);
		adjust_packet(entry, answer_pkt, query_pkt);
		if(verbose) ldns_pkt_print(logfile, answer_pkt);
		status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
		log_msg("Answer packet size: %u bytes.\n", (unsigned int)answer_size);
		if (status != LDNS_STATUS_OK) {
			log_msg("Error creating answer: %s\n", ldns_get_errorstr_by_id(status));
			ldns_pkt_free(query_pkt);
			return;
		}
		ldns_pkt_free(answer_pkt);
		answer_pkt = NULL;

		if(p->packet_sleep) {
			if(verbose) log_msg("sleeping for next packet"
				" %d secs\n", p->packet_sleep);
			sleep(p->packet_sleep);
			if(verbose) log_msg("wakeup for next packet "
				"(slept %d secs)\n", p->packet_sleep);
		}
		sendfunc(outbuf, answer_size, userdata);
		LDNS_FREE(outbuf);
		outbuf = NULL;
		answer_size = 0;
	}
	ldns_pkt_free(query_pkt);
}

struct handle_udp_userdata {
	int udp_sock;
	struct sockaddr_storage addr_him;
	socklen_t hislen;
};
static void
send_udp(uint8_t* buf, size_t len, void* data)
{
	struct handle_udp_userdata *userdata = (struct handle_udp_userdata*)data;
	/* udp send reply */
	ssize_t nb;
	nb = sendto(userdata->udp_sock, buf, len, 0, 
		(struct sockaddr*)&userdata->addr_him, userdata->hislen);
	if(nb == -1)
		log_msg("sendto(): %s\n", strerror(errno));
	else if((size_t)nb != len)
		log_msg("sendto(): only sent %d of %d octets.\n", 
			(int)nb, (int)len);
}

static void
handle_udp(int udp_sock, struct entry* entries, int *count)
{
	ssize_t nb;
	uint8_t inbuf[INBUF_SIZE];
	struct handle_udp_userdata userdata;
	userdata.udp_sock = udp_sock;

	userdata.hislen = (socklen_t)sizeof(userdata.addr_him);
	/* udp recv */
	nb = recvfrom(udp_sock, inbuf, INBUF_SIZE, 0, 
		(struct sockaddr*)&userdata.addr_him, &userdata.hislen);
	if (nb < 1) {
		log_msg("recvfrom(): %s\n", strerror(errno));
		return;
	}
	handle_query(inbuf, nb, entries, count, transport_udp, send_udp, &userdata);
}

static void
read_n_bytes(int sock, uint8_t* buf, size_t sz)
{
	size_t count = 0;
	while(count < sz) {
		ssize_t nb = read(sock, buf+count, sz-count);
		if(nb < 0) {
			log_msg("read(): %s\n", strerror(errno));
			return;
		}
		count += nb;
	}
}

static void
write_n_bytes(int sock, uint8_t* buf, size_t sz)
{
	size_t count = 0;
	while(count < sz) {
		ssize_t nb = write(sock, buf+count, sz-count);
		if(nb < 0) {
			log_msg("write(): %s\n", strerror(errno));
			return;
		}
		count += nb;
	}
}

struct handle_tcp_userdata {
	int s;
};
static void
send_tcp(uint8_t* buf, size_t len, void* data)
{
	struct handle_tcp_userdata *userdata = (struct handle_tcp_userdata*)data;
	uint16_t tcplen;
	/* tcp send reply */
	tcplen = htons(len);
	write_n_bytes(userdata->s, (uint8_t*)&tcplen, sizeof(tcplen));
	write_n_bytes(userdata->s, buf, len);
}

static void
handle_tcp(int tcp_sock, struct entry* entries, int *count)
{
	int s;
	struct sockaddr_storage addr_him;
	socklen_t hislen;
	uint8_t inbuf[INBUF_SIZE];
	uint16_t tcplen;
	struct handle_tcp_userdata userdata;

	/* accept */
	hislen = (socklen_t)sizeof(addr_him);
	if((s = accept(tcp_sock, (struct sockaddr*)&addr_him, &hislen)) < 0) {
		log_msg("accept(): %s\n", strerror(errno));
		return;
	}
	userdata.s = s;

	/* tcp recv */
	read_n_bytes(s, (uint8_t*)&tcplen, sizeof(tcplen));
	tcplen = ntohs(tcplen);
	if(tcplen >= INBUF_SIZE) {
		log_msg("query %d bytes too large, buffer %d bytes.\n",
			tcplen, INBUF_SIZE);
		close(s);
		return;
	}
	read_n_bytes(s, inbuf, tcplen);

	handle_query(inbuf, tcplen, entries, count, transport_tcp, send_tcp, &userdata);
	close(s);

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
	int udp_sock, tcp_sock;
	fd_set rset, wset, eset;
	struct timeval timeout;
	int maxfd;

	/* dns */
	struct entry* entries;
	
	/* parse arguments */
	logfile = stdout;
	prog_name = argv[0];
	log_msg("%s: start\n", prog_name);
	while((c = getopt(argc, argv, "p:v")) != -1) {
		switch(c) {
		case 'p':
			port = atoi(optarg);
			if (port < 1) {
				error("Invalid port %s, use a number.", optarg);
			}
			break;
		case 'v':
			verbose++;
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
	log_msg("Reading datafile %s\n", datafile);
	entries = read_datafile(datafile);
	
	log_msg("Listening on port %d\n", port);
	if((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		error("udp socket(): %s\n", strerror(errno));
	}
	if((tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error("tcp socket(): %s\n", strerror(errno));
	}
	c = 1;
	if(setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(int)) < 0) {
		error("setsockopt(SO_REUSEADDR): %s\n", strerror(errno));
	}

	/* bind ip4 */
	if (bind_port(udp_sock, port)) {
		error("cannot bind(): %s\n", strerror(errno));
	}
	if (bind_port(tcp_sock, port)) {
		error("cannot bind(): %s\n", strerror(errno));
	}
	if (listen(tcp_sock, CONN_BACKLOG) < 0) {
		error("listen(): %s\n", strerror(errno));
	}

	/* service */
	count = 0;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	while (1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_ZERO(&eset);
		FD_SET(udp_sock, &rset);
		FD_SET(tcp_sock, &rset);
		maxfd = udp_sock;
		if(tcp_sock > maxfd)
			maxfd = tcp_sock;
		if(select(maxfd+1, &rset, &wset, &eset, NULL) < 0) {
			error("select(): %s\n", strerror(errno));
		}
		if(FD_ISSET(udp_sock, &rset)) {
			handle_udp(udp_sock, entries, &count);
		}
		if(FD_ISSET(tcp_sock, &rset)) {
			handle_tcp(tcp_sock, entries, &count);
		}
	}
        return 0;
}
