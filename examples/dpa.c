

#include "config.h"

#include <ldns/dns.h>

#include <errno.h>

int verbosity = 1;

#define ETHER_HEADER_LENGTH 14
#define UDP_HEADER_LENGTH 8

#define MAX_MATCHES 20
#define MAX_OPERATORS 7


/* global options */
pcap_dumper_t *dumper = NULL;
bool show_filter_matches = false;
size_t total_nr_of_dns_packets = 0;

/* To add a match,
 * - add it to the enum
 * - add it to the table_matches const
 * - add a handler to value_matches
 * - tell in get_string_value() where in the packet the data lies
 * - add to parser?
 * - add to show_match_ function
 */
enum enum_match_ids {
	MATCH_ID,
	MATCH_OPCODE,
	MATCH_RCODE,
	MATCH_PACKETSIZE,
	MATCH_QR,
	MATCH_TC,
	MATCH_AD,
	MATCH_CD,
	MATCH_RD,
	MATCH_EDNS,
	MATCH_EDNS_PACKETSIZE,
	MATCH_DO,
	MATCH_QUESTION_SIZE,
	MATCH_ANSWER_SIZE,
	MATCH_AUTHORITY_SIZE,
	MATCH_ADDITIONAL_SIZE,
	MATCH_SRC_ADDRESS,
	MATCH_DST_ADDRESS,
	MATCH_TIMESTAMP,
	MATCH_QUERY,
	MATCH_ANSWER,
	MATCH_AUTHORITY,
	MATCH_ADDITIONAL,
	MATCH_LAST
};
typedef enum enum_match_ids match_id;

enum enum_counter_types {
	TYPE_INT,
	TYPE_BOOL,
	TYPE_OPCODE,
	TYPE_RCODE,
	TYPE_STRING,
	TYPE_TIMESTAMP,
	TYPE_ADDRESS,
	TYPE_RR,
	TYPE_LAST
};
typedef enum enum_counter_types counter_type;

const ldns_lookup_table lt_types[] = {
	{TYPE_INT, "int" },
	{TYPE_BOOL, "bool" },
	{TYPE_OPCODE, "opcode" },
	{TYPE_RCODE, "rcode" },
	{TYPE_STRING, "string" },
	{TYPE_TIMESTAMP, "timestamp" }, 
	{TYPE_ADDRESS, "address" }, 
	{TYPE_RR, "rr" },
	{ 0, NULL }
};

enum enum_type_operators {
	OP_EQUAL,
	OP_NOTEQUAL,
	OP_GREATER,
	OP_LESSER,
	OP_GREATEREQUAL,
	OP_LESSEREQUAL,
	OP_CONTAINS,
	OP_LAST
};
typedef enum enum_type_operators type_operator;

const ldns_lookup_table lt_operators[] = {
	{ OP_EQUAL, "=" },
	{ OP_NOTEQUAL, "!=" },
	{ OP_GREATER, ">" },
	{ OP_LESSER, "<" },
	{ OP_GREATEREQUAL, ">=" },
	{ OP_LESSEREQUAL, "<=" },
	{ OP_CONTAINS, "~=" },
	{ 0, NULL }
};

const char *get_op_str(type_operator op) {
	const ldns_lookup_table *lt;
	lt = ldns_lookup_by_id((ldns_lookup_table *) lt_operators, op);
	if (lt) {
		return lt->name;
	} else {
		fprintf(stderr, "Unknown operator id: %u", op);
		exit(1);
	}
}

type_operator
get_op_id(char *op_str)
{
	const ldns_lookup_table *lt;
	lt = ldns_lookup_by_name((ldns_lookup_table *) lt_operators, op_str);
	if (lt) {
		return (type_operator) lt->id;
	} else {
		fprintf(stderr, "Unknown operator: %s", op_str);
		exit(1);
		return TYPE_INT;
	}
}

struct struct_type_operators {
	counter_type type;
	size_t operator_count;
	type_operator operators[10];
};
typedef struct struct_type_operators type_operators;

const type_operators const_type_operators[] = {
	{ TYPE_INT, 6, { OP_EQUAL, OP_NOTEQUAL, OP_GREATER, OP_LESSER, OP_GREATEREQUAL, OP_LESSEREQUAL } },
	{ TYPE_BOOL, 2, { OP_EQUAL, OP_NOTEQUAL} },
	{ TYPE_OPCODE, 2, { OP_EQUAL, OP_NOTEQUAL} },
	{ TYPE_RCODE, 2, { OP_EQUAL, OP_NOTEQUAL} },
	{ TYPE_STRING, 3, { OP_EQUAL, OP_NOTEQUAL, OP_CONTAINS} },
	{ TYPE_TIMESTAMP, 6, { OP_EQUAL, OP_NOTEQUAL, OP_GREATER, OP_LESSER, OP_GREATEREQUAL, OP_LESSEREQUAL } },
	{ TYPE_ADDRESS, 3, { OP_EQUAL, OP_NOTEQUAL, OP_CONTAINS} },
	{ TYPE_RR, 3, { OP_EQUAL, OP_NOTEQUAL, OP_CONTAINS} },
	{ 0, 0, { 0 } }
};

const type_operators *
get_type_operators(counter_type type) {
	const type_operators *to = const_type_operators;
	while (to) {
		if (to->type == type) {
			return to;
		}
		to++;
	}
	return NULL;
}

struct struct_match_table {
	match_id id;
	const char *name;
	const char *description;
	const counter_type type;
};
typedef struct struct_match_table match_table;

/* order of entries has been changed after gprof analysis, and reasoning
 * about the uses of -u arguments
 */
const match_table matches[] = {
	{ MATCH_QUERY, "query", "String representation of the query RR", TYPE_RR },
	{ MATCH_SRC_ADDRESS, "srcaddress", "address the packet was sent from", TYPE_ADDRESS },
	{ MATCH_TIMESTAMP, "timestamp", "time the packet was sent", TYPE_TIMESTAMP },
	{ MATCH_DST_ADDRESS, "dstaddress", "address the packet was sent to", TYPE_ADDRESS },
	{ MATCH_EDNS_PACKETSIZE, "edns-packetsize", "packets size specified in edns rr", TYPE_INT },
	{ MATCH_ID, "id", "id of the packet", TYPE_INT },
	{ MATCH_OPCODE, "opcode", "opcode of packet (rfc1035)", TYPE_OPCODE },
	{ MATCH_RCODE, "rcode", "response code of packet", TYPE_RCODE },
	{ MATCH_PACKETSIZE, "packetsize", "size of packet in bytes", TYPE_INT },
	{ MATCH_QR, "qr", "value of qr bit", TYPE_BOOL },
	{ MATCH_TC, "tc", "value of tc bit", TYPE_BOOL },
	{ MATCH_AD, "ad", "value of ad bit", TYPE_BOOL },
	{ MATCH_CD, "cd", "value of cd bit", TYPE_BOOL },
	{ MATCH_RD, "rd", "value of rd bit", TYPE_BOOL },
	{ MATCH_EDNS, "edns", "existence of edns rr", TYPE_BOOL },
	{ MATCH_DO, "do", "value of do bit", TYPE_BOOL },
	{ MATCH_QUESTION_SIZE, "questionsize", "number of rrs in the question section", TYPE_INT },
	{ MATCH_ANSWER_SIZE, "answersize", "number of rrs in the answer section", TYPE_INT },
	{ MATCH_AUTHORITY_SIZE, "authoritysize", "number of rrs in the authority section", TYPE_INT },
	{ MATCH_ADDITIONAL_SIZE, "additionalsize", "number of rrs in the additional section", TYPE_INT },
	{ MATCH_ANSWER, "answer", "String representation of the answer RRs", TYPE_RR },
	{ MATCH_AUTHORITY, "authority", "String representation of the authority RRs", TYPE_RR },
	{ MATCH_ADDITIONAL, "additional", "String representation of the additional RRs", TYPE_RR },
	{ 0, NULL , NULL, TYPE_INT}
};

enum enum_match_expression_operators {
	MATCH_EXPR_OR,
	MATCH_EXPR_AND,
	MATCH_EXPR_LEAF
};
typedef enum enum_match_expression_operators match_expression_operator;

struct struct_match_operation {
	match_id id;
	type_operator operator;
	char *value;
};
typedef struct struct_match_operation match_operation;

typedef struct struct_match_expression match_expression;
struct struct_match_expression {
	/* and or or, or leaf (in which case there are no subtrees, but only a match_table */
	match_expression_operator op;
	match_expression *left;
	match_expression *right;
	match_operation *match;
	size_t count;
};

typedef struct struct_match_counters match_counters;
struct struct_match_counters {
/*
	match_expression **counter;
	size_t size;
*/
	match_expression *match;
	match_counters *left;
	match_counters *right;
};

match_table *
get_match_by_name(char *name) {
	match_table *mt = (match_table *) matches;

	if (name) {
		while (mt->name != NULL) {
			if (strcasecmp(name, mt->name) == 0) {
				return mt;
			}
			mt++;
		}
	}
	return NULL;
}

match_table *
get_match_by_id(match_id id) {
	match_table *mt = (match_table *) matches;

	while (mt->name != NULL) {
		if (mt->id == id) {
			return mt;
		}
		mt++;
	}
	return NULL;
}

const char *
get_match_name_str(match_id id) {
	match_table *mt = get_match_by_id(id);
	if (mt) {
		return mt->name;
	} else {
		fprintf(stderr, "Unknown match id: %u\n", id);
		exit(1);
		return "Unknown match id";
	}
}

bool is_match_name(char *name) {
	match_table *mt = get_match_by_name(name);
	if (mt) {
		return true;
	} else {
		return false;
	}
}

void
print_match_operation(FILE *output, match_operation *mc)
{
	match_table *mt = NULL;
	ldns_lookup_table *lt;
	struct timeval time;
	int value;
	size_t pos;
	char *tmp;

	if (mc) {
		mt = get_match_by_id(mc->id);

		if (mt) {
			fprintf(output, "%s %s ",mt->name, get_op_str(mc->operator));
			
			switch (mt->type) {
				case TYPE_INT:
				case TYPE_STRING:
				case TYPE_ADDRESS:
				case TYPE_RR:
					fprintf(output, "'%s'", mc->value);
					break;
				case TYPE_BOOL:
					if (strncmp(mc->value, "1", 2) == 0) {
						fprintf(output,"'true'");
					} else {
						fprintf(output,"'false'");
					}
					break;
				case TYPE_OPCODE:
					value = atoi(mc->value);
					lt = ldns_lookup_by_id(ldns_opcodes, value);
					if (lt) {
						fprintf(output, lt->name);
					} else {
						fprintf(output, mc->value);
					}
					break;
				case TYPE_RCODE:
					value = atoi(mc->value);
					lt = ldns_lookup_by_id(ldns_rcodes, value);
					if (lt) {
						fprintf(output, lt->name);
					} else {
						fprintf(output, mc->value);
					}
					break;
				case TYPE_TIMESTAMP:
					time.tv_sec = (time_t) atol(mc->value);
					tmp = ctime((time_t*)&time);
					for (pos = 0; pos < strlen(tmp); pos++) {
						if (tmp[pos] == '\n') {
							tmp[pos] = '\0';
						}
					}
					fprintf(output, "%s", tmp);
					break;
				default:
				fprintf(output, "'%s'", mc->value);
			}

		} else {
			fprintf(output, "%u %s '%s'", mc->id, get_op_str(mc->operator), mc->value);
		}
	} else {
		fprintf(output, "(nil)");
	}
}

void
print_match_expression(FILE *output, match_expression *expr)
{
	if (expr) {
		switch (expr->op) {
			case MATCH_EXPR_OR:
				fprintf(output, "(");
				print_match_expression(output, expr->left);
				fprintf(output, " | ");
				print_match_expression(output, expr->right);
				fprintf(output, ")");
				break;
			case MATCH_EXPR_AND:
				fprintf(output, "(");
				print_match_expression(output, expr->left);
				fprintf(output, " & ");
				print_match_expression(output, expr->right);
				fprintf(output, ")");
				break;
			case MATCH_EXPR_LEAF:
				print_match_operation(output, expr->match);
				break;
			default:
/*
				fprintf(output, "ERROR PRINTING MATCH: unknown op: %u\n", expr->op);
				exit(1);
*/
				fprintf(output, "(");
if (expr->left) {
	print_match_expression(output, expr->left);
}
				fprintf(output, " ? ");
if (expr->right) {
	print_match_expression(output, expr->right);
}
				fprintf(output, ") _");
if (expr->match) {
	print_match_operation(output, expr->match);				
}
fprintf(output, "_");
		}
	} else {
		printf("(nil)");
	}			
}

size_t 
calculate_counters_total(match_counters *counters)
{
	size_t result = 0;
	if (counters) {
		if (counters->left) {
			result += calculate_counters_total(counters->left);
		}
		if (counters->match) {
			result += counters->match->count;
		}
		if (counters->right) {
			result += calculate_counters_total(counters->left);
		}
	}
	
	return result;
}

void
print_counters(FILE *output, match_counters *counters, bool show_percentages, size_t total, int count_minimum)
{
	double percentage;

	if (!counters || !output) {
		return;
	}

	if (counters->left) {
		print_counters(output, counters->left, show_percentages, total, count_minimum);
	}
	if (counters->match) {
		if (count_minimum < (int) counters->match->count) {
			print_match_expression(output, counters->match);
			printf(": %u", (unsigned int) counters->match->count);
			if (show_percentages) {
				percentage = (double) counters->match->count / (double) total * 100.0;
				printf(" (%.2f%%)", percentage);
			}
			printf("\n");
		}
	}
	if (counters->right) {
		print_counters(output, counters->right, show_percentages, total, count_minimum);
	}
	
	return;	
}

/*
 * Calculate the total for all match operations with the same id as this one
 * (if they are 'under' this one in the tree, which should be the case in
 * the unique counter tree
 */
size_t
calculate_total_value(match_counters *counters, match_operation *cur)
{
	size_t result = 0;
	
	if (!counters) {
		return 0;
	}
	
	if (counters->match->match->id == cur->id) {
		result = atol(counters->match->match->value) * counters->match->count;
	}
	
	if (counters->left) {
		result += calculate_total_value(counters->left, cur);
	}
	if (counters->right) {
		result += calculate_total_value(counters->right, cur);
	}
	
	return result;
}

size_t
calculate_total_count_matches(match_counters *counters, match_operation *cur)
{
	size_t result = 0;
	
	if (!counters) {
		return 0;
	}
	
	if (counters->match->match->id == cur->id) {
		result = 1;
	}
	
	if (counters->left) {
		result += calculate_total_count_matches(counters->left, cur);
	}
	if (counters->right) {
		result += calculate_total_count_matches(counters->right, cur);
	}
	
	return result;
}

size_t
calculate_total_count(match_counters *counters, match_operation *cur)
{
	size_t result = 0;
	
	if (!counters) {
		return 0;
	}
	
	if (counters->match->match->id == cur->id) {
		result = counters->match->count;
	}
	
	if (counters->left) {
		result += calculate_total_count(counters->left, cur);
	}
	if (counters->right) {
		result += calculate_total_count(counters->right, cur);
	}
	
	return result;
}

void
print_counter_averages(FILE *output, match_counters *counters, match_operation *cur)
{
	size_t total_value;
	size_t total_count;
	match_table *mt;
	
	if (!counters || !output) {
		return;
	}
	
	if (!cur) {
		cur = counters->match->match;
		mt = get_match_by_id(cur->id);
		total_value = calculate_total_value(counters, cur);
		total_count = calculate_total_count(counters, cur);
		printf("Average for %s: (%u / %u) %.02f\n", mt->name, total_value, total_count, (float) total_value / (float) total_count);
		if (counters->left) {
			print_counter_averages(output, counters->left, cur);
		}
		if (counters->right) {
			print_counter_averages(output, counters->right, cur);
		}
	} else {
		if (counters->left) {
			if (counters->left->match->match->id != cur->id) {
				print_counter_averages(output, counters->left, NULL);
			}
		}
		if (counters->right) {
			if (counters->right->match->match->id != cur->id) {
				print_counter_averages(output, counters->right, NULL);
			}
		}
	}
	
	return;	
}

void
print_counter_average_count(FILE *output, match_counters *counters, match_operation *cur)
{
	size_t total_matches;
	size_t total_count;
	match_table *mt;
	
	if (!counters || !output) {
		return;
	}
	
	if (!cur) {
		cur = counters->match->match;
		mt = get_match_by_id(cur->id);
		total_matches = calculate_total_count_matches(counters, cur);
		total_count = calculate_total_count(counters, cur);
		printf("Average count for %s: (%u / %u) %.02f\n", mt->name, total_count, total_matches, (float) total_count / (float) total_matches);
		if (counters->left) {
			print_counter_averages(output, counters->left, cur);
		}
		if (counters->right) {
			print_counter_averages(output, counters->right, cur);
		}
	} else {
		if (counters->left) {
			if (counters->left->match->match->id != cur->id) {
				print_counter_averages(output, counters->left, NULL);
			}
		}
		if (counters->right) {
			if (counters->right->match->match->id != cur->id) {
				print_counter_averages(output, counters->right, NULL);
			}
		}
	}
	
	return;	
}

bool
match_int(type_operator operator,
          char *value,
	  char *mvalue)
{
	int a, b;

	if (!value || !mvalue) {
		return false;
	}

	a = atoi(value);
	b = atoi(mvalue);

	switch (operator) {
		case OP_EQUAL:
			return a == b;
			break;
		case OP_NOTEQUAL:
			return a != b;
			break;
		case OP_GREATER:
			return a > b;
			break;
		case OP_LESSER:
			return a < b;
			break;
		case OP_GREATEREQUAL:
			return a >= b;
			break;
		case OP_LESSEREQUAL:
			return a <= b;
			break;
		default:
			fprintf(stderr, "Unknown operator: %u\n", operator);
			exit(2);
	}
}

bool
match_opcode(type_operator operator,
             char *value,
             char *mvalue) {
	ldns_pkt_opcode a, b;
	int i;
	ldns_lookup_table *lt;

	/* try parse name first, then parse as int */
	lt = ldns_lookup_by_name(ldns_opcodes, value);
	if (lt) {
		a = lt->id;
	} else {
		i = atoi(value);
		if (i >= 0 && !isdigit(value[0]) == 0) {
			lt = ldns_lookup_by_id(ldns_opcodes, i);
			if (lt) {
				a = lt->id;
			} else {
				fprintf(stderr, "Unknown opcode: %s\n", value);
				exit(1);
				return false;
			}
		} else {
			fprintf(stderr, "Unknown opcode: %s\n", value);
			exit(1);
			return false;
		}
	}

	lt = ldns_lookup_by_name(ldns_opcodes, mvalue);
	if (lt) {
		b = lt->id;
	} else {
		i = atoi(mvalue);
		if (i >= 0 && !isdigit(mvalue[0]) == 0) {
			lt = ldns_lookup_by_id(ldns_opcodes, i);
			if (lt) {
				b = lt->id;
			} else {
				fprintf(stderr, "Unknown opcode: %s\n", mvalue);
				exit(1);
				return false;
			}
		} else {
			fprintf(stderr, "Unknown opcode: %s\n", mvalue);
			exit(1);
			return false;
		}
	}

	switch(operator) {
		case OP_EQUAL:
			return a == b;
			break;
		case OP_NOTEQUAL:
			return a != b;
			break;
		default:
			fprintf(stderr, "Error bad operator for opcode: %s\n", get_op_str(operator));
			return false;
			break;
	}
}

bool
match_str(type_operator operator,
          char *value,
          char *mvalue)
{
	if (operator == OP_CONTAINS) {
		return strcasestr(value, mvalue) != 0;
	} else if (operator == OP_EQUAL) {
		return strcmp(value, mvalue) == 0;
	} else {
		return strcmp(value, mvalue) != 0;
	}	
}

bool
match_rcode(type_operator operator,
             char *value,
             char *mvalue) {
	int a, b;
	int i;
	ldns_lookup_table *lt;

	/* try parse name first, then parse as int */
	lt = ldns_lookup_by_name(ldns_rcodes, value);
	if (lt) {
		a = lt->id;
	} else {
		i = atoi(value);
		if (i >= 0 && !isdigit(value[0]) == 0) {
			lt = ldns_lookup_by_id(ldns_rcodes, i);
			if (lt) {
				a = lt->id;
			} else {
				fprintf(stderr, "Unknown rcode: %s\n", value);
				exit(1);
				return false;
			}
		} else {
			fprintf(stderr, "Unknown rcode: %s\n", value);
			exit(1);
			return false;
		}
	}

	lt = ldns_lookup_by_name(ldns_rcodes, mvalue);
	if (lt) {
		b = lt->id;
	} else {
		i = atoi(mvalue);

		if (i >= 0 && !isdigit(mvalue[0]) == 0) {
			lt = ldns_lookup_by_id(ldns_rcodes, i);
			if (lt) {
				b = lt->id;
			} else {
				fprintf(stderr, "Unknown rcode: %s\n", mvalue);
				exit(1);
				return false;
			}
		} else {
			fprintf(stderr, "Unknown rcode: %s\n", mvalue);
			exit(1);
			return false;
		}
	}

	switch(operator) {
		case OP_EQUAL:
			return a == b;
			break;
		case OP_NOTEQUAL:
			return a != b;
			break;
		default:
			fprintf(stderr, "Error bad operator for rcode: %s\n", get_op_str(operator));
			return false;
			break;
	}
}

bool
value_matches(match_id id,
        type_operator operator,
        char *value,
        char *mvalue)
{
	int result;

	if (verbosity >= 5) {
		printf("Match %s: %s %s %s: ", get_match_name_str(id), value, get_op_str(operator), mvalue);
	}
	switch(id) {
		case MATCH_OPCODE:
			result = match_opcode(operator, value, mvalue);
			break;
		case MATCH_RCODE:
			result = match_rcode(operator, value, mvalue);
			break;
		case MATCH_ID:
		case MATCH_QR:
		case MATCH_TC:
		case MATCH_AD:
		case MATCH_CD:
		case MATCH_RD:
		case MATCH_DO:
		case MATCH_PACKETSIZE:
		case MATCH_EDNS:
		case MATCH_EDNS_PACKETSIZE:
		case MATCH_QUESTION_SIZE:
		case MATCH_ANSWER_SIZE:
		case MATCH_AUTHORITY_SIZE:
		case MATCH_ADDITIONAL_SIZE:
		case MATCH_TIMESTAMP:
			result = match_int(operator, value, mvalue);
			break;
		case MATCH_QUERY:
		case MATCH_ANSWER:
		case MATCH_AUTHORITY:
		case MATCH_ADDITIONAL:
			result = match_str(operator, value, mvalue);
			break;
		case MATCH_SRC_ADDRESS:
		case MATCH_DST_ADDRESS:
			result = match_str(operator, value, mvalue);
			break;
		default:
			fprintf(stderr, "Error: value_matches() for operator %s not implemented yet.\n", get_op_str(id));
			exit(3);
	}
	if (verbosity >= 5) {
		if (result) {
			printf("true\n");
		} else {
			printf("false\n");
		}
	}
	return result;
}
	

#if 0
bool
count_match(match_counters *counters,
            match_id id,
	    char *value
	   )
{
	size_t i;
	match_table *mt;

	if (counters) {
		for(i = 0; i < counters->size; i++) {
			if (id == counters->counter[i].id) {
				if (value) {
					if (value_matches(id, 
					                  counters->counter[i].operator,
					                  value,
					                  counters->counter[i].value)) {

						if (verbosity >= 5) {
							mt = get_match_by_id(counters->counter[i].id);
							if (mt) {
								printf("MATCH: %s: %s %s %s\n", mt->name, value, get_op_str(counters->counter[i].operator), counters->counter[i].value);
							} else {
								printf("MATCH: <unknown?>: %s %s %s\n", value, get_op_str(counters->counter[i].operator), counters->counter[i].value);
							}
						}
						counters->counter[i].count++;
						return true;
					}
				} else {
					/*counters->counter[i].count++;*/
				}
			}
		}
	}
	return false;
}

/* if value == NULL, always count */
bool
count_match_i(match_counters *counters,
              match_id id,
              int value)
{
	char intbuf[20];
	bool result;

	memset(intbuf, 0, 10);
	snprintf(intbuf, 20, "%d", value);
	result = count_match(counters, id, intbuf);
	return result;
}
#endif

char *
get_string_value(match_id id, ldns_pkt *pkt, ldns_rdf *src_addr, ldns_rdf *dst_addr)
{
	char *val;
	match_table *mt;
	size_t valsize = 100;

	val = malloc(valsize);
	memset(val, 0, valsize);

	switch(id) {
		case MATCH_QR:
			snprintf(val, valsize, "%u", ldns_pkt_qr(pkt));
			break;
		case MATCH_ID:
			snprintf(val, valsize, "%u", ldns_pkt_id(pkt));
			break;
		case MATCH_OPCODE:
			snprintf(val, valsize, "%u", ldns_pkt_get_opcode(pkt));
			break;
		case MATCH_RCODE:
			snprintf(val, valsize, "%u", ldns_pkt_rcode(pkt));
			break;
		case MATCH_PACKETSIZE:
			snprintf(val, valsize, "%u", (unsigned int) ldns_pkt_size(pkt));
			break;
		case MATCH_TC:
			snprintf(val, valsize, "%u", ldns_pkt_tc(pkt));
			break;
		case MATCH_AD:
			snprintf(val, valsize, "%u", ldns_pkt_ad(pkt));
			break;
		case MATCH_CD:
			snprintf(val, valsize, "%u", ldns_pkt_cd(pkt));
			break;
		case MATCH_RD:
			snprintf(val, valsize, "%u", ldns_pkt_rd(pkt));
			break;
		case MATCH_EDNS:
			snprintf(val, valsize, "%u", ldns_pkt_edns(pkt));
			break;
		case MATCH_EDNS_PACKETSIZE:
			snprintf(val, valsize, "%u", ldns_pkt_edns_udp_size(pkt));
			break;
		case MATCH_DO:
			snprintf(val, valsize, "%u", ldns_pkt_edns_do(pkt));
			break;
		case MATCH_QUESTION_SIZE:
			snprintf(val, valsize, "%u", ldns_pkt_qdcount(pkt));
			break;
		case MATCH_ANSWER_SIZE:
			snprintf(val, valsize, "%u", ldns_pkt_ancount(pkt));
			break;
		case MATCH_AUTHORITY_SIZE:
			snprintf(val, valsize, "%u", ldns_pkt_nscount(pkt));
			break;
		case MATCH_ADDITIONAL_SIZE:
			snprintf(val, valsize, "%u", ldns_pkt_arcount(pkt));
			break;
		case MATCH_SRC_ADDRESS:
			free(val);
			val = ldns_rdf2str(src_addr);
			break;
		case MATCH_DST_ADDRESS:
			free(val);
			val = ldns_rdf2str(dst_addr);
			break;
		case MATCH_TIMESTAMP:
			snprintf(val, valsize, "%u", (unsigned int) ldns_pkt_timestamp(pkt).tv_sec);
			break;
		case MATCH_QUERY:
			if (ldns_pkt_qdcount(pkt) > 0) {
				free(val);
				val = ldns_rr2str(ldns_rr_list_rr(ldns_pkt_question(pkt), 0));
				/* replace \n for nicer printing later */
				if (strchr(val, '\n')) {
					*(strchr(val, '\n')) = '\0';
				}
			} else {
				val[0] = '\0';
			}
			break;
		case MATCH_ANSWER:
			if (ldns_pkt_ancount(pkt) > 0) {
				free(val);
				val = ldns_rr_list2str(ldns_pkt_answer(pkt));
			} else {
				val[0] = '\0';
			}
			break;
		case MATCH_AUTHORITY:
			if (ldns_pkt_nscount(pkt) > 0) {
				free(val);
				val = ldns_rr_list2str(ldns_pkt_authority(pkt));
			} else {
				val[0] = '\0';
			}
			break;
		case MATCH_ADDITIONAL:
			if (ldns_pkt_arcount(pkt) > 0) {
				free(val);
				val = ldns_rr_list2str(ldns_pkt_additional(pkt));
			} else {
				val[0] = '\0';
			}
			break;
		default:
			mt = get_match_by_id(id);
			if (!mt) {
				printf("ERROR UNKNOWN MATCH_TABLE ID %u\n", id);
				exit(1);
			}
			printf("Matcher for %s not implemented yet\n", mt->name);
			exit(1);
			return NULL;
	}

	return val;
}

/*
bool
match_pkt(ldns_pkt *pkt, match_counter *counter)
{
	bool result;
	char *val;

	if (!pkt || !counter) {
		return false;
	} else {
		val = get_string_value(counter->id, pkt);
		if (!val) {
			return false;
		}
		result = value_matches(counter->id, counter->operator, val, counter->value);
		if (result) {
			counter->count++;
		}
		free(val);
		return result;
	}
}
*/
bool
match_packet_to_operation(ldns_pkt *pkt, ldns_rdf *src_addr, ldns_rdf *dst_addr, match_operation *operation)
{
	bool result;
	char *val;

	if (!pkt || !operation) {
		return false;
	} else {
		val = get_string_value(operation->id, pkt, src_addr, dst_addr);
		if (!val) {
			return false;
		}
		result = value_matches(operation->id, operation->operator, val, operation->value);
		free(val);
		return result;
	}
}



/*
int
add_counter(match_counters *counters,
            match_expression *expr)
{
		counters->counter = realloc(counters->counter, (counters->size + 1) * sizeof(match_expression *));
		counters->counter[counters->size] = expr;
		counters->size = counters->size + 1;

		return 0;
}
*/

int
match_expression_compare_count(const void *a, const void *b)
{
	match_expression *mea, *meb;
	
	if (!a) {
		return 1;
	} else if (!b) {
		return -1;
	} else {
		mea = (match_expression *) a;
		meb = (match_expression *) b;
		
		if (mea->count < meb->count) {
			return -1;
		} else if (mea->count > meb->count) {
			return 1;
		} else {
			return 0;
		}
	}
}

int
match_expression_compare_count_p(const void *a, const void *b)
{
	match_expression **pmea, **pmeb;
	
	if (!a) {
		return 1;
	} else if (!b) {
		return -1;
	} else {
		pmea = (match_expression **) a;
		pmeb = (match_expression **) b;
		return match_expression_compare_count(*pmea, *pmeb);
	}
}

int
match_operation_compare(const void *a, const void *b)
{
	match_operation *moa, *mob;
	match_table *mt;
	long ia, ib;

	if (!a) {
		return 1;
	} else if (!b) {
		return -1;
	} else {
		moa = (match_operation *) a;
		mob = (match_operation *) b;

		if (moa->id < mob->id) {
			return -1;
		} else if (moa->id > mob->id) {
			return 1;
		} else {
			if (moa->operator < mob->operator) {
				return -1;
			} else if (moa->operator > mob->operator) {
				return 1;
			} else {
				mt = get_match_by_id(moa->id);
				if (mt) {
					switch (mt->type) {
						case TYPE_INT:
						case TYPE_TIMESTAMP:
						case TYPE_BOOL:
						case TYPE_OPCODE:
						case TYPE_RCODE:
							ia = atol(moa->value);
							ib = atol(mob->value);
							return ia - ib;
							break;
						case TYPE_STRING:
						case TYPE_ADDRESS:
						case TYPE_RR:
						default:
							return strcmp(moa->value, mob->value);
							break;
					}
				} else {
					return strcmp(moa->value, mob->value);
				}
			}
		}
	}
}

int
match_expression_compare(const void *a, const void *b)
{
	match_expression *mea, *meb;
	
	if (!a) {
		return 1;
	} else if (!b) {
		return -1;
	} else {
		mea = (match_expression *) a;
		meb = (match_expression *) b;
		
		if (mea->op < meb->op) {
			return -1;
		} else if (mea->op > meb->op) {
			return 1;
		} else {
			switch(mea->op) {
				case MATCH_EXPR_AND:
				case MATCH_EXPR_OR:
					if (match_expression_compare(mea->left, meb->left) < 0) {
						return -1;
					} else if (match_expression_compare(mea->left, meb->left) > 0) {
						return 1;
					} else {
						return match_expression_compare(mea->right, meb->right);
					}
					break;
				case MATCH_EXPR_LEAF:
					return match_operation_compare(mea->match, meb->match);
					break;
				default:
					fprintf(stderr, "Unknown Match Expression logic operator: %u\n", mea->op);
					exit(1);
			}
		}
	}
}
int
match_expression_compare_p(const void *a, const void *b)
{
	
	match_expression **pmea, **pmeb;
	
	if (!a) {
		return 1;
	} else if (!b) {
		return -1;
	} else {
		pmea = (match_expression **) a;
		pmeb = (match_expression **) b;
		return match_expression_compare(*pmea, *pmeb);
	}
}

/**
 * If count is true, and the counter is found, its count is increased by 1
 */
int
add_match_counter(match_counters *counters,
		  match_expression *expr,
                  bool count)
{
	int cmp;
	match_counters *new;

	if (!counters || !expr) {
		return -1;
	} else {
		if (counters->match) {
			cmp = match_expression_compare(counters->match, 
			                               expr);
			if (cmp > 0) {
				if (counters->left) {
					return add_match_counter(counters->left,
					                         expr,
					                         count);
				} else {
					new = malloc(sizeof(match_counters));
					new->left = NULL;
					new->right = NULL;
					new->match = expr;
					counters->left = new;
					return 0;
				}
			} else if (cmp < 0) {
				if (counters->right) {
					return add_match_counter(counters->right,
					                         expr,
					                         count);
				} else {
					new = malloc(sizeof(match_counters));
					new->left = NULL;
					new->right = NULL;
					new->match = expr;
					counters->right = new;
					return 0;
				}
			} else  {
				/* already there? */
				if (count) {
					counters->match->count++;
				}
				return 1;
			}
		} else {
			/* shouldn't happen but anyway */
			counters->match = expr;
		}
	}
	return 0;
}

bool
match_dns_packet_to_expr(ldns_pkt *pkt, ldns_rdf *src_addr, ldns_rdf *dst_addr, match_expression *expr)
{
	bool result;

	if (!pkt || !expr) {
		return false;
	}
	
	switch(expr->op) {
		case MATCH_EXPR_OR:
			result = (match_dns_packet_to_expr(pkt, src_addr, dst_addr, expr->left) ||
			       match_dns_packet_to_expr(pkt, src_addr, dst_addr, expr->right));
			break;
		case MATCH_EXPR_AND:
			result = (match_dns_packet_to_expr(pkt, src_addr, dst_addr, expr->left) &&
			       match_dns_packet_to_expr(pkt, src_addr, dst_addr, expr->right));
			break;
		case MATCH_EXPR_LEAF:
			result = match_packet_to_operation(pkt, src_addr, dst_addr, expr->match);
			break;
		default:
			fprintf(stderr, "Error, unknown expression operator %u\n", expr->op);
			fprintf(stderr, "full expression:\n");
			print_match_expression(stderr, expr);
			fprintf(stderr, "\n");
			exit(1);
	}

	if (result) {
		if (verbosity >= 5) {
			printf("Found Match:\n");
			print_match_expression(stdout, expr);
			printf("\nCount now %u\n", (unsigned int) expr->count);
		}
		expr->count++;
	}

	return result;
}

bool
match_expression_equals(match_expression *expr1, match_expression *expr2)
{
	if (!expr1 || !expr2) {
		return false;
	}

	switch(expr1->op) {
		case MATCH_EXPR_OR:
		case MATCH_EXPR_AND:
			if (!expr2->left || !expr2->right) {
				return false;
			}
			return (match_expression_equals(expr1->left, expr2->left) &&
			        match_expression_equals(expr1->right, expr2->right)
			       );
			break;
		case MATCH_EXPR_LEAF:
			if (!expr2->match) {
				return false;
			}
			return expr1->match->id == expr2->match->id &&
			       expr1->match->operator == expr2->match->operator &&
			       strcmp(expr1->match->value, expr2->match->value) == 0;
			break;
		default:
			return false;
	}

}


void
free_match_operation(match_operation *operation)
{
	if (operation) {
		if (operation->value) {
			free(operation->value);
		}
		free(operation);
	}
}

void
free_match_expression(match_expression *expr)
{
	if (expr) {
		switch(expr->op) {
			case MATCH_EXPR_OR:
			case MATCH_EXPR_AND:
				free_match_expression(expr->left);
				free_match_expression(expr->right);
				break;
			case MATCH_EXPR_LEAF:
				free_match_operation(expr->match);
				break;
		}
		free(expr);
	}
}

void
free_counters(match_counters *counters)
{
	if (counters) {
		if (counters->left) {
			free_counters(counters->left);
		}
		if (counters->match) {
			free_match_expression(counters->match);
		}
		if (counters->right) {
			free_counters(counters->right);
		}
		free(counters);
	}
}

void
match_pkt_counters(ldns_pkt *pkt, ldns_rdf *src_addr, ldns_rdf *dst_addr, match_counters *counts)
{
	if (counts->left) {
		match_pkt_counters(pkt, src_addr, dst_addr, counts->left);
	}
	if (counts->match) {
		if (match_dns_packet_to_expr(pkt, src_addr, dst_addr, counts->match)) {
/*
			counts->match->count++;
*/
		}
	}
	if (counts->right) {
		match_pkt_counters(pkt, src_addr, dst_addr, counts->right);
	}	
}

void
match_pkt_uniques(ldns_pkt *pkt, ldns_rdf *src_addr, ldns_rdf *dst_addr, match_counters *uniques, match_id unique_ids[], size_t unique_id_count)
{
	match_expression *me;
	size_t i;
	match_operation *mo;
	int add_result;
	
	for (i = 0; i < unique_id_count; i++) {
		mo = malloc(sizeof(match_operation));
		mo->id = unique_ids[i];
		mo->operator = OP_EQUAL;
		mo->value = get_string_value(mo->id, pkt, src_addr, dst_addr);

		me = malloc(sizeof(match_expression));
		me->op = MATCH_EXPR_LEAF;
		me->left = NULL;
		me->right = NULL;
		me->match = mo;
		me->count = 1;

		add_result = add_match_counter(uniques, me, true);
		/* if result=1 it was already found, so delete new one */
		if (add_result == 1) {
			free_match_expression(me);
		}
	}

#if 0
	size_t i, j;
	bool found;
	match_expression *me;
	match_operation *mo;

	/* get the value, match uniques for that, if not match, add new */
	/* all unique values should be MATCH_EXPR_LEAF */
		found = false;
		for (j = 0; j < uniques->size; j++) {
			if (uniques->counter[j]->match->id == unique_ids[i]) {
				if (match_dns_packet_to_expr(pkt, src_addr, dst_addr, uniques->counter[j])) {
					found = true;
				}
			}
		}
		if (!found) {
			mo = malloc(sizeof(match_operation));
			mo->id = unique_ids[i];
			mo->operator = OP_EQUAL;
			mo->value = get_string_value(mo->id, pkt, src_addr, dst_addr);

			me = malloc(sizeof(match_expression));
			me->match = mo;
			me->op = MATCH_EXPR_LEAF;
			me->left = NULL;
			me->right = NULL;
			me->count = 1;

			add_counter(uniques, me);
		}
	}
#endif
}


/*
void
print_match_counter(FILE *output, match_counter *mc)
{
	match_table *mt = NULL;
	if (mc) {
		mt = get_match_by_id(mc->id);
		if (mt) {
			fprintf(output, "%s %s '%s'", mt->name, get_op_str(mc->operator), mc->value);
		} else {
			fprintf(output, "%u %s '%s'", mc->id, get_op_str(mc->operator), mc->value);
		}
	} else {
		fprintf(output, "(nil)");
	}
}

*/
match_expression *
parse_match_expression(char *string)
{
	match_expression *expr;
	size_t i,j;
	size_t leftstart, leftend = 0;
	char *left_str, *op, *val;
	match_table *mt;
	match_operation *mo = NULL;
	const type_operators *tos;
	match_expression *result;
	ldns_rr *qrr;
	ldns_lookup_table *lt = NULL;

	/* remove whitespace */
	char *str = malloc(strlen(string) + 1);

	j = 0;
	for (i = 0; i < strlen(string); i++) {
/*
		if(!isspace(string[i])) {
*/
			str[j] = string[i];
			j++;
/*
		}
*/
	}
	str[j] = '\0';
	
	/*
	printf("Parsing: %s\n", string);
	printf("Parsing short : %s\n", str);
	*/
	expr = malloc(sizeof(match_expression));
	expr->left = NULL;
	expr->right = NULL;
	expr->match = NULL;
	expr->count = 0;
	leftstart = 0;
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '&') {
			expr->op = MATCH_EXPR_AND;
			if (!expr->left) {
				left_str = malloc(leftend - leftstart + 2);
				strncpy(left_str, &str[leftstart], leftend-leftstart+1);
				left_str[leftend - leftstart + 1] = '\0';
				expr->left = parse_match_expression(left_str);
				free(left_str);
			}
			expr->right = parse_match_expression(&str[i+1]);
			if (expr->left && expr->right) {
				result = expr;
				goto done;
			} else {
				result = NULL;
				goto done;
			}
		} else if (str[i] == '|') {
			expr->op = MATCH_EXPR_OR;
			if (!expr->left) {
				left_str = malloc(leftend - leftstart + 2);
				strncpy(left_str, &str[leftstart], leftend-leftstart+1);
				left_str[leftend - leftstart + 1] = '\0';
				expr->left = parse_match_expression(left_str);
				free(left_str);
			}
			expr->right = parse_match_expression(&str[i+1]);
			expr->count = 0;
			if (expr->left && expr->right) {
				result = expr;
				goto done;
			} else {
				result = NULL;
				goto done;
			}
		} else if (str[i] == '(') {
			leftstart = i + 1;
			j = 1;
			while (j > 0) {
				i++;
				if (i > strlen(str)) {
					printf("parse error: no closing bracket: %s\n", str);
					printf("                                 ");
					for (j = 0; j < leftstart - 1; j++) {
						printf(" ");	
					}
					printf("^\n");
					result = NULL;
					goto done;
				}
				if (str[i] == ')') {
					j--;
				} else if (str[i] == '(') {
					j++;
				} else {
				}
			}
			leftend = i-1;
			left_str = malloc(leftend - leftstart + 1);
			strncpy(left_str, &str[leftstart], leftend - leftstart + 1);
			expr->left = parse_match_expression(left_str);
			free(left_str);
			if (i >= strlen(str)-1) {
				result = expr->left;
				goto done;
			}
		} else if (str[i] == ')') {
			printf("parse error: ) without (\n");
			result = NULL;
			goto done;
		} else {
			leftend = i;
		}
	}
	
	/* no operators or hooks left, expr should be of the form
	   <name><operator><value> now */
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '=' ||
		    str[i] == '>' ||
		    str[i] == '<' ||
		    str[i] == '!' ||
		    str[i] == '~'
		   ) {
		 	leftend = i-1;
			op = malloc(3);
			j = 0;
			op[j] = str[i];
			i++;
			j++;
			
			if (i > strlen(str)) {
				printf("parse error no right hand side: %s\n", str);
				result = NULL;
				goto done;
			}
			if (str[i] == '=' ||
			    str[i] == '>' ||
			    str[i] == '<' ||
			    str[i] == '!' ||
			    str[i] == '~'
			   ) {
			   	op[j] = str[i];
				i++;
			   	j++;
				if (i > strlen(str)) {
					printf("parse error no right hand side: %s\n", str);
					result = NULL;
					goto done;
				}
			}
			op[j] = '\0';
			left_str = malloc(leftend - leftstart + 2);
			strncpy(left_str, &str[leftstart], leftend - leftstart + 1);
			left_str[leftend - leftstart + 1] = '\0';
			mt = get_match_by_name(left_str);
			if (!mt) {
				printf("parse error: unknown match name: %s\n", left_str);
				result = NULL;
				goto done;
			} else {
				/* check if operator is allowed */
				tos = get_type_operators(mt->type);
				for (j = 0; j < tos->operator_count; j++) {
					if (get_op_id(op) == tos->operators[j]) {
						mo = malloc(sizeof(match_operation));
						mo->id = mt->id;
						mo->operator = get_op_id(op);
						switch (mt->type) {
							case TYPE_BOOL:
								val = malloc(2);
								if (strncmp(&str[i], "true", 5) == 0 ||
								    strncmp(&str[i], "TRUE", 5) == 0 ||
								    strncmp(&str[i], "True", 5) == 0 ||
								    strncmp(&str[i], "1", 2) == 0
								) {
									val[0] = '1';
									val[1] = '\0';
								} else if (strncmp(&str[i], "false", 5) == 0 ||
								    strncmp(&str[i], "FALSE", 5) == 0 ||
								    strncmp(&str[i], "False", 5) == 0 ||
								    strncmp(&str[i], "0", 2) == 0
								) {

									val[0] = '0';
								} else {
									fprintf(stderr, "Bad value for bool: %s\n", &str[i]);
									exit(EXIT_FAILURE);
								}
								val[1] = '\0';
								break;
							case TYPE_RR:
								/* convert first so we have the same strings for the same rrs in match_ later */
								/*
								qrr = ldns_rr_new_frm_str(&str[i], LDNS_DEFAULT_TTL, NULL);
								if (!qrr) {
									fprintf(stderr, "Bad value for RR: %s\n", &str[i]);
									exit(EXIT_FAILURE);
								}
								val = ldns_rr2str(qrr);
								*/
								/* remove \n for readability */
								/*
								if (strchr(val, '\n')) {
									*(strchr(val, '\n')) = '\0';
								}
								ldns_rr_free(qrr);
								*/
								val = strdup(&str[i]);
								break;
							case TYPE_OPCODE:
								lt = ldns_lookup_by_name(ldns_opcodes, &str[i]);
								if (lt) {
									val = malloc(4);
									snprintf(val, 3, "%u", lt->id);
								} else {
									val = malloc(strlen(str) - i + 1);
									strcpy(val, &str[i]);
								}
								break;
							case TYPE_RCODE:
								lt = ldns_lookup_by_name(ldns_rcodes, &str[i]);
								if (lt) {
									val = malloc(4);
									snprintf(val, 3, "%u", lt->id);
								} else {
									val = malloc(strlen(str) - i + 1);
									strcpy(val, &str[i]);
								}
								break;
							default:
								val = malloc(strlen(str) - i + 1);
								strcpy(val, &str[i]);
								break;
						}
						mo->value = val;
					}
				}
				if (!mo) {
					printf("parse error: operator %s not allowed for match %s\n", op, left_str);
					result = NULL;
					goto done;
				}
			}
			free(left_str);
			free(op);
			expr->match = mo;
			expr->op = MATCH_EXPR_LEAF;
			result = expr;
			goto done;
		}
	}

	result = NULL;
	
	done:
	free(str);
	if (!result) {
		free_match_expression(expr);
	}
	return result;
	
}
/* end of matches and counts */
void 
usage(FILE *output)
{
	fprintf(output, "Usage: dpa [OPTIONS] <pcap file>\n");
	fprintf(output, "Options:\n");
	fprintf(output, "\t-c <exprlist>:\tCount occurrences of matching expressions\n");
	fprintf(output, "\t-f <expression>:\tFilter occurrences of matching expressions\n");
	fprintf(output, "\t-h:\t\tshow this help\n");
	fprintf(output, "\t-p:\t\tshow percentage of -u and -c values (of the total of\n\t\t\tmatching on the -f filter. if no filter is given,\n\t\t\tpercentages are on all correct dns packets)\n");
	fprintf(output, "\t-of <file>:\tWrite pcap packets that match the -f flag to file\n");
	fprintf(output, "\t-s:\t\tshow possible match names\n");
	fprintf(output, "\t-s <matchname>:\tshow possible match operators and values for <name>\n");
	fprintf(output, "\t-sf:\t\tPrint packet that match -f. If no -f is given, print\n\t\t\tall dns packets\n");
	fprintf(output, "\t-u <matchnamelist>:\tCount all occurrences of matchname\n");
	fprintf(output, "\t-ua:\t\tShow average value of every -u matchname\n");
	fprintf(output, "\t-uac:\t\tShow average count of every -u matchname\n");
	fprintf(output, "\t-um <number>:\tOnly show -u results that occured more than number times\n");
	fprintf(output, "\t-v <level>:\tbe more verbose\n");
	fprintf(output, "\n");
	fprintf(output, "The filename '-' stands for stdin or stdout, so you can use \"-of -\" if you want to pipe the output to another process\n");
	fprintf(output, "\n");
	fprintf(output, "A <list> is a comma separated list of items\n");
	fprintf(output, "\n");
	fprintf(output, "An expression has the following form:\n");
	fprintf(output, "<expr>:\t(<expr>)\n");
	fprintf(output, "\t<expr> | <expr>\n");
	fprintf(output, "\t<expr> & <expr>\n");
	fprintf(output, "\t<match>\n");
	fprintf(output, "\n");
	fprintf(output, "<match>:\t<matchname> <operator> <value>\n");
	fprintf(output, "\n");
	fprintf(output, "See the -s option for possible matchnames, operators and values.\n");
}

void
show_match_names(char *name)
{
	size_t j;
	match_table *mt;
	ldns_lookup_table *lt;
	const type_operators *tos;
	char *str;
	size_t i;
	
	if (name) {
		mt = get_match_by_name(name);
		if (mt) {
			printf("%s:\n", mt->name);
			printf("\t%s.\n", mt->description);
			printf("\toperators: ");
			printf("\t");
			tos = get_type_operators(mt->type);
			if (tos)  {
				for (j = 0; j < tos->operator_count; j++) {
					printf("%s ", get_op_str(tos->operators[j]));
/*
					lt = ldns_lookup_by_id((ldns_lookup_table *) lt_operators, tos->operators[j]);
					if (lt) {
						printf("%s ", lt->name);
					} else {
						printf("? ");
					}
*/
				}
			} else {
				printf("unknown type");
			}
			
			printf("\n");
			printf("\tValues:\n");
			switch (mt->type) {
				case TYPE_INT:
					printf("\t\t<Integer>\n");
					break;
				case TYPE_BOOL:
					printf("\t\t0\n");
					printf("\t\t1\n");
					printf("\t\ttrue\n");
					printf("\t\tfalse\n");
					break;
				case TYPE_OPCODE:
					printf("\t\t<Integer>\n");
					lt = ldns_opcodes;
					while (lt->name != NULL) {
						printf("\t\t%s\n", lt->name);
						lt++;
					}
					break;
				case TYPE_RCODE:
					printf("\t\t<Integer>\n");
					lt = ldns_rcodes;
					while (lt->name != NULL) {
						printf("\t\t%s\n", lt->name);
						lt++;
					}
					break;
				case TYPE_STRING:
					printf("\t\t<String>\n");
					break;
				case TYPE_TIMESTAMP:
					printf("\t\t<Integer> (seconds since epoch)\n");
					break;
				case TYPE_ADDRESS:
					printf("\t\t<IP address>\n");
					break;
				case TYPE_RR:
					printf("\t\t<Resource Record>\n");
					break;
				default:
					break;
			}
		} else {
			printf("Unknown match name: %s\n", name);
		}
	} else {
		mt = (match_table *) matches;
		while (mt->name != NULL) {
			str = (char *) mt->name;
			printf("%s:", str);
			i = strlen(str) + 1;
			while (i < 24) {
				printf(" ");
				i++;
			}
			printf("%s\n", mt->description);
			mt++;
		}
	}
}

int
handle_ether_packet(const u_char *data, struct pcap_pkthdr cur_hdr, match_counters *count, match_expression *match_expr, match_counters *uniques, match_id unique_ids[], size_t unique_id_count)
{
	struct ether_header *eptr;
	struct ip *iptr;
	int ip_hdr_size;
	u_int8_t protocol;
	size_t data_offset = 0;
	ldns_rdf *src_addr, *dst_addr;
	uint8_t *ap;
	char *astr;
	bpf_u_int32 len = cur_hdr.caplen;
	struct timeval timestamp;
/*
printf("timeval: %u ; %u\n", cur_hdr.ts.tv_sec, cur_hdr.ts.tv_usec);
*/
	
	uint8_t *dnspkt;
	
	ldns_pkt *pkt;
	ldns_status status;
	
	/* lets start with the ether header... */
	eptr = (struct ether_header *) data;
	/* Do a couple of checks to see what packet type we have..*/
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
	{
		if (verbosity >= 5) {
			printf("Ethernet type hex:%x dec:%d is an IP packet\n",
				ntohs(eptr->ether_type),
				ntohs(eptr->ether_type));
		}

		data_offset = ETHER_HEADER_LENGTH;
		iptr = (struct ip *) (data + data_offset);


		/* in_addr portability woes, going manual for now */
		/* ipv4 */
		ap = (uint8_t *) &(iptr->ip_src);
		astr = malloc(INET_ADDRSTRLEN);
		if (inet_ntop(AF_INET, ap, astr, INET_ADDRSTRLEN)) {
			if (ldns_str2rdf_a(&src_addr, astr) == LDNS_STATUS_OK) {
				
			}
			free(astr);
		}
		ap = (uint8_t *) &(iptr->ip_dst);
		astr = malloc(INET_ADDRSTRLEN);
		if (inet_ntop(AF_INET, ap, astr, INET_ADDRSTRLEN)) {
			if (ldns_str2rdf_a(&dst_addr, astr) == LDNS_STATUS_OK) {
				
			}
			free(astr);
		}

		ip_hdr_size = iptr->ip_hl * 4;
		protocol = iptr->ip_p;
		
		data_offset += ip_hdr_size;

		if (protocol == IPPROTO_UDP) {
			data_offset += UDP_HEADER_LENGTH;
			
			dnspkt = (uint8_t *) (data + data_offset);

			/*printf("packet starts at byte %u\n", data_offset);*/

			status = ldns_wire2pkt(&pkt, dnspkt, len - data_offset);

			if (status != LDNS_STATUS_OK) {
				if (verbosity >= 3) {
					printf("No dns packet: %s\n", ldns_get_errorstr_by_id(status));
				}
			} else {
				timestamp.tv_sec = cur_hdr.ts.tv_sec;
				timestamp.tv_usec = cur_hdr.ts.tv_usec;
				ldns_pkt_set_timestamp(pkt, timestamp);
			
				if (verbosity >= 4) {
					printf("DNS packet\n");
					ldns_pkt_print(stdout, pkt);
					printf("\n\n");
				}

				if (match_expr) {
					if (match_dns_packet_to_expr(pkt, src_addr, dst_addr, match_expr)) {
						/* if outputfile write */
						if (dumper) {
							pcap_dump((u_char *)dumper, &cur_hdr, data);
						}
						if (show_filter_matches) {
							printf(";; From: ");
							ldns_rdf_print(stdout, src_addr);
							printf("\n");
							printf(";; To:   ");
							ldns_rdf_print(stdout, dst_addr);
							printf("\n");
							ldns_pkt_print(stdout, pkt);
							printf("------------------------------------------------------------\n\n");
						}
					} else {
						ldns_pkt_free(pkt);
						ldns_rdf_deep_free(src_addr);
						ldns_rdf_deep_free(dst_addr);
						return 0;
					}
				} else {
					if (show_filter_matches) {
						printf(";; From: ");
						ldns_rdf_print(stdout, src_addr);
						printf("\n");
						printf(";; To:   ");
						ldns_rdf_print(stdout, dst_addr);
						printf("\n");
						ldns_pkt_print(stdout, pkt);
						printf("------------------------------------------------------------\n\n");
					}
				}

				/* General counters here */
				total_nr_of_dns_packets++;

				match_pkt_counters(pkt, src_addr, dst_addr, count);
				match_pkt_uniques(pkt, src_addr, dst_addr, uniques, unique_ids, unique_id_count);

				ldns_pkt_free(pkt);
				pkt = NULL;
			}
			ldns_rdf_deep_free(src_addr);
			ldns_rdf_deep_free(dst_addr);

		}
		
	} else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
		if (verbosity >= 5) {
			printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
				ntohs(eptr->ether_type),
				ntohs(eptr->ether_type));
		}
	} else {
		if (verbosity >= 5) {
			printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
		}
	}

	return 0;
}

bool
parse_match_list(match_counters *counters, char *string)
{
	size_t i;
	match_expression *expr;
/*	match_counter *mc;*/
	size_t lastpos = 0;
	char *substring;

	/*printf("Parsing match list: '%s'\n", string);*/

	for (i = 0; i < strlen(string); i++) {
		if (string[i] == ',') {
			if (i<2) {
				fprintf(stderr, "Matchlist cannot start with ,\n");
				return false;
			} else {
				substring = malloc(strlen(string)+1);
				strncpy(substring, &string[lastpos], i - lastpos + 1);
				substring[i - lastpos] = '\0';
				expr = parse_match_expression(substring);
				if (!expr) {
					return false;
				}
				free(substring);
				/*
				if (expr->op != MATCH_EXPR_LEAF) {
					fprintf(stderr, "Matchlist can only contain <match>, not a logic expression\n");
					return false;
				}
				*/
				add_match_counter(counters, expr, false);
				lastpos = i+1;
			}
		}
	}
	substring = malloc(strlen(string) + 1);
	strncpy(substring, &string[lastpos], i - lastpos + 1);
	substring[i - lastpos] = '\0';
	expr = parse_match_expression(substring);

	if (!expr) {
		fprintf(stderr, "Bad match: %s\n", substring);
		return false;
	}
	free(substring);
	/*
	if (expr->op != MATCH_EXPR_LEAF) {
		fprintf(stderr, "Matchlist can only contain <match>, not a logic expression\n");
		return false;
	}
	*/
	add_match_counter(counters, expr, false);
	return true;
}

bool
parse_uniques(match_id ids[], size_t *count, char *string)
{
	size_t i, j, lastpos;
	char *str, *strpart;
	match_table *mt;

	/*printf("Parsing unique counts: '%s'\n", string);*/
	str = malloc(strlen(string) + 1);
	j = 0;
	for (i = 0; i < strlen(string); i++) {
		if (!isspace(string[i])) {
			str[j] = string[i];
			j++;
		}
	}
	str[j] = '\0';

	lastpos = 0;
	for (i = 0; i <= strlen(str); i++) {
		if (str[i] == ',' || i >= strlen(str)) {
			strpart = malloc(i - lastpos + 1);
			strncpy(strpart, &str[lastpos], i - lastpos);
			strpart[i - lastpos] = '\0';
			if ((mt = get_match_by_name(strpart))) {
				ids[*count] = mt->id;
				*count = *count + 1;
			} else {
				printf("Error parsing match list; unknown match name: %s\n", strpart);
				return false;
			}
			free(strpart);
			lastpos = i + 1;
		}
	}
	if (i > lastpos) {
		strpart = malloc(i - lastpos + 1);
		strncpy(strpart, &str[lastpos], i - lastpos);
		strpart[i - lastpos] = '\0';
		if ((mt = get_match_by_name(strpart))) {
			ids[*count] = mt->id;
			*count = *count + 1;
		} else {
			printf("Error parsing match list; unknown match name: %s\n", strpart);
			return false;
		}
		free(strpart);
		lastpos = i + 1;
	}
	free(str);
	return true;
}

int main(int argc, char *argv[]) {

	int i;
	int status = EXIT_SUCCESS;
	bool ok = false;
	match_counters *count = malloc(sizeof(match_counters));
	const char *inputfile = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pc = NULL;
	const u_char *cur;
	struct pcap_pkthdr cur_hdr;
	match_expression *expr = NULL;
	match_id unique_ids[MAX_MATCHES];
	size_t unique_id_count = 0; /* number of unique counters */
	match_counters *uniques = malloc(sizeof(match_counters));
	char *dumpfile = NULL;

	bool show_percentages = false;
	bool show_averages = false;
	bool show_average_count = false;
	int unique_minimum = 0;

	count->left = NULL;
	count->match = NULL;
	count->right = NULL;
	uniques->left = NULL;
	uniques->match = NULL;
	uniques->right = NULL;

	for (i = 1; i < argc; i++) {


		if (strncmp(argv[i], "-c", 3) == 0) {
			if (i + 1 < argc) {
				if (!parse_match_list(count, argv[i + 1])) {
					status = EXIT_FAILURE;
					goto exit;
				}
				i++;
			} else {
				usage(stderr);
				status = EXIT_FAILURE;
				goto exit;
			}
		} else 	if (strncmp(argv[i], "-f", 3) == 0) {
			if (i + 1 < argc) {
				if (expr || strchr(argv[i+1], ',')) {
					fprintf(stderr, "You can only specify 1 filter expression.\n");
					status = EXIT_FAILURE;
					goto exit;
				}
				expr = parse_match_expression(argv[i + 1]);
				i++;
			} else {
				usage(stderr);
				status = EXIT_FAILURE;
				goto exit;
			}
		} else if (strncmp(argv[i], "-h", 3) == 0) {
			usage(stdout);
			status = EXIT_SUCCESS;
			goto exit;
		} else if (strncmp(argv[i], "-p", 3) == 0) {
			show_percentages = true;
		} else if (strncmp(argv[i], "-of", 4) == 0) {
			if (i + 1 < argc) {
				dumpfile = argv[i + 1];
				i++;
			} else {
				usage(stderr);
				status = EXIT_FAILURE;
				goto exit;
			}
		} else if (strncmp(argv[i], "-s", 3) == 0) {
			if (i + 1 < argc) {
				show_match_names(argv[i + 1]);
			} else {
				show_match_names(NULL);
			}
			status = EXIT_SUCCESS;
			goto exit;
		} else if (strncmp(argv[i], "-sf", 4) == 0) {
			show_filter_matches = true;
		} else if (strncmp(argv[i], "-u", 3) == 0) {
			if (i + 1 < argc) {
				if (!parse_uniques(unique_ids, &unique_id_count, argv[i + 1])) {
					status = EXIT_FAILURE;
					goto exit;
				}
				i++;
			} else {
				usage(stderr);
				status = EXIT_FAILURE;
				goto exit;
			}
		} else if (strcmp("-ua", argv[i]) == 0) {
			show_averages = true;
		} else if (strcmp("-uac", argv[i]) == 0) {
			show_average_count = true;
		} else if (strcmp("-um", argv[i]) == 0) {
			if (i + 1 < argc) {
				unique_minimum = atoi(argv[i+1]);
				i++;
			} else {
				fprintf(stderr, "-um requires an argument");
				usage(stderr);
				status = EXIT_FAILURE;
				goto exit;
			}
		} else if (strcmp("-v", argv[i]) == 0) {
			i++;
			if (i < argc) {
				verbosity = atoi(argv[i]);
			}
		} else {
			if (inputfile) {
				fprintf(stderr, "You can only specify 1 input file\n");
				exit(1);
			}
			inputfile = argv[i];
		}
	}

	if (!inputfile) {
		inputfile = "-";
	}

	if (verbosity >= 5) {
		printf("Filter:\n");
		print_match_expression(stdout, expr);
		printf("\n\n");
	}

	pc = pcap_open_offline(inputfile, errbuf);
	
	if (!pc) {
		printf("Error opening pcap file %s: %s\n", inputfile, errbuf);
		exit(1);
	}

	if (dumpfile) {
	        dumper = pcap_dump_open(pc, dumpfile);

		if (!dumper) {
			printf("Error opening pcap dump file %s: %s\n", dumpfile, errbuf);
			exit(1);
		}
	}

	while ((cur = pcap_next(pc, &cur_hdr))) {
		if (verbosity >= 5) {
			printf("\n\n\n[PKT_HDR] caplen: %u \tlen: %u\n", cur_hdr.caplen, cur_hdr.len);
		}
		handle_ether_packet(cur, cur_hdr, count, expr, uniques, unique_ids, unique_id_count);
	}

	if (dumper) {
		pcap_dump_close(dumper);
	}

	pcap_close(pc);
	
	if (show_percentages) {
		fprintf(stdout, "Total number of DNS packets evaluated: %u\n", (unsigned int) total_nr_of_dns_packets);
	}
	if (count->match) {
		print_counters(stdout, count, show_percentages, total_nr_of_dns_packets, 0);
	}
	if (uniques->match) {
		print_counters(stdout, uniques, show_percentages, total_nr_of_dns_packets, unique_minimum);
		if (show_averages) {
			print_counter_averages(stdout, uniques, NULL);
		}
		if (show_average_count) {
			print_counter_average_count(stdout, uniques, NULL);
		}
	}

	exit:

	free_match_expression(expr);
	free_counters(count);
	free_counters(uniques);

	return status;
}



