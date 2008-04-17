
/* standard includes */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

/* for networking */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>

/* ldns */
#include "ldns/ldns.h"

#define DEFAULT_PORT    53
#define DEFAULT_CONFIG  "example/masterdont.conf"
#define MAX_TCP 	200 /* max number concurrent tcp queries */
#define SERVER_BUFFER_SIZE 65535 /* bytes */
#define TCP_LISTEN_BACKLOG 15 /* max number of waiting connections */
#define TCP_PKT_SIZE	16384 /* bytes size max tcp packet */

