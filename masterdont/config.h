
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
#include <fcntl.h>
#include <sys/stat.h>

/* ldns */
#include "ldns/ldns.h"

#define DEFAULT_CONFIG  "example/masterdont.conf"

