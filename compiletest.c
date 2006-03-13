
#include "ldns/config.h"
#include <ldns/dns.h>

int main(void) {
  ldns_rr *rr = ldns_rr_new();
  ldns_rr_free(rr);
  return 0;
}

