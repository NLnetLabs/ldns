/*
 * root.c
 * Function to handle to the rootservers
 * and to update and prime them
 * (c) 2005 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include "drill.h"
#include <ldns/dns.h>

/* a global list of the root-servers */
ldns_rr_list *global_dns_root;

/* put a hardcoded list in the root and
 * init the root rrlist structure */
void
init_root(void)
{
	ldns_rr *r;
	
	global_dns_root = ldns_rr_list_new();

	r = ldns_rr_new_frm_str("a.root-servers.net 3600 IN A 198.41.0.4", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);

	r = ldns_rr_new_frm_str("b.root-servers.net 3600 IN A 192.228.79.201", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);

	r = ldns_rr_new_frm_str("c.root-servers.net 3600 IN A 192.33.4.12", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("d.root-servers.net 3600 IN A 128.8.10.90", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("e.root-servers.net 3600 IN A 192.203.230.10", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("f.root-servers.net 3600 IN A 192.5.5.241", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("g.root-servers.net 3600 IN A 192.112.36.4", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("h.root-servers.net 3600 IN A 128.63.2.53", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("i.root-servers.net 3600 IN A 192.36.148.17", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("j.root-servers.net 3600 IN A 192.58.128.30", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("k.root-servers.net 3600 IN A 193.0.14.129", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("l.root-servers.net 3600 IN A 198.32.64.12", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
	
	r = ldns_rr_new_frm_str("m.root-servers.net 3600 IN A 202.12.27.33", 0, NULL);
	ldns_rr_list_push_rr(global_dns_root, r);
}
