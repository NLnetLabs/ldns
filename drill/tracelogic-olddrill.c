/* tracelogic.c
 */
/**
 * Performs a secure lookup - this should be folded into the above one
 */
ldns_rr *
do_trace_secure(ldns_rr *q, int protocol, int print)
{
	struct t_dpacket *p = NULL;
	struct t_dpacket *a = NULL;
	struct t_dpacket *ds = NULL;
	struct t_dpacket *ds_recv = NULL;
	struct t_dpacket *pkeys = NULL;
	struct t_rr *nsrr = NULL;
	struct t_rr *authsec = NULL;
	struct t_rr *dsrr = NULL;
	struct t_rr *keys = NULL;
	struct t_rr *dss = NULL;
	struct t_rr *rrsig = NULL;
	struct t_rr *answer = NULL;
	struct t_rdata *current_zone;
	unsigned int secure = 1;
	uint8_t label_count;
	
	/* prepare the query packet */
	p = dpacket_create();
	dpacket_add_rr(q, SEC_QUESTION, p);
	SET_DNSSEC(p);
	if (protocol == PROTO_UDP)
		SET_UDPSIZE(p, drill_opt->bufsize);

	if (print) print_packet_dense(p);

	nsrr 	= root_servers;
	current_zone = rdata_create((uint8_t *) "",0);

	while (dpacket_type((a = send_packet(p, nsrr, protocol, NULL))) == PKT_REFERRAL) {

		if (print) { 
			print_packet_dense(a);
			printf("\n");
		}

		if (secure == 1) {
			/* Try the get a set of keys from the
			 * current nameserver */
			mesg("%s %s", "Asking DNSKEY for", rdata2str(current_zone));
			pkeys = do_query(current_zone ,TYPE_DNSKEY, nsrr, protocol);
			if (pkeys) {
				keys = dpacket_get_rrset(current_zone, TYPE_DNSKEY, pkeys, SEC_ANSWER);
				if (keys) {
					prettyprint_rr(keys, FOLLOW, NO_COMMENT, NO_LONG);

					rrsig = dpacket_get_rrsig(keys, pkeys);			
					if (rrsig) {
						prettyprint_rr(rrsig, FOLLOW, NO_COMMENT, NO_LONG);
						/* try to validate */
						if (verify_rrsig(keys, rrsig, keys) == RET_SUC)
							mesg("The signature of the key validated");
					}
					
					xfree(keys); keys = NULL;
				}
				xfree(pkeys); pkeys = NULL;
			}
		}

		/* get the a records of the ns in the packet */
		nsrr = dpacket_get_rrset(NULL, TYPE_A, a, SEC_ADD);
		
		/* get the auth servers here - for the referral name
		 * -> to get the DS */
		/* The can also live the in SEC_ANSWER...... */
		authsec = dpacket_get_rrset(NULL, TYPE_NS, a, SEC_AUTH);

		/* out of baliwick servers don't need glue 
		 * if there is no glue - we need to fetch the addresses
		 * of the nameserver ourselves */
		if (!nsrr) {
			mesg("%s", "fetching glue!");
			nsrr = get_ns_addresses(a, protocol, SEC_AUTH);
		}

		/* still nothing */
		if (!nsrr) 
			error("%s", "No glue found - giving up");
		
		if (secure == 1) {
			/* we're are secure, try to lookup DS records */
			/* a = received, is delegation, show name */
			/* does this delegation have a DS?? */
			if (!authsec) {
				warning("%s", ";; No auth section found - not doing DNSSEC!");
			} else {
				/* Try the get the parental DS for the
				 * child zone */
				ds = dpacket_create();
				dpacket_add_rr(rr_create(authsec->name, TYPE_DS, DEF_TTL, SEC_QUESTION),
						SEC_QUESTION, ds);
				/* ASK the DS to the current nameservers */	
				ds_recv = send_packet(ds, nsrr, protocol, NULL);

				mesg("%s %s\n", "Asking DS for", rdata2str(authsec->name));

				print_packet_dense(ds_recv);
				dsrr = dpacket_get_rrset(authsec->name, TYPE_DS, ds_recv, SEC_ANSWER);
				
				if (!dsrr) {
					mesg("%s", "No DS found...");
				} else {
					mesg("%s", "Yes a DS found...");
					rrsig = dpacket_get_rrsig(dsrr, ds_recv);			
					print_rr(dsrr, FOLLOW);
					if (rrsig)
						print_rr(rrsig, FOLLOW);

				}
			xfree(dsrr); dsrr = NULL;
			}
		}
		if (print) printf("\n");
		xfree(a); a = NULL;
		xfree(current_zone);
		current_zone = authsec->name;
	}

	a = send_packet(p, nsrr, protocol, NULL); /* last step */
	rrsig = NULL;
	/* we should now have our answer - could be NXDOMAIN - 
	 * no find the right DS's - we do this by label chopping:
	 * DS sub.sub.nl ; DS sub.nl; DS nl; DS .
	 */
	dss = rr_create(q->name, TYPE_DS, DEF_TTL, SEC_QUESTION);
	
	/* Also ask for DNSKEYs, this is needed if all these zones
	 * are served from 1 server - if so we won't reach this state via
	 * the referrals, but we just "get here"
	 */
	for (label_count = 0; label_count < label_cnt(q); ++label_count) {
		
		mesg("%s %s", "After querying for DS for", 
				rdata2str(chop_labels_left(dss, label_count)->name));

		mesg("%s %s", "After querying for DNSKEY for", 
				rdata2str(chop_labels_left(dss, label_count)->name));

		ds_recv = do_query_rr(chop_labels_left(dss, label_count),
				nsrr, protocol);
		
		pkeys   = do_query(chop_labels_left(dss, label_count)->name, TYPE_DNSKEY,
				nsrr, protocol);

		if (ds_recv)
			dsrr = dpacket_get_rrset((chop_labels_left(dss, label_count)->name), 
					TYPE_DS, ds_recv, SEC_ANSWER);
		
		if (pkeys)
			keys = dpacket_get_rrset((chop_labels_left(dss, label_count)->name),
					TYPE_DNSKEY, pkeys, SEC_ANSWER);
		if (keys) {
			prettyprint_rr(keys, FOLLOW, NO_COMMENT, NO_LONG);
			rrsig = dpacket_get_rrsig(keys, pkeys);
			if (rrsig)  {
				prettyprint_rr(rrsig, FOLLOW, NO_COMMENT, NO_LONG);
				if (verify_rrsig(keys, rrsig, keys) == RET_SUC) 
					mesg("The signature of the key validated");
				xfree(rrsig); rrsig = NULL;
			}
			xfree(keys); keys = NULL;
		}

		if (dsrr)  {
			rrsig = dpacket_get_rrsig(dsrr, ds_recv);			
			prettyprint_rr(dsrr, FOLLOW, NO_COMMENT, NO_LONG);
			if (rrsig)  {
				prettyprint_rr(rrsig, FOLLOW, NO_COMMENT, NO_LONG);
				xfree(rrsig); rrsig = NULL;
			}
			xfree(dsrr); dsrr = NULL;
			printf("\n");
		}
		xfree(pkeys); pkeys = NULL;
		xfree(ds_recv); ds_recv = NULL;
			
	}

	if (a) {
		if (print) {
			print_packet_dense(a);
			printf("\n");
		}
		/* look in the answer section?? */
		/* this is dangerous 'cause I don't know what I'm looking
		 * for. Think cname etc.
		 */
		answer = dpacket_get_rrset(q->name, q->type, a, SEC_ANSWER);
		if (answer) {
			prettyprint_rr(answer, FOLLOW, NO_COMMENT, NO_LONG);
			rrsig = dpacket_get_rrsig(answer, a);
		}
		if (rrsig) 
			prettyprint_rr(rrsig, FOLLOW, NO_COMMENT, NO_LONG);
		else 
			verbose("No signature found");
		return(answer);
		/* get the SIG */
	} else {
		warning("%s", "Empty response\n");
		return NULL;
	}
}
