-- ldns defines

LDNS_SECTION_QUESTION 		= 0
LDNS_SECTION_ANSWER 		= 1
LDNS_SECTION_AUTHORITY 		= 2
LDNS_SECTION_ADDITIONAL 	= 3
LDNS_SECTION_ANY 		= 4
LDNS_SECTION_ANY_NOQUESTION 	= 5

-- Now the scary ldns_* stuff

my_rr = l_rr_new_frm_str("www.miek.nl  IN A 192.168.1.2")
my_rr2 = l_rr_new_frm_str("www.miek.nl")

l_rr_print(my_rr)
l_rr_print(my_rr2)

my_pkt = l_pkt_new()

my_pkt = l_pkt_push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)

l_pkt_print(my_pkt)
