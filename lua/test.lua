-- source the lib file with the function
dofile("rns-lib.lua")

-- Now the scary ldns_* stuff
my_rr2 = l_rr_new_frm_str("www.miek.nl")
my_rr = l_rr_new_frm_str("www.miek.nl  IN A 192.168.1.2")
my_rr4 = l_rr_new_frm_str("www.atoom.net. IN A 192.168.1.2")

l_rr_print(my_rr)
l_rr_print(my_rr2)
l_rr_print(my_rr4)

my_pkt = l_pkt_new()

my_pkt = l_pkt_push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)

l_pkt_print(my_pkt)

my_pkt = l_pkt_push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr2)

my_rr3 = l_pkt_get_rr(my_pkt, 0);
l_rr_print(my_rr3)
my_rr3 = l_pkt_get_rr(my_pkt, 1);
l_rr_print(my_rr3)

l_pkt_print(my_pkt)
my_rr5 = l_pkt_set_rr(my_pkt, my_rr4, 1)
l_rr_print(my_rr5)

l_pkt_print(my_pkt)
