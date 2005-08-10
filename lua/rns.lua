-- source the lib file with the function
dofile("rns-lib.lua")

rr1 = l_rr_new_frm_str("www.miek.nl  IN A 192.168.1.2", 0, nil)
rr2 = l_rr_new_frm_str("miek.nl  IN ns gaap", 0, nil)
rr3 = l_rr_new_frm_str("miek.nl  IN ns gaap2", 0, nil)
rr4 = l_rr_new_frm_str("www.atoom.net. IN A 192.168.1.2", 0, nil)
rr5 = l_rr_new_frm_str("www.nlnetlabs.nl IN A 192.168.1.2", 0, nil)
rr6 = l_rr_new_frm_str("www.nlnet.nl IN A 192.168.1.2", 0, nil)

pkt = l_pkt_new()
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, rr1)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, rr4)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, rr2)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, rr3)

l_pkt_print(pkt)

lua_reverse_pkt(pkt)

l_pkt_print(pkt)

--lua_insert_end_rr(pkt, rr6)
lua_insert_rr(pkt, rr5, 3)
l_pkt_print(pkt)

-- l_pkt_print(pkt)

-- now do it at random
-- lua_transpose_rr_random(pkt)

-- print again
-- l_pkt_print(pkt)

-- spkt = l_pkt2string(pkt)

-- len = string.len(spkt)

-- print(len)

-- print(spkt)
-- print (string.byte(spkt,160))
