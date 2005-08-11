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

-- make rdf with an ip
rdf_ip = l_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
-- connect and bind to a server udp socket
socket = l_server_socket_udp(rdf_ip, 5353)
--
-- read from the socket
wirebuf = l_read_wire_udp(socket)
--lua_debug("what I read")
-- close the socket
l_server_socket_close_udp(socket)
-- convert the packet


	lua_debug("I shouldn't be here")
	wirepkt = l_buf2pkt(wirebuf)
	-- print the packet
	l_pkt_print(wirepkt)
lua_debug("The end")
