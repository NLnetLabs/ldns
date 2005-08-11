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

---- Setup a server to listen to UDP
-- make rdf with an ip
rdf_ip = l_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
-- connect and bind to a server udp socket
socket = l_server_socket_udp(rdf_ip, 5353)

-- read from the socket, this blocks...
-- in what order
wirebuf, sockaddr_from, fromlen  = l_read_wire_udp(socket)

print("From len", fromlen)
print("From len", wirebuf)
print("From len", sockaddr_from)

if wirebuf == nil then
	lua_debug("nothing received")
else
	-- somebody is listening
	wirepkt = l_buf2pkt(wirebuf)
	lua_debug("received from the interface")
	l_pkt_print(wirepkt)

	wirebuf2 = l_pkt2buf(pkt)
	bytes = l_write_wire_udp(socket, wirebuf2, rdf_ip, 5353);
	print("wrote bytes", bytes)
	l_pkt_print(pkt)
	
end

-- close the socket
l_server_socket_close_udp(socket)
