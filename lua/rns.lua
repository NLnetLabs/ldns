-- source the lib file with the function
dofile("rns-lib.lua")

rr1 = record.new_frm_str("www.miek.nl  IN A 192.168.1.2", 0, nil)
rr2 = record.new_frm_str("miek.nl  IN ns gaap", 0, nil)
rr3 = record.new_frm_str("miek.nl  IN ns gaap2", 0, nil)
rr4 = record.new_frm_str("www.atoom.net. IN A 192.168.1.2", 0, nil)
rr5 = record.new_frm_str("www.nlnetlabs.nl IN A 192.168.1.2", 0, nil)
rr6 = record.new_frm_str("www.nlnet.nl IN A 192.168.1.2", 0, nil)

pkt = packet.new()
pkt = packet.push_rr(pkt, LDNS_SECTION_ANSWER, rr1)
pkt = packet.push_rr(pkt, LDNS_SECTION_ANSWER, rr4)
pkt = packet.push_rr(pkt, LDNS_SECTION_AUTHORITY, rr2)
pkt = packet.push_rr(pkt, LDNS_SECTION_AUTHORITY, rr3)

---- Setup a server to listen to UDP
-- make rdf with an ip
rdf_ip = rdf.new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
-- connect and bind to a server udp socket
socket = l_server_socket_udp(rdf_ip, 5353)

-- read from the socket, this blocks...
-- in what order
wirebuf, sockaddr_from, fromlen  = l_read_wire_udp(socket)

if wirebuf == nil then
	lua_debug("nothing received")
else
	-- somebody is listening
	wirepkt = buffer.to_pkt(wirebuf)

	lua_debug("received from the interface")

	id = packet.id(wirepkt);
	packet.print(wirepkt)

	-- set the id on the outgoing packet
	packet.set_id(pkt, id)
	wirebuf2 = packet.to_buf(pkt)

	rdf_listen, port_listen = rdf.sockaddr_to_rdf(sockaddr_from)

	bytes = l_write_wire_udp(socket, wirebuf2, rdf_listen, port_listen);
	lua_debug("wrote bytes", bytes)
	packet.print(pkt)
	
end

-- close the socket
l_server_socket_close_udp(socket)
