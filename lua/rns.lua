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
rdf_ip = rdf.new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
socket = udp.open(rdf_ip, 5353)

-- read from the socket, this blocks...
wirebuf, sockaddr_from, fromlen  = udp_read(socket) -- this works
--wirebuf, sockaddr_from, fromlen  = udp.read(socket) -- this doesn't

-- wrap this in new functions
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
	lua_packet_ancount_incr(pkt, 2)
	wirebuf2 = packet.to_buf(pkt)

	bytes = lua_udp_write(socket, wirebuf2, sockaddr_from)
	if bytes == -1 then
		lua_debug("write error")
	else 
		lua_debug("wrote bytes", bytes)
		packet.print(pkt)
	end
	
end

udp.close(socket)
