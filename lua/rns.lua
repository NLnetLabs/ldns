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

---- Setup a server to listen to UDP -- bit strange to first
-- make a rdf out of it and then continue with the sockaddr struct
rdf_ip = rdf.new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
socket = udp.server_open(rdf_ip, 5353)
if socket == nil then
        os.exit(EXIT_FAILURE)
end


while true do
	-- read from the socket, this blocks...
	wirebuf, sockaddr_from  = udp.read(socket)

	-- wrap this in new functions
	if wirebuf == nil then
		lua_debug("nothing received")
	else
		-- somebody is writing
		wirepkt = buffer.to_pkt(wirebuf)

		lua_debug("received from the interface")

		-- next we must send it to our recursive nameserver
		-- and pick up the result
		-- then we modify the result somewhat and sent it back
		-- to the client

		id = packet.id(wirepkt);
		packet.print(wirepkt)

		-- set the id on the outgoing packet
		packet.set_id(pkt, id)
		lua_packet_ancount_incr(pkt, 2)
		wirebuf2 = packet.to_buf(pkt)

		-- write back to the client
		bytes = lua_udp_write(socket, wirebuf2, sockaddr_from)
		if bytes == -1 then
			lua_debug("write error")
		else 
			lua_debug("wrote bytes", bytes)
			packet.print(pkt)
		end
		
	end
end
udp.close(socket)
