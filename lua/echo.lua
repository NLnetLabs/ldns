-- source the lib file with the function
dofile("rns-lib.lua")

-- echo whatever is received

-- this function disfigures the packet
function lua_packet_mangle(orig_packet)
--	Dont do anything just mirror
--	local rr1 = record.new_frm_str("www.miek.nl IN A 127.0.0.1")
--	packet.push_rr(orig_packet, LDNS_SECTION_ANSWER, rr1)
	return(packet.to_buf(orig_packet))
end

rdf_ip = rdf.new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1")
socket = udp.server_open(rdf_ip, 5353)
if socket == nil then
	os.exit(EXIT_FAILURE)
end

rdf_ip_nameserver = rdf.new_frm_str(LDNS_RDF_TYPE_A, "213.154.224.39")

while true do
	-- read from the socket, this blocks...
	wirebuf, sockaddr_from  = udp.read(socket)

	-- wrap this in new functions
	if wirebuf == nil then
		lua_debug("nothing received")
	else
		-- somebody is writing
		wirepkt = buffer.to_pkt(wirebuf)
		packet.print(wirepkt)

		wirebuf2 = packet.to_buf(wirepkt)

		-- send it to /our/ nameserver
		socket_nameserver = udp.open(rdf_ip_nameserver, 53)
		if socket_nameserver == nil then
			os.exit(EXIT_FAILURE)
		end

		nameserver_bytes = udp.write(socket_nameserver, wirebuf2, rdf_ip_nameserver, 53)
		if nameserver_bytes == nil then
			lua_debug("ns write error")
		end

		nameserver_buf, sockaddr_from_nameserver  = udp.read(socket_nameserver)
		udp.close(socket_nameserver)

		nameserver_pkt = buffer.to_pkt(nameserver_buf)
		packet.print(nameserver_pkt)
		
		-- make a new buf and write that back to the client
		nsbuf2 = lua_packet_mangle(nameserver_pkt)
		bytes = lua_udp_write(socket, nsbuf2, sockaddr_from) --this works

		if bytes == nil then
			lua_debug("write error")
		end

		buffer.free(nsbuf2)
		buffer.free(nameserver_buf)
		buffer.free(wirebuf2)
		buffer.free(wirebuf)
		
	end
end
udp.close(socket)
