-- source the lib file with the function
dofile("rns-lib.lua")

-- echo whatever is received

pkt = packet.new()

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
		lua_debug("received from the nameserver")
		packet.print(nameserver_pkt)
if true then

		-- next we must send it to our recursive nameserver
		-- and pick up the result
		-- then we modify the result somewhat and sent it back
		-- to the client
		
		-- write back to the client
		-- This is fishy
		nsbuf2 = packet.to_buf(nameserver_pkt)
		bytes = lua_udp_write(socket, nsbuf2, sockaddr_from)
else
		bytes = lua_udp_write(socket, wirebuf2, sockaddr_from)
end
		if bytes == nil  then
			lua_debug("write error")
		else 
			lua_debug("wrote bytes", bytes)
			packet.print(pkt)
		end
		
	end
end
udp.close(socket)
