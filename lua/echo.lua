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
		else 
			lua_debug("wrote %d bytes", nameserver_bytes)
		end

		nameserver_buf, sockaddr_from_nameserver  = udp.read(socket_nameserver)
		udp.close(socket_nameserver)

		nameserver_pkt = buffer.to_pkt(nameserver_buf)
		lua_debug("received from the nameserver")
		packet.print(nameserver_pkt)

		-- write back to the client
		-- This is fishy, why the new buf??
		nsbuf2 = packet.to_buf(nameserver_pkt)

		print("nsbuf2")
		buffer.info(nsbuf2)
		print("nameserver_buf")
		buffer.info(nameserver_buf)

		bytes = lua_udp_write(socket, nsbuf2, sockaddr_from) --this works
		--bytes = lua_udp_write(socket, nameserver_buf, sockaddr_from) ----this not
		--but is the above legal?? --

		if bytes == nil  then
			lua_debug("write error")
		end

		buffer.free(nsbuf2)
		buffer.free(nameserver_buf)
		buffer.free(wirebuf2)
		buffer.free(wirebuf)
		
	end
end
udp.close(socket)
