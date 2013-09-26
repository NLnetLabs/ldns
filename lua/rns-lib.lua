-- ldns defines - need a better way to keep these current
LDNS_SECTION_QUESTION 		= 0
LDNS_SECTION_ANSWER 		= 1
LDNS_SECTION_AUTHORITY 		= 2
LDNS_SECTION_ADDITIONAL 	= 3
LDNS_SECTION_ANY 		= 4
LDNS_SECTION_ANY_NOQUESTION 	= 5

-- rdf types
LDNS_RDF_TYPE_NONE		= 0
LDNS_RDF_TYPE_DNAME		= 1
LDNS_RDF_TYPE_INT8		= 1
LDNS_RDF_TYPE_INT16		= 3
LDNS_RDF_TYPE_INT32		= 4
LDNS_RDF_TYPE_A			= 5
LDNS_RDF_TYPE_AAAA		= 6
LDNS_RDF_TYPE_STR		= 7
LDNS_RDF_TYPE_APL		= 8
LDNS_RDF_TYPE_B32_EXT		= 9
LDNS_RDF_TYPE_B64		= 10
LDNS_RDF_TYPE_HEX		= 11
LDNS_RDF_TYPE_NSEC		= 12
LDNS_RDF_TYPE_TYPE		= 13
LDNS_RDF_TYPE_CLASS		= 14
LDNS_RDF_TYPE_CERT		= 15
LDNS_RDF_TYPE_ALG		= 16
LDNS_RDF_TYPE_UNKNOWN		= 17
LDNS_RDF_TYPE_TIME		= 18
LDNS_RDF_TYPE_PERIOD		= 19
LDNS_RDF_TYPE_TSIGTIME		= 20
LDNS_RDF_TYPE_HIP		= 21
LDNS_RDF_TYPE_INT16_DATA	= 22
LDNS_RDF_TYPE_SERVICE		= 23
LDNS_RDF_TYPE_LOC		= 24
LDNS_RDF_TYPE_WKS		= 25
LDNS_RDF_TYPE_NSAP		= 26
LDNS_RDF_TYPE_ATMA		= 27
LDNS_RDF_TYPE_IPSECKEY		= 28

function lua_debug(...)
	print("[lua]", unpack(arg))
end

-- transpose 2 rrs in a pkt --
function lua_record_transpose(pkt, n1, n2)
	print("[info] [RR] transpose", n1, n2)
	local rr_n1 = packet.get_rr(pkt, n1)
	local rr_n2 = packet.set_rr(pkt, rr_n1, n2)
	local rr_tm = packet.set_rr(pkt, rr_n2, n1)
	record.free(rm_tm)
end

-- _R := random
function lua_record_transpose_R(pkt)
	local total = packet.rrcount(pkt) - 1
	local rn1 = math.random(0, total)
	local rn2 = math.random(0, total)
	lua_transpose_record(pkt, rn1, rn2)
end

-- substitute, add, remove
function lua_record_insert(pkt, r, n)
	print("[info] [RR] insert after", n)
	packet.insert_rr(pkt, r, n)
end

-- add an rr to the end of a pkt --
-- _E := end
function lua_record_insert_E(pkt, r)
	local n = packet.rrcount(pkt) - 1
	print(n)
	lua_insert_rr(pkt, r, n)
end

-- remove an rr from the end of a pkt --
--pop??
function lua_record_remove_E(pkt, n)
	print("[info] [RR] remove", "end")
end

-- increment the ancount
function lua_packet_ancount_incr(pkt, n)
	print("[info] [PKT] ancount incr", n)
	an = packet.ancount(pkt)
	n = an + n
	packet.set_ancount(pkt, n)
end

---------------------------------
-- higher level                --
---------------------------------

-- reverse all the rrs in a pkt --
function lua_packet_reverse(pkt)
	local total = packet.rrcount(pkt) - 1
	for i=0, (total / 2) do
		lua_transpose_rr(pkt, i, total - i)
	end
end

-- write a buffer to a socket
function lua_udp_write(socket, buffer_wire, sock_from)
	-- convert the sockaddr_storage to something we
	-- can work with
	
	-- checks
	if socket == 0 then return -1 end
	if buffer_wire == nil then return -1 end
	if sock_from == nil then return -1 end
	
	rdf_listen, port_listen = rdf.sockaddr_to_rdf(sock_from)

	bytes = udp.write(socket, buffer_wire, rdf_listen, port_listen) 
	return bytes
end


-- initialize the pseudo random number generator
-- frm: http://lua-users.org/wiki/MathLibraryTutorial
function lua_rand_init() 
	math.randomseed(os.time())
	math.random()
	math.random()
	math.random()
end
lua_rand_init()
