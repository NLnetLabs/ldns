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
LDNS_RDF_TYPE_B64		= 9
LDNS_RDF_TYPE_HEX		= 10
LDNS_RDF_TYPE_NSEC		= 11
LDNS_RDF_TYPE_TYPE		= 12
LDNS_RDF_TYPE_CLASS		= 13
LDNS_RDF_TYPE_CERT		= 14
LDNS_RDF_TYPE_ALG		= 15
LDNS_RDF_TYPE_UNKNOWN		= 16
LDNS_RDF_TYPE_TIME		= 17
LDNS_RDF_TYPE_PERIOD		= 18
LDNS_RDF_TYPE_TSIGTIME		= 19
LDNS_RDF_TYPE_TSIG		= 20
LDNS_RDF_TYPE_INT16_DATA	= 21
LDNS_RDF_TYPE_SERVICE		= 22
LDNS_RDF_TYPE_LOC		= 23
LDNS_RDF_TYPE_WKS		= 24
LDNS_RDF_TYPE_NSA		= 25
LDNS_RDF_TYPE_IPSECKEY		= 26


function lua_debug(msg)
	print("[lua]", msg)
end

-- transpose 2 rrs in a pkt --
function lua_transpose_rr(pkt, n1, n2)
	print("[info] [RR] transpose", n1, n2)
	local rr_n1 = l_pkt_get_rr(pkt, n1)
	local rr_n2 = l_pkt_set_rr(pkt, rr_n1, n2)
	local rr_tm = l_pkt_set_rr(pkt, rr_n2, n1)
	l_rr_free(rm_tm)
end

function lua_transpose_rr_random(pkt)
	local total = l_pkt_rr_count(pkt) - 1
	local rn1 = math.random(0, total)
	local rn2 = math.random(0, total)
	lua_transpose_rr(pkt, rn1, rn2)
end

-- substitute, add, remove
function lua_insert_rr(pkt, r, n)
	print("[info] [RR] insert after", n)
	l_pkt_insert_rr(pkt, r, n)
end

-- add an rr to the end of a pkt --
function lua_insert_end_rr(pkt, r)
	local n = l_pkt_rr_count(pkt) - 1
	print(n)
	lua_insert_rr(pkt, r, n)
end

-- remove an rr from the end of a pkt --
function lua_remove_rr(pkt, n)
	print("[info] [RR] remove", "end")
end

-- convert a ldns_buffer to a string in lua
function lua_buf_to_string(buf)
end

---------------------------------
-- higher level                --
---------------------------------

-- reverse all the rrs in a pkt --
function lua_reverse_pkt(pkt)
	local total = l_pkt_rr_count(pkt) - 1
	for i=0, (total / 2) do
		lua_transpose_rr(pkt, i, total - i)
	end
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
