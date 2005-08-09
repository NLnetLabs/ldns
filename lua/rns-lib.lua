-- ldns defines
LDNS_SECTION_QUESTION 		= 0
LDNS_SECTION_ANSWER 		= 1
LDNS_SECTION_AUTHORITY 		= 2
LDNS_SECTION_ADDITIONAL 	= 3
LDNS_SECTION_ANY 		= 4
LDNS_SECTION_ANY_NOQUESTION 	= 5

-- dofile (filename)
-- swap 2 rrs in a pkt --
function lua_transpose_rr(pkt, n1, n2)
	print("[info] [RR] transpose", n1, n2)
	local rr_n1 = l_pkt_get_rr(pkt, n1)
	local rr_n2 = l_pkt_set_rr(pkt, rr_n1, n2)
	local rr_tm = l_pkt_set_rr(pkt, rr_n2, n1)
	-- rm_tm is mem leak atm -- need free functions of ldns
end

function lua_transpose_rr_random(pkt)
	local total = l_pkt_rr_count(pkt) - 1
	local rn1 = math.random(0, total)
	local rn2 = math.random(0, total)
	lua_swap_rr(pkt, rn1, rn2)
end

-- substiture, add, remove

---------------------------------
-- these are more higher level --
---------------------------------

-- reverse all the rrs in a pkt --
function lua_reverse_pkt(pkt)
	local total = l_pkt_rr_count(pkt) - 1
	for i=0, (total / 2) do
		lua_swap_rr(pkt, i, total - i)
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
