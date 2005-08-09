-- ldns defines
LDNS_SECTION_QUESTION 		= 0
LDNS_SECTION_ANSWER 		= 1
LDNS_SECTION_AUTHORITY 		= 2
LDNS_SECTION_ADDITIONAL 	= 3
LDNS_SECTION_ANY 		= 4
LDNS_SECTION_ANY_NOQUESTION 	= 5

-- dofile (filename)
-- swap 2 rrs in a pkt --
function lua_swap_rr(pkt, n1, n2)
	print("[info] [RR] swapping", n1, n2)
	local rr_n1 = l_pkt_get_rr(pkt, n1)
	local rr_n2 = l_pkt_set_rr(pkt, rr_n1, n2)
	local rr_tm = l_pkt_set_rr(pkt, rr_n2, n1)
	-- rm_tm is mem leak atm -- need free functions of ldns
end

function lua_swap_rr_random(pkt)
	local total = l_pkt_rr_count(pkt) - 1
	local rn1 = math.random(0, total)
	local rn2 = math.random(0, total)
	lua_swap_rr(pkt, rn1, rn2)
end

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

rr1 = l_rr_new_frm_str("www.miek.nl  IN A 192.168.1.2")
rr2 = l_rr_new_frm_str("miek.nl  IN ns gaap")
rr3 = l_rr_new_frm_str("miek.nl  IN ns gaap2")
rr4 = l_rr_new_frm_str("www.atoom.net. IN A 192.168.1.2")

pkt = l_pkt_new()
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, rr1)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, rr4)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, rr2)
pkt = l_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, rr3)

l_pkt_print(pkt)

lua_reverse_pkt(pkt)

l_pkt_print(pkt)

-- now do it at random
lua_swap_rr_random(pkt)

-- print again
l_pkt_print(pkt)
