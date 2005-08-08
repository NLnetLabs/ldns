-- ldns defines

LDNS_SECTION_QUESTION 		= 0
LDNS_SECTION_ANSWER 		= 1
LDNS_SECTION_AUTHORITY 		= 2
LDNS_SECTION_ADDITIONAL 	= 3
LDNS_SECTION_ANY 		= 4
LDNS_SECTION_ANY_NOQUESTION 	= 5

-- swap 2 rrs in a pkt --
function lua_swap_rr (pkt, n1, n2)

	local rr_n1 = l_pkt_get_rr(pkt, n1)
	local rr_n2 = l_pkt_set_rr(pkt, rr_n1, n2)
	local rr_tm = l_pkt_set_rr(pkt, rr_n2, n1)

	-- rm_tm is mem leak atm -- need free functions of ldns
end


-- reverse all the rrs in a pkt --
function lua_reverse_pkt (pkt)
	local total
	
	total = l_pkt_rr_count(pkt) - 1;
	local j = total / 2

	for i=0, (total / 2) do
		print(i, total - i)
		lua_swap_rr(pkt, i, total - i)
	end

end

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
