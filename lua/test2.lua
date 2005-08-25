-- source the lib file with the function
dofile("rns-lib.lua")

my_pkt = packet.new()

my_rdf = rdf.new_frm_str(LDNS_RDF_TYPE_DNAME, "miek.nl")
if my_rdf == nil then
	print("failure")
end
rdf.print(my_rdf)

my_rr = record.new_frm_str("www.miek.nl in a 192.168.1.1")
record.print(my_rr)

my_pkt = packet.new()
packet.push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)
packet.push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)
packet.push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)

lua_record_insert(my_pkt, my_rr, 2)

packet.print(my_pkt)
