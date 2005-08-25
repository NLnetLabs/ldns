-- source the lib file with the function
dofile("rns-lib.lua")

my_pkt = packet.new()

my_rdf = rdf.new_frm_str(LDNS_RDF_TYPE_DNAME, "miek.nl")
if my_rdf == nil then
	print("failure")
end
rdf.print(my_rdf,"\n")
