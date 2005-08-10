-- test rdf stuff

dofile("rns-lib.lua")

rdf = l_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "miek.nl")
l_rdf_print(rdf)
print()
