-- source the lib file with the function
dofile("rns-lib.lua")

-- Now the scary ldns_* stuff
my_rr = record.new_frm_str("www.miek.nl  IN A 192.168.1.2")
my_rr2 = record.new_frm_str("www.miek.nl")
my_rr4 = record.new_frm_str("www.atoom.net. IN A 192.168.1.2")

record.print(my_rr)
record.print(my_rr2)
record.print(my_rr4)

my_pkt = packet.new();

my_pkt = packet.push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr)

packet.print(my_pkt)

my_pkt = packet.push_rr(my_pkt, LDNS_SECTION_ANSWER, my_rr2)

my_rr3 = packet.get_rr(my_pkt, 0);
record.print(my_rr3)
my_rr3 = packet.get_rr(my_pkt, 1);
record.print(my_rr3)

packet.print(my_pkt)
my_rr5 = packet.set_rr(my_pkt, my_rr4, 1)
record.print(my_rr5)

packet.set_id(my_pkt, 1505)

packet.print(my_pkt)
