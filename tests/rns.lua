-- call a C function

avg, sum = l_average(10, 20, 30, 40, 50)

print("The average is ", avg)
print("The sum is ", sum)

-- Now the scary ldns_* stuff

my_rr = l_rr_new_frm_str("miek.nl")
