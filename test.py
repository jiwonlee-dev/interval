import os

print "setup start: "
os.system("./interval setup sample_msk.key")

print "keygen start: "
os.system("./interval keygen 3 sample_msk.key sample_dk.key")

print "message(Hello World!) created."
msgfile = open("sample_msg.in", "w")
msgfile.write("Hello World!")
msgfile.close()

print "encrypt(with interval: 1-5) start: "
os.system("./interval encrypt sample_msg.in 1 5 sample_hdr.dat")

print "decrypt(with id: 3) start: "
os.system("./interval decrypt sample_hdr.dat sample_dk.key 1 5 3 sample_msg.out")

print "decrypted message: "
os.system("cat sample_msg.out")
print "\n"

print "sets(1-5, 7-10, 14-15) created."
setfile = open("sample_sets.in", "w")
setfile.write("3\n")
setfile.write("1-5\n")
setfile.write("7-10\n")
setfile.write("14-15\n")
setfile.close()

print "broadcast(with sets) start: "
os.system("./interval broadcast sample_msg.in sample_sets.in sample_hdrlist.dat")

print "receive(with id: 3) start: "
os.system("./interval receive sample_hdrlist.dat sample_dk.key 3 sample_msg.out")

print "decrypted message: "
os.system("cat sample_msg.out")
print "\n"

#remove all
os.system("rm publickey.key")
os.system("rm sample_msk.key")
os.system("rm sample_dk.key")
os.system("rm sample_msg.in")
os.system("rm sample_hdr.dat")
os.system("rm sample_msg.out")
os.system("rm sample_sets.in")
os.system("rm sample_hdrlist.dat")
