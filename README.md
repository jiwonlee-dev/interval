# Interval BE [Lin10]

Usage: ./interval option

option:

setup - setup msk_out_filename

	ex: ./interval setup sample_msk.key

keygen - keygen id msk_in_filename dk_out_filename

	ex: ./interval keygen 3 sample_msk.key sample_deckey.key

encrypt - encrypt msg_filename interval_left interval_right hdr_out_filename

	ex: ./interval encrypt sample_msg.dat 1 5 sample_hdr.dat

decrypt - decrypt hdr_in_filename dk_in_filename interval_left interval_right id msg_out_filename

	ex: ./interval decrypt sample_hdr.dat sample_deckey.key 1 5 3 sample_msg.dat

