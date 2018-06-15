# Interval BE [Lin10]
Usage: ./interval option

option:

setup - s msk_out_filename
	ex: ./interval s sample_msk.key

keygen - k id msk_in_filename dk_out_filename
	ex: ./interval k 3 sample_msk.key sample_deckey.key

encrypt - e msg_filename interval_left interval_right hdr_out_filename
	ex: ./interval e sample_msg.dat 1 5 sample_hdr.dat

decrypt - d hdr_in_filename dk_in_filename id interval_left interval_right msg_out_filename
	ex: ./interval d sample_hdr.dat sample_deckey.key 3 1 5 sample_msg.dat

Note: Setup is initially required for other phases.

