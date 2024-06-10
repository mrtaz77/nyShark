import socket, struct, textwrap

def unpack_ethernet_frame(data):
	"""
	! — is used to specify it is Network Data. 
		Network Data is represented in Big-Endian
		while the Host Data is represented in Little-Endian format, 
		given the Host's CPU is Intel
	6s — to specify 6 continuous bytes of dest_mac_addr
	6s — to specify 6 continuous bytes of src_mac_addr
	H — to specify 2 bytes as Type
	The s, H here are format characters.
	We passed Raw_Data only till the 14th byte with data[:14]. From data[14:] is our actual payload. 
	"""
	dest_mac_addr, src_mac_addr, ethernet_protocol = struct.unpack('! 6s 6s H', data[:14])
	return dest_mac_addr, src_mac_addr, ethernet_protocol



