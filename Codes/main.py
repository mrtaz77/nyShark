import socket, struct, textwrap
import pyuac

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
	dest_mac_addr_bytes, src_mac_addr_bytes, host_order = struct.unpack('! 6s 6s H', data[:14])
	return dest_mac_addr_bytes, src_mac_addr_bytes, host_order

def get_sent_data_from_ethernet_frame(data):
	return data[14:]

def convert_host_order_to_network_order(num):
	return socket.htons(num)

def get_mac_address(mac_addr_bytes):
	mac_addr = map('{:02x}'.format, mac_addr_bytes)
	return (':'.join(mac_addr)).upper()