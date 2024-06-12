import socket, struct, textwrap
from formatting import *

RECEIVER_PORT = 65535
COUNTER = 0

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

def unpack_ipv4_packet(data):
	'''
	In an IPv4 packet, the Internet Header Length (IHL) field specifies the length of the header. This field is a 4-bit value that represents the number of 32-bit words (4-byte blocks) in the header. Since each 32-bit word is 4 bytes, to get the header length in bytes, you multiply the IHL value by 4.
	'''
	version, header_length_in_bytes = data[0] >> 4, (data[0] & 0xf) * 4
	'''
	The struct.unpack format string ! 8x B B 2x 4s 4s is used to skip the first 8 bytes (for fields we don't need in this example) and then extract:
	ttl: 1 byte
	protocol: 1 byte
	Skip 2 bytes
	src: 4 bytes (source IP address)
	dst: 4 bytes (destination IP address)
	'''
	ttl, protocol, ipv4_src_bytes, ipv4_dest_bytes = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length_in_bytes, ttl, protocol, ipv4_src_bytes, ipv4_dest_bytes

def unpack_icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum

def unpack_tcp_packet(data):
	src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) << 2
	flags = offset_reserved_flags & 0x3f
	urg_flag = flags >> 5
	ack_flag = (flags & 0b010000) >> 4
	rst_flag = (flags & 0b001000) >> 3
	psh_flag = (flags & 0b000100) >> 2
	syn_flag = (flags & 0b000010) >> 1
	fin_flag = (flags & 0b000001)
	return src_port, dst_port, seq, ack, offset, urg_flag, ack_flag, rst_flag, psh_flag, syn_flag, fin_flag

def unpack_udp_packet(data):
	src_prt, dst_prt, length = struct.unpack('! H H H', data[:6])
	return src_prt, dst_prt, length

def get_data_from_icmp_packet(data):
	return data[4:]

def get_data_from_tcp_packet(data, offset):
	return data[offset:]

def get_ipv4_packet_from_ethernet_frame(data):
	return data[14:]

def get_data_from_ipv4_packet(data, header_length):
	return data[header_length:]

def get_data_from_udp_packet(data):
	return data[8:]

def convert_host_order_to_network_order(num):
	return socket.htons(num)

def get_mac_address(mac_addr_bytes):
	mac_addr = map('{:02x}'.format, mac_addr_bytes)
	return (':'.join(mac_addr)).upper()

def get_ipv4_address(ipv4_addr_bytes):
	return '.'.join(str, ipv4_addr_bytes)

def init_connection():
	'''
	- Creating the Socket:
		conn = socket.socket(...) initializes a new socket and assigns it to the variable conn.
	- Address Family (AF_PACKET):
		socket.AF_PACKET specifies that this socket will operate at the link layer, meaning it will handle raw Ethernet frames directly.
	- Socket Type (SOCK_RAW):
		socket.SOCK_RAW specifies that this socket will handle raw packets, providing access to the entire packet, including headers and payloads.
	- Protocol (ntohs(3)):
		socket.ntohs(3) specifies the protocol. 
		By using socket.ntohs, the protocol number is converted from network byte order to host byte order.
		The value 3 corresponds to ETH_P_ALL, meaning the socket will capture all Ethernet protocols.
	'''
	return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def packet_display_adapter(dest_mac_addr_bytes, src_mac_addr_bytes, host_order):
	return get_mac_address(dest_mac_addr_bytes), get_mac_address(src_mac_addr_bytes), convert_host_order_to_network_order(host_order)

def run():
	conn = init_connection()
	while True:
		raw_data, address = conn.recvfrom(RECEIVER_PORT)
		dest_mac_addr_bytes, src_mac_addr_bytes, host_order = unpack_ethernet_frame(raw_data)
		dest_mac, src_mac, eth_proto = packet_display_adapter(dest_mac_addr_bytes, src_mac_addr_bytes, host_order)
		display_packet(dest_mac, src_mac, eth_proto)
		ipv4_packet = get_ipv4_packet_from_ethernet_frame(raw_data)

def display_packet(dest_mac, src_mac, ethernet_protocol):
	global COUNTER
	COUNTER += 1
	print('\nEthernet frame {}'.format(COUNTER))
	print(indent(1)+'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_protocol))

def display_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if not size & 1:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
	run()