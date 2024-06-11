import socket, struct, textwrap
import pyuac

RECEIVER_PORT = 65535

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
	This line gets the IP address of the local machine.
	socket.gethostname() retrieves the hostname of the local machine.
	socket.gethostbyname() converts the hostname to its corresponding IP address.
	HOST will hold the local IP address.
	'''
	HOST = socket.gethostbyname(socket.gethostname())
	'''
	This creates a raw socket.
	socket.AF_INET specifies the address family for IPv4.
	socket.SOCK_RAW specifies that this is a raw socket, allowing for low-level network packet access.
	'''
	conn = socket.socket(socket.AF_INET, socket.SOCK_RAW)
	'''
	This binds the raw socket to the local IP address (HOST) and an arbitrary port number (0).
	Binding to port 0 tells the operating system to choose an arbitrary available port.
	'''
	conn.bind((HOST, 0))
	'''
	This uses the ioctl (input/output control) method to enable promiscuous mode on the socket.
	socket.SIO_RCVALL is a socket I/O control code specific to Windows that enables a socket to receive all packets.
	socket.RCVALL_ON is the flag to turn on promiscuous mode.
	In promiscuous mode, the network interface card (NIC) captures all packets on the network, regardless of their destination.
	NOTE : Creating raw sockets and enabling promiscuous mode typically requires elevated permissions (administrator or root access).
	'''
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)	
	'''
	Summary : Get local IP-addr > create raw socket for IPv4 > Bind to local IP on any port > enable promiscuous mode
	'''
	return conn

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
	print('\nEthernet frame')
	print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_protocol))

def pyuac_run_as_admin():
	if not pyuac.isUserAdmin():
		print("Re-launching as admin using pyuac!")
		pyuac.runAsAdmin()
	else: 
		run()  # Already an admin here.

if __name__ == '__main__':
	pyuac_run_as_admin()