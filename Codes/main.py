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

def run():
	conn = init_connection()
	while True:
		raw_data, address = conn.recvfrom(65536)
		dest_mac_addr_bytes, src_mac_addr_bytes, host_order = unpack_ethernet_frame(raw_data)
		dest_mac_addr = get_mac_address(dest_mac_addr_bytes)
		src_mac_addr = get_mac_address(src_mac_addr_bytes)
		ethernet_protocol = convert_host_order_to_network_order(host_order)
		display_packet(dest_mac_addr, src_mac_addr, ethernet_protocol)

def display_packet(dest_mac, src_mac, ethernet_protocol):
	print('\nEthernet frame')
	print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_protocol))

if __name__ == '__main__':
	if not pyuac.isUserAdmin():
		print("Re-launching as admin!")
		pyuac.runAsAdmin()
	else:        
		run()  # Already an admin here.