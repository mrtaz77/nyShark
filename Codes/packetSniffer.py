from layers.EthernetFrame import EthernetFrame
from artwork import *
import socket
from scapy.utils import PcapWriter
from scapy.all import Ether
import os

BUFFER_SIZE = 65536

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

def sniff():
	conn = init_connection()
	script_directory = os.path.dirname(os.path.abspath(__file__))
	pcap_file_path = os.path.join(script_directory, "output.pcap")
	pcap_writer = PcapWriter(pcap_file_path, append=True, sync=True)
	layer = EthernetFrame()
	try:
		while True:
			raw_data, address = conn.recvfrom(BUFFER_SIZE)
			pcap_writer.write(Ether(raw_data))
			layer.unpack(raw_data)
			layer.show()
	except KeyboardInterrupt:
		conn.close()

if __name__ == '__main__':
	init()
	nyShark_artwork()
	sniff()