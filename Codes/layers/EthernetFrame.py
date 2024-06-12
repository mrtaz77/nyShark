from layers.Layer import Layer
from layers.IPv4Packet import IPv4Packet
from layers.Protocol import Protocol
from formatting import indent
from artwork import CYAN
import struct

class EthernetFrame(Layer):
	ETHERNET_FRAME_DATA_OFFSET = 14

	def __init__(self):
		self.counter = 0

	def unpack(self, data):
		self.counter += 1
		"""
		! — is used to specify it is Network Data. 
			Network Data is represented in Big-Endian
			while the Host Data is represented in Little-Endian format, 
			given the Host's CPU is Intel
		6s — to specify 6 continuous bytes of dst_mac_addr
		6s — to specify 6 continuous bytes of src_mac_addr
		H — to specify 2 bytes as Type
		The s, H here are format characters.
		We passed Raw_Data only till the 14th byte with data[:14]. From data[14:] is our actual payload. 
		"""
		dst_mac_addr_bytes, src_mac_addr_bytes, self.protocol_type = struct.unpack('! 6s 6s H', data[:EthernetFrame.ETHERNET_FRAME_DATA_OFFSET])
		self.adapt(dst_mac_addr_bytes, src_mac_addr_bytes)

		self.decide_next_layer()
		
		if self.next_layer:
			self.next_layer.unpack(data[EthernetFrame.ETHERNET_FRAME_DATA_OFFSET:])

	def decide_next_layer(self):
		if self.protocol_type == Protocol['IPv4'].value:
			self.setNext(IPv4Packet())

	def adapt(self, dst_mac_addr_bytes, src_mac_addr_bytes):
		self.dst_mac = self.get_mac_address(dst_mac_addr_bytes)
		self.src_mac = self.get_mac_address(src_mac_addr_bytes)

	def get_mac_address(self, mac_addr_bytes):
		mac_addr = map('{:02x}'.format, mac_addr_bytes)
		return (':'.join(mac_addr)).upper()

	def show(self):
		print(CYAN + '\nEthernet frame {}'.format(self.counter))
		print(indent(1)+'Destination: {}, Source: {}, Protocol: {}'.format(self.dst_mac, self.src_mac, Protocol(self.protocol_type).name))
		if self.next_layer:
			self.next_layer.show()