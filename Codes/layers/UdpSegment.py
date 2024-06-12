from layers.Layer import Layer
from layers.Data import Data
from formatting import *
from artwork import YELLOW
import struct

class UdpSegment(Layer):
	UDP_OFFSET = 8

	def __init__(self):
		self.setNext(Data())

	def unpack(self, data):
		'''! - Network byte order (big-endian)
		H - Unsigned short (2 bytes)
		Unpacking the data[:8] extracts:
		- src_port: Source port (2 bytes)
		- dst_port: Destination port (2 bytes)
		- length: Length of the UDP segment (2 bytes)
		- checksum: Checksum (2 bytes)
		'''
		self.src_port, self.dst_port, self.length, self.checksum = struct.unpack('! H H H H', data[:UdpSegment.UDP_OFFSET])
	
		if self.next_layer:
			self.next_layer.unpack(data[UdpSegment.UDP_OFFSET:])

	def show(self):
		print(YELLOW + indent(2,EXPANDED) + 'UDP Segment:')
		print(indent(3) + 'Src Port: {}, Dst Port: {}'.format(self.src_port, self.dst_port))
		print(indent(3) + 'Length: {}, Checksum: {}'.format(self.length, self.checksum))
		if self.next_layer:
			self.next_layer.show()