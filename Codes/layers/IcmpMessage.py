from layers.Layer import Layer
from layers.Data import Data
from formatting import *
from artwork import YELLOW
import struct

class IcmpMessage(Layer):
	ICMP_OFFSET = 4

	def __init__(self):
		self.setNext(Data())

	def unpack(self, data):
		'''
		The struct.unpack format string ! B B H is used to extract the first 4 bytes of the ICMP packet:
		icmp_type: 1 byte (specifies the ICMP message type)
		code: 1 byte (provides further information about the ICMP message type)
		checksum: 2 bytes (used for error-checking the ICMP header and data)
		'''
		self.icmp_type, self.code, self.checksum = struct.unpack('! B B H', data[:IcmpMessage.ICMP_OFFSET])

		if self.next_layer:
			self.next_layer.unpack(data[IcmpMessage.ICMP_OFFSET:])

	def show(self):
		print(YELLOW + indent(2,EXPANDED) + 'ICMP Message:')
		print(indent(3) + 'Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code, self.checksum))
		if self.next_layer:
			self.next_layer.show()