from layers.Layer import Layer
from layers.Data import Data
from formatting import *
from artwork import YELLOW
import struct

class TcpSegment(Layer):
	def __init__(self):
		self.setNext(Data())

	def unpack(self, data):
		'''
		The struct.unpack format string ! H H L L H is used to extract the first 14 bytes of the TCP packet:
		src_port: 2 bytes (source port number)
		dst_port: 2 bytes (destination port number)
		seq: 4 bytes (sequence number)
		ack: 4 bytes (acknowledgment number)
		offset_reserved_flags: 2 bytes (data offset, reserved bits, and flags)
		'''
		self.src_port, self.dst_port, self.seq, self.ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
		'''
		The data offset specifies the size of the TCP header in 32-bit words.
		To get the size in bytes, multiply the offset by 4.
		The offset is stored in the high 4 bits of the offset_reserved_flags field.
		'''
		self.offset = (offset_reserved_flags >> 12) << 2
		'''
		The last 6 bits of the offset_reserved_flags field are used for TCP flags.
		Extract the flags by masking out the offset and reserved bits.
		Each flag is represented by a single bit, and they are extracted individually.
		'''
		flags = offset_reserved_flags & 0x3f
		self.tcp_flags = {
			'Urgent': (flags >> 5) & 0x1,
			'Acknowledgement': (flags >> 4) & 0x1,
			'Push': (flags >> 3) & 0x1,
			'Reset': (flags >> 2) & 0x1,
			'Syn': (flags >> 1) & 0x1,
			'Fin': flags & 0x1
		}

		if self.next_layer:
			self.next_layer.unpack(data[self.offset:])

	def show_flags(self):
		i = 1
		n = len(self.tcp_flags.items())
		print(indent(3,EXPANDED) + 'Flags:')
		for flag_name, flag_value in self.tcp_flags.items():
			flag = dots(i - 1) + str(flag_value) + dots(n - i) + " = " + flag_name + ": "
			if flag_value:
				flag += "Set"
			else:
				flag += "Not set"
			print(data_indent(4) + flag)
			i += 1

	def show(self):
		print(YELLOW + indent(2,EXPANDED) + 'TCP Segment:')
		print(indent(3) + 'Src Port: {}, Dst Port: {}'.format(self.src_port, self.dst_port))
		print(indent(3) + 'Sequence: {}, Acknowledgement: {}, Offset: {}'.format(self.seq, self.ack, self.offset))
		self.show_flags()
		if self.next_layer:
			self.next_layer.show()