from layers.Layer import Layer
from layers.IcmpMessage import IcmpMessage
from layers.TcpSegment import TcpSegment
from layers.UdpSegment import UdpSegment
from layers.Protocol import Protocol
from formatting import *
from artwork import GREEN
import struct

class IPv4Packet(Layer):
	IPv4_PACKET_OFFSET = 20

	def unpack(self, data):
		'''
		In an IPv4 packet, the Internet Header Length (IHL) field specifies the length of the header.
		This field is a 4-bit value that represents the number of 32-bit words (4-byte blocks) in the header.
		Since each 32-bit word is 4 bytes, to get the header length in bytes, you multiply the IHL value by 4.
		'''
		self.version, self.header_length_in_bytes = data[0] >> 4, (data[0] & 0xf) * 4
		'''
		The struct.unpack format string ! 8x B B 2x 4s 4s is used to skip the first 8 bytes (for fields we don't need in this example) and then extract:
		ttl: 1 byte
		protocol: 1 byte
		Skip 2 bytes
		src: 4 bytes (source IP address)
		dst: 4 bytes (destination IP address)
		'''
		self.ttl, self.protocol, ipv4_src_bytes, ipv4_dst_bytes = struct.unpack('! 8x B B 2x 4s 4s', data[:IPv4Packet.IPv4_PACKET_OFFSET])
		self.adapt(ipv4_src_bytes, ipv4_dst_bytes)

		self.decide_next_layer()

		if self.next_layer:
			self.next_layer.unpack(data[self.header_length_in_bytes:])

	def decide_next_layer(self):
		if self.protocol == Protocol['ICMP'].value:
			self.setNext(IcmpMessage())
		elif self.protocol == Protocol['TCP'].value:
			self.setNext(TcpSegment())
		elif self.protocol == Protocol['UDP'].value:
			self.setNext(UdpSegment())

	def adapt(self, ipv4_src_bytes, ipv4_dst_bytes):
		self.src_addr = self.get_ipv4_address(ipv4_src_bytes)
		self.dst_addr = self.get_ipv4_address(ipv4_dst_bytes)

	def get_ipv4_address(self, ipv4_addr_bytes):
		return '.'.join(map(str, ipv4_addr_bytes))

	def show(self):
		print(GREEN + indent(1,EXPANDED) + 'IPv4 Packet:')
		print(indent(2) + 'Version: {}, Header Length: {}, TTL: {}'.format(self.version, self.header_length_in_bytes, self.ttl))
		print(indent(2) + 'Protocol: {}, Source: {}, Destination: {}'.format(Protocol(self.protocol).name, self.src_addr, self.dst_addr))
		if self.next_layer:
			self.next_layer.show()