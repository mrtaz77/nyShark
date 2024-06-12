from layers.Layer import Layer
from formatting import indent, data_indent
from artwork import WHITE
import textwrap

class Data(Layer):
	def unpack(self, data):
		self.data = data
	
	def format_multiline_data(self, prefix, string, size=80):
		size -= len(prefix)
		if isinstance(string, bytes):
			string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
			if size % 2:
				size -= 1
		return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

	
	def show(self):
		print(WHITE + indent(2) + 'Data:')
		print(self.format_multiline_data(data_indent(3), self.data))