from abc import ABC, abstractmethod

class Layer(ABC):
	def __init__(self):
		self.next_layer = None

	@abstractmethod
	def unpack(self, data):
		pass
	
	def setNext(self, layer):
		self.next_layer = layer
	
	@abstractmethod
	def show(self):
		pass