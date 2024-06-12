from abc import ABC, abstractmethod

class Layer(ABC):
	@abstractmethod
	def unpack(self, data):
		pass
	
	@abstractmethod
	def setNext(self, layer):
		pass
	
	@abstractmethod
	def show(self):
		pass