from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation
from keras.optimizers import SGD
import numpy as np 

class NerualNetwork:
	def start_analiz(self,header_packet):
		model = load_model("my_model.h5")
		test_dump = np.array([[header_packet["2L"]["Protocol_type"]
							,header_packet["3L"]["TTL"]
							,header_packet["3L"]["Protocol_type"]
							,header_packet["4L"]["Source_port"]
							,header_packet["4L"]["Destination_port"]
							,header_packet["4L"]["Acknowledgment_number"]
							,header_packet["4L"]["Sequence_number"]
							,header_packet["4L"]["Flags"]]])
		if(model.predict(test_dump) == [[1]]):
			print("Ports scaning")
