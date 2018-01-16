from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation
from keras.optimizers import SGD
from data_parser import *
import numpy as np 
import dpkt

model = Sequential()
model.add(Dense(8, activation='relu', input_dim=8))
model.add(Dropout(0.5))
model.add(Dense(4, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(1, activation='sigmoid'))
model.compile(optimizer='rmsprop',
          loss='binary_crossentropy',
          metrics=['accuracy'])

# f = open("nmap_TCP.pcap","rb")
# pcap = dpkt.pcap.Reader(f)
# for ts, buf in pcap:
# 	dump_all = PARSER.start_parser(buf)
# 	if(dump_all["2L"]["Protocol_type"] == 2054):
# 		continue
# 	train_dump = np.array([[dump_all["2L"]["Protocol_type"]
# 							,dump_all["3L"]["TTL"]
# 							,dump_all["3L"]["Protocol_type"]
# 							,dump_all["4L"]["Source_port"]
# 							,dump_all["4L"]["Destination_port"]
# 							,dump_all["4L"]["Acknowledgment_number"]
# 							,dump_all["4L"]["Sequence_number"]
# 							,dump_all["4L"]["Flags"]]])
# 	train_rez = np.array([[1]])
# 	model.fit(train_dump, train_rez, batch_size=1, epochs=100)
i = 0
f = open("capture.pcap","rb")
model1 = load_model("my_model.h5")
# model.save("my_model.h5")

pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
	i += 1
	dump_all = PARSER.start_parser(buf)
	if(dump_all["3L"]["Protocol_type"] != 6):
 		continue
	test_dump = np.array([[dump_all["2L"]["Protocol_type"]
							,dump_all["3L"]["TTL"]
							,dump_all["3L"]["Protocol_type"]
							,dump_all["4L"]["Source_port"]
							,dump_all["4L"]["Destination_port"]
							,dump_all["4L"]["Acknowledgment_number"]
							,dump_all["4L"]["Sequence_number"]
							,dump_all["4L"]["Flags"]]])
	print("%i - %f" % (i,model1.predict(test_dump)))