from keras.models import Sequential
from keras.layers.core import Dense, Dropout, Activation
from keras.optimizers import SGD
import numpy as np 
import dpkt

def TAKE_EHT(main_buf_eth):
	return_struct_eth = {}
	eth = dpkt.ethernet.Ethernet(main_buf_eth)
	return_struct_eth["dst"] = eth.dst
	return_struct_eth["src"] = eth.src
	return_struct_eth["type"] = eth.type
	return return_struct_eth, TAKE_IP(eth)

def TAKE_IP(main_eth_ip):
	return_struct_ip = {}
	ip = main_eth_ip.data
	if (main_eth_ip.type == 0x0800):	
		return_struct_ip["dst"] = ip.dst
		return_struct_ip["src"] = ip.src
		return_struct_ip["tos"] = ip.tos
		return_struct_ip["len"] = ip.len
		return_struct_ip["id"] = ip.id
		return_struct_ip["off"] = ip.off
		return_struct_ip["ttl"] = ip.ttl
		return_struct_ip["p"] = ip.p
		return_struct_ip["sum"] = ip.sum
		return_struct_ip["hl"] = ip.hl
		return return_struct_ip
	if (main_eth_ip.type == 0x86DD):
		return_struct_ip["dst"] = ip.dst
		return_struct_ip["src"] = ip.src
		return_struct_ip["tos"] = ip.plen
		return_struct_ip["len"] = ip.nxt
		return_struct_ip["id"] = ip.hlim
		return_struct_ip["off"] = ip.flow
		return return_struct_ip

model = Sequential()
model.add(Dense(8, activation='relu', input_dim=6))
model.add(Dropout(0.5))
model.add(Dense(4, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(1, activation='sigmoid'))
model.compile(optimizer='rmsprop',
          loss='binary_crossentropy',
          metrics=['accuracy'])

f = open("train_dump.pcap","rb")
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
	dump_eth, dump_ip = TAKE_EHT(buf)
	train_dump = np.array([[int(dump_eth["dst"].hex(),16)
							,int(dump_eth["src"].hex(),16)
							,int(dump_ip["dst"].hex(),16)
							,int(dump_ip["src"].hex(),16)
							,dump_ip["sum"]
							,dump_ip["ttl"]]])
	train_rez = np.array([[1]])
	model.fit(train_dump, train_rez, batch_size=1, epochs=100)
i = 0
f = open("capture.pcap","rb")
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
	i += 1
	dump_eth, dump_ip = TAKE_EHT(buf)
	test_dump = np.array([[int(dump_eth["dst"].hex(),16)
							,int(dump_eth["src"].hex(),16)
							,int(dump_ip["dst"].hex(),16)
							,int(dump_ip["src"].hex(),16)
							,dump_ip["sum"]
							,dump_ip["ttl"]]])
	print("%i - %f" % (i,model.predict(test_dump)))