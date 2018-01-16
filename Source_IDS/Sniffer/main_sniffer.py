import socket
from data_parser import *
# from NN import *
from static_data_trafic.db import *

class SNIFFER:
	def __init__(self):
		work_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		DATA.CREATE()
		# Network = NerualNetwork()
		while(True):
			data, address = work_socket.recvfrom(65535)
			header_packet = PARSER.start_parser(data)
			DATA.INSERT_DATA(header_packet)
			print(header_packet)
			# if(header_packet["3L"]["Protocol_type"] != 6):
			# 	print(header_packet["3L"]["Protocol_type"])
			# 	continue	
			# print(Network.start_analiz(header_packet))

start = SNIFFER()