import socket
from data_parser import *

class SNIFFER:
	def __init__(self):
		work_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

		while(True):
			data, address = work_socket.recvfrom(65535)
			rezult_eth,rezult_ip = PARSER.TAKE_2(data)
			print(rezult_eth,rezult_ip)


start = SNIFFER()