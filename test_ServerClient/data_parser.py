import dpkt
import struct


class PARSER:

	def start_parser(headers_data):
		all_headers_data = {}
		all_headers_data["2L"] = PARSER.headers_data_2L(headers_data)
		all_headers_data["3L"] = PARSER.headers_data_3L(headers_data)
		all_headers_data["4L"] = PARSER.headers_data_4L(headers_data)
		return all_headers_data

	def headers_data_2L(main_data):												#Eth
		return_struct_2 = {}
		eth = dpkt.ethernet.Ethernet(main_data)
		return_struct_2["Destination"] = eth.dst.hex()
		return_struct_2["Source"] = eth.src.hex()
		return_struct_2["Protocol_type"] = eth.type
		return return_struct_2

	def headers_data_3L(main_data_2):
		return_struct_3 = {}
		eth_data = dpkt.ethernet.Ethernet(main_data_2)
		main_data_3 = eth_data.data
		if (eth_data.type == 0x0800):	 										#IPv4
			return_struct_3["Destination"] = main_data_3.dst.hex()
			return_struct_3["Source"] = main_data_3.src.hex()
			return_struct_3["Type_of_service"] = main_data_3.tos
			return_struct_3["Len_packet"] = main_data_3.len
			return_struct_3["Identificator"] = main_data_3.id
			return_struct_3["Fragmentation_flags"] = main_data_3.off
			return_struct_3["TTL"] = main_data_3.ttl
			return_struct_3["Protocol_type"] = main_data_3.p
			return_struct_3["Checksum"] = main_data_3.sum
			return_struct_3["Len_headers"] = main_data_3.hl
		if (eth_data.type == 0x86DD):											#IPv6
			return_struct_3["Destination"] = main_data_3.dst
			return_struct_3["Source"] = main_data_3.src
			return_struct_3["Type_of_service"] = main_data_3.plen
			return_struct_3["Len_packet"] = main_data_3.nxt
			return_struct_3["Identificator"] = main_data_3.hlim
		if (eth_data.type == 0x0806):											#ARP
			return_struct_3["Hardware_type"] = main_data_3.hrd
			return_struct_3["Protocol_type"] = main_data_3.pro
			return_struct_3["Hardware_length"] = main_data_3.hln
			return_struct_3["Protocol_length"] = main_data_3.pln
			return_struct_3["Operation"] = main_data_3.op
			return_struct_3["Sender_hardware_address"] = main_data_3.sha.hex()
			return_struct_3["Source"] = int(main_data_3.spa.hex(),16)
			return_struct_3["Target_hardware_address"] = main_data_3.tha.hex()
			return_struct_3["Destination"] = int(main_data_3.tpa.hex(),16)
		return return_struct_3

	def headers_data_4L(main_data_3):
		return_struct_4 = {}
		ip_data = dpkt.ethernet.Ethernet(main_data_3).data
		main_data_4 = ip_data.data
		eth_data = dpkt.ethernet.Ethernet(main_data_3)
		if (eth_data.type == 0x0806):
			return 0
		if (ip_data.p == 6):													#TCP
			return_struct_4["Source_port"] = main_data_4.sport
			return_struct_4["Destination_port"] = main_data_4.dport
			return_struct_4["Sequence_number"] = main_data_4.seq
			return_struct_4["Acknowledgment_number"] = main_data_4.ack
			return_struct_4["Type_of_servicef"] = main_data_4.off
			return_struct_4["Flags"] = main_data_4.flags
			return_struct_4["Size_window"] = main_data_4.win
			return_struct_4["Checksum"] = main_data_4.sum
			return_struct_4["Index_of_importance"] = main_data_4.urp
		if (ip_data.p == 17):													#UDP
			return_struct_4["Source_port"] = main_data_4.sport
			return_struct_4["Destination_port"] = main_data_4.dport
			return_struct_4["Length"] = main_data_4.ulen
			return_struct_4["Checksum"] = main_data_4.sum
		if (ip_data.p == 1):													#ICMP
			return_struct_4["Type_packet"] = main_data_4.type
			return_struct_4["Code"] = main_data_4.code
			return_struct_4["Checksum"] = main_data_4.sum
		if (ip_data.p == 2):													#IGMP
			return_struct_4["Type_packet"] = main_data_4.type
			return_struct_4["Max_resp_code"] = main_data_4.maxresp
			return_struct_4["Checksum"] = main_data_4.sum
			return_struct_4["Group_address"] = main_data_4.group
		return return_struct_4