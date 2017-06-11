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
	if (main_eth_ip.type == 2048):	
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
	if (main_eth_ip.type == 34525):
		return_struct_ip["dst"] = ip.dst
		return_struct_ip["src"] = ip.src
		return_struct_ip["tos"] = ip.plen
		return_struct_ip["len"] = ip.nxt
		return_struct_ip["id"] = ip.hlim
		return_struct_ip["off"] = ip.flow
		return return_struct_ip


f = open('capture.pcap')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
	print TAKE_EHT(buf)