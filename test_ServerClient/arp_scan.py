from scapy.all import *
import sys
import re
import logging
import threading
import multiprocessing


def save_arp(packet):
	mac_ip_address_table = {}
	if packet[ARP].op == 2: #response
		check_ip_mac = False
		if packet[ARP].psrc in mac_ip_address_table:
				check_ip_mac = True
		if check_ip_mac == False:
			mac_ip_address_table[packet[ARP].psrc] = packet[ARP].hwsrc
		return logging.info('Response: {} has address {}'.format(packet[ARP].hwsrc, packet[ARP].psrc))

def sniff_arp():
	sniff(prn=save_arp, filter='arp')

def scan(ip):
	send(ARP(op=ARP.who_has, pdst=ip))

def scan_arp(network_ip,mask):
	for_id = 0
	for mask_id in mask:
		if mask_id != '255':
			if for_id == 0:
				logging.error("ERROR MASK")
				break
			elif for_id == 1:
				logging.error("ERROR MASK")
				break
			elif for_id == 2:
				for id_ip_2 in range(network_ip[2],254):
					for id_ip_3 in range(network_ip[3], 254):
						scan_ip = str(network_ip[0]) + "." + str(network_ip[1]) + "." + str(id_ip_2) + "." + str(id_ip_3)
						start_scan(scan_ip)
				break
			elif for_id == 3:
				for id_ip in range(network_ip[3],254):
					scan_ip = str(network_ip[0])+"."+str(network_ip[1])+"."+str(network_ip[2])+"."+str(id_ip)
					start_scan(scan_ip)
				break
		for_id += 1

def start_scan(host_ip):
		start_sniff1 = threading.Thread(target=scan, args=(host_ip,))
		start_sniff1.daemon = False
		start_sniff1.start()

# if __name__ == "__main__":
# 	try:
# 		logging.basicConfig(level=logging.DEBUG)
# 		network_ip = re.findall(r'(\d+).',sys.argv[1]+'.')
# 		network_mask = re.findall(r'(\d+).',sys.argv[2]+'.')
# 		main_network_ip = [int(network_ip[0])&int(network_mask[0]),int(network_ip[1])&int(network_mask[1]),int(network_ip[2])&int(network_mask[2]),int(network_ip[3])&int(network_mask[3])]
# 		logging.debug("Main network: %i.%i.%i.%i", main_network_ip[0],main_network_ip[1],main_network_ip[2],main_network_ip[3])
# 		start_sniff = multiprocessing.Process(target=sniff_arp)
# 		start_sniff.daemon = True
# 		start_sniff.start()
# 		scan_arp(main_network_ip,network_mask)
# 	except:
# 		logging.info("#### Write ip interface and mask network ####")
# 		logging.info("#### Example /python3 {fale_name} 192.168.2.0 255.255.255.0 ####")