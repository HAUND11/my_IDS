from scapy.all import *
import sys
import re
import threading
import multiprocessing


def save_arp(packet):
	if packet[ARP].op == 2: #response
		return 'Response: {} has address {}'.format(packet[ARP].hwsrc, packet[ARP].psrc)
def sniff_arp():
	sniff(prn=save_arp, filter='arp')

def scan(ip):
	send(ARP(op=ARP.who_has, pdst=ip))

def scan_arp(network_ip,mask):
	for_id = 0
	for mask_id in mask:
		if mask_id != '255':
			if for_id == 0:
				print("0")
				break
			elif for_id == 1:
				print("1")
				break
			elif for_id == 2:
				for id_ip_2 in range(network_ip[2],255):
					for id_ip_3 in range(network_ip[3], 255):
						scan_ip = str(network_ip[0]) + "." + str(network_ip[1]) + "." + str(id_ip_2) + "." + str(id_ip_3)
						start_scan(scan_ip)
				break
			elif for_id == 3:
				for id_ip in range(network_ip[3],255):
					scan_ip = str(network_ip[0])+"."+str(network_ip[1])+"."+str(network_ip[2])+"."+str(id_ip)
					start_scan(scan_ip)
				break
		for_id += 1

def start_scan(host_ip):
		start_sniff1 = threading.Thread(target=scan, args=(host_ip,))
		start_sniff1.daemon = False
		start_sniff1.start()

if __name__ == "__main__":
	try:
		import logging
		logging.basicConfig(level=logging.DEBUG)
		network_ip = re.findall(r'(\d+).',sys.argv[1]+'.')
		network_mask = re.findall(r'(\d+).',sys.argv[2]+'.')
		main_network_ip = [int(network_ip[0])&int(network_mask[0]),int(network_ip[1])&int(network_mask[1]),int(network_ip[2])&int(network_mask[2]),int(network_ip[3])&int(network_mask[3])]
		logging.debug("Main network: %i.%i.%i.%i", main_network_ip[0],main_network_ip[1],main_network_ip[2],main_network_ip[3])
		start_sniff = multiprocessing.Process(target=sniff_arp)
		start_sniff.daemon = True
		start_sniff.start()
		scan_arp(main_network_ip,network_mask)
	except:
		print("#### Write ip interface and mask network ####")
		print("#### Example /python3 {fale_name} 192.168.2.0 255.255.255.0 ####")