from scapy.all import *
import threading
import multiprocessing

def save_arp(packet):
	if packet[ARP].op == 2: #response
		return '*Response: {} has address {}'.format(packet[ARP].hwsrc, packet[ARP].psrc)

def sniff_arp():
	sniff(prn=save_arp, filter='arp')

def scan(ip):
	send(ARP(op=ARP.who_has, pdst="192.168.56."+str(ip)))

def scan_arp():
	a = 0
	while(a<256):
		start_sniff1 = threading.Thread(target=scan, args=(a,))
		start_sniff1.daemon = False
		start_sniff1.start()
		a += 1

if __name__ == "__main__":
	start_sniff = multiprocessing.Process(target=sniff_arp)
	start_sniff.daemon = True
	start_sniff.start()
	scan_arp()

