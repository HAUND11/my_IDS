from scapy.all import *

def random_headers():
# VARIABLES
	hwsrc = ("%x:%x:%x:%x:%x:%x" % (random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255)))
	hwdst = ("%x:%x:%x:%x:%x:%x" % (random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255),random.randint(0,255)))
	src = ("%i.%i.%i.%i" % (random.randint(1,255),random.randint(1,255),random.randint(1,255),random.randint(1,255)))
	#dst = ("%i.%i.%i.%i" % (random.randint(1,255),random.randint(1,255),random.randint(1,255),random.randint(1,255)))
	dst = "192.168.57.101"
	sport = random.randint(1024,65535)
	#dport = random.randint(1024,65535)
	dport = 80
	return hwsrc,hwdst,src,dst,sport,dport


while(1):
	hwsrc,hwdst,src,dst,sport,dport = random_headers()
#ARP request
	send(ARP(op=ARP.who_has, psrc=src, pdst=dst))
#ARP response
	send(ARP(op=ARP.is_at, psrc=src, hwsrc=hwsrc, pdst=dst))
#TCP PSH
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='P',seq=1000))
#TCP FIN
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='F',seq=1000))
#TCP URG
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='U',seq=1000))
#TCP ECE
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='E',seq=1000))
#TCP CWR
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='C',seq=1000))
#TCP RST
	send(IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags='R',seq=1000))
# SYN
	ip=IP(src=src,dst=dst)
	SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
	SYNACK=sr1(ip/SYN)
	break

#TCP ACK
#	ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
#	send(ip/ACK)

