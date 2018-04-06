from scapy.all import   *
from static_data_trafic.db import *
import logging

class ARP_PING_SCAN(object):

    def arping_scan(main_network):
        packet = arping(main_network)
        index = 0
        try:
            while True:
                if not DATA.CHEK_ARP_DATA_IN_TABLE(packet[0][index][1][1].psrc, packet[0][index][1][1].hwsrc):
                    DATA.INSERT_ARP_DATA(packet[0][index][1][1].psrc, packet[0][index][1][1].hwsrc)
                    logging.info('Response: {} has address {}'.format(packet[0][index][1][1].hwsrc, packet[0][index][1][1].psrc))
                index += 1
        except:
            logging.info("Scanning finish")

# if __name__ == "__main__":
#     ARP_PING_SCAN.arping_scan("192.168.0.0-254")