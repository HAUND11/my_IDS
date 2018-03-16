from data_parser import *
from arp_scan import *
from static_data_trafic.db import *
import socket
import rsa
import re
import logging
import multiprocessing


class SETTINGS_BOT():

    def __init__(self):
        DATA.CREATE()
        logging.basicConfig(level=logging.DEBUG)
        server_ip, host_ip, host_mask =SETTINGS_BOT.get_config_settings(self)
        SETTINGS_BOT.scan_ip_mac_hosts(self,host_ip,host_mask)
        SETTINGS_BOT.connect_to_server(self,server_ip,host_ip)

    def scan_ip_mac_hosts(self,interface_ip,mask):
        try:
            logging.basicConfig(level=logging.DEBUG)
            network_ip = re.findall(r'(\d+).', interface_ip[0] + '.')
            network_mask = re.findall(r'(\d+).', mask[0] + '.')
            main_network_ip = [int(network_ip[0]) & int(network_mask[0]), int(network_ip[1]) & int(network_mask[1]),
                               int(network_ip[2]) & int(network_mask[2]), int(network_ip[3]) & int(network_mask[3])]
            logging.debug("Main network: %i.%i.%i.%i", main_network_ip[0], main_network_ip[1], main_network_ip[2],
                          main_network_ip[3])
            start_sniff = multiprocessing.Process(target=sniff_arp)
            start_sniff.daemon = True
            start_sniff.start()
            scan_arp(main_network_ip, network_mask)
        except:
            logging.info("#### Write ip interface and mask network ####")
            logging.info("#### Example 192.168.2.0 255.255.255.0 ####")

    def get_config_settings(self):
        try:
            config_file = open("bot_net_config.conf",'r')
            settings_bot = config_file.read()
            server_ip = re.findall(r'ip_server-(.*)',settings_bot)
            host_ip = re.findall(r'ip_host-(.*)',settings_bot)
            host_mask = re.findall(r'host_mask-(.*)',settings_bot)
        except IOError:
            logging.error("Error open config file")
        finally:
            config_file.close()

        return server_ip,host_ip,host_mask

    def connect_to_server(self,server_ip,host_ip):
        try:
            bot_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            bot_socket.connect((server_ip[0],9000))
            SYN_data = bytes(server_ip[0]+":CONNECT:SYN",encoding='utf-8')
            bot_socket.sendall(SYN_data)
            while True:
                ACK_pubkey_e = bot_socket.recv(1024)
                if ACK_pubkey_e != b'':
                    bot_socket.sendall(b'True correct pubkey e')
                    break
            while True:
                ACK_pubkey_n = bot_socket.recv(1024)
                if ACK_pubkey_n != b'':
                    bot_socket.sendall(b'True correct pubkey n')
                    break
            pubkey_for_server = rsa.PublicKey(int(ACK_pubkey_n.decode("utf-8")) ,int(ACK_pubkey_e.decode("utf-8")) )
            if pubkey_for_server["e"] and pubkey_for_server["n"]:
                logging.info("BOT START %r",bot_socket)
                server_ip_for_check = re.findall(r'(\d+).', server_ip[0] + '.')
                controll_number = (int(server_ip_for_check[0])+int(server_ip_for_check[1])+int(server_ip_for_check[2])+int(server_ip_for_check[3]))*9000
                crypt_mess = rsa.encrypt(bytes(str(controll_number),encoding='utf-8'),pubkey_for_server)
                bot_socket.sendall(crypt_mess)

                logging.info("STARTING SNIFF NETWORK")
                SNIFFER(bot_socket)
        finally:
            bot_socket.sendall(b'Close connect')

class SNIFFER(object):

    def __init__(self, bot_socket):
        sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            data, address = sniff_socket.recvfrom(65535)
            header_packet = PARSER.start_parser(data)
            print(header_packet)
            # if header_packet["3L"]["Protocol_type"] == 1:
            #     bot_socket.sendall(data)


if __name__ == "__main__":
    bot = SETTINGS_BOT()