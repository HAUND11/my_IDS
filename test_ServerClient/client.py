from data_parser import *
from scapy.all import *
from arp_scan import *
from send_to_server import *
from headers_protocol_control import *
from static_data_trafic.db import *
import socket,\
        rsa,\
        re,\
        logging,\
        multiprocessing,\
        time


class SETTINGS_BOT():

    def __init__(self):
        Create_DB_result = DATA.CREATE(self)
        logging.basicConfig(level=logging.DEBUG)
        Get_config_result, server_ip, host_ip, host_mask,main_network_ip = self.get_config_settings()
        # Scan_result = self.scan_ip_mac_hosts(main_network_ip,host_mask)
        Connect_result, socket_main, pubkey_for_server = self.connect_to_server(server_ip,host_ip)
        time.sleep(15)
        if Create_DB_result and Get_config_result:# and Scan_result and Connect_result:
            ip_mac_hosts = DATA.GET_ALL_DATA_ARP_HOST(self)
            self.bot_work_result(True,socket_main,pubkey_for_server,ip_mac_hosts)
            SNIFFER(socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server)
        else:
            self.bot_work_result(False, 0, 0,0)

    def bot_work_result(self,Settings_result, socket_main,pubkey_for_server,ip_mac_hosts):
        if Settings_result:
            print(ip_mac_hosts)
        else:
            socket_main.sendall("Error")
            # socket_main.sendall(rsa.encrypt(bytes("Error",encoding='utf-8'),pubkey_for_server))

    def scan_ip_mac_hosts(self,main_network_ip,network_mask):
        try:
            logging.basicConfig(level=logging.DEBUG)
            start_sniff = multiprocessing.Process(target=sniff_arp)
            start_sniff.daemon = True
            start_sniff.start()
            scan_arp(main_network_ip, network_mask)
            return True
        except:
            logging.info("#### Error scanning host ####")
            return False

    def get_config_settings(self):
        try:
            config_file = open("bot_net_config.conf",'r')
            settings_bot = config_file.read()
            server_ip = re.findall(r'ip_server-(.*)',settings_bot)
            host_ip = re.findall(r'ip_host-(.*)',settings_bot)
            host_mask = re.findall(r'host_mask-(.*)',settings_bot)
            network_ip = re.findall(r'(\d+).', host_ip[0] + '.')
            network_mask = re.findall(r'(\d+).', host_mask[0] + '.')
            main_network_ip = [int(network_ip[0]) & int(network_mask[0]), int(network_ip[1]) & int(network_mask[1]),
                               int(network_ip[2]) & int(network_mask[2]), int(network_ip[3]) & int(network_mask[3])]
            return True, server_ip, network_ip, network_mask,main_network_ip
        except IOError:
            logging.error("Error open config file")
            return False, -1,-1,-1
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
                return True,bot_socket,pubkey_for_server
        except:
            logging.ERROR("Connect error")
            return False, 0, 0

class SNIFFER(object):

    def __init__(self,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server):
        sniff(filter="ip",prn=sniff_packets(socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server))
        # sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        # while True:
        #     data, address = sniff_socket.recvfrom(65535)
        #     header_packet = PARSER.start_parser(data)
        #     print(header_packet)

def sniff_packets(socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server):
    def packets_take(packets):
        try:
            check = check_input_output(packets,main_network_ip,host_mask)
            if check == "Input":
                Control_ip_network_result = CONTROL.control_ip_input_network(packets,ip_mac_hosts)
                if Control_ip_network_result != True:
                    Control_ip_network_result = "Bad input ip"
                    print(Control_ip_network_result)
                    send_data_structure = {"id": 10,
                                           "key_warning": 100,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip ,
                                           "warning": "{0} -> {1}".format(packets[0][1].src,packets[0][1].dst)}
                    SEND_DATA.send_to_server_warning("warning_incorrect_input_ip",socket_main,pubkey_for_server,send_data_structure)
            elif check == "Output":
                Control_ip_network_result = CONTROL.control_ip_output_network(packets,main_network_ip,host_mask,ip_mac_hosts)
                if Control_ip_network_result != True:
                    Control_ip_network_result = "Bad output ip"
                    print(Control_ip_network_result)
        except AttributeError:
            return None


    return packets_take

def check_input_output(packets,main_network_ip,host_mask):
    network_ip_src = re.findall(r'(\d+).', packets[0][1].src + '.')
    network_ip_dst = re.findall(r'(\d+).', packets[0][1].dst + '.')
    output = True
    input = True
    for ip_index in range(0,4):
        if (int(network_ip_src[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
            output = False
        if (int(network_ip_dst[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
            input = False
    if output == True : return "Output"
    elif input == True : return "Input"
    else: return "Forvard"



if __name__ == "__main__":
    bot = SETTINGS_BOT()