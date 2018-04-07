import socket,\
        rsa,\
        re,\
        logging,\
        multiprocessing,\
        time, \
        threading


from data_parser import *
from scapy.all import *
from arping_scan import *
from send_to_server import *
from headers_protocol_control import *
from static_data_trafic.db import *
from segment_network_data import *

warning_id = 0
segment_static_data = {"input_bytes" : 0,
                   "output_bytes" : 0,
                   "internal_bytes" : 0,
                   "internal_tcp_syn": 0,
                   "internal_tcp_rst": 0,
                   "internal_tcp_ack": 0,
                   "internal_tcp_syn_ack": 0,
                   "internal_tcp_psh_ack": 0,
                   "internal_udp": 0,
                   "input_tcp_syn": 0,
                   "input_tcp_rst": 0,
                   "input_tcp_ack": 0,
                   "input_tcp_syn_ack": 0,
                   "input_tcp_psh_ack": 0,
                   "input_udp": 0,
                   "output_udp": 0,
                   "output_tcp_syn_ack": 0,
                   "output_tcp_psh_ack": 0,
                   "output_tcp_syn": 0,
                   "output_tcp_rst": 0,
                   "output_tcp_ack": 0}

segment_data = {"input_bytes/s" : 0,
                "output_bytes/s" : 0,
                "internal_bytes/s": 0,
                "internal_tcp_syn/s": 0,
                "internal_tcp_rst/s": 0,
                "internal_tcp_ack/s": 0,
                "internal_tcp_syn_ack/s": 0,
                "internal_tcp_psh_ack/s": 0,
                "internal_udp/s": 0,
                "input_tcp_syn/s" : 0,
                "input_tcp_rst/s" : 0,
                "input_tcp_ack/s" : 0,
                "input_tcp_syn_ack/s": 0,
                "input_tcp_psh_ack/s": 0,
                "input_udp/s": 0,
                "output_udp/s": 0,
                "output_tcp_psh_ack/s": 0,
                "output_tcp_syn_ack/s": 0,
                "output_tcp_syn/s": 0,
                "output_tcp_rst/s": 0,
                "output_tcp_ack/s": 0}

class SETTINGS_BOT():

    def __init__(self):
        Create_DB_result = DATA.CREATE(self)
        logging.basicConfig(level=logging.DEBUG)
        (Get_config_result, configurate_bot) = self.get_config_settings()
        Scan_result = self.scan_ip_mac_hosts(configurate_bot["main_network_arping"])
        (Connect_result, socket_main, pubkey_for_server) = self.connect_to_server(configurate_bot["server_ip"],configurate_bot["network_ip"])
        if Create_DB_result and Get_config_result and Scan_result and Connect_result:
            ip_mac_hosts = DATA.GET_ALL_DATA_ARP_HOST(self)
            self.bot_work_result(True,socket_main,pubkey_for_server,ip_mac_hosts)
            SNIFFER(configurate_bot["host_ip"],socket_main,configurate_bot["main_network_ip"],configurate_bot["network_mask"],ip_mac_hosts,pubkey_for_server)
        else:
            self.bot_work_result(False, 0, 0,0)

    def bot_work_result(self,Settings_result, socket_main,pubkey_for_server,ip_mac_hosts):
        if Settings_result:
            print(ip_mac_hosts)
        else:
            socket_main.sendall("Error")

    def scan_ip_mac_hosts(self,main_network_arping):
        try:
            logging.basicConfig(level=logging.DEBUG)
            ARP_PING_SCAN.arping_scan(main_network_arping)
            return True
        except:
            logging.info("#### Error scanning host ####")
            return False

    def get_config_settings(self):
        try:
            configurate_bot = {}
            config_file = open("bot_net_config.conf",'r')
            settings_bot = config_file.read()
            configurate_bot["main_network_arping"] = re.findall(r'main_network-(.*)',settings_bot)
            configurate_bot["server_ip"] = re.findall(r'ip_server-(.*)',settings_bot)
            configurate_bot["host_ip"] = re.findall(r'ip_host-(.*)',settings_bot)
            configurate_bot["host_mask"] = re.findall(r'host_mask-(.*)',settings_bot)
            configurate_bot["network_ip"] = re.findall(r'(\d+).', configurate_bot["host_ip"][0] + '.')
            configurate_bot["network_mask"] = re.findall(r'(\d+).', configurate_bot["host_mask"][0] + '.')
            configurate_bot["main_network_ip"] = [int(configurate_bot["network_ip"][0]) & int(configurate_bot["network_mask"][0]),
                                                  int(configurate_bot["network_ip"][1]) & int(configurate_bot["network_mask"][1]),
                                                  int(configurate_bot["network_ip"][2]) & int(configurate_bot["network_mask"][2]),
                                                  int(configurate_bot["network_ip"][3]) & int(configurate_bot["network_mask"][3])]
            return True, configurate_bot
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

"""
Main Sniff class
"""

class SNIFFER(object):

    def __init__(self,host_ip,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server):
        time_time =  threading.Thread(target=SNIFFER.segment_data_save)
        time_time.daemon = True
        time_time.start()
        sniff(filter="ip" ,prn=sniff_packets(host_ip,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server))

    """
    Mbit/s
    """


    def segment_data_save():
        while True:
            time.sleep(10)

            global segment_data
            global segment_static_data

            segment_data["input_bytes/s"] = segment_static_data["input_bytes"] * 8 / 1024 / 1024 / 10
            segment_data["output_bytes/s"] = segment_static_data["output_bytes"] * 8 / 1024 / 1024 / 10
            segment_data["internal_bytes/s"] = segment_static_data["internal_bytes"] * 8 / 1024 / 1024 / 10
            for index_keys in segment_static_data:
                if index_keys != "input_bytes" and index_keys != "output_bytes" and index_keys != "internal_bytes":
                    segment_data[index_keys+"/s"] = segment_static_data[index_keys] / 10
                    segment_static_data[index_keys] = 0
                else:
                    segment_static_data[index_keys] = 0
                    continue

            print("input bytes - {0} :: output - {1} :: interal - {2}".format(segment_data["input_bytes/s"],
                                                                              segment_data["output_bytes/s"],
                                                                              segment_data["internal_bytes/s"]))


""" 
    key_warning:
    100 - incorrect dst ip
    101 - incorrect src ip
    102 - incorrect src mac
    103 - incorrect dst mac
    104 - incorrect interal src ip
    105 - incorrect interal dst ip
    106 - incorrect interal src mac
    107 - incorrect interal dst mac
    """

def sniff_packets(host_ip,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server):
    def packets_take(packets):
        try:

            global warning_id
            global segment_static_data

            check = CONTROL.check_input_output(host_ip,packets,main_network_ip,host_mask)
            if check == "Input":

                segment_static_data["input_bytes"] = segment_static_data["input_bytes"] + len(packets.original)
                SEGMENT_DATA.segment_data_check(packets,segment_static_data,check)

                Control_ip_network_result = CONTROL.control_ip_input_network(packets,ip_mac_hosts)
                if Control_ip_network_result == 0:
                    warning_id += 1
                    Control_ip_network_result = "100 - incorrect dst ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 100,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip ,
                                           "warning": "{0} -> {1}".format(packets[0][1].src,packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning",socket_main,pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result)
                elif Control_ip_network_result == 2:
                    warning_id += 1
                    Control_ip_network_result = "103 - incorrect dst mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 103,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {2}({1}) ".format(packets[0][1].src, packets[0].dst,
                                                                               packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result)
            elif check == "Output":

                segment_static_data["output_bytes"] = segment_static_data["output_bytes"] + len(packets.original)
                SEGMENT_DATA.segment_data_check(packets, segment_static_data, check)

                Control_ip_network_result = CONTROL.control_ip_output_network(packets,main_network_ip,host_mask,ip_mac_hosts)
                if Control_ip_network_result == 0:
                    warning_id += 1
                    Control_ip_network_result = "101 - incorrect src ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 101,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {1}".format(packets[0][1].src, packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result)
                elif Control_ip_network_result == 2:
                    warning_id += 1
                    Control_ip_network_result = "102 - incorrect src mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 102,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0}({1}) -> {2}".format(packets[0][1].src,packets[0].src, packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main,pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result)
            elif check == "Internal traffic":

                segment_static_data["internal_bytes"] = segment_static_data["internal_bytes"] + len(packets.original)
                SEGMENT_DATA.segment_data_check(packets, segment_static_data, check)


                Control_ip_network_result_src = CONTROL.control_ip_input_network(packets,ip_mac_hosts)

                if Control_ip_network_result_src == 0:
                    warning_id += 1
                    Control_ip_network_result_src = "104 - incorrect interal dst ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 104,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip ,
                                           "warning": "{0} -> {1}".format(packets[0][1].src,packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning",socket_main,pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result_src)
                elif Control_ip_network_result_src == 2:
                    warning_id += 1
                    Control_ip_network_result_src = "106 - incorrect interal dst mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 106,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {2}({1}) ".format(packets[0][1].src, packets[0].dst,
                                                                               packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_src)

                Control_ip_network_result_dst = CONTROL.control_ip_output_network(packets, main_network_ip, host_mask, ip_mac_hosts)

                if Control_ip_network_result_dst == 0:
                    warning_id += 1
                    Control_ip_network_result_dst = "105 - incorrect src ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 105,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {1}".format(packets[0][1].src, packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_dst)
                elif Control_ip_network_result_dst == 2:
                    warning_id += 1
                    Control_ip_network_result_dst = "107 - incorrect src mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 107,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0}({1}) -> {2}".format(packets[0][1].src, packets[0].src,
                                                                               packets[0][1].dst)}
                    rez = SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_dst)

        except:
            return None


    return packets_take




if __name__ == "__main__":
    bot = SETTINGS_BOT()