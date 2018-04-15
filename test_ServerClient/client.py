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
segment_static_data = {"arp_1" : 0,
                       "arp_2" : 0,
                    "input_bytes" : 0,
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
"input_tcp_rst_ack": 0,
"internal_tcp_rst_ack": 0,
"output_tcp_rst_ack": 0,
                   "output_tcp_syn_ack": 0,
                   "output_tcp_psh_ack": 0,
                   "output_tcp_syn": 0,
                   "output_tcp_rst": 0,
                   "output_tcp_ack": 0}

key_warning_structure = {
    3 : { 0 : "108-Net Unreachable",
     1 :  "109-Host Unreachable ",
     2 : "110-Protocol Unreachable",
     3 :  "111-Port Unreachable" 	,
     4 :  "112-Fragmentation Needed and Don't Fragment was Set",
     5 :  "113-Source Route Failed ",
     6 : "114-Destination Network Unknown",
     7 : "115-Destination Host Unknown ",
     8 : "116-Source Host Isolated ",
     9 : "117-Communication with Destination Network is Administratively Prohibited",
     10 : "118-Communication with Destination Host is Administratively Prohibited ",
     11 : "119-Destination Network Unreachable for Type of Service ",
     12 : "120-Destination Host Unreachable for Type of Service ",
     13 : "121-Communication Administratively Prohibited ",
     14 : "122-Host Precedence Violation ",
     15 : "123-Precedence cutoff in effect"},
    11 : { 0 : "124-Time to Live exceeded in Transit",
     1 : "125-Fragment Reassembly Time Exceeded"},
    12 : { 0 : "126-Pointer indicates the error 	",
     1 : "127-Missing a Required Option ",
     2 : "128-Bad Length"}}

"""
ICMP:
type 3 >>>>>
0 	Net Unreachable 	[RFC792]
1 	Host Unreachable 	[RFC792]
2 	Protocol Unreachable 	[RFC792]
3 	Port Unreachable 	[RFC792]
4 	Fragmentation Needed and Don't Fragment was Set 	[RFC792]
5 	Source Route Failed 	[RFC792]
6 	Destination Network Unknown 	[RFC1122]
7 	Destination Host Unknown 	[RFC1122]
8 	Source Host Isolated 	[RFC1122]
9 	Communication with Destination Network is Administratively Prohibited 	[RFC1122]
10 	Communication with Destination Host is Administratively Prohibited 	[RFC1122]
11 	Destination Network Unreachable for Type of Service 	[RFC1122]
12 	Destination Host Unreachable for Type of Service 	[RFC1122]
13 	Communication Administratively Prohibited 	[RFC1812]
14 	Host Precedence Violation 	[RFC1812]
15 	Precedence cutoff in effect
type 11 >>>>>
0 	Time to Live exceeded in Transit 	
1 	Fragment Reassembly Time Exceeded 	
type 12 >>>>>
0 	Pointer indicates the error 	
1 	Missing a Required Option 	[RFC1108]
2 	Bad Length
"""
segment_data_icmp = {"Input_icmp_0_0" : 0,"Input_icmp_8_0": 0,
                     "Input_icmp_3_0": 0,"Input_icmp_3_1": 0,"Input_icmp_3_2": 0,"Input_icmp_3_3": 0,"Input_icmp_3_4": 0,
                     "Input_icmp_3_5": 0,"Input_icmp_3_6": 0,"Input_icmp_3_7": 0,"Input_icmp_3_8": 0,"Input_icmp_3_9": 0,
                     "Input_icmp_3_10": 0,"Input_icmp_3_11": 0,"Input_icmp_3_12": 0,"Input_icmp_3_13": 0,"Input_icmp_3_14": 0,"Input_icmp_3_15": 0,
                     "Input_icmp_11_0": 0,"Input_icmp_11_1": 0,
                     "Input_icmp_12_0": 0,"Input_icmp_12_1": 0,"Input_icmp_12_2": 0,
                     "Output_icmp_0_0": 0, "Output_icmp_8_0": 0,
                     "Output_icmp_3_0": 0, "Output_icmp_3_1": 0, "Output_icmp_3_2": 0, "Output_icmp_3_3": 0, "Output_icmp_3_4": 0,
                     "Output_icmp_3_5": 0, "Output_icmp_3_6": 0, "Output_icmp_3_7": 0, "Output_icmp_3_8": 0, "Output_icmp_3_9": 0,
                     "Output_icmp_3_10": 0, "Output_icmp_3_11": 0, "Output_icmp_3_12": 0, "Output_icmp_3_13": 0, "Output_icmp_3_14": 0, "Output_icmp_3_15": 0,
                     "Output_icmp_11_0": 0, "Output_icmp_11_1": 0,
                     "Output_icmp_12_0": 0, "Output_icmp_12_1": 0, "Output_icmp_12_2": 0,
                     "Internal_icmp_0_0": 0, "Internal_icmp_8_0": 0,
                     "Internal_icmp_3_0": 0, "Internal_icmp_3_1": 0, "Internal_icmp_3_2": 0, "Internal_icmp_3_3": 0, "Internal_icmp_3_4": 0,
                     "Internal_icmp_3_5": 0, "Internal_icmp_3_6": 0, "Internal_icmp_3_7": 0, "Internal_icmp_3_8": 0, "Internal_icmp_3_9": 0,
                     "Internal_icmp_3_10": 0, "Internal_icmp_3_11": 0, "Internal_icmp_3_12": 0, "Internal_icmp_3_13": 0, "Internal_icmp_3_14": 0, "Internal_icmp_3_15": 0,
                     "Internal_icmp_11_0": 0, "Internal_icmp_11_1": 0,
                     "Internal_icmp_12_0": 0, "Internal_icmp_12_1": 0, "Internal_icmp_12_2": 0,
                     }

segment_data = {"input_bytes/s" : 0,
                "output_bytes/s" : 0,
                "internal_bytes/s": 0}

class SETTINGS_BOT():

    def __init__(self):
        Create_DB_result = DATA.CREATE(self)
        logging.basicConfig(level=logging.DEBUG)
        (Get_config_result, configurate_bot) = self.get_config_settings()
        Scan_result = self.scan_ip_mac_hosts(configurate_bot["main_network_arping"])
        (Connect_result, socket_main, pubkey_for_server) = self.connect_to_server(configurate_bot["server_ip"],configurate_bot["network_ip"])
        if Create_DB_result and Get_config_result and Scan_result and Connect_result:
            ip_mac_hosts = DATA.GET_ALL_DATA_ARP_HOST(self)
            time.sleep(5)
            SEND_DATA.bot_work_result(True,socket_main,pubkey_for_server,ip_mac_hosts)
            SNIFFER(configurate_bot["host_ip"],socket_main,configurate_bot["main_network_ip"],configurate_bot["network_mask"],ip_mac_hosts,pubkey_for_server)
        else:
            self.bot_work_result(False, 0, 0,0)

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
        sniff(prn=sniff_packets(host_ip,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server))

    """
    Mbit/s
    """


    def segment_data_save():
        while True:
            time.sleep(10)

            global segment_data
            global segment_static_data
            global segment_data_icmp

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

            for index_keys_icmp in segment_data_icmp:
                segment_data[index_keys_icmp+"/s"] = segment_data_icmp[index_keys_icmp] / 10
                segment_data_icmp[index_keys_icmp] = 0

            print("input bytes - {0} :: output - {1} :: interal - {2}".format(segment_data["input_bytes/s"],
                                                                              segment_data["output_bytes/s"],
                                                                              segment_data["internal_bytes/s"]))


"""
key_warning:
    100 : Incorrect dst ip
    102 : Incorrect src mac
    103 : Incorrect dst mac
    104 : Incorrect interal src ip
    105 : Incorrect interal dst ip
    106 : Incorrect interal src mac
    107 : Incorrect interal dst macv
    108 : Net Unreachable 
    109 : Host Unreachable 
    110 : Protocol Unreachable 
    111 : Port Unreachable 	
    112 : Fragmentation Needed and Don't Fragment was Set 
    113 : Source Route Failed 
    114 : Destination Network Unknown
    115 : Destination Host Unknown 
    116 : Source Host Isolated 
    117 : Communication with Destination Network is Administratively Prohibited 
    118 : Communication with Destination Host is Administratively Prohibited 
    119 : Destination Network Unreachable for Type of Service 
    120	: Destination Host Unreachable for Type of Service 
    121 : Communication Administratively Prohibited 
    122 : Host Precedence Violation 
    123 : Precedence cutoff in effect
    124 : Time to Live exceeded in Transit 	
    125 : Fragment Reassembly Time Exceeded 	
    126 : Pointer indicates the error 	
    127 : Missing a Required Option 
    128 : Bad Length
    129 : Host get RST
    130 : Host get RST/ASK
"""

def sniff_packets(host_ip,socket_main,main_network_ip,host_mask,ip_mac_hosts,pubkey_for_server):
    def packets_take(packets):
        try:

            global warning_id
            global segment_static_data
            global key_warning_structure

            check = CONTROL.check_input_output(host_ip,packets,main_network_ip,host_mask)
            SEGMENT_DATA.segment_data_check(packets, segment_static_data, segment_data_icmp, check)

            if check == "Input":

                segment_static_data["input_bytes"] = segment_static_data["input_bytes"] + len(packets.original)

                Control_ip_network_result = CONTROL.control_ip_input_network(packets,ip_mac_hosts)
                if Control_ip_network_result == 0:
                    warning_id += 1
                    Control_ip_network_result = "100 - incorrect dst ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 100,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip ,
                                           "warning": "{0} -> {1} [{2}] Incorrect dst ip".format(packets[0][1].src,packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning",socket_main,pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result)
                elif Control_ip_network_result == 2:
                    warning_id += 1
                    Control_ip_network_result = "103 - incorrect dst mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 103,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {2}({1}) [{3}] Incorrect dst mac".format(packets[0][1].src, packets[0].dst,
                                                                               packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result)
            elif check == "Output":

                segment_static_data["output_bytes"] = segment_static_data["output_bytes"] + len(packets.original)

                Control_ip_network_result = CONTROL.control_ip_output_network(packets,ip_mac_hosts)
                if Control_ip_network_result == 0:
                    warning_id += 1
                    Control_ip_network_result = "101 - incorrect src ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 101,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {1} [{2}] Incorrect src ip".format(packets[0][1].src, packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result)
                elif Control_ip_network_result == 2:
                    warning_id += 1
                    Control_ip_network_result = "102 - incorrect src mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 102,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0}({1}) -> {2} [{3}] Incorrect src mac".format(packets[0][1].src,packets[0].src, packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main,pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result)
            elif check == "Internal traffic":

                segment_static_data["internal_bytes"] = segment_static_data["internal_bytes"] + len(packets.original)

                Control_ip_network_result_src = CONTROL.control_ip_input_network(packets,ip_mac_hosts)

                if Control_ip_network_result_src == 0:
                    warning_id += 1
                    Control_ip_network_result_src = "104 - incorrect interal dst ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 104,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip ,
                                           "warning": "{0} -> {1} [{2}] Incorrect interal dst ip".format(packets[0][1].src,packets[0][1].dst,packets[0][1].id)}
                    rez = SEND_DATA.send_to_server_warning("warning",socket_main,pubkey_for_server,send_data_structure)
                    print(Control_ip_network_result_src)
                elif Control_ip_network_result_src == 2:
                    warning_id += 1
                    Control_ip_network_result_src = "106 - incorrect interal dst mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 106,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {2}({1}) [{3}] Incorrect interal dst mac".format(packets[0][1].src, packets[0].dst,
                                                                               packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_src)

                Control_ip_network_result_dst = CONTROL.control_ip_output_network(packets, ip_mac_hosts)

                if Control_ip_network_result_dst == 0:
                    warning_id += 1
                    Control_ip_network_result_dst = "105 - incorrect src ip"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 105,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0} -> {1} [{2}] Incorrect interal dst ip".format(packets[0][1].src, packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_dst)
                elif Control_ip_network_result_dst == 2:
                    warning_id += 1
                    Control_ip_network_result_dst = "107 - incorrect src mac"
                    send_data_structure = {"id": warning_id,
                                           "key_warning": 107,
                                           "time": time.ctime(),
                                           "main_network_ip": main_network_ip,
                                           "warning": "{0}({1}) -> {2} [{3}] Incorrect interal src mac".format(packets[0][1].src, packets[0].src,
                                                                               packets[0][1].dst,packets[0][1].id)}
                    SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                    print(Control_ip_network_result_dst)


            (check_type_headers, type_proto ,headers_type, headers_code) = CONTROL.ckeck_headerst_type_protocol(packets)

            if check_type_headers ==  True:
                if type_proto == 1:
                    warning_id += 1
                    Control_ip_network_result_headers = key_warning_structure[headers_type][headers_type]

                    if int(Control_ip_network_result_headers[0:3]) == 111:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Port {1} in host {0} unreachable".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 110:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Protocol Unreachable".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 112:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Fragmentation Needed and Don't Fragment was Set ".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 113:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Source Route Failed".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 114:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Destination Network Unknown".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 115:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Destination Host Unknown".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 116:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Source Host Isolated".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 117:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Communication with Destination Network is Administratively Prohibited".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 118:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Communication with Destination Host is Administratively Prohibited".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 119:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Destination Network Unreachable for Type of Service".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 120:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Destination Host Unreachable for Type of Service".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 121:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Communication Administratively Prohibited".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 122:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Host Precedence Violation".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 123:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Precedence cutoff in effect".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 124:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Time to Live exceeded in Transit".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 125:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Fragment Reassembly Time Exceeded".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 126:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Pointer indicates the error".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 127:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Missing a Required Option".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    elif int(Control_ip_network_result_headers[0:3]) == 128:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Bad Length".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                    else:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}]".format(packets[0][1].src,packets[0][4].dport,
                                                                     packets[0][1].dst,packets[0][4].sport, packets[0][1].id)
                elif packets[0][1].proto == 6:
                    if packets[0][2].flags == 4:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Host {2} get RST".format(packets[0][1].src, packets[0][2].dport,
                                                                             packets[0][1].dst, packets[0][2].sport,
                                                                             packets[0][1].id)
                        Control_ip_network_result_headers = "129-Host get RST"
                    elif packets[0][2].flags == 20:
                        warning_string = "{0}::{1} -> {2}::{3} [{4}] Host {2} get RST/ASK".format(packets[0][1].src, packets[0][2].dport,
                                                                             packets[0][1].dst, packets[0][2].sport,
                                                                             packets[0][1].id)
                        Control_ip_network_result_headers = "130-Host get RST"
                send_data_structure = {"id": warning_id,
                                       "key_warning": int(Control_ip_network_result_headers[0:3]),
                                       "time": time.ctime(),
                                       "main_network_ip": main_network_ip,
                                       "warning": warning_string}
                SEND_DATA.send_to_server_warning("warning", socket_main, pubkey_for_server, send_data_structure)
                print(Control_ip_network_result_headers)


        except:
            return None


    return packets_take




if __name__ == "__main__":
    bot = SETTINGS_BOT()