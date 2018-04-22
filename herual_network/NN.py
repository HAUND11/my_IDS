from scapy.all import *
import numpy as np

"""
ARP-scan(запросы без ответов)
TCP-scan()
UDP-scan
"""


dst_dst = "192.168.9.1"
src_src = "192.168.9.130"

check_summary = 0

finish_array = []
rezult_array = []

segment_data_no = {"arp_1" : 0,
                       "arp_2" : 1,
                    "input_bytes" : 2,
                   "output_bytes" : 3,
                   "internal_bytes" : 4,
                   "internal_tcp_syn": 5,
                   "internal_tcp_rst": 6,
                   "internal_tcp_ack": 7,
                   "internal_tcp_syn_ack": 8,
                   "internal_tcp_psh_ack": 9,
                   "internal_udp": 10,
                   "input_tcp_syn": 11,
                   "input_tcp_rst": 12,
                   "input_tcp_ack": 13,
                   "input_tcp_syn_ack": 14,
                   "input_tcp_psh_ack": 15,
                   "input_udp": 16,
                   "output_udp": 17,
                   "output_tcp_syn_ack": 18,
                   "output_tcp_psh_ack": 19,
                   "output_tcp_syn": 20,
                   "output_tcp_rst": 21,
                   "output_tcp_ack": 22,
                       "Input_icmp_0_0": 23, "Input_icmp_8_0": 24,
                       "Input_icmp_3_0": 25, "Input_icmp_3_1": 26, "Input_icmp_3_2": 27, "Input_icmp_3_3": 28,
                       "Input_icmp_3_4": 29,
                       "Input_icmp_3_5": 30, "Input_icmp_3_6": 31, "Input_icmp_3_7": 32, "Input_icmp_3_8": 33,
                       "Input_icmp_3_9": 34,
                       "Input_icmp_3_10": 35, "Input_icmp_3_11": 36, "Input_icmp_3_12": 37, "Input_icmp_3_13": 38,
                       "Input_icmp_3_14": 39, "Input_icmp_3_15": 40,
                       "Input_icmp_11_0": 41, "Input_icmp_11_1": 42,
                       "Input_icmp_12_0": 43, "Input_icmp_12_1": 44, "Input_icmp_12_2": 45,
                       "Output_icmp_0_0": 46, "Output_icmp_8_0": 47,
                       "Output_icmp_3_0": 48, "Output_icmp_3_1": 49, "Output_icmp_3_2": 50, "Output_icmp_3_3": 51,
                       "Output_icmp_3_4": 52,
                       "Output_icmp_3_5": 53, "Output_icmp_3_6": 54, "Output_icmp_3_7": 55, "Output_icmp_3_8": 56,
                       "Output_icmp_3_9": 57,
                       "Output_icmp_3_10": 58, "Output_icmp_3_11": 59, "Output_icmp_3_12": 60, "Output_icmp_3_13": 61,
                       "Output_icmp_3_14": 62, "Output_icmp_3_15": 63,
                       "Output_icmp_11_0": 64, "Output_icmp_11_1": 65,
                       "Output_icmp_12_0": 66, "Output_icmp_12_1": 67, "Output_icmp_12_2": 68,
                       "Internal_icmp_0_0": 69, "Internal_icmp_8_0": 70,
                       "Internal_icmp_3_0": 71, "Internal_icmp_3_1": 72, "Internal_icmp_3_2": 73, "Internal_icmp_3_3": 74,
                       "Internal_icmp_3_4": 75,
                       "Internal_icmp_3_5": 76, "Internal_icmp_3_6": 77, "Internal_icmp_3_7": 78, "Internal_icmp_3_8": 79,
                       "Internal_icmp_3_9": 80,
                       "Internal_icmp_3_10": 81, "Internal_icmp_3_11": 82, "Internal_icmp_3_12": 83,
                       "Internal_icmp_3_13": 84, "Internal_icmp_3_14": 85, "Internal_icmp_3_15": 86,
                       "Internal_icmp_11_0": 87, "Internal_icmp_11_1": 88,
                       "Internal_icmp_12_0": 89, "Internal_icmp_12_1": 90, "Internal_icmp_12_2": 91,
                        "input_tcp_rst_ack": 92,
                        "internal_tcp_rst_ack": 93,
                        "output_tcp_rst_ack": 94,

                       }

input_train_array = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
summary_input_train_array = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
rezult_array_pcap = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

class READ_TRAFFIC(object):

    def read_pcap(dump_traffic_file):
        dump_traffic = rdpcap(dump_traffic_file)
        return dump_traffic

    def network_traffic_in_ou_inp(headers_packet):
        if headers_packet.type == 2048:
            if headers_packet[1].dst == dst_dst:
                input_train_array[3] = input_train_array[3] + len(headers_packet)
                return "Output"
            elif headers_packet[1].dst == src_src:
                input_train_array[2] = input_train_array[2] + len(headers_packet)
                return "Input"
            else:
                input_train_array[4] = input_train_array[4] + len(headers_packet)
                return "Internal traffic"

    def segment_data_check(headers,traff_check):
        """ check IPv4 """
        if headers[0].type == 2048:
            """ check TCP / UDP """
            if headers[0][1].proto == 6:
                """
                 flags ACK / SYN / RST / SYN_ASK / PSH_ACK
                """
                if headers[0][2].flags == 16:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_ack"]] = input_train_array[segment_data_no["input_tcp_ack"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_ack"]] = input_train_array[segment_data_no["output_tcp_ack"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_ack"]] = input_train_array[segment_data_no["internal_tcp_ack"]] + 1
                    return input_train_array
                elif headers[0][2].flags == 2:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_syn"]] = input_train_array[segment_data_no["input_tcp_syn"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_syn"]] = input_train_array[segment_data_no["output_tcp_syn"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_syn"]] = input_train_array[segment_data_no["internal_tcp_syn"]] + 1
                    return input_train_array
                elif headers[0][2].flags == 4:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_rst"]] = input_train_array[segment_data_no["input_tcp_rst"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_rst"]] = input_train_array[segment_data_no["output_tcp_rst"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_rst"]] = input_train_array[segment_data_no["internal_tcp_rst"]] + 1
                    return input_train_array
                elif headers[0][2].flags == 18:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_syn_ack"]] = input_train_array[segment_data_no["input_tcp_syn_ack"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_syn_ack"]] = input_train_array[segment_data_no["output_tcp_syn_ack"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_syn_ack"]] = input_train_array[segment_data_no["internal_tcp_syn_ack"]] + 1
                    return input_train_array
                elif headers[0][2].flags == 20:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_rst_ack"]] = input_train_array[segment_data_no["input_tcp_rst_ack"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_rst_ack"]] = input_train_array[segment_data_no["output_tcp_rst_ack"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_rst_ack"]] = input_train_array[segment_data_no["internal_tcp_rst_ack"]] + 1
                    return input_train_array
                elif headers[0][2].flags == 24:
                    if traff_check == "Input":
                        input_train_array[segment_data_no["input_tcp_psh_ack"]] = input_train_array[segment_data_no["input_tcp_psh_ack"]] + 1
                    elif traff_check == "Output":
                        input_train_array[segment_data_no["output_tcp_psh_ack"]] = input_train_array[segment_data_no["output_tcp_psh_ack"]] + 1
                    elif traff_check == "Internal traffic":
                        input_train_array[segment_data_no["internal_tcp_psh_ack"]] = input_train_array[segment_data_no["internal_tcp_psh_ack"]] + 1
                    return input_train_array
            elif headers[0][1].proto == 17:
                if traff_check == "Input":
                    input_train_array[segment_data_no["input_udp"]] = input_train_array[segment_data_no["input_udp"]] + 1
                elif traff_check == "Output":
                    input_train_array[segment_data_no["output_udp"]] = input_train_array[segment_data_no["output_udp"]] + 1
                elif traff_check == "Internal traffic":
                    input_train_array[segment_data_no["internal_udp"]] = input_train_array[segment_data_no["internal_udp"]] + 1
                return input_train_array
            elif headers[0][1].proto == 1:
                if traff_check == "Input":
                    input_train_array[segment_data_no["Input_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] = \
                        input_train_array[segment_data_no["Input_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] + 1
                elif traff_check == "Output":
                    input_train_array[segment_data_no["Output_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] = \
                        input_train_array[segment_data_no["Output_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] + 1
                elif traff_check == "Internal traffic":
                    input_train_array[segment_data_no["Internal_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] = \
                        input_train_array[segment_data_no["Internal_icmp_{0}_{1}".format(headers[0][2].type, headers[0][2].code)]] + 1
                return input_train_array
        elif headers[0].type == 2054:
            input_train_array[segment_data_no["arp_{}".format(headers[0][1].op)]] = input_train_array[segment_data_no["arp_{}".format(headers[0][1].op)]] + 1
            return input_train_array


    def clear_array():
        global check_summary
        check_summary += 1
        for index in range(0,95):
            if index == 2 or index == 3 or index == 4:
                summary_input_train_array[index] = summary_input_train_array[index] + input_train_array[index] * 8 / 1024 / 1024 / 1
            else:
                summary_input_train_array[index] = summary_input_train_array[index] + input_train_array[index] / 1
            input_train_array[index] = 0

    def create_data_train():
        array_train = np.array([[]])
        all_arrays = np.array([[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]])
        value = {"flood": [0, 0, 0, 0, 0, 0, 1], "normal": [0, 0, 0, 0, 0, 0, 0]}
        reault_train = np.array([value["normal"]])
        for index_index_array in range(0,94):
            if index_index_array != 2 or index_index_array != 3 or index_index_array != 4:
                for index_array_5 in range(0,95):
                    for index_num in range(0,95):
                        if index_index_array == index_num:
                            array_train = np.append(array_train,3000/1)
                        elif index_array_5 == index_num:
                            array_train = np.append(array_train, 1 / 1)
                        else:
                            array_train = np.append(array_train, 0 / 1)
                    asdasd = np.array([array_train])
                    all_arrays = np.concatenate((all_arrays,asdasd))
                    asdasd = np.array([value["flood"]])
                    reault_train = np.concatenate((reault_train,asdasd))
                    array_train = np.array([])

        return all_arrays,reault_train
if __name__ == "__main__":
     all_pcap_file =[ 'arp_scan.pcap', 'nmap_sN_192.168.9.130_192.168.9.1.pcap', 'nmap_sX_192.168.9.130_192.168.9.1.pcap',
     'nmap_sA_192.168.9.130_192.168.9.1.pcap',  'nmap_sS_192.168.9.130_192.168.9.1.pcap',  'nmap_sU_192.168.9.130_192.168.9.1.pcap',
       'nmap_sF_192.168.9.130_192.168.9.1.pcap', 'nmap_sT_192.168.9.130_192.168.9.1.pcap']#,'flood_TR.pcap', 'flood_TRA.pcap','flood_TS.pcap']

     # ins, outs = READ_TRAFFIC.create_data_train()

     # for index_pcap in all_pcap_file:
     #     pcap_file = READ_TRAFFIC.read_pcap(index_pcap)
     #     index_packet = 0
     #     time_start = pcap_file[0].time
     #     try:
     #         while True:
     #            if pcap_file[index_packet].time - time_start <= 1:
     #                status_packet = READ_TRAFFIC.network_traffic_in_ou_inp(pcap_file[index_packet])
     #                READ_TRAFFIC.segment_data_check(pcap_file[index_packet],status_packet)
     #                index_packet+=1
     #            else:
     #                time_start = pcap_file[index_packet].time
     #                READ_TRAFFIC.clear_array()
     #     except:
     #         if check_summary == 0 :
     #             for index in range(0, 95):
     #                 summary_input_train_array[index] = summary_input_train_array[index] + input_train_array[index] / 1
     #             for index_in in range(0,95):
     #                 summary_input_train_array[index_in]  = input_train_array[index_in] / 1
     #                 input_train_array[index_in] = 0
     #         else:
     #             for index in range(0, 95):
     #                 summary_input_train_array[index] = summary_input_train_array[index] + input_train_array[index] / 1
     #             for index in range(0, 95):
     #                 summary_input_train_array[index] = summary_input_train_array[index] / check_summary
     #         print(index_pcap)
     #         print(summary_input_train_array)
     #         rezult_array_pcap.append(summary_input_train_array)
     #         for index in range(0, 95):
     #             summary_input_train_array[index] = 0
     #             input_train_array[index] = 0

     # rezult_pcap = {"arp_scan" : [1,0,0,0,0,0,0],
     #                "sN": [0, 1, 0, 0, 0, 0, 0],
     #                "sX": [1, 1, 0, 0, 0, 0, 0],
     #                "sA": [0, 0, 1, 0, 0, 0, 0],
     #                "sS": [1, 0, 1, 0, 0, 0, 0],
     #                "sU": [0, 1, 1, 0, 0, 0, 0],
     #                "sF": [1, 1, 1, 0, 0, 0, 0],
     #                "sT": [0, 0, 0, 1, 0, 0, 0],}
     # ins = np.array([[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     #                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]], dtype='float32')
     # outs = np.array([[0,0,0,0,0,0,0]])
     # ins = np.concatenate((ins,rezult_array_pcap))
     # outs = np.concatenate((outs, np.array([[0,0,0,0,0,0,0]])))
     # outs = np.concatenate((outs,np.array([rezult_pcap["arp_scan"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sN"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sX"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sA"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sS"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sU"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sF"]])))
     # outs = np.concatenate((outs, np.array([rezult_pcap["sT"]])))

     ins = np.array([[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[300,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]])
     outs = np.array([[0,0,0,0,0,0,0],
                      [1, 0, 0, 0, 0, 0, 0],
                      [0, 1, 1, 0, 0, 0, 0],
                      [0, 1, 0, 1, 0, 0, 0],
                      [0, 1, 0, 0, 1, 0, 0],
                      [0, 0, 1, 1, 0, 0, 0],
                      [0, 0, 1, 0, 1, 0, 0],
                      [0, 0, 1, 0, 0, 1, 0],
                      [0, 0, 0, 0, 0, 1, 1],
                      [0, 0, 0, 0, 1, 0, 1],
                      [0, 0, 0, 1, 0, 0, 1]])

     from keras.models import Sequential
     from keras.layers.core import Dense, Dropout, Activation
     from keras.optimizers import SGD
     from keras.models import model_from_json
     import numpy as np

     model = Sequential()
     model.add(Dense(64, input_dim=95))    # input layerbatch_size=
     model.add(Activation('tanh'))
     model.add(Dropout(0,5))
     model.add(Dense(64, input_dim=95))  # input layer
     model.add(Activation('tanh'))
     model.add(Dropout(0,5))
     model.add(Dense(7))                 # output layer
     model.add(Activation('sigmoid')) # sigmoid - %, softmax

     sgd = SGD(lr=0.1)
     model.compile(loss='binary_crossentropy', optimizer='rmsprop', metrics=['accuracy'])
     model.fit(ins, outs,batch_size=32 ,epochs=100)
     for index_test in range(0,11):
        rezult = model.predict(np.array([ins[index_test]]))
        print("{}. - ".format(index_test),np.around(rezult) )
     model_json = model.to_json()
     with open("model.json", "w") as json_file:
            json_file.write(model_json)

     model.save_weights("model.h5")
     print("Saved model to disk")
