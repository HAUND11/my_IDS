from scapy.all import *

class CONTROL(object):

    def control_ip_input_network(header_packet,ip_mac_hosts):
        result = 0
        if header_packet[0].type == 2048:
            for ip_mac_index in ip_mac_hosts:
                if ip_mac_index[1] == header_packet[0][1].dst:
                    result = 1
                    if ip_mac_index[2] != header_packet[0].dst:
                        result = 2
                    break
            return result

    def control_ip_output_network(header_packet,ip_mac_hosts):
        result = 0
        if header_packet[0].type == 2048:
            for ip_mac_index in ip_mac_hosts:
                if ip_mac_index[1] == header_packet[0][1].src:
                    result = 1
                    if ip_mac_index[2] != header_packet[0].src:
                        result = 2
                    break
            return result

    def check_input_output(host_ip,packets, main_network_ip, host_mask):
        network_ip_src = re.findall(r'(\d+).', packets[0][1].src + '.')
        network_ip_dst = re.findall(r'(\d+).', packets[0][1].dst + '.')
        output = True
        input = True
        if host_ip[0] == packets[0][1].src:
            for ip_index in range(0, 4):
                if (int(network_ip_dst[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                    input = False
        elif host_ip[0] == packets[0][1].dst:
            for ip_index in range(0, 4):
                if (int(network_ip_src[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                    output = False
        else:
            for ip_index in range(0, 4):
                if (int(network_ip_src[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                    output = False
                if (int(network_ip_dst[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                    input = False
        if output == True and input == True:
            return "Internal traffic"
        elif output == True:
            return "Output"
        elif input == True:
            return "Input"
        else:
            return "Forvard"