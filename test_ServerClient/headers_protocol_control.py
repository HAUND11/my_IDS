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
        # if result == 0: return result
        # for mac_index in ip_mac_hosts:
        #     if mac_index[2] == header_packet[0].dst:
        #         result = 1
        #         break
        #     else:
        #         result = 2
            return result

    def control_ip_output_network(header_packet,main_network_ip,host_mask,ip_mac_hosts):
        # network_ip = re.findall(r'(\d+).', header_packet[0][1].src + '.')
        result = 0
        # for ip_index in range(0,4):
        #     if (int(network_ip[ip_index]) & int(host_mask[ip_index])) == int(main_network_ip[ip_index]):
        #         continue
        #     else:
        #         result = 0
        #         return result
        if header_packet[0].type == 2048:
            for ip_mac_index in ip_mac_hosts:
                if ip_mac_index[1] == header_packet[0][1].src:
                    result = 1
                    if ip_mac_index[2] != header_packet[0].src:
                        result = 2
                    break
        # if result == 0: return result
        # for mac_index in ip_mac_hosts:
        #     if mac_index[2] == header_packet[0].src:
        #         break
        #     else:
        #         result = 2
            return result

    def check_input_output(packets, main_network_ip, host_mask):
        network_ip_src = re.findall(r'(\d+).', packets[0][1].src + '.')
        network_ip_dst = re.findall(r'(\d+).', packets[0][1].dst + '.')
        output = True
        input = True
        for ip_index in range(0, 4):
            if (int(network_ip_src[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                output = False
            if (int(network_ip_dst[ip_index]) & int(host_mask[ip_index])) != int(main_network_ip[ip_index]):
                input = False
        if output == True:
            return "Output"
        elif input == True:
            return "Input"
        else:
            return "Forvard"