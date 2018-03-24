from scapy.all import *

class CONTROL(object):

    def control_ip_input_network(header_packet,ip_mac_hosts):
        result = 0
        for ip_index in ip_mac_hosts:
            if ip_index[1] == header_packet[0][1].dst:
                result = 1
        if result == 0: return result
        for mac_index in ip_mac_hosts:
            print(header_packet[Ether].dst)
            if mac_index[2] == header_packet[Ether].dst:
                result = 1
                break
            else:
                result = 2
        return result

    def control_ip_output_network(header_packet,main_network_ip,host_mask,ip_mac_hosts):
        network_ip = re.findall(r'(\d+).', header_packet[0][1].src + '.')
        result = 1
        for ip_index in range(0,4):
            if (int(network_ip[ip_index]) & int(host_mask[ip_index])) == int(main_network_ip[ip_index]):
                continue
            else:
                result = 0
                return result
        for ip_index in ip_mac_hosts:
            if ip_index[1] == header_packet[0][1].src:
                result = 1
                break
            else:
                result = 0
        if result == 0: return result
        for mac_index in ip_mac_hosts:
            if mac_index[2] == header_packet[Ether].src:
                break
            else:
                result = 2
        return result