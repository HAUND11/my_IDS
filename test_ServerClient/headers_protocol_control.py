from scapy.all import *

class CONTROL(object):

    def control_ip_input_network(header_packet,ip_mac_hosts):
        for ip_index in ip_mac_hosts:
            if ip_index[1] == header_packet[0][1].dst:
                return True

        return False

    def control_ip_output_network(header_packet,main_network_ip,host_mask,ip_mac_hosts):
        network_ip = re.findall(r'(\d+).', header_packet[0][1].src + '.')
        result = True
        for ip_index in range(0,4):
            if (int(network_ip[ip_index]) & int(host_mask[ip_index])) == int(main_network_ip[ip_index]):
                continue
            else:
                result = False
        for ip_index in ip_mac_hosts:
            if ip_index[1] == header_packet[0][1].src:
                result = True
                break
            else:
                result = False
        return result