from scapy.all import *

class SEGMENT_DATA(object):
    """
    TIME !!!!!!!!!!!!!!!!!!!!!
    Example:
    'L2': {'type': 2048, 'dst': '20:4e:7f:51:4d:66', 'src': 'ac:2b:6e:8c:c7:6f'}
    'L3': {'ttl': 64, 'frag': 0, 'id': 47734,
            'src': '192.168.1.3', 'version': 4, 'tos': 0, 'dst': '173.194.222.198',
             'ihl': 5, 'len': 678, 'flags': 2, 'proto': 6, 'options': [], 'chksum': 12199}
    'L4': {'urgptr': 0, 'ack': 1154425737, 'sport': 35846, 'seq': 2136115724,
            'window': 1447, 'dport': 443, 'flags': 24, 'dataofs': 5, 'reserved': 0, 'options': [], 'chksum': 32770}
    """

    def data_pars(self,headers):
        headers_packet = {"L2": None,
                          "L3" : None,
                          "L4" : None}
        headers_packet["L2"] = headers.fields
        headers_packet["L3"] = headers[0][1].fields
        headers_packet["L4"] = headers[0][2].fields
        return headers_packet

    """
    URG|ACK|PSH|RST|SYN|FIN
    32 |16 | 8 | 4 | 2 | 1

    ACK=16
    SYN=2
    RST=4
    ACK+PSH=24
    SYN+ACK=20
    """

    def segment_data_check(headers,segment_data_no,traff):
        if headers[0].type == 2048:
            if headers[0][1].proto == 6:
                if headers[0][2].flags == 16:
                    if traff == "Input": segment_data_no["input_tcp_ack"] = segment_data_no["input_tcp_ack"] + 1
                    elif traff == "Output": segment_data_no["output_tcp_ack"] = segment_data_no["output_tcp_ack"] + 1
                    return segment_data_no
                elif headers[0][2].flags == 2:
                    if traff == "Input": segment_data_no["input_tcp_syn"] = segment_data_no["input_tcp_syn"] + 1
                    elif traff == "Output": segment_data_no["output_tcp_syn"] = segment_data_no["output_tcp_syn"] + 1
                    return segment_data_no
                elif headers[0][2].flags == 4:
                    if traff == "Input": segment_data_no["input_tcp_rst"] = segment_data_no["input_tcp_rst"] + 1
                    elif traff == "Output": segment_data_no["output_tcp_rst"] = segment_data_no["output_tcp_rst"] + 1
                    return segment_data_no
        else:
            return None

