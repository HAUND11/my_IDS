from scapy.all import *
import threading
import time

segment_data = {"bytes" : 0,
                "bytes/s" : 0,
                "tcp_syn/s" : 0,}

class SEGMENT_DATA(object):

    def __init__(self):
        time_time =  threading.Thread(target=SEGMENT_DATA.segment_data_save)
        time_time.daemon = True
        time_time.start()


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
        global segment_data
        segment_data["bytes"] = segment_data["bytes"] + len(headers.original)
        headers_packet = {"L2": None,
                          "L3" : None,
                          "L4" : None}
        headers_packet["L2"] = headers.fields
        headers_packet["L3"] = headers[0][1].fields
        headers_packet["L4"] = headers[0][2].fields
        # print(headers_packet)


    def segment_data_save():
        while True:
            time.sleep(10)
            global segment_data
            segment_data["bytes/s"] = segment_data["bytes"]*8/1024/1024/10
            segment_data["bytes"] = 0
            print(segment_data["bytes/s"])



def capture_trafick(packet):
    seg.data_pars(packet)





if __name__ == "__main__":
    seg = SEGMENT_DATA()
    sniff(filter="ip",prn=capture_trafick)