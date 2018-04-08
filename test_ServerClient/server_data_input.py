import rsa, \
        socket

print_mess_warning = {
    100 : 'Incorrect dst ip',
    101 : "Incorrect src ip",
    102 : 'Incorrect src mac',
    103 : 'Incorrect dst mac',
    104 : 'Incorrect interal src ip',
    105 : 'Incorrect interal dst ip',
    106 : 'Incorrect interal src mac',
    107 : 'Incorrect interal dst macv',
    108 : 'Net Unreachable ',
    109 : 'Host Unreachable ',
    110 : 'Protocol Unreachable',
    111 : 'Port Unreachable '	,
    112 : "Fragmentation Needed and Don't Fragment was Set",
    113 : 'Source Route Failed ',
    114 : 'Destination Network Unknown',
    115 : 'Destination Host Unknown ',
    116 : 'Source Host Isolated ',
    117 : 'Communication with Destination Network is Administratively Prohibited',
    118 : 'Communication with Destination Host is Administratively Prohibited ',
    119 : 'Destination Network Unreachable for Type of Service' ,
    120	: 'Destination Host Unreachable for Type of Service' ,
    121 : 'Communication Administratively Prohibited ',
    122 : 'Host Precedence Violation ',
    123 : 'Precedence cutoff in effect',
    124 : 'Time to Live exceeded in Transit',
    125 : 'Fragment Reassembly Time Exceeded' ,
    126 : 'Pointer indicates the error' 	,
    127 : 'Missing a Required Option ',
    128 : 'Bad Length'}


class DATA_INPUT(object):

    def warning(self,connection,GUI_data_print,privkey):

        global print_mess_warning

        connection.sendall(b'start')
        send_data_structure = {"id": 0,
                               "key_warning": 0,
                               "time": 0,
                               "main_network_ip": 0,
                               "warning": 0}
        for index_structure in send_data_structure.keys():
            key_structure = connection.recv(1024)
            key_structure_decrypt = rsa.decrypt(key_structure, privkey)
            if key_structure_decrypt != b'':
                connection.sendall(b'next_data')
                data = connection.recv(1024)
                data_decrypt = rsa.decrypt(data, privkey)
            send_data_structure[key_structure_decrypt.decode("utf-8")] = data_decrypt

        data_print_on_display = "REALT{0} :: {1} :: {2} :: {3} :: {4} ".format(
            send_data_structure['time'].decode("utf-8"),
            send_data_structure['main_network_ip'].decode("utf-8")[1:-1],
            send_data_structure['id'].decode("utf-8"),
            send_data_structure['key_warning'].decode("utf-8"),
            send_data_structure['warning'].decode("utf-8"))

        # data_print_on_display = data_print_on_display + print_mess_warning[int(send_data_structure['key_warning'].decode("utf-8"))]

        GUI_data_print.sendall(bytes(data_print_on_display, encoding="utf-8"))