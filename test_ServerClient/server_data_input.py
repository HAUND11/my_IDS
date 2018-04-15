import rsa, \
        socket
from db_serv import *



class DATA_INPUT(object):

    def warning(self,connection,GUI_data_print,privkey):


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

        DATA.INSERT_DATA_VALUE_SIGNAL(int(send_data_structure['key_warning'].decode("utf-8")),send_data_structure['main_network_ip'].decode("utf-8")[1:-1],data_print_on_display)
        DATA.UPDATE_DATA_VALUE_STATIC(int(send_data_structure['key_warning'].decode("utf-8")))

        GUI_data_print.sendall(bytes(data_print_on_display, encoding="utf-8"))