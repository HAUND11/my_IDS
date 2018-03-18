import socket,\
        rsa


class SEND_DATA(object):

    def send_to_server_warning(command,socket_main,pubkey_for_server,send_data_structure):
        if send_data_structure['key_warning'] == 100:
             socket_main.sendall(rsa.encrypt(bytes(command, encoding='utf-8'), pubkey_for_server))
             for index_structure in send_data_structure.keys():
                 socket_main.sendall(rsa.encrypt(bytes(str(send_data_structure[index_structure]),encoding='utf-8'),pubkey_for_server))
             socket_main.sendall(b'END')
                 # socket_main.sendall(rsa.encrypt(bytes(str(key_warning), encoding='utf-8'), pubkey_for_server))
                 # socket_main.sendall(rsa.encrypt(bytes(str(host_ip), encoding='utf-8'), pubkey_for_server))
                 # socket_main.sendall(rsa.encrypt(bytes(warning, encoding='utf-8'), pubkey_for_server))
                 # socket_main.sendall(rsa.encrypt(data, pubkey_for_server))