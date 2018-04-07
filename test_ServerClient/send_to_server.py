import socket,\
        rsa


class SEND_DATA(object):

    def send_to_server_warning(command,socket_main,pubkey_for_server,send_data_structure):
             socket_main.sendall(rsa.encrypt(bytes(command, encoding='utf-8'), pubkey_for_server))
             if socket_main.recv(1024) == b'start':
                 for index_structure in send_data_structure.keys():
                     socket_main.sendall(rsa.encrypt(bytes(index_structure,encoding='utf-8'),pubkey_for_server))
                     if socket_main.recv(1024) == b'next_data':
                        if type(send_data_structure[index_structure]) != str:
                            socket_main.sendall(rsa.encrypt(bytes(str(send_data_structure[index_structure]),encoding='utf-8'),pubkey_for_server))
                        else:
                            socket_main.sendall(rsa.encrypt(bytes(send_data_structure[index_structure], encoding='utf-8'),pubkey_for_server))

             return True