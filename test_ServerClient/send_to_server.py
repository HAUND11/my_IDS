import socket,\
        rsa, \
        time


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
                            socket_main.sendall(rsa.encrypt(bytes(send_data_structure[index_structure], encoding='utf-8'),pubkey_for_server))\

    def bot_work_result(Settings_result, socket_main,pubkey_for_server,ip_mac_hosts):
        try:
            if Settings_result:
                socket_main.sendall(rsa.encrypt(b'list_widget', pubkey_for_server))
                time.sleep(1)
                socket_main.sendall(rsa.encrypt(bytes(str(len(ip_mac_hosts)),encoding='utf-8'), pubkey_for_server))
                for index_ip_mac in ip_mac_hosts:
                    time.sleep(1)
                    socket_main.sendall(rsa.encrypt(bytes(index_ip_mac[1], encoding='utf-8'), pubkey_for_server))
                    if socket_main.recv(1024):
                        time.sleep(1)
                        socket_main.sendall(rsa.encrypt(bytes(index_ip_mac[2], encoding='utf-8'), pubkey_for_server))

            else:
                socket_main.sendall("Error")
        except:
            print("Error send list ip_mac")
