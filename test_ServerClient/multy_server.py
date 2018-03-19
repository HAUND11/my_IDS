import multiprocessing,\
    socket,\
    sys, \
    time, \
    threading, \
    re
from PyQt5.QtWidgets import QApplication, \
    QBoxLayout, \
    QWidget, \
    QPushButton, \
    QTabWidget, \
    QTextEdit, \
    QTableView,\
    QListWidget, \
    QListWidgetItem
from PyQt5.QtCore import pyqtSlot

server_name = "127.0.0.1"
DEBUG = " :: DEBUG :: {}".format(sys.platform)
INFO = " :: INFO :: {}".format(sys.platform)
WARNING = " :: WARNING :: {}".format(sys.platform)
ERROR = " :: ERROR :: {}".format(sys.platform)

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Intrusion Detection System'
        self.initUI()

    def initUI(self):
        """Buttron bind server"""
        self.setWindowTitle(self.title)
        self.button_bind_server = QPushButton('Bind server', self)
        self.button_bind_server.move(1800, 950)
        self.button_bind_server.resize(80,30)
        self.button_bind_server.clicked.connect(self.on_click_bind_server)
        """Button close IDS"""
        self.button_exit = QPushButton('Close', self)
        self.button_exit.move(1800, 990)
        self.button_exit.resize(80, 30)
        self.button_exit.clicked.connect(self.on_click_exit)
        """DEBUG box"""
        self.messege_box = QTextEdit(self)
        self.messege_box.move(10,870)
        self.messege_box.resize(1750,150)
        """List widget"""
        self.ip_list = QListWidget(self)
        self.ip_list.move(10,10)
        self.ip_list.resize(280,850)
        QListWidgetItem("172.17.0.2",self.ip_list)
        """Tab Widget
            -DEBUG
            -Real time"""
        self.tabs = QTabWidget(self)
        self.tab_real_time = QWidget()
        self.tabs.resize(1460, 850)
        self.tabs.addTab(self.tab_real_time, "Real time")
        self.tabs.move(300,10)
        """Real time widgets
            -TextEdit"""
        self.tab_real_time.layout = QBoxLayout(0,self)
        self.messege_box_real_time = QTextEdit(self)
        self.param_table = QTableView(self)
        self.tab_real_time.layout.addWidget(self.messege_box_real_time)
        self.tab_real_time.layout.addWidget(self.param_table)
        self.tab_real_time.setLayout(self.tab_real_time.layout)

        self.showMaximized()

    def add_text_real_time(self, messege_text):
        self.messege_box_real_time.append(messege_text)

    def add_text_debug(self, messege_text):
        self.messege_box.append(messege_text)

    def data_socket_GUI(self):
        GUI_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        GUI_socket.bind(("127.0.0.1", 55555))
        GUI_socket.listen(1)
        GUI_conn, GUI_address = GUI_socket.accept()
        if GUI_conn != False and GUI_address != False:
            while(True):
                text_data = GUI_conn.recv(1024)
                if text_data != b'':
                    ex.add_text_debug(text_data.decode('utf-8'))




    @pyqtSlot()
    def on_click_bind_server(self):
        server = Server(server_name, 9000)  ### ИНИЦИАЛИАЦИЯ СЕРВЕРА class Server
        try:
            threading.Thread(target=server.start, name="Server_thread").start()      ### ЗАПУСК СЕРВЕРА
            threading.Thread(target=ex.data_socket_GUI, name="GUI_print_data_thread").start()
        except:
            ex.add_text_debug("{0} {1} Unexpected exception".format(time.ctime(),ERROR))
        # finally:
        #     ex.add_text_real_time("{} Shutting down".format(INFO))
    def on_click_exit(self):
        try:
            for process in multiprocessing.active_children():  ### ЗАКРЫТИЕ ВСЕХ СОЕДИНЕНИЙ
                ex.add_text_debug("{0} {1} Shutting down process {2}".format(time.ctime(),INFO,process))
                process.terminate()
                process.join()
        finally:
            sys.exit()


class Server(object): ### основной поток
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def start(self):      ### НАСТРОЙКА АДАПТЕРА И ПРИВЯЗКА
        try:
            ex.add_text_debug("{0} {1} Listening {2}:{3}".format(time.ctime(),DEBUG,self.hostname,self.port))
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(1)
            GUI_data_print = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            GUI_data_print.connect(("127.0.0.1", 55555))
        except:
            ex.add_text_debug("{0} {1} Error bind on {2}:{3}".format(time.ctime(),ERROR,self.hostname,self.port))
        while True:                                                             ### ОЖИДАНИЕ ПОДКЛЮЧЕНИЕ И ЗАПУСК ОТДЕЛЬНОГО ПРОЦЕССА ПОД КЛИЕНТА
            conn, address = self.socket.accept()
            if conn != False and address != False:
                ex.add_text_debug("{0} {1} Got connection".format(time.ctime(),DEBUG))
                process = multiprocessing.Process(target=handle, args=(conn, address,GUI_data_print))
                # process = threading.Thread(target=handle,args=(conn,address))
                process.daemon = True
                process.start()
                ex.add_text_debug("{0} {1} Started process {2}".format(time.ctime(),DEBUG,process))

def handle(connection, address,GUI_data_print):                                                ### РАБОТА СЕРВЕРА С КЛИЕНТОМ(доп поток)
    import crypto
    try:
        GUI_data_print.sendall(bytes("{0} {1} Connected {2} at {3}".format(time.ctime(),DEBUG,connection, address),encoding='utf-8'))
        while True:
            SYN_data = connection.recv(1024)
            if SYN_data == bytes(server_name+":CONNECT:SYN",encoding='utf-8'):
                time.sleep(0.5)
                GUI_data_print.sendall(bytes("{0} {1} Received start work {2}".format(time.ctime(),DEBUG,address), encoding='utf-8'))
                crypto_keys = crypto.Crypto()

                while True:
                    connection.sendall(bytes(str(crypto_keys.init_keys()["e"]),encoding='utf-8'))
                    if connection.recv(1024) == b'True correct pubkey e':
                        break
                while True:
                    connection.sendall(bytes(str(crypto_keys.init_keys()["n"]),encoding='utf-8'))
                    if connection.recv(1024) == b'True correct pubkey n':
                        break
                GUI_data_print.sendall(bytes("{0} {1} Sent keys".format(time.ctime(),DEBUG), encoding='utf-8'))
                while True:
                    bot_check_number = connection.recv(1024)
                    if bot_check_number != b'':
                        bot_controll_number = crypto_keys.decrypted(bot_check_number)
                        server_ip_for_check = re.findall(r'(\d+).', server_name + '.')
                        server_controll_nuber = (int(server_ip_for_check[0])+int(server_ip_for_check[1])+int(server_ip_for_check[2])+int(server_ip_for_check[3]))*9000
                        if server_controll_nuber == int(bot_controll_number):
                            GUI_data_print.sendall(bytes("{0} {1} Check summ is correct".format(time.ctime(),DEBUG), encoding='utf-8'))
                            break

                while True:
                    command_bot = connection.recv(1024)
                    if command_bot == b'Close connect':
                        try:
                            GUI_data_print.sendall(bytes("{0} {1} Closing socket".format(time.ctime(),DEBUG), encoding='utf-8'))
                            connection.close()
                            break
                        except:
                            GUI_data_print.sendall(bytes("{0} {1} Error closing socket".format(time.ctime(),ERROR), encoding='utf-8'))
                    else:
                        first_command = crypto_keys.decrypted(command_bot)
                        if first_command == b'warning_incorrect_input_ip':
                            connection.sendall(b'start')
                            send_data_structure = {"id": 0,
                                                   "key_warning": 0,
                                                   "time": 0,
                                                   "main_network_ip": 0,
                                                   "warning": 0}
                            for index_structure in send_data_structure.keys():
                                key_structure = connection.recv(1024)
                                if key_structure != b'':
                                    connection.sendall(b'next_data')
                                    data = connection.recv(1024)
                                # decrypt_data = crypto_keys.decrypted(data)
                                send_data_structure[key_structure.decode("utf-8")] = data
                                print(data)

                            GUI_data_print.sendall(bytes(send_data_structure["warning"].decode("utf-8"),encoding="utf-8"))
    except:
        GUI_data_print.sendall(bytes("{0} {1} Problem handling".format(time.ctime(),ERROR), encoding='utf-8'))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())