import multiprocessing,\
    socket,\
    sys, \
    time, \
    threading, \
    re, \
    rsa
from db_serv import *
from PyQt5.QtWidgets import QApplication, \
    QBoxLayout, \
    QWidget, \
    QPushButton, \
    QTabWidget, \
    QTextEdit, \
    QTableView,\
    QListWidget, \
    QListWidgetItem
from PyQt5.QtGui import *
from PyQt5.QtCore import pyqtSlot

server_name = "127.0.0.1"

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
    128 : 'Bad Length',
    129 : 'Host get RST',
    130 : 'Host get RST/ACk'}

"""Print data"""

DEBUG = " :: DEBUG :: {}".format(sys.platform)
INFO = " :: INFO :: {}".format(sys.platform)
WARNING = " :: WARNING :: {}".format(sys.platform)
ERROR = " :: ERROR :: {}".format(sys.platform)

"""Warning print
    tine :: main_network :: id :: key_warning :: messedge"""

class App(QWidget):

    def __init__(self):
        DATA.CREATE()
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
        self.ip_list.itemClicked.connect(self.on_click_list_widget_item)
        """Tab Widget
            -DEBUG
            -Real time"""
        self.tabs = QTabWidget(self)
        self.tab_real_time = QWidget()
        self.tabs.resize(1460, 850)
        self.tabs.addTab(self.tab_real_time, "Real time")
        self.tabs.move(300,10)

        """Real time widgets
            -TextEdit
            -TableView"""

        self.messege_box_real_time = QTextEdit(self.tab_real_time)
        self.param_table = QTableView(self.tab_real_time)
        self.messege_box_real_time.resize(1000,821)
        self.param_table.move(1002,0)
        self.param_table.resize(454,821)
        self.model_for_table_view = QStandardItemModel(self.param_table)
        self.model_for_table_view.setHorizontalHeaderLabels(["Value","Comments"])
        self.model_for_table_view.setVerticalHeaderLabels(["100", "101", "102", "103", "104", "105",
                                                           "106", "107", "108", "109", "110", "111",
                                                           "112", "113", "114", "115", "116", "117",
                                                           "118", "119", "120", "121", "122", "123",
                                                           "124", "125", "126", "127", "128","129","130"])
        self.param_table.setModel(self.model_for_table_view)
        self.param_table.setAlternatingRowColors(True)
        self.param_table.setAutoScroll(True)

        for index_new_data_table in range(100,131):
            self.model_for_table_view.setItem(index_new_data_table-100, 0, QStandardItem("0"))
            self.model_for_table_view.setItem(index_new_data_table - 100, 1, QStandardItem(print_mess_warning[index_new_data_table]))

        self.showMaximized()
        time_time = threading.Thread(target=self.update_data_while)
        time_time.daemon = True
        time_time.start()

    def update_data_while(self):
        while True:
            time.sleep(10)
            update_data = DATA.GET_ALL_DATA()
            for index_update_data in update_data:
                self.model_for_table_view.setItem(index_update_data[1]-100, 0, QStandardItem(str(index_update_data[2])))

    def add_text_real_time(self, messege_text):
        self.messege_box_real_time.append(messege_text)

    def add_text_debug(self, messege_text):
        self.messege_box.append(messege_text)

    def add_item_on_list_widget(self,ip_mac_table):
        for index_list_widget in ip_mac_table:
            self.ip_list.addItem(index_list_widget[1])

    def data_socket_GUI(self):
        GUI_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        GUI_socket.bind(("127.0.0.1", 55555))
        GUI_socket.listen(1)
        GUI_conn, GUI_address = GUI_socket.accept()
        if GUI_conn != False and GUI_address != False:
            while(True):
                text_data = GUI_conn.recv(1024)
                text_data = text_data.decode('utf-8')
                if text_data[0:5] == "DEBUG":
                    ex.add_text_debug(text_data[5:])
                elif text_data[0:5] == "REALT":
                    ex.add_text_real_time(text_data[5:])
                elif text_data[0:5] == "LISTW":
                    ip_mac_table = DATA.GET_ALL_DATA_ARP_HOST()
                    ex.add_item_on_list_widget(ip_mac_table)




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

    def on_click_close_tab(self):
        self.tabs.removeTab(self.tabs.currentIndex())

    def on_click_push_update(self):
        self.messege_box_real_time_to_host.clear()
        for index_new_data_table in range(100,131):
            self.model_for_table_view_tab.setItem(index_new_data_table-100, 0, QStandardItem("0"))

        data_print = DATA.GET_ALL_DATA_SIGNAL()
        for index_print in data_print:
            ip_src_dst = re.findall(r'(\d+\.\d+\.\d+\.\d+)', index_print[3])
            if ip_src_dst[0] == self.ip_tab.text() or ip_src_dst[1] == self.ip_tab.text():
                self.messege_box_real_time_to_host.append(index_print[3][5:])
                self.model_for_table_view_tab.setItem(index_print[2] - 100, 0, QStandardItem(str(int(self.model_for_table_view_tab.data(self.model_for_table_view_tab.index(index_print[2] - 100, 0))) + 1)))


    def on_click_list_widget_item(self,item):
        global print_mess_warning

        self.tab_to_host= QWidget()
        self.ip_tab = item
        self.tabs.addTab(self.tab_to_host, item.text())
        button_close = QPushButton("Close tab",self.tab_to_host)
        button_push = QPushButton("Update", self.tab_to_host)
        self.messege_box_real_time_to_host = QTextEdit(self.tab_to_host)
        self.param_table_to_host = QTableView(self.tab_to_host)
        self.messege_box_real_time_to_host.resize(1000, 821)
        self.param_table_to_host.move(1002, 0)
        button_close.move(1280,780)
        button_push.move(1080, 780)
        self.param_table_to_host.resize(454, 750)
        self.model_for_table_view_tab = QStandardItemModel(self.param_table_to_host)
        self.model_for_table_view_tab.setHorizontalHeaderLabels(["Value"])
        self.model_for_table_view_tab.setVerticalHeaderLabels(["100", "101", "102","103","104","105",
                                                           "106", "107", "108", "109", "110", "111",
                                                           "112", "113", "114", "115", "116", "117",
                                                           "118", "119", "120", "121", "122", "123",
                                                           "124", "125", "126", "127", "128", "129","130"])
        self.param_table_to_host.setModel(self.model_for_table_view_tab)
        self.param_table_to_host.setAlternatingRowColors(True)
        self.param_table_to_host.setAutoScroll(True)

        button_close.clicked.connect(self.on_click_close_tab)
        button_push.clicked.connect(self.on_click_push_update)

        for index_new_data_table in range(100,131):
            self.model_for_table_view_tab.setItem(index_new_data_table-100, 0, QStandardItem("0"))
            self.model_for_table_view_tab.setItem(index_new_data_table - 100, 1, QStandardItem(print_mess_warning[index_new_data_table]))

        data_print = DATA.GET_ALL_DATA_SIGNAL()
        for index_print in data_print:
            ip_src_dst = re.findall(r'(\d+\.\d+\.\d+\.\d+)', index_print[3])
            if ip_src_dst[0] == item.text() or ip_src_dst[1] == item.text():
                self.messege_box_real_time_to_host.append(index_print[3][5:])
                self.model_for_table_view_tab.setItem(index_print[2]-100,0,QStandardItem(str(int(self.model_for_table_view_tab.data(self.model_for_table_view_tab.index(index_print[2] - 100, 0)))+1)))



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

def handle(connection, address,GUI_data_print):
    ### РАБОТА СЕРВЕРА С КЛИЕНТОМ(доп поток)
    import server_data_input
    input_to_server = server_data_input.DATA_INPUT()

    # try:
    GUI_data_print.sendall(bytes("DEBUG{0} {1} Connected {2} at {3}".format(time.ctime(),DEBUG,connection, address),encoding='utf-8'))
    while True:
            SYN_data = connection.recv(1024)
            if SYN_data == bytes(server_name+":CONNECT:SYN",encoding='utf-8'):
                time.sleep(0.5)
                GUI_data_print.sendall(bytes("DEBUG{0} {1} Received start work {2}".format(time.ctime(),DEBUG,address), encoding='utf-8'))
                # crypto_keys = crypto.Crypto()
                (pubkey, privkey) = rsa.newkeys(1024, accurate=True, poolsize=1)
                while True:
                    connection.sendall(bytes(str(pubkey["e"]),encoding='utf-8'))
                    if connection.recv(1024) == b'True correct pubkey e':
                        break
                while True:
                    connection.sendall(bytes(str(pubkey["n"]),encoding='utf-8'))
                    if connection.recv(1024) == b'True correct pubkey n':
                        break
                GUI_data_print.sendall(bytes("DEBUG{0} {1} Sent keys".format(time.ctime(),DEBUG), encoding='utf-8'))
                while True:
                    bot_check_number = connection.recv(1024)
                    if bot_check_number != b'':
                        bot_controll_number = rsa.decrypt(bot_check_number,privkey)
                        server_ip_for_check = re.findall(r'(\d+).', server_name + '.')
                        server_controll_nuber = (int(server_ip_for_check[0])+int(server_ip_for_check[1])+int(server_ip_for_check[2])+int(server_ip_for_check[3]))*9000
                        if server_controll_nuber == int(bot_controll_number):
                            GUI_data_print.sendall(bytes("DEBUG{0} {1} Check summ is correct".format(time.ctime(),DEBUG), encoding='utf-8'))
                            break

                while True:
                    command_bot = connection.recv(1024)
                    if command_bot == b'Close connect':
                        try:
                            GUI_data_print.sendall(bytes("DEBUG{0} {1} Closing socket".format(time.ctime(),DEBUG), encoding='utf-8'))
                            connection.close()
                            break
                        except:
                            GUI_data_print.sendall(bytes("DEBUG{0} {1} Error closing socket".format(time.ctime(),ERROR), encoding='utf-8'))
                    else:
                        first_command = rsa.decrypt(command_bot,privkey)
                        if first_command == b'warning':
                            input_to_server.warning(connection,GUI_data_print,privkey)
                        elif first_command == b'list_widget':
                            data_list_widget = {"host_ip" : 0 , "host_mac" : 0}
                            index_for =  int(rsa.decrypt(connection.recv(1024),privkey).decode("utf-8"))
                            for index_list in range(0,index_for):
                                data_list_widget["host_ip"] = rsa.decrypt(connection.recv(1024),privkey).decode("utf-8")
                                connection.sendall(b'dfjktrnb')  # next data
                                data_list_widget["host_mac"] = rsa.decrypt(connection.recv(1024), privkey).decode("utf-8")
                                if not DATA.CHEK_ARP_DATA_IN_TABLE(data_list_widget["host_ip"],data_list_widget["host_mac"]):
                                    DATA.INSERT_ARP_DATA(data_list_widget["host_ip"],data_list_widget["host_mac"])
                            GUI_data_print.sendall(b'LISTW')

    # except:
    #     GUI_data_print.sendall(bytes("DEBUG{0} {1} Problem handling".format(time.ctime(),ERROR), encoding='utf-8'))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())