import multiprocessing,\
    socket,\
    sys, \
    time, \
    threading, \
    re
from PyQt5.QtWidgets import QApplication, \
    QVBoxLayout, \
    QWidget, \
    QPushButton, \
    QTabWidget, \
    QTextEdit
from PyQt5.QtCore import pyqtSlot

server_name = "127.0.0.1"
DEBUG = "{0} :: DEBUG :: {1}".format(time.ctime(),sys.platform)
INFO = "{0} :: INFO :: {1}".format(time.ctime(),sys.platform)
WARNING = "{0} :: WARNING :: {1}".format(time.ctime(),sys.platform)
ERROR = "{0} :: ERROR :: {1}".format(time.ctime(),sys.platform)

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Intrusion Detection System'
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.button = QPushButton('Bind server', self)
        self.button.move(1600, 950)
        self.button.resize(300,50)
        self.button.clicked.connect(self.on_click)

        self.tabs = QTabWidget(self)
        self.tab_real_time = QWidget()
        self.tab_debag = QWidget()
        self.tabs.resize(1600, 930)
        self.tabs.addTab(self.tab_debag, "DEBAG")
        self.tabs.addTab(self.tab_real_time, "Real time")
        self.tabs.move(300,10)

        self.tab_debag.layout = QVBoxLayout(self)
        self.messege_box = QTextEdit(self)
        self.tab_debag.layout.addWidget(self.messege_box)
        self.tab_debag.setLayout(self.tab_debag.layout)

        self.showMaximized()

    def add_text_real_time(self, messege_text):
        self.messege_box.append(messege_text)

    @pyqtSlot()
    def on_click(self):
        server = Server(server_name, 9000)  ### ИНИЦИАЛИАЦИЯ СЕРВЕРА class Server
        try:
            threading.Thread(target=server.start, name="Server_thread").start()       ### ЗАПУСК СЕРВЕРА
        except:
            ex.add_text_real_time("{} Unexpected exception".format(ERROR))
        # finally:
        #     ex.add_text_real_time("{} Shutting down".format(INFO))
        #     for process in multiprocessing.active_children():  ### ЗАКРЫТИЕ ВСЕХ СОЕДИНЕНИЙ
        #         ex.add_text_real_time("{0} Shutting down process {1}".format(INFO,process))
        #         process.terminate()
        #         process.join()


class Server(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def start(self):      ### НАСТРОЙКА АДАПТЕРА И ПРИВЯЗКА
        try:
            ex.add_text_real_time("{0} Listening {1}:{2}".format(DEBUG,self.hostname,self.port))
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(1)
        except:
            ex.add_text_real_time("{0} Error bind on {1}:{2}".format(ERROR,self.hostname,self.port))
        while True:                                                             ### ОЖИДАНИЕ ПОДКЛЮЧЕНИЕ И ЗАПУСК ОТДЕЛЬНОГО ПРОЦЕССА ПОД КЛИЕНТА
            conn, address = self.socket.accept()
            ex.add_text_real_time("{} Got connection".format(DEBUG))
            # process = multiprocessing.Process(target=handle, args=(conn, address))
            process = threading.Thread(target=handle,args=(conn,address))
            process.daemon = True
            process.start()
            ex.add_text_real_time("{0}Started process {1}".format(DEBUG,process))

def handle(connection, address):                                                ### РАБОТА СЕРВЕРА С КЛИЕНТОМ
    import crypto
    try:
        ex.add_text_real_time("{0} Connected {1} at {2}".format(DEBUG,connection, address))
        while True:
            SYN_data = connection.recv(1024)
            if SYN_data == bytes(server_name+":CONNECT:SYN",encoding='utf-8'):
                ex.add_text_real_time("{0} Received start work {1}".format(DEBUG,SYN_data))
                crypto_keys = crypto.Crypto()
                while True:
                    connection.sendall(bytes(str(crypto_keys.init_keys()["e"]),encoding='utf-8'))
                    if connection.recv(1024) == b"True correct pubkey e": break
                while True:
                    connection.sendall(bytes(str(crypto_keys.init_keys()["n"]),encoding='utf-8'))
                    if connection.recv(1024) == b"True correct pubkey n": break
                ex.add_text_real_time("{} Sent keys".format(DEBUG))
                while True:
                    bot_check_number = connection.recv(1024)
                    if bot_check_number != b'':
                        bot_controll_number = crypto_keys.decrypted(bot_check_number)
                        server_ip_for_check = re.findall(r'(\d+).', server_name + '.')
                        server_controll_nuber = (int(server_ip_for_check[0])+int(server_ip_for_check[1])+int(server_ip_for_check[2])+int(server_ip_for_check[3]))*9000
                        if server_controll_nuber == int(bot_controll_number):
                            ex.add_text_real_time("{} Check summ is correct".format(DEBUG))
                            print(bot_controll_number)
    except:
        ex.add_text_real_time("{} Problem handling request".format(ERROR))
    finally:
        ex.add_text_real_time("{} Closing socket".format(DEBUG))
        connection.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())