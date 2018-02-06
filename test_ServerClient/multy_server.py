import multiprocessing
import threading
import socket
import sys
from PyQt5.QtWidgets import QApplication, \
    QVBoxLayout, \
    QWidget, \
    QPushButton, \
    QTabWidget, \
    QTextEdit
from PyQt5.QtCore import pyqtSlot
server_name = "127.0.0.1"

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'Intrusion Detection System'
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.button = QPushButton('Send command', self)
        self.button.move(1400, 950)
        self.button.resize(300,50)
        self.button.clicked.connect(self.on_click)

        self.tabs = QTabWidget(self)
        self.tab_real_time = QWidget()
        self.tab_ip_host = QWidget()
        self.tabs.resize(1600, 890)
        self.tabs.addTab(self.tab_real_time, "Real time")
        self.tabs.addTab(self.tab_ip_host, "Hosts")
        self.tabs.move(300,30)

        self.tab_real_time.layout = QVBoxLayout(self)
        self.messedge_box = QTextEdit(self)
        self.tab_real_time.layout.addWidget(self.messedge_box)
        self.tab_real_time.setLayout(self.tab_real_time.layout)

        self.showMaximized()

    def add_text_real_time(self, messedge_text):
        self.messedge_box.append(messedge_text)

    @pyqtSlot()
    def on_click(self):
        start_prog()


class Server(object):
    def __init__(self, hostname, port):
        import logging
        self.logger = logging.getLogger("server")
        self.hostname = hostname
        self.port = port

    def start(self):                                                            ### НАСТРОЙКА АДАПТЕРА И ПРИВЯЗКА
        self.logger.debug("listening")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen(1)

        while True:                                                             ### ОЖИДАНИЕ ПОДКЛЮЧЕНИЕ И ЗАПУСК ОТДЕЛЬНОГО ПРОЦЕССА ПОД КЛИЕНТА
            conn, address = self.socket.accept()
            self.logger.debug("Got connection")
            process = multiprocessing.Process(target=handle, args=(conn, address))
            process.daemon = True
            process.start()
            self.logger.debug("Started process %r", process)

def start_prog():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    server = Server(server_name, 9000)                                            ### ИНИЦИАЛИАЦИЯ СЕРВЕРА class Server
    try:
        logging.info("Listening")
        server.start()                                                           ### ЗАПУСК СЕРВЕРА
    except:
        logging.exception("Unexpected exception")
    finally:
        logging.info("Shutting down")
        for process in multiprocessing.active_children():                        ### ЗАКРЫТИЕ ВСЕХ СОЕДИНЕНИЙ
            logging.info("Shutting down process %r", process)
            process.terminate()
            process.join()

def handle(connection, address):                                                ### РАБОТА СЕРВЕРА С КЛИЕНТОМ
    import crypto
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("process-%r" % (address,))
    try:
        logger.debug("Connected %r at %r", connection, address)
        while True:
            SYN_data = connection.recv(1024)
            if SYN_data == bytes(server_name+":CONNECT:SYN",encoding='utf-8'):
                logger.debug("Received start work %r", SYN_data)
                crypto_keys = crypto.Crypto()
                connection.sendall(bytes(str(crypto_keys.init_keys()["e"]),encoding='utf-8'))
                connection.sendall(bytes(str(crypto_keys.init_keys()["n"]),encoding='utf-8'))
                logger.debug("Sent keys")
                while True:
                    packet_headers = connection.recv(1024)
                    if packet_headers != b'':
                        hi = crypto_keys.decrypted(packet_headers)
                        print(hi)
    except:
        logger.exception("Problem handling request")
    finally:
        logger.debug("Closing socket")
        connection.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())


logging.info("All done")