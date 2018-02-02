import multiprocessing
import socket
server_name = "127.0.0.1"

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


if __name__ == "__main__":
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
server.close()
logging.info("All done")