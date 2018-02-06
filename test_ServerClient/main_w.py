import sys
from PyQt5.QtWidgets import QApplication, \
    QVBoxLayout, \
    QWidget, \
    QPushButton, \
    QTabWidget, \
    QTextEdit
from PyQt5.QtCore import pyqtSlot


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
        sys.exit(app.exec_())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())