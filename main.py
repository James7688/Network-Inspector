import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, IP, UDP

class SniffThread(QThread):
    new_packet = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        sniff(filter="udp", prn=self.packet_callback, store=0)

    def packet_callback(self, packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                packet_info = f"New Packet: {ip_layer.src} -> {ip_layer.dst}, UDP Port: {udp_layer.sport} -> {udp_layer.dport}\n"
                self.new_packet.emit(packet_info)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

        self.sniff_thread = SniffThread()
        self.sniff_thread.new_packet.connect(self.update_packets)
        self.sniff_thread.start()

    def initUI(self):
        self.setWindowTitle("Network Traffic Inspector")

        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

    def update_packets(self, packet_info):
        self.text_edit.append(packet_info)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
