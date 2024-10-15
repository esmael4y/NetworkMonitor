import sys
import psutil
import scapy.all as scapy
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget, QPushButton, QTextEdit, QScrollArea, QFileDialog, QLabel, QRadioButton, QButtonGroup, QDialog, QDialogButtonBox
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from collections import defaultdict, deque
import csv
from fpdf import FPDF

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        def packet_callback(packet):
            packet_info = {'size': len(packet)}
            if scapy.IP in packet:
                packet_info['src_ip'] = packet[scapy.IP].src
                packet_info['dst_ip'] = packet[scapy.IP].dst
                packet_info['proto'] = packet[scapy.IP].proto
                if scapy.TCP in packet:
                    packet_info['sport'] = packet[scapy.TCP].sport
                    packet_info['dport'] = packet[scapy.TCP].dport
                elif scapy.UDP in packet:
                    packet_info['sport'] = packet[scapy.UDP].sport
                    packet_info['dport'] = packet[scapy.UDP].dport
            self.packet_captured.emit(packet_info)

        scapy.sniff(prn=packet_callback, store=False)

    def stop(self):
        self.running = False

class SaveDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Save Data")
        self.setGeometry(200, 200, 300, 150)

        self.layout = QVBoxLayout(self)

        self.label = QLabel("Choose the format to save the data:")
        self.layout.addWidget(self.label)

        self.pdf_radio = QRadioButton("PDF")
        self.csv_radio = QRadioButton("CSV")
        self.layout.addWidget(self.pdf_radio)
        self.layout.addWidget(self.csv_radio)

        self.button_group = QButtonGroup(self)
        self.button_group.addButton(self.pdf_radio)
        self.button_group.addButton(self.csv_radio)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

    def get_selected_format(self):
        if self.pdf_radio.isChecked():
            return 'pdf'
        elif self.csv_radio.isChecked():
            return 'csv'
        return None

class NetworkMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitor")
        self.setGeometry(100, 100, 1000, 800)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.setup_packet_capture_tab()
        self.setup_network_usage_tab()
        self.setup_statistics_tab()

        self.packet_capture_thread = PacketCaptureThread()
        self.packet_capture_thread.packet_captured.connect(self.update_packet_info)
        self.packet_capture_thread.start()

        self.network_usage_timer = QTimer(self)
        self.network_usage_timer.timeout.connect(self.update_network_usage)
        self.network_usage_timer.start(1000)  # Update every second

        self.packet_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.packet_sizes = []
        self.network_stats = {'bytes_sent': [], 'bytes_recv': []}
        self.recent_packets = deque(maxlen=20)

    def setup_packet_capture_tab(self):
        packet_capture_widget = QWidget()
        packet_capture_layout = QVBoxLayout(packet_capture_widget)

        self.packet_info_text = QTextEdit()
        self.packet_info_text.setReadOnly(True)
        packet_capture_layout.addWidget(self.packet_info_text)

        update_button = QPushButton("Update Packet Display")
        update_button.clicked.connect(self.update_packet_display)
        packet_capture_layout.addWidget(update_button)

        save_data_button = QPushButton("Save Packet Data")
        save_data_button.clicked.connect(self.open_save_dialog)
        packet_capture_layout.addWidget(save_data_button)

        self.tabs.addTab(packet_capture_widget, "Packet Capture")

    def setup_network_usage_tab(self):
        network_usage_widget = QWidget()
        network_usage_layout = QVBoxLayout(network_usage_widget)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        self.network_usage_figure, axes = plt.subplots(2, 2, figsize=(15, 12))
        self.ax1, self.ax2, self.ax3, self.ax4 = axes[0, 0], axes[0, 1], axes[1, 0], axes[1, 1]

        self.network_usage_canvas = FigureCanvas(self.network_usage_figure)
        scroll_layout.addWidget(self.network_usage_canvas)

        scroll_area.setWidget(scroll_content)
        network_usage_layout.addWidget(scroll_area)

        self.tabs.addTab(network_usage_widget, "Network Usage")

    def setup_statistics_tab(self):
        statistics_widget = QWidget()
        statistics_layout = QVBoxLayout(statistics_widget)

        self.statistics_text = QTextEdit()
        self.statistics_text.setReadOnly(True)
        statistics_layout.addWidget(self.statistics_text)

        update_stats_button = QPushButton("Update Statistics")
        update_stats_button.clicked.connect(self.update_statistics)
        statistics_layout.addWidget(update_stats_button)

        self.tabs.addTab(statistics_widget, "Statistics")

    def update_packet_info(self, packet_info):
        self.recent_packets.appendleft(packet_info)

        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
            self.packet_counts[(packet_info['src_ip'], packet_info['dst_ip'])] += 1
        if 'proto' in packet_info:
            self.protocol_counts[packet_info['proto']] += 1
        if 'sport' in packet_info:
            self.port_counts[packet_info['sport']] += 1
        if 'dport' in packet_info:
            self.port_counts[packet_info['dport']] += 1
        self.packet_sizes.append(packet_info['size'])

    def update_packet_display(self):
        self.packet_info_text.clear()
        for packet in self.recent_packets:
            self.packet_info_text.append(str(packet))

    def update_network_usage(self):
        stats = psutil.net_io_counters()
        self.network_stats['bytes_sent'].append(stats.bytes_sent)
        self.network_stats['bytes_recv'].append(stats.bytes_recv)

        self.ax1.clear()
        self.ax1.plot(self.network_stats['bytes_sent'], label='Bytes Sent')
        self.ax1.plot(self.network_stats['bytes_recv'], label='Bytes Received')
        self.ax1.set_title('Network Usage Over Time')
        self.ax1.set_xlabel('Time (seconds)')
        self.ax1.set_ylabel('Bytes')
        self.ax1.legend()

        self.ax2.clear()
        self.ax2.bar(range(len(self.protocol_counts)), list(self.protocol_counts.values()), align='center')
        self.ax2.set_title('Protocol Distribution')
        self.ax2.set_xlabel('Protocol')
        self.ax2.set_ylabel('Packet Count')
        self.ax2.set_xticks(range(len(self.protocol_counts)))
        self.ax2.set_xticklabels(list(self.protocol_counts.keys()))

        self.ax3.clear()
        self.ax3.hist(self.packet_sizes, bins=20)
        self.ax3.set_title('Packet Size Distribution')
        self.ax3.set_xlabel('Packet Size (bytes)')
        self.ax3.set_ylabel('Frequency')

        self.ax4.clear()
        sorted_connections = sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        labels = [f"{conn[0]}\n->\n{conn[1]}" for conn, _ in sorted_connections]
        sizes = [count for _, count in sorted_connections]
        self.ax4.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        self.ax4.set_title('Top 5 IP Connections')
        self.network_usage_figure.tight_layout()
        
        self.network_usage_canvas.draw()

    def update_statistics(self):
        stats = "Network Traffic Analysis Statistics:\n\n"

        stats += "Packet Statistics:\n"
        stats += f"Total packets captured: {sum(self.packet_counts.values())}\n"
        if self.packet_sizes:
            stats += f"Average packet size: {sum(self.packet_sizes) / len(self.packet_sizes):.2f} bytes\n\n"

        stats += "Top 5 IP Connections:\n"
        sorted_connections = sorted(self.packet_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for connection, count in sorted_connections:
            stats += f"{connection[0]} -> {connection[1]}: {count} packets\n"
            stats += "\n"

        stats += "Protocol Distribution:\n"
        for proto, count in self.protocol_counts.items():
            stats += f"Protocol {proto}: {count} packets\n"
        stats += "\n"

        stats += "Top 5 Active Ports:\n"
        sorted_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for port, count in sorted_ports:
            stats += f"Port {port}: {count} packets\n"

        self.statistics_text.setText(stats)

    def open_save_dialog(self):
        dialog = SaveDialog(self)
        if dialog.exec_():
            file_format = dialog.get_selected_format()
            if file_format:
                options = QFileDialog.Options()
                file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", f"{file_format.upper()} Files (*.{file_format});;All Files (*)", options=options)
                if file_name:
                    self.save_data(file_name, file_format)

    def save_data(self, file_name, file_format):
        if file_format == 'csv':
            self.save_to_csv(file_name)
        elif file_format == 'pdf':
            self.save_to_pdf(file_name)

    def save_to_csv(self, file_name):
        with open(file_name, mode='w', newline='') as file:
            writer = csv.writer(file)
            
            # Save Packet Info
            writer.writerow(['Packet Capture'])
            writer.writerow(['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Size'])
            for packet in self.recent_packets:
                writer.writerow([packet.get('src_ip', ''), packet.get('dst_ip', ''), packet.get('proto', ''), packet.get('sport', ''), packet.get('dport', ''), packet.get('size', '')])
            
            writer.writerow([])
            
            # Save Network Statistics
            writer.writerow(['Network Statistics'])
            writer.writerow(['Bytes Sent', 'Bytes Received'])
            for sent, recv in zip(self.network_stats['bytes_sent'], self.network_stats['bytes_recv']):
                writer.writerow([sent, recv])
            
            writer.writerow([])

            # Save Protocol Counts
            writer.writerow(['Protocol Distribution'])
            writer.writerow(['Protocol', 'Count'])
            for proto, count in self.protocol_counts.items():
                writer.writerow([proto, count])

            writer.writerow([])

            # Save Packet Size Distribution
            writer.writerow(['Packet Size Distribution'])
            writer.writerow(['Packet Size', 'Frequency'])
            for size in self.packet_sizes:
                writer.writerow([size])

    def save_to_pdf(self, file_name):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Save Packet Info
        pdf.cell(200, 10, txt="Packet Capture Data", ln=True, align='C')
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        pdf.cell(40, 10, "Source IP")
        pdf.cell(40, 10, "Destination IP")
        pdf.cell(40, 10, "Protocol")
        pdf.cell(40, 10, "Source Port")
        pdf.cell(40, 10, "Destination Port")
        pdf.cell(20, 10, "Size")
        pdf.ln(10)
        for packet in self.recent_packets:
            pdf.cell(40, 10, str(packet.get('src_ip', '')))
            pdf.cell(40, 10, str(packet.get('dst_ip', '')))
            pdf.cell(40, 10, str(packet.get('proto', '')))
            pdf.cell(40, 10, str(packet.get('sport', '')))
            pdf.cell(40, 10, str(packet.get('dport', '')))
            pdf.cell(20, 10, str(packet.get('size', '')))
            pdf.ln(10)

        # Save Network Statistics
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Network Statistics", ln=True, align='C')
        pdf.ln(10)
        pdf.cell(50, 10, "Bytes Sent", 0, 0)
        pdf.cell(50, 10, "Bytes Received", 0, 1)
        for sent, recv in zip(self.network_stats['bytes_sent'], self.network_stats['bytes_recv']):
            pdf.cell(50, 10, str(sent))
            pdf.cell(50, 10, str(recv))
            pdf.ln(10)

        # Save Protocol Counts
        pdf.add_page()
        pdf.cell(200, 10, txt="Protocol Distribution", ln=True, align='C')
        pdf.ln(10)
        pdf.cell(60, 10, "Protocol")
        pdf.cell(60, 10, "Count", ln=1)
        for proto, count in self.protocol_counts.items():
            pdf.cell(60, 10, str(proto))
            pdf.cell(60, 10, str(count), ln=1)

        # Save Packet Size Distribution
        pdf.add_page()
        pdf.cell(200, 10, txt="Packet Size Distribution", ln=True, align='C')
        pdf.ln(10)
        for size in self.packet_sizes:
            pdf.cell(40, 10, str(size))
            pdf.ln(10)

        pdf.output(file_name)

    def closeEvent(self, event):
        self.packet_capture_thread.stop()
        self.packet_capture_thread.wait()
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitorGUI()
    window.show()
    sys.exit(app.exec_())
