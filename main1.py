import csv
import ipaddress
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QSpacerItem,
    QSizePolicy,
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# 尝试导入真实扫描接口
# 如果 scanner_adapter.py 有问题，程序不会直接崩溃，而是使用模拟扫描
try:
    from scanner_adapter import real_scan
    ADAPTER_AVAILABLE = True
except Exception as e:
    ADAPTER_AVAILABLE = False
    ADAPTER_ERROR = str(e)


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "Remote Desktop",
    6379: "Redis",
    8080: "HTTP-Proxy",
}


class PortScannerWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("网络端口扫描系统")
        self.resize(1100, 720)

        self.results = []

        self.init_ui()
        self.apply_style()

        if not ADAPTER_AVAILABLE:
            self.log("[WARNING] scanner_adapter.py 导入失败，当前使用模拟扫描模式")
            self.log(f"[WARNING] 错误信息：{ADAPTER_ERROR}")

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        # ================== 标题区 ==================
        title_label = QLabel("网络端口扫描系统")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 28px;
                font-weight: bold;
                color: #1f3a5f;
                padding-top: 10px;
                padding-bottom: 4px;
            }
        """)

        subtitle_label = QLabel("支持 ICMP 主机探测、TCP Connect、TCP SYN、TCP FIN 扫描与结果导出")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #64748b;
                padding-bottom: 8px;
            }
        """)

        main_layout.addWidget(title_label)
        main_layout.addWidget(subtitle_label)

        # ================== 参数输入区 ==================
        input_group = QGroupBox("扫描参数")
        input_layout = QGridLayout()

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("例如：127.0.0.1 或 192.168.1.1")
        self.ip_input.setText("127.0.0.1")

        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("例如：20")
        self.start_port_input.setText("20")

        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("例如：100")
        self.end_port_input.setText("100")

        input_layout.addWidget(QLabel("目标 IP："), 0, 0)
        input_layout.addWidget(self.ip_input, 0, 1)

        input_layout.addWidget(QLabel("起始端口："), 0, 2)
        input_layout.addWidget(self.start_port_input, 0, 3)

        input_layout.addWidget(QLabel("结束端口："), 0, 4)
        input_layout.addWidget(self.end_port_input, 0, 5)

        input_group.setLayout(input_layout)

        # ================== 扫描方式区 ==================
        method_group = QGroupBox("扫描方式")
        method_layout = QHBoxLayout()

        self.icmp_check = QCheckBox("ICMP 主机检测")
        self.connect_check = QCheckBox("TCP Connect")
        self.syn_check = QCheckBox("TCP SYN")
        self.fin_check = QCheckBox("TCP FIN")

        self.icmp_check.setChecked(True)
        self.connect_check.setChecked(True)

        method_layout.addWidget(self.icmp_check)
        method_layout.addWidget(self.connect_check)
        method_layout.addWidget(self.syn_check)
        method_layout.addWidget(self.fin_check)
        method_layout.addStretch()

        method_group.setLayout(method_layout)

        # ================== 按钮区 ==================
        button_layout = QHBoxLayout()

        self.start_button = QPushButton("开始扫描")
        self.clear_button = QPushButton("清空结果")
        self.export_button = QPushButton("导出 CSV")

        self.start_button.clicked.connect(self.start_scan)
        self.clear_button.clicked.connect(self.clear_results)
        self.export_button.clicked.connect(self.export_csv)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.export_button)
        button_layout.addStretch()

        # ================== 状态区 ==================
        status_layout = QHBoxLayout()

        self.status_label = QLabel("当前状态：等待扫描")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)

        # ================== 结果表格 ==================
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout()

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels([
            "目标 IP",
            "主机状态",
            "扫描方式",
            "端口号",
            "端口状态",
            "服务名称",
        ])

        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setShowGrid(True)
        self.result_table.setAlternatingRowColors(True)

        result_layout.addWidget(self.result_table)
        result_group.setLayout(result_layout)

        # ================== 日志区 ==================
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout()

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)

        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)

        # ================== 总布局 ==================
        main_layout.addWidget(input_group)
        main_layout.addWidget(method_group)
        main_layout.addLayout(button_layout)
        main_layout.addLayout(status_layout)
        main_layout.addWidget(result_group, stretch=3)
        main_layout.addWidget(log_group, stretch=1)

        central_widget.setLayout(main_layout)

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f4f6f9;
            }

            QGroupBox {
                font-size: 15px;
                font-weight: bold;
                border: 1px solid #cfd6e4;
                border-radius: 8px;
                margin-top: 12px;
                background-color: #ffffff;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #1f3a5f;
            }

            QLabel {
                font-size: 14px;
                color: #333333;
            }

            QLineEdit {
                height: 30px;
                border: 1px solid #c8d0dc;
                border-radius: 6px;
                padding-left: 8px;
                font-size: 14px;
                background-color: #ffffff;
            }

            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }

            QCheckBox {
                font-size: 14px;
                spacing: 6px;
            }

            QPushButton {
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 14px;
                font-weight: bold;
            }

            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f8fafc;
                gridline-color: #dbe3ef;
                border: 1px solid #cfd6e4;
                font-size: 14px;
            }

            QHeaderView::section {
                background-color: #1f3a5f;
                color: white;
                padding: 6px;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }

            QTextEdit {
                background-color: #0f172a;
                color: #d1e7ff;
                border-radius: 6px;
                font-size: 13px;
                padding: 6px;
            }

            QProgressBar {
                border: 1px solid #cfd6e4;
                border-radius: 6px;
                background-color: #ffffff;
                height: 18px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 6px;
            }
        """)

        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
            }
            QPushButton:hover {
                background-color: #15803d;
            }
            QPushButton:pressed {
                background-color: #166534;
            }
        """)

        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #64748b;
            }
            QPushButton:hover {
                background-color: #475569;
            }
            QPushButton:pressed {
                background-color: #334155;
            }
        """)

        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
            QPushButton:pressed {
                background-color: #1e40af;
            }
        """)

    def log(self, message: str):
        self.log_output.append(message)
        self.log_output.ensureCursorVisible()
     
    def show_message(self, title: str, text: str, icon_type="warning"):
        box = QMessageBox(self)

        if icon_type == "warning":
            box.setIcon(QMessageBox.Warning)
        elif icon_type == "critical":
            box.setIcon(QMessageBox.Critical)
        elif icon_type == "information":
            box.setIcon(QMessageBox.Information)
        else:
            box.setIcon(QMessageBox.NoIcon)

        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.Ok)
        box.setDefaultButton(QMessageBox.Ok)

    # 关键：强制弹窗变宽，避免中文显示不完整
        box.setMinimumWidth(460)
        box.setStyleSheet("""
            QMessageBox {
                background-color: #ffffff;
            }

            QLabel {
                min-width: 360px;
                font-size: 14px;
                color: #111827;
            }

            QPushButton {
                min-width: 80px;
                min-height: 28px;
                background-color: #2563eb;
                color: white;
                border-radius: 5px;
                padding: 5px 12px;
            }

            QPushButton:hover {
                background-color: #1d4ed8;
            }  
        """)

        # 再加一个水平撑开项，进一步防止 Linux 下宽度不足
        layout = box.layout()
        spacer = QSpacerItem(420, 0, QSizePolicy.Minimum, QSizePolicy.Expanding)
        layout.addItem(spacer, layout.rowCount(), 0, 1, layout.columnCount())

        box.exec()


    def set_status(self, text: str, progress: int | None = None):
        self.status_label.setText(f"当前状态：{text}")
        if progress is not None:
            self.progress_bar.setValue(progress)
        QApplication.processEvents()

    def get_selected_methods(self):
        methods = []

        if self.icmp_check.isChecked():
            methods.append("ICMP")
        if self.connect_check.isChecked():
            methods.append("TCP Connect")
        if self.syn_check.isChecked():
            methods.append("TCP SYN")
        if self.fin_check.isChecked():
            methods.append("TCP FIN")

        return methods

    def validate_input(self):
        ip = self.ip_input.text().strip()
        start_port_text = self.start_port_input.text().strip()
        end_port_text = self.end_port_input.text().strip()

        if not ip:
            raise ValueError("目标 IP 不能为空")

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("目标 IP 格式不正确")

        if not start_port_text.isdigit() or not end_port_text.isdigit():
            raise ValueError("端口必须是数字")

        start_port = int(start_port_text)
        end_port = int(end_port_text)

        if start_port < 1 or end_port > 65535:
            raise ValueError("端口范围必须在 1 到 65535 之间")

        if start_port > end_port:
            raise ValueError("起始端口不能大于结束端口")

        methods = self.get_selected_methods()

        if not methods:
            raise ValueError("请至少选择一种扫描方式")

        return ip, start_port, end_port, methods

    def start_scan(self):
        try:
            ip, start_port, end_port, methods = self.validate_input()
        except ValueError as e:
            self.show_message("输入错误", str(e), "warning")
            return

        self.start_button.setEnabled(False)
        self.set_status("正在扫描", 10)

        self.log("=" * 60)
        self.log(f"[INFO] 开始扫描目标：{ip}")
        self.log(f"[INFO] 端口范围：{start_port}-{end_port}")
        self.log(f"[INFO] 扫描方式：{', '.join(methods)}")

        try:
            if ADAPTER_AVAILABLE:
                self.log("[INFO] 当前使用真实扫描模块")
                scan_results = real_scan(ip, start_port, end_port, methods)
            else:
                self.log("[WARNING] 当前使用模拟扫描模块")
                scan_results = self.mock_scan(ip, start_port, end_port, methods)

            self.set_status("正在显示结果", 80)

            for result in scan_results:
                normalized = self.normalize_result(result)
                self.add_result_to_table(normalized)
                self.results.append(normalized)

            self.set_status("扫描完成", 100)
            self.log(f"[INFO] 扫描完成，共生成 {len(scan_results)} 条结果")

        except Exception as e:
            self.set_status("扫描出错", 0)
            self.log(f"[ERROR] 扫描模块出错：{e}")
            self.show_message("扫描错误", str(e), "critical")

        finally:
            self.start_button.setEnabled(True)

    def mock_scan(self, ip: str, start_port: int, end_port: int, methods: list[str]):
        results = []

        host_status = "在线" if "ICMP" in methods else "未检测"

        for method in methods:
            if method == "ICMP":
                results.append({
                    "ip": ip,
                    "host_status": host_status,
                    "method": "ICMP",
                    "port": "-",
                    "port_status": "-",
                    "service": "-",
                })
                continue

            for port in range(start_port, min(end_port, start_port + 9) + 1):
                service = COMMON_SERVICES.get(port, "Unknown")
                port_status = "开放" if port in COMMON_SERVICES else "关闭"

                results.append({
                    "ip": ip,
                    "host_status": host_status,
                    "method": method,
                    "port": port,
                    "port_status": port_status,
                    "service": service,
                })

        return results

    def normalize_result(self, result: dict):
        return {
            "ip": result.get("ip", ""),
            "host_status": result.get("host_status", "未检测"),
            "method": result.get("method", "Unknown"),
            "port": result.get("port", "-"),
            "port_status": result.get("port_status", "未知"),
            "service": result.get("service", "Unknown"),
        }

    def add_result_to_table(self, result: dict):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        values = [
            result["ip"],
            result["host_status"],
            result["method"],
            str(result["port"]),
            result["port_status"],
            result["service"],
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignCenter)

            # 第 4 列是端口状态，索引为 4
            if col == 4:
                if value == "开放":
                    item.setForeground(QBrush(QColor("#15803d")))
                    item.setBackground(QBrush(QColor("#dcfce7")))
                elif value == "关闭":
                    item.setForeground(QBrush(QColor("#dc2626")))
                    item.setBackground(QBrush(QColor("#fee2e2")))
                elif value == "过滤":
                    item.setForeground(QBrush(QColor("#d97706")))
                    item.setBackground(QBrush(QColor("#fef3c7")))
                elif value == "错误":
                    item.setForeground(QBrush(QColor("#991b1b")))
                    item.setBackground(QBrush(QColor("#fecaca")))
                elif value == "未知":
                    item.setForeground(QBrush(QColor("#4b5563")))
                    item.setBackground(QBrush(QColor("#e5e7eb")))
                elif value == "开放或过滤":
                    item.setForeground(QBrush(QColor("#7c3aed")))
                    item.setBackground(QBrush(QColor("#ede9fe")))

            self.result_table.setItem(row, col, item)

    def clear_results(self):
        self.result_table.setRowCount(0)
        self.results.clear()
        self.log_output.clear()
        self.set_status("等待扫描", 0)

    def export_csv(self):
        if not self.results:
            
            self.show_message("导出失败", "当前没有可导出的扫描结果", "warning")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出扫描结果",
            "scan_result.csv",
            "CSV Files (*.csv)"
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "ip",
                        "host_status",
                        "method",
                        "port",
                        "port_status",
                        "service",
                    ]
                )
                writer.writeheader()
                writer.writerows(self.results)

            self.show_message("导出成功", f"扫描结果已导出到：\n{file_path}", "information")
            self.log(f"[INFO] 扫描结果已导出：{file_path}")

        except Exception as e:
            
            self.show_message("失败", "no 扫描结果", "information")
            self.log(f"[ERROR] 导出失败：{e}")


def main():
    app = QApplication(sys.argv)
    window = PortScannerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

