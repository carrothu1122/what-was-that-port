"""
scanner_adapter.py

作用：
1. 作为 GUI 和底层扫描模块之间的适配层；
2. 统一把 ICMP、TCP Connect、TCP SYN、TCP FIN 的结果转换成界面表格需要的 list[dict]；
3. 避免因为某个扫描模块导入失败导致整个图形界面直接崩溃。
"""

import platform
import subprocess
from typing import Any


COMMON_SERVICES = {
    20: "FTP-Data",
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


def get_service_name(port: Any) -> str:
    """根据端口号返回常见服务名称。"""
    if port in (None, "", "-"):
        return "-"
    try:
        return COMMON_SERVICES.get(int(port), "Unknown")
    except (TypeError, ValueError):
        return "Unknown"


def convert_status(status: Any) -> str:
    """把底层模块返回的英文/内部状态转换成界面中文显示。"""
    status_map = {
        "open": "开放",
        "closed": "关闭",
        "filtered": "过滤",
        "open|filtered": "开放或被过滤",
        "unreachable": "不可达",
        "error": "错误",
        "unknown": "未知",
        "打开(丢弃)": "开放或被过滤",
        "关闭(RST)": "关闭",
        "有连接(ACK)": "有连接",
    }
    return status_map.get(str(status), str(status))


def make_row(ip: str, host_status: str, method: str, port: Any, port_status: str, service: str | None = None) -> dict:
    """生成 GUI 表格需要的一行结果。"""
    return {
        "ip": ip,
        "host_status": host_status,
        "method": method,
        "port": port,
        "port_status": port_status,
        "service": service if service is not None else get_service_name(port),
    }


def make_error_row(ip: str, host_status: str, method: str, message: str) -> dict:
    """生成错误提示行，避免 GUI 崩溃。"""
    return make_row(
        ip=ip,
        host_status=host_status,
        method=method,
        port="-",
        port_status=f"错误：{message}",
        service="-",
    )


def icmp_ping(ip: str, timeout: float = 1.0) -> tuple[str, str]:
    """
    用系统 ping 命令做 ICMP 主机存活检测。
    返回：(host_status, detail)
    """
    system = platform.system().lower()

    if "windows" in system:
        # Windows: -n 次数, -w 超时毫秒
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # Linux/macOS: -c 次数, -W 超时秒
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1.5,
        )
        if completed.returncode == 0:
            return "在线", "ICMP 有响应"
        return "无响应", "ICMP 无响应或被防火墙过滤"
    except Exception as exc:
        return "未知", f"ICMP 检测失败：{exc}"


def scan_tcp_connect(ip: str, ports: list[int], host_status: str) -> list[dict]:
    """调用 TCP Connect 扫描模块。"""
    rows: list[dict] = []
    try:
        from tcp_connect_scanner import TCPConnectScanner

        scanner = TCPConnectScanner(timeout=1.0)
        scan_results = scanner.scan_ports(host=ip, ports=ports, max_workers=50)

        for r in scan_results:
            rows.append(make_row(
                ip=r.host,
                host_status=host_status,
                method="TCP Connect",
                port=r.port,
                port_status=convert_status(r.status),
            ))

    except Exception as exc:
        rows.append(make_error_row(ip, host_status, "TCP Connect", str(exc)))

    return rows


def scan_tcp_syn(ip: str, ports: list[int], host_status: str) -> list[dict]:
    """调用 TCP SYN 扫描模块。SYN 通常需要 sudo/root 权限。"""
    rows: list[dict] = []
    try:
        from tcp_syn_scanner import TCPSYNScanner

        scanner = TCPSYNScanner(timeout=2.0)
        scan_results = scanner.scan_ports(host=ip, ports=ports, max_workers=50)

        for r in scan_results:
            rows.append(make_row(
                ip=r.host,
                host_status=host_status,
                method="TCP SYN",
                port=r.port,
                port_status=convert_status(r.status),
            ))

    except Exception as exc:
        rows.append(make_error_row(ip, host_status, "TCP SYN", str(exc)))

    return rows


def scan_tcp_fin(ip: str, ports: list[int], host_status: str) -> list[dict]:
    """调用 TCP FIN 扫描模块。FIN 通常需要 sudo/root 权限。"""
    rows: list[dict] = []
    try:
        from tcp_fin_scanner import scan_ports

        scan_results = scan_ports(
            target=ip,
            ports=ports,
            timeout=1.0,
            retries=1,
        )

        for r in scan_results:
            rows.append(make_row(
                ip=r.host,
                host_status=host_status,
                method="TCP FIN",
                port=r.port,
                port_status=convert_status(r.status),
            ))

    except Exception as exc:
        rows.append(make_error_row(ip, host_status, "TCP FIN", str(exc)))

    return rows


def real_scan(ip: str, start_port: int, end_port: int, methods: list[str]) -> list[dict]:
    """
    GUI 统一调用入口。

    输入：
        ip: 目标 IP
        start_port: 起始端口
        end_port: 结束端口
        methods: GUI 勾选的扫描方式列表

    输出：
        list[dict]，每个 dict 可直接显示到 GUI 表格。
    """
    ports = list(range(start_port, end_port + 1))
    rows: list[dict] = []

    host_status = "未检测"

    if "ICMP" in methods:
        host_status, detail = icmp_ping(ip, timeout=1.0)
        rows.append(make_row(
            ip=ip,
            host_status=host_status,
            method="ICMP",
            port="-",
            port_status=detail,
            service="-",
        ))

    if "TCP Connect" in methods:
        rows.extend(scan_tcp_connect(ip, ports, host_status))

    if "TCP SYN" in methods:
        rows.extend(scan_tcp_syn(ip, ports, host_status))

    if "TCP FIN" in methods:
        rows.extend(scan_tcp_fin(ip, ports, host_status))

    return rows
