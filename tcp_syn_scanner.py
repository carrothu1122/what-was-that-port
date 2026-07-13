#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
模块名称：tcp_syn_scanner.py

功能：
    实现 TCP SYN 端口扫描功能。

扫描原理：
    TCP SYN 扫描也叫“半开放扫描”。
    程序向目标端口发送 SYN 数据包。

判断规则：
    1. 如果目标端口开放：
        目标主机返回 SYN/ACK

    2. 如果目标端口关闭：
        目标主机返回 RST

    3. 如果没有响应：
        可能被防火墙过滤，记为 filtered

注意：
    本模块只判断端口状态，不判断端口运行的具体服务。
    Linux 下通常需要 sudo 权限运行。
    sudo python3 tcp_syn_scanner.py
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

try:
    from .models import TCPSYNScanResult
    from .utils import parse_ports
except ImportError:  # 兼容直接运行本文件：python tcp_syn_scanner.py
    from models import TCPSYNScanResult
    from utils import parse_ports

try:
    from scapy.all import IP, TCP, ICMP, sr1, send, RandShort, conf
except ImportError:
    raise ImportError("请先安装 scapy：pip install scapy")


class TCPSYNScanner:
    """
    TCP SYN 扫描器类
    """

    def __init__(self, timeout: float = 2.0):
        """
        初始化扫描器

        Args:
            timeout: 等待目标响应的超时时间，单位为秒
        """
        self.timeout = timeout
        conf.verb = 0

    def scan_port(self, host: str, port: int) -> TCPSYNScanResult:
        """
        扫描单个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            port: 目标端口号

        Returns:
            TCPSYNScanResult: 扫描结果对象
        """

        if port < 1 or port > 65535:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message="Invalid port number"
            )

        try:
            source_port = int(RandShort())

            syn_packet = IP(dst=host) / TCP(
                sport=source_port,
                dport=port,
                flags="S",
                seq=1000
            )

            response = sr1(
                syn_packet,
                timeout=self.timeout,
                verbose=False
            )

            if response is None:
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    response_flags=None,
                    error_message="No response"
                )

            if response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                flags_value = int(tcp_flags)

                # SYN/ACK = 0x12，表示端口开放
                if flags_value & 0x12 == 0x12:
                    rst_packet = IP(dst=host) / TCP(
                        sport=source_port,
                        dport=port,
                        flags="R",
                        seq=response.getlayer(TCP).ack
                    )

                    send(rst_packet, verbose=False)

                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="open",
                        response_flags=str(tcp_flags),
                        error_message="收到SYN/ACK → 端口开放"
                    )

                # RST = 0x14 或 0x04，表示端口关闭
                elif flags_value & 0x04 == 0x04:
                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="closed",
                        response_flags=str(tcp_flags),
                        error_message="收到RST → 端口关闭"
                    )

                else:
                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="filtered",
                        response_flags=str(tcp_flags),
                        error_message="Unexpected TCP response"
                    )

            elif response.haslayer(ICMP):
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    response_flags=None,
                    error_message="Received ICMP unreachable"
                )

            else:
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    response_flags=None,
                    error_message="Unknown response"
                )

        except PermissionError as e:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message=f"Permission error: {e}"
            )

        except Exception as e:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message=str(e)
            )

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        max_workers: int = 50
    ) -> List[TCPSYNScanResult]:
        """
        扫描多个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            ports: 端口列表
            max_workers: 最大线程数

        Returns:
            List[TCPSYNScanResult]: 扫描结果列表
        """

        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_tasks = [
                executor.submit(self.scan_port, host, port)
                for port in ports
            ]

            for future in as_completed(future_tasks):
                results.append(future.result())

        results.sort(key=lambda item: item.port)
        return results


def print_scan_results(results: List[TCPSYNScanResult]) -> None:
    """
    打印扫描结果，方便调试
    """

    print("-" * 100)
    print(f"{'Host':<18}{'Port':<10}{'Status':<12}{'Flags':<12}{'Message'}")
    print("-" * 100)

    for result in results:
        print(
            f"{result.host:<18}"
            f"{result.port:<10}"
            f"{result.status:<12}"
            f"{str(result.response_flags):<12}"
            f"{result.error_message}"
        )

    print("-" * 100)


if __name__ == "__main__":
    """
    单独运行本文件时，用于调试。
    被其他模块 import 时，不会执行这里。
    """

    # ===== 调试参数（以SSH/FTP端口扫描为例） =====
    target_host = "10.181.211.172"   # 请改为实际目标 IP
    port_input = "21,22"             # FTP(21) + SSH(22)
    timeout = 2.0
    max_workers = 20

    print("TCP SYN 扫描 —— 以 SSH(22) / FTP(21) 为例")
    print(f"目标主机：{target_host}")
    print(f"扫描端口：{port_input}")
    print()

    try:
        ports = parse_ports(port_input)

        scanner = TCPSYNScanner(timeout=timeout)
        scan_results = scanner.scan_ports(
            host=target_host,
            ports=ports,
            max_workers=max_workers
        )

        print_scan_results(scan_results)

    except ValueError as e:
        print(f"端口输入错误：{e}")

    except KeyboardInterrupt:
        print("\n扫描已手动终止")
