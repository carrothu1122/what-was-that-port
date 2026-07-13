#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名称：tcp_connect_scanner.py

功能：
    实现 TCP connect 端口扫描功能。

扫描原理：
    TCP connect 扫描是最基本的 TCP 扫描方式。
    如果目标端口处于监听状态，connect() 成功，表示端口开放。
    如果目标端口关闭，connect() 失败并抛出 socket error，表示端口关闭或连接失败。

注意：
    本模块只判断端口是否开放，不判断端口运行的具体服务。
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

try:
    from .models import TCPConnectScanResult
    from .utils import parse_ports
except ImportError:  # 兼容直接运行本文件：python tcp_connect_scanner.py
    from models import TCPConnectScanResult
    from utils import parse_ports


class TCPConnectScanner:
    """
    TCP Connect 扫描器类
    """

    def __init__(self, timeout: float = 1.0):
        """
        初始化扫描器

        Args:
            timeout: 连接超时时间，单位为秒
        """
        self.timeout = timeout

    def scan_port(self, host: str, port: int) -> TCPConnectScanResult:
        """
        扫描单个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            port: 目标端口号

        Returns:
            TCPConnectScanResult: 扫描结果对象
        """

        if port < 1 or port > 65535:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=None,
                error_message="Invalid port number"
            )

        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))

            # connect() 成功不抛异常，相当于底层返回 0
            if result == 0:
                return TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="open",
                    error_code=0,
                    error_message="connect()返回0"
                )

            # connect_ex() 超时和被拒绝均返回错误码，常见超时 errno 为 110/10060
            timeout_codes = {110, 10060}
            if result in timeout_codes:
                return TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    error_code=result,
                    error_message=f"SOCKET-TIMEOUT (errno={result})"
                )

            return TCPConnectScanResult(
                host=host,
                port=port,
                status="closed",
                error_code=result,
                error_message=f"SOCKET-ERROR (errno={result})"
            )

        except socket.timeout as e:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="filtered",
                error_code=None,
                error_message=str(e)
            )

        except socket.gaierror as e:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=e.errno,
                error_message=str(e)
            )

        except PermissionError as e:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=e.errno,
                error_message=f"Permission error: {e}"
            )

        except OSError as e:
            # connect() 被拒绝 → 端口关闭，底层返回 SOCKET-ERROR
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="closed",
                error_code=e.errno,
                error_message=f"SOCKET-ERROR (errno={e.errno})"
            )

        finally:
            if sock is not None:
                sock.close()

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        max_workers: int = 50
    ) -> List[TCPConnectScanResult]:
        """
        扫描多个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            ports: 端口列表
            max_workers: 最大线程数

        Returns:
            List[TCPConnectScanResult]: 扫描结果列表
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


def print_scan_results(results: List[TCPConnectScanResult]) -> None:
    """
    打印扫描结果，方便调试
    """

    print("-" * 90)
    print(f"{'Host':<18}{'Port':<10}{'Status':<15}{'Error Code':<12}{'Message'}")
    print("-" * 90)

    for result in results:
        print(
            f"{result.host:<18}"
            f"{result.port:<10}"
            f"{result.status:<15}"
            f"{str(result.error_code):<12}"
            f"{result.error_message}"
        )

    print("-" * 90)


if __name__ == "__main__":
    """
    单独运行本文件时，用于调试。
    被其他模块 import 时，不会执行这里。
    """

    # ===== 调试参数（以SSH/FTP端口扫描为例） =====
    target_host = "127.0.0.1"   # 请改为实际目标 IP
    port_input = "21,22"        # FTP(21) + SSH(22)
    timeout = 2.0
    max_workers = 20

    print("TCP Connect 扫描 —— 以 SSH(22) / FTP(21) 为例")
    print(f"目标主机：{target_host}")
    print(f"扫描端口：{port_input}")
    print()

    try:
        ports = parse_ports(port_input)

        scanner = TCPConnectScanner(timeout=timeout)
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
