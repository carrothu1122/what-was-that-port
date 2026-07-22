#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UDP 端口扫描器

UDP 没有 TCP 握手，因此扫描结果天然存在不确定性：
1. 收到 UDP 响应 → open
2. 收到 ICMP Type 3 Code 3 (Port Unreachable) → closed
3. 无响应 → open|filtered
4. 收到管理禁止类 ICMP → filtered
5. 收到网络/主机/协议不可达 ICMP → unreachable
"""

import argparse
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Dict, List

try:
    from scapy.all import DNS, DNSQR, IP, UDP, ICMP, Raw, sr1, conf
    _SCAPY_IMPORT_ERROR = None
except Exception as exc:
    DNS = None
    DNSQR = None
    IP = None
    UDP = object()
    ICMP = object()
    Raw = None
    sr1 = None
    conf = None
    _SCAPY_IMPORT_ERROR = exc

try:
    from .models import UDPScanResult
    from .utils import parse_ports, validate_target
except ImportError:
    from models import UDPScanResult
    from utils import parse_ports, validate_target


_FILTERED_ICMP_CODES = {9, 10, 13}
_UNREACHABLE_ICMP_CODES = {0, 1, 2}


def build_udp_payload(port: int):
    """为常见 UDP 服务提供轻量探针，提高收到应用层响应的概率。"""
    if _SCAPY_IMPORT_ERROR is not None:
        return None

    if port == 53 and DNS is not None and DNSQR is not None:
        return DNS(rd=1, qd=DNSQR(qname="example.com"))

    if port == 123 and Raw is not None:
        return Raw(load=b"\x1b" + (b"\x00" * 47))

    if port in {161, 162} and Raw is not None:
        return Raw(load=b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")

    return Raw(load=b"") if Raw is not None else b""


def classify_response(response):
    """
    根据 UDP 扫描响应判断端口状态。

    返回：
        state, marker, reason
    """
    if response is None:
        return "open|filtered", None, "无响应 - 端口可能开放，也可能被防火墙过滤"

    if response.haslayer(UDP):
        return "open", "UDP", "收到 UDP 响应 - 端口开放"

    if response.haslayer(ICMP):
        icmp_type = int(response[ICMP].type)
        icmp_code = int(response[ICMP].code)

        if icmp_type == 3 and icmp_code == 3:
            return "closed", "ICMP", "收到 ICMP Port Unreachable - 端口关闭"

        if icmp_type == 3 and icmp_code in _FILTERED_ICMP_CODES:
            return "filtered", "ICMP", f"收到 ICMP 管理禁止，type={icmp_type}，code={icmp_code}"

        if icmp_type == 3 and icmp_code in _UNREACHABLE_ICMP_CODES:
            return "unreachable", "ICMP", f"收到 ICMP 不可达，type={icmp_type}，code={icmp_code}"

        return "unknown", "ICMP", f"收到 ICMP，type={icmp_type}，code={icmp_code}"

    return "unknown", None, "收到无法识别的响应"


def udp_scan_port(
    target: str,
    port: int,
    timeout: float = 2.0,
    retries: int = 1,
) -> UDPScanResult:
    """扫描单个 UDP 端口。"""
    if port < 1 or port > 65535:
        return UDPScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message="Invalid port number",
        )

    if _SCAPY_IMPORT_ERROR is not None:
        return UDPScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message="错误：未安装 Scapy，请执行：pip install scapy",
        )

    try:
        packet = IP(dst=target) / UDP(dport=port) / build_udp_payload(port)

        response = None
        for _ in range(retries + 1):
            response = sr1(packet, timeout=timeout, verbose=0)
            if response is not None:
                break

        state, marker, reason = classify_response(response)
        return UDPScanResult(
            host=target,
            port=port,
            status=state,
            response_flags=marker,
            error_message=reason,
        )

    except PermissionError as exc:
        return UDPScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message=f"权限不足: {exc}",
        )
    except Exception as exc:
        return UDPScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message=str(exc),
        )


def scan_ports(
    target: str,
    ports: List[int],
    timeout: float = 2.0,
    retries: int = 1,
    max_workers: int = 50,
) -> List[UDPScanResult]:
    """并发扫描多个 UDP 端口，结果按端口排序。"""
    if max_workers < 1:
        raise ValueError("max_workers 必须大于等于 1")

    results: List[UDPScanResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port: Dict[Future, int] = {
            executor.submit(
                udp_scan_port,
                target=target,
                port=port,
                timeout=timeout,
                retries=retries,
            ): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
            except Exception as exc:
                result = UDPScanResult(
                    host=target,
                    port=port,
                    status="error",
                    response_flags=None,
                    error_message=str(exc),
                )
            results.append(result)

    results.sort(key=lambda result: result.port)
    return results


def create_parser():
    parser = argparse.ArgumentParser(description="UDP 端口扫描器")
    parser.add_argument("target", type=validate_target, help="目标 IPv4 地址")
    parser.add_argument("-p", "--ports", type=parse_ports, required=True, help="扫描端口，例如 53,123 或 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="等待响应时间，默认 2 秒")
    parser.add_argument("-r", "--retries", type=int, default=1, help="无响应后的额外重试次数，默认 1 次")
    parser.add_argument("-w", "--workers", type=int, default=50, help="并发线程数，默认 50")
    return parser


def main():
    if conf is not None:
        conf.verb = 0

    parser = create_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("timeout 必须大于 0")
    if args.retries < 0:
        parser.error("retries 不能小于 0")
    if args.workers <= 0:
        parser.error("workers 必须大于 0")

    results = scan_ports(
        target=args.target,
        ports=args.ports,
        timeout=args.timeout,
        retries=args.retries,
        max_workers=args.workers,
    )

    print("-" * 100)
    print(f"{'HOST':<18}{'PORT':<8}{'STATUS':<16}{'RESPONSE':<14}{'DETAIL'}")
    print("-" * 100)
    for result in results:
        print(
            f"{result.host:<18}"
            f"{result.port:<8}"
            f"{result.status:<16}"
            f"{str(result.response_flags):<14}"
            f"{result.error_message}"
        )
    print("-" * 100)


if __name__ == "__main__":
    main()
