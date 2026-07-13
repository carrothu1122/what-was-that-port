#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP FIN 端口扫描器

仅负责判断端口状态，不进行服务识别。

判断规则：
1. 收到 TCP RST：
   closed

2. 没有收到响应：
   open|filtered

3. 收到特定 ICMP 不可达报文：
   filtered

安装：
    pip install scapy

Linux：
    sudo python3 tcp_fin_scanner.py 192.168.1.10 -p 21,22,80

"""

import argparse
import random
import sys
import time
from typing import List

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
except ImportError:
    print("错误：未安装 Scapy，请执行：pip install scapy")
    sys.exit(1)

try:
    from .models import TCPFINScanResult
    from .utils import parse_ports, validate_target
except ImportError:  # 兼容直接运行本文件：python tcp_fin_scanner.py
    from models import TCPFINScanResult
    from utils import parse_ports, validate_target


# ============================================================
#  核心扫描逻辑（不包含任何 print）
# ============================================================

def classify_response(response):
    """
    根据响应判断端口状态（对应 PPT 三种情况）。

    返回：
        state, reason
    """

    if response is None:
        # 端口打开，且没有连接 → 直接丢弃（无响应）
        return "打开(丢弃)", "无响应 — 端口打开且无连接, 直接丢弃"

    if response.haslayer(TCP):
        flags = int(response[TCP].flags)

        # 收到 ACK → 存在对应连接
        if flags & 0x10 and not (flags & 0x04):
            return "有连接(ACK)", "收到ACK — 存在对应连接"

        # 收到 RST → 端口关闭
        if flags & 0x04:
            return "关闭(RST)", "收到RST — 端口关闭"

        flag_text = response[TCP].sprintf("%TCP.flags%")
        return "unknown", f"收到 TCP 标志：{flag_text}"

    if response.haslayer(ICMP):
        icmp_type = int(response[ICMP].type)
        icmp_code = int(response[ICMP].code)

        if icmp_type == 3 and icmp_code in {1, 2, 3, 9, 10, 13}:
            return "filtered", f"收到 ICMP 不可达，type={icmp_type}，code={icmp_code}"

        return "unknown", f"收到 ICMP，type={icmp_type}，code={icmp_code}"

    return "unknown", "收到无法识别的响应"


def fin_scan_port(
    target: str,
    port: int,
    timeout: float = 1.0,
    retries: int = 1
) -> TCPFINScanResult:
    """
    对单个端口进行 TCP FIN 扫描（纯逻辑，不打印）。

    Args:
        target: 目标 IPv4 地址
        port: 端口号
        timeout: 等待响应超时时间（秒）
        retries: 无响应时的重试次数

    Returns:
        TCPFINScanResult: 扫描结果
    """

    if port < 1 or port > 65535:
        return TCPFINScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message="Invalid port number"
        )

    try:
        source_port = random.randint(32768, 60999)

        packet = (
            IP(dst=target)
            / TCP(
                sport=source_port,
                dport=port,
                flags="F",
                seq=random.randint(0, 2**32 - 1)
            )
        )

        response = None
        for _ in range(retries + 1):
            response = sr1(packet, timeout=timeout, verbose=0)
            if response is not None:
                break

        state, reason = classify_response(response)

        response_flags = None
        if response is not None and response.haslayer(TCP):
            response_flags = str(response[TCP].flags)

        return TCPFINScanResult(
            host=target,
            port=port,
            status=state,
            response_flags=response_flags,
            error_message=reason
        )

    except PermissionError as e:
        return TCPFINScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message=f"权限不足: {e}"
        )

    except Exception as e:
        return TCPFINScanResult(
            host=target,
            port=port,
            status="error",
            response_flags=None,
            error_message=str(e)
        )


def scan_ports(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    retries: int = 1,
    delay: float = 0.05
) -> List[TCPFINScanResult]:
    """
    扫描多个端口（纯逻辑，不打印）。

    Args:
        target: 目标 IPv4 地址
        ports: 端口列表
        timeout: 等待响应超时时间（秒）
        retries: 无响应时的重试次数
        delay: 每个端口之间的延迟（秒），用于降低扫描速率

    Returns:
        List[TCPFINScanResult]: 扫描结果列表，按端口号排序
    """

    results = []

    for port in ports:
        result = fin_scan_port(
            target=target,
            port=port,
            timeout=timeout,
            retries=retries
        )
        results.append(result)

        if delay > 0:
            time.sleep(delay)

    results.sort(key=lambda r: r.port)
    return results


# ============================================================
#  展示层（打印相关函数，不修改扫描逻辑）
# ============================================================

def print_scan_results(
    results: List[TCPFINScanResult],
    show_all: bool = True
) -> None:
    """
    打印扫描结果列表。

    Args:
        results: 扫描结果列表
        show_all: 是否显示全部端口（默认全部显示）
    """

    print("-" * 70)
    print(f"{'PORT':<10}{'STATE':<22}{'REASON'}")
    print("-" * 70)

    for r in results:
        if not show_all and "关闭" in r.status:
            continue
        print(f"{r.port:<10}{r.status:<22}{r.error_message}")

    print("-" * 70)


def print_summary(results: List[TCPFINScanResult]) -> None:
    """
    输出扫描汇总统计。
    """

    statistics = {
        "打开(丢弃)": 0,
        "关闭(RST)": 0,
        "有连接(ACK)": 0,
        "filtered": 0,
        "unknown": 0,
        "error": 0,
    }

    for r in results:
        state = r.status
        if state in statistics:
            statistics[state] += 1
        else:
            statistics["unknown"] += 1

    print("\n========== 扫描汇总 ==========")
    print(f"打开(丢弃)  ：{statistics['打开(丢弃)']}  ← 端口打开且无连接，直接丢弃")
    print(f"关闭(RST)  ：{statistics['关闭(RST)']}  ← 端口关闭，返回RST")
    print(f"有连接(ACK)：{statistics['有连接(ACK)']}  ← 存在对应连接，返回ACK")
    print(f"filtered   ：{statistics['filtered']}")
    print(f"unknown    ：{statistics['unknown']}")
    print(f"error      ：{statistics['error']}")
    print("==============================")

    print(
        "\n说明：FIN 扫描中，端口打开且无连接时目标直接丢弃 FIN 包（无响应）；"
    )
    print(
        "端口关闭时返回 RST；若已存在连接则返回 ACK。"
    )


# ============================================================
#  命令行入口
# ============================================================

def create_parser():
    """创建命令行参数解析器。"""

    parser = argparse.ArgumentParser(
        description="TCP FIN 端口扫描器"
    )

    parser.add_argument(
        "target",
        type=validate_target,
        help="目标 IPv4 地址"
    )

    parser.add_argument(
        "-p", "--ports",
        type=parse_ports,
        required=True,
        help="扫描端口，例如 21,22,80 或 1-1024"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="等待响应时间，默认 1 秒"
    )

    parser.add_argument(
        "-r", "--retries",
        type=int,
        default=1,
        help="无响应时重试次数，默认 1 次"
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.05,
        help="每个端口之间的延迟，默认 0.05 秒"
    )

    parser.add_argument(
        "--show-all",
        action="store_true",
        help="显示全部端口（默认即全部显示，此选项保留兼容）"
    )

    return parser


def main():
    """命令行主函数。"""

    conf.verb = 0

    parser = create_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("timeout 必须大于 0")
    if args.retries < 0:
        parser.error("retries 不能小于 0")
    if args.delay < 0:
        parser.error("delay 不能小于 0")

    print("请确保仅扫描自己拥有或已获得明确授权的主机。")

    try:
        print("\n========== TCP FIN 扫描 ==========")
        print(f"目标地址：{args.target}")
        print(f"端口数量：{len(args.ports)}")
        print(f"超时时间：{args.timeout} 秒")
        print(f"重试次数：{args.retries}")
        print("==================================\n")

        results = scan_ports(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
        )

        print_scan_results(results, show_all=args.show_all)
        print_summary(results)

    except PermissionError:
        print("\n权限不足：TCP FIN 扫描需要原始套接字权限。")
        print("Linux 请使用 sudo")

    except OSError as error:
        print(f"\n网络或抓包错误：{error}")

    except KeyboardInterrupt:
        print("\n扫描已终止。")


if __name__ == "__main__":
    main()
