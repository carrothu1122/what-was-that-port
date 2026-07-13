#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一命令行入口。
"""

import argparse
import json
import sys
from typing import Iterable, List

from .host_discovery import icmp_probe
from .service_fingerprint import scan_services
from .tcp_connect_scanner import TCPConnectScanner
from .utils import parse_ports, validate_target


METHOD_LABELS = {
    "connect": "TCP Connect",
    "syn": "TCP SYN",
    "fin": "TCP FIN",
    "fingerprint": "TCP Connect",
}

PORT_STATUS_EN = {
    "open": "open",
    "closed": "closed",
    "filtered": "filtered",
    "error": "error",
    "打开(丢弃)": "open",
    "关闭(RST)": "closed",
    "有连接(ACK)": "connected",
    "unknown": "unknown",
}

PORT_STATUS_ZH = {
    "open": "开放",
    "closed": "关闭",
    "filtered": "过滤",
    "error": "错误",
    "打开(丢弃)": "开放",
    "关闭(RST)": "关闭",
    "有连接(ACK)": "已有连接",
    "unknown": "未知",
}


def _host_status_from_port_statuses(port_statuses: Iterable[str], lang: str) -> str:
    statuses = list(port_statuses)
    if any(status in {"open", "closed", "打开(丢弃)", "关闭(RST)", "有连接(ACK)"} for status in statuses):
        return "online" if lang == "en" else "在线"
    if statuses and all(status in {"filtered", "error"} for status in statuses):
        return "unknown" if lang == "en" else "未知"
    return "unknown" if lang == "en" else "未知"


def _map_port_status(status: str, lang: str) -> str:
    mapping = PORT_STATUS_EN if lang == "en" else PORT_STATUS_ZH
    return mapping.get(status, status)


def _scan_results_to_frontend_records(results: List, method: str, lang: str) -> List[dict]:
    host_status = _host_status_from_port_statuses(
        [getattr(result, "status", "unknown") for result in results],
        lang,
    )
    method_label = METHOD_LABELS.get(method, method)

    return [
        {
            "ip": result.host,
            "host_status": host_status,
            "method": method_label,
            "port": result.port,
            "port_status": _map_port_status(result.status, lang),
            "service": None,
        }
        for result in results
    ]


def _fingerprint_results_to_frontend_records(results: List, lang: str) -> List[dict]:
    host_status = "online" if any(result.open for result in results) else ("unknown" if lang == "en" else "未知")
    if lang == "zh" and host_status == "online":
        host_status = "在线"

    return [
        {
            "ip": result.host,
            "host_status": host_status,
            "method": METHOD_LABELS["fingerprint"],
            "port": result.port,
            "port_status": ("open" if lang == "en" else "开放") if result.open else ("closed" if lang == "en" else "关闭"),
            "service": result.service.upper() if result.service else None,
        }
        for result in results
    ]


def _print_json(records: List[dict]) -> None:
    print(json.dumps(records, ensure_ascii=False, indent=4))


def _print_port_results(results: Iterable) -> None:
    print("-" * 100)
    print(f"{'HOST':<18}{'PORT':<8}{'STATUS':<16}{'FLAGS/CODE':<14}{'DETAIL'}")
    print("-" * 100)

    for result in results:
        flags_or_code = getattr(result, "response_flags", None)
        if flags_or_code is None:
            flags_or_code = getattr(result, "error_code", None)

        detail = getattr(result, "error_message", "")
        print(
            f"{result.host:<18}"
            f"{result.port:<8}"
            f"{result.status:<16}"
            f"{str(flags_or_code):<14}"
            f"{detail}"
        )

    print("-" * 100)


def _print_fingerprint_results(results: Iterable) -> None:
    print("-" * 110)
    print(f"{'HOST':<18}{'PORT':<8}{'OPEN':<8}{'SERVICE':<14}{'VERSION':<34}{'DETAIL'}")
    print("-" * 110)

    for result in results:
        print(
            f"{result.host:<18}"
            f"{result.port:<8}"
            f"{str(result.open):<8}"
            f"{str(result.service or '-'):<14}"
            f"{str(result.version or '-'):<34}"
            f"{result.detail}"
        )

    print("-" * 110)


def scan_command(args: argparse.Namespace) -> int:
    target = validate_target(args.target)

    if args.mode == "connect":
        scanner = TCPConnectScanner(timeout=args.timeout)
        results = scanner.scan_ports(target, args.ports, max_workers=args.workers)
    elif args.mode == "syn":
        from .tcp_syn_scanner import TCPSYNScanner

        scanner = TCPSYNScanner(timeout=args.timeout)
        results = scanner.scan_ports(target, args.ports, max_workers=args.workers)
    elif args.mode == "fin":
        from .tcp_fin_scanner import scan_ports as fin_scan_ports

        results = fin_scan_ports(
            target=target,
            ports=args.ports,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
        )
    else:
        raise ValueError(f"不支持的扫描模式：{args.mode}")

    if args.json:
        _print_json(_scan_results_to_frontend_records(results, args.mode, args.lang))
    else:
        _print_port_results(results)
    return 0


def fingerprint_command(args: argparse.Namespace) -> int:
    target = validate_target(args.target)
    results = scan_services(target, args.ports, timeout=args.timeout)
    if args.json:
        _print_json(_fingerprint_results_to_frontend_records(results, args.lang))
    else:
        _print_fingerprint_results(results)
    return 0


def ping_command(args: argparse.Namespace) -> int:
    result = icmp_probe(args.target, timeout_ms=args.timeout_ms)
    status = "alive" if result.alive else "down"
    rtt = "-" if result.rtt_ms is None else f"{result.rtt_ms:.2f} ms"
    print(f"{result.host} ({result.resolved_ip or '-'}) {status}, rtt={rtt}, {result.reason}")
    return 0 if result.alive else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tcp-scanner", description="端口扫描系统统一入口")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="执行端口扫描")
    scan_parser.add_argument("target", help="目标 IPv4 地址")
    scan_parser.add_argument("-p", "--ports", type=parse_ports, required=True, help="端口，如 22,80 或 1-1024")
    scan_parser.add_argument(
        "-m",
        "--mode",
        choices=["connect", "syn", "fin"],
        default="connect",
        help="扫描方式，默认 connect",
    )
    scan_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="超时时间，默认 1 秒")
    scan_parser.add_argument("-w", "--workers", type=int, default=50, help="并发线程数，仅 connect/syn 有效")
    scan_parser.add_argument("-r", "--retries", type=int, default=1, help="重试次数，仅 fin 有效")
    scan_parser.add_argument("-d", "--delay", type=float, default=0.05, help="端口间隔，仅 fin 有效")
    scan_parser.add_argument("--json", action="store_true", help="输出前端接入用 JSON")
    scan_parser.add_argument("--lang", choices=["en", "zh"], default="en", help="JSON 状态语言，默认英文")
    scan_parser.set_defaults(func=scan_command)

    fp_parser = subparsers.add_parser("fingerprint", help="识别开放端口服务指纹")
    fp_parser.add_argument("target", help="目标 IPv4 地址")
    fp_parser.add_argument("-p", "--ports", type=parse_ports, required=True, help="端口，如 22,80 或 1-1024")
    fp_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="超时时间，默认 3 秒")
    fp_parser.add_argument("--json", action="store_true", help="输出前端接入用 JSON")
    fp_parser.add_argument("--lang", choices=["en", "zh"], default="en", help="JSON 状态语言，默认英文")
    fp_parser.set_defaults(func=fingerprint_command)

    ping_parser = subparsers.add_parser("ping", help="ICMP 主机存活探测")
    ping_parser.add_argument("target", help="目标 IPv4 地址或域名")
    ping_parser.add_argument("--timeout-ms", type=int, default=1000, help="超时时间，默认 1000ms")
    ping_parser.set_defaults(func=ping_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if hasattr(args, "timeout") and args.timeout <= 0:
        parser.error("timeout 必须大于 0")
    if hasattr(args, "workers") and args.workers <= 0:
        parser.error("workers 必须大于 0")
    if hasattr(args, "retries") and args.retries < 0:
        parser.error("retries 不能小于 0")
    if hasattr(args, "delay") and args.delay < 0:
        parser.error("delay 不能小于 0")
    if hasattr(args, "timeout_ms") and args.timeout_ms <= 0:
        parser.error("timeout-ms 必须大于 0")

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
