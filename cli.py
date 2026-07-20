#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一命令行入口。
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List

try:
    from .host_discovery import icmp_probe
    from .service_fingerprint import scan_services
    from .tcp_connect_scanner import TCPConnectScanner
    from .utils import parse_ports, validate_target
except ImportError:
    from host_discovery import icmp_probe
    from service_fingerprint import scan_services
    from tcp_connect_scanner import TCPConnectScanner
    from utils import parse_ports, validate_target


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
    "open|filtered": "open|filtered",
    "unreachable": "unreachable",
    "error": "error",
    "unknown": "unknown",
}

PORT_STATUS_ZH = {
    "open": "开放",
    "closed": "关闭",
    "filtered": "过滤",
    "open|filtered": "开放或被过滤",
    "unreachable": "不可达",
    "error": "错误",
    "unknown": "未知",
}


def _host_status_from_port_statuses(port_statuses: Iterable[str], lang: str) -> str:
    statuses = list(port_statuses)
    if any(status in {"open", "closed"} for status in statuses):
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


def _render_json(records: List[dict]) -> str:
    return json.dumps(records, ensure_ascii=False, indent=4)


def _print_json(records: List[dict]) -> None:
    print(_render_json(records))


def _render_port_results(results: Iterable) -> str:
    lines = ["-" * 100, f"{'HOST':<18}{'PORT':<8}{'STATUS':<16}{'FLAGS/CODE':<14}{'DETAIL'}", "-" * 100]

    for result in results:
        flags_or_code = getattr(result, "response_flags", None)
        if flags_or_code is None:
            flags_or_code = getattr(result, "error_code", None)

        detail = getattr(result, "error_message", "")
        lines.append(
            f"{result.host:<18}"
            f"{result.port:<8}"
            f"{result.status:<16}"
            f"{str(flags_or_code):<14}"
            f"{detail}"
        )

    lines.append("-" * 100)
    return "\n".join(lines)


def _print_port_results(results: Iterable) -> None:
    print(_render_port_results(results))


def _render_fingerprint_results(results: Iterable) -> str:
    lines = ["-" * 110, f"{'HOST':<18}{'PORT':<8}{'OPEN':<8}{'SERVICE':<14}{'VERSION':<34}{'DETAIL'}", "-" * 110]

    for result in results:
        lines.append(
            f"{result.host:<18}"
            f"{result.port:<8}"
            f"{str(result.open):<8}"
            f"{str(result.service or '-'):<14}"
            f"{str(result.version or '-'):<34}"
            f"{result.detail}"
        )

    lines.append("-" * 110)
    return "\n".join(lines)


def _print_fingerprint_results(results: Iterable) -> None:
    print(_render_fingerprint_results(results))


def _safe_export_name(value: object) -> str:
    safe_value = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._-")
    return safe_value or "output"


def _build_export_filename(command: str, target: str, mode: str | None = None, use_json: bool = False) -> str:
    base_name = f"{command}_{_safe_export_name(target)}"
    if mode:
        base_name = f"{base_name}_{_safe_export_name(mode)}"
    return f"{base_name}.json" if use_json else f"{base_name}.txt"


def _write_output_file(content: str, export_dir: str, filename: str) -> str:
    export_path = Path(export_dir).expanduser()
    export_path.mkdir(parents=True, exist_ok=True)
    output_file = export_path / filename
    output_file.write_text(content, encoding="utf-8")
    return str(output_file)


def _maybe_export_output(args: argparse.Namespace, content: str, command: str, target: str, mode: str | None = None) -> None:
    if not getattr(args, "export_results", False):
        return

    export_dir = getattr(args, "export_dir", None)
    if not export_dir:
        try:
            export_dir = input("请输入导出目录（留空取消导出）: ").strip()
        except EOFError:
            return

    if not export_dir:
        return

    output_file = _write_output_file(
        content,
        export_dir,
        _build_export_filename(command, target, mode=mode, use_json=getattr(args, "json", False)),
    )
    print(f"结果已导出至: {output_file}")


def scan_command(args: argparse.Namespace) -> int:
    target = validate_target(args.target)

    if args.mode == "connect":
        scanner = TCPConnectScanner(timeout=args.timeout)
        results = scanner.scan_ports(target, args.ports, max_workers=args.workers)
    elif args.mode == "syn":
        try:
            from .tcp_syn_scanner import TCPSYNScanner
        except ImportError:
            from tcp_syn_scanner import TCPSYNScanner

        scanner = TCPSYNScanner(timeout=args.timeout)
        results = scanner.scan_ports(target, args.ports, max_workers=args.workers)
    elif args.mode == "fin":
        try:
            from .tcp_fin_scanner import scan_ports as fin_scan_ports
        except ImportError:
            from tcp_fin_scanner import scan_ports as fin_scan_ports

        results = fin_scan_ports(
            target=target,
            ports=args.ports,
            timeout=args.timeout,
            retries=args.retries,
        )
    else:
        raise ValueError(f"不支持的扫描模式：{args.mode}")

    if args.json:
        output_text = _render_json(_scan_results_to_frontend_records(results, args.mode, args.lang))
        _print_json(_scan_results_to_frontend_records(results, args.mode, args.lang))
    else:
        output_text = _render_port_results(results)
        _print_port_results(results)

    _maybe_export_output(args, output_text, "scan", args.target, mode=args.mode)
    return 0


def fingerprint_command(args: argparse.Namespace) -> int:
    target = validate_target(args.target)
    results = scan_services(target, args.ports, timeout=args.timeout)
    if args.json:
        output_text = _render_json(_fingerprint_results_to_frontend_records(results, args.lang))
        _print_json(_fingerprint_results_to_frontend_records(results, args.lang))
    else:
        output_text = _render_fingerprint_results(results)
        _print_fingerprint_results(results)

    _maybe_export_output(args, output_text, "fingerprint", args.target)
    return 0


def ping_command(args: argparse.Namespace) -> int:
    result = icmp_probe(args.target, timeout_ms=args.timeout_ms)
    status = "alive" if result.alive else "down"
    rtt = "-" if result.rtt_ms is None else f"{result.rtt_ms:.2f} ms"
    output_text = f"{result.host} ({result.resolved_ip or '-'}) {status}, rtt={rtt}, {result.reason}"
    print(output_text)
    _maybe_export_output(args, output_text, "ping", args.target)
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
    scan_parser.add_argument("--json", action="store_true", help="输出前端接入用 JSON")
    scan_parser.add_argument("--lang", choices=["en", "zh"], default="en", help="JSON 状态语言，默认英文")
    scan_parser.add_argument("--export-results", action="store_true", help="执行后将结果导出到目录")
    scan_parser.add_argument("--export-dir", default=None, help="导出目录；未提供时将提示输入")
    scan_parser.set_defaults(func=scan_command)

    fp_parser = subparsers.add_parser("fingerprint", help="识别开放端口服务指纹")
    fp_parser.add_argument("target", help="目标 IPv4 地址")
    fp_parser.add_argument("-p", "--ports", type=parse_ports, required=True, help="端口，如 22,80 或 1-1024")
    fp_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="超时时间，默认 3 秒")
    fp_parser.add_argument("--json", action="store_true", help="输出前端接入用 JSON")
    fp_parser.add_argument("--lang", choices=["en", "zh"], default="en", help="JSON 状态语言，默认英文")
    fp_parser.add_argument("--export-results", action="store_true", help="执行后将结果导出到目录")
    fp_parser.add_argument("--export-dir", default=None, help="导出目录；未提供时将提示输入")
    fp_parser.set_defaults(func=fingerprint_command)

    ping_parser = subparsers.add_parser("ping", help="ICMP 主机存活探测")
    ping_parser.add_argument("target", help="目标 IPv4 地址或域名")
    ping_parser.add_argument("--timeout-ms", type=int, default=1000, help="超时时间，默认 1000ms")
    ping_parser.add_argument("--export-results", action="store_true", help="执行后将结果导出到目录")
    ping_parser.add_argument("--export-dir", default=None, help="导出目录；未提供时将提示输入")
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
    if hasattr(args, "timeout_ms") and args.timeout_ms <= 0:
        parser.error("timeout-ms 必须大于 0")

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
