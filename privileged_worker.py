#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Privileged JSON worker for raw-socket scans.

This process is intended to be launched by pkexec from the GUI. It reads one
JSON request from stdin and writes one JSON response to stdout.
"""

import json
import sys
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scanner_adapter import get_advanced_methods, scan_privileged_methods_direct


def _error(message: str) -> int:
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    return 1


def _validate_request(payload: Any) -> tuple[str, list[int], list[str], str]:
    if not isinstance(payload, dict):
        raise ValueError("请求必须是 JSON object")

    ip = payload.get("ip")
    ports = payload.get("ports")
    methods = payload.get("methods")
    host_status = payload.get("host_status", "未检测")

    if not isinstance(ip, str) or not ip:
        raise ValueError("ip 字段无效")
    if not isinstance(ports, list) or not ports:
        raise ValueError("ports 字段无效")
    if not isinstance(methods, list) or not methods:
        raise ValueError("methods 字段无效")
    if not isinstance(host_status, str):
        raise ValueError("host_status 字段无效")

    normalized_ports: list[int] = []
    for port in ports:
        try:
            value = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"端口无效：{port}") from exc
        if value < 1 or value > 65535:
            raise ValueError(f"端口超出范围：{value}")
        normalized_ports.append(value)

    normalized_methods = get_advanced_methods([str(method) for method in methods])
    if not normalized_methods:
        raise ValueError("没有需要高级权限的扫描方式")

    return ip, normalized_ports, normalized_methods, host_status


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        ip, ports, methods, host_status = _validate_request(payload)
        rows = scan_privileged_methods_direct(ip, ports, methods, host_status)
    except Exception as exc:
        return _error(str(exc))

    print(json.dumps({"ok": True, "rows": rows}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
