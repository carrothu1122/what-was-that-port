#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Privileged JSON worker for raw-socket scans.

This process is launched by a platform-specific elevation helper. It reads a
request JSON file and writes a result JSON file so Linux pkexec and Windows UAC
can share the same worker protocol.
"""

import json
import sys
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from privilege_adapter import get_advanced_methods
from scanner_adapter import scan_privileged_methods_direct


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _error(result_path: Path | None, message: str) -> int:
    payload = {"ok": False, "error": message}
    if result_path is None:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        _write_result(result_path, payload)
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
    result_path: Path | None = None
    try:
        if len(sys.argv) != 3:
            raise ValueError("用法：privileged_worker.py <request.json> <result.json>")

        request_path = Path(sys.argv[1])
        result_path = Path(sys.argv[2])
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        ip, ports, methods, host_status = _validate_request(payload)
        rows = scan_privileged_methods_direct(ip, ports, methods, host_status)
    except Exception as exc:
        return _error(result_path, str(exc))

    _write_result(result_path, {"ok": True, "rows": rows})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
