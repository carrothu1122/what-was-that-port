import json
from types import SimpleNamespace

import scanner_adapter
from scanner_adapter import (
    convert_status,
    get_advanced_methods,
    get_service_name,
    make_error_row,
    make_row,
    needs_privileged_scan,
    scan_privileged_methods_with_pkexec,
)


def test_get_service_name_handles_common_unknown_and_empty_ports():
    assert get_service_name(80) == "HTTP"
    assert get_service_name("443") == "HTTPS"
    assert get_service_name(65000) == "Unknown"
    assert get_service_name("-") == "-"


def test_convert_status_maps_core_scanner_statuses_to_chinese():
    assert convert_status("open") == "开放"
    assert convert_status("closed") == "关闭"
    assert convert_status("filtered") == "过滤"
    assert convert_status("open|filtered") == "开放或被过滤"
    assert convert_status("unreachable") == "不可达"


def test_detects_advanced_scan_methods():
    methods = ["ICMP", "TCP Connect", "TCP SYN", "UDP"]

    assert get_advanced_methods(methods) == ["TCP SYN", "UDP"]
    assert needs_privileged_scan(methods) is True
    assert needs_privileged_scan(["ICMP", "TCP Connect"]) is False


def test_make_row_and_error_row_have_stable_frontend_shape():
    assert make_row("192.0.2.1", "在线", "TCP Connect", 80, "开放") == {
        "ip": "192.0.2.1",
        "host_status": "在线",
        "method": "TCP Connect",
        "port": 80,
        "port_status": "开放",
        "service": "HTTP",
        "response_flags": None,
        "error_message": None,
        "elapsed_ms": None,
    }

    assert make_error_row("192.0.2.1", "未知", "TCP SYN", "需要 root") == {
        "ip": "192.0.2.1",
        "host_status": "未知",
        "method": "TCP SYN",
        "port": "-",
        "port_status": "错误：需要 root",
        "service": "-",
        "response_flags": None,
        "error_message": "需要 root",
        "elapsed_ms": None,
    }


def test_make_row_handles_udp_method_and_common_service():
    assert make_row("192.0.2.1", "未检测", "UDP", 53, "开放或被过滤") == {
        "ip": "192.0.2.1",
        "host_status": "未检测",
        "method": "UDP",
        "port": 53,
        "port_status": "开放或被过滤",
        "service": "DNS",
        "response_flags": None,
        "error_message": None,
        "elapsed_ms": None,
    }


def test_pkexec_worker_rows_are_returned(monkeypatch):
    row = make_row("192.0.2.1", "在线", "UDP", 53, "开放", response_flags="UDP")
    completed = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"ok": True, "rows": [row]}, ensure_ascii=False),
        stderr="",
    )

    monkeypatch.setattr(scanner_adapter, "is_running_as_root", lambda: False)
    monkeypatch.setattr(scanner_adapter, "is_pkexec_available", lambda: True)
    monkeypatch.setattr(scanner_adapter.subprocess, "run", lambda *args, **kwargs: completed)

    assert scan_privileged_methods_with_pkexec(
        "192.0.2.1",
        [53],
        ["UDP"],
        "在线",
    ) == [row]
