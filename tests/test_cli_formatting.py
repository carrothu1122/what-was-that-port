from types import SimpleNamespace

from cli import (
    _build_export_filename,
    _fingerprint_results_to_frontend_records,
    _host_status_from_port_statuses,
    _render_json,
    _scan_results_to_frontend_records,
)


def test_host_status_does_not_treat_fin_open_filtered_as_online():
    assert _host_status_from_port_statuses(["open"], "en") == "online"
    assert _host_status_from_port_statuses(["closed"], "zh") == "在线"
    assert _host_status_from_port_statuses(["open|filtered"], "en") == "unknown"
    assert _host_status_from_port_statuses(["filtered", "error"], "zh") == "未知"


def test_scan_results_to_frontend_records_maps_method_and_status_language():
    results = [
        SimpleNamespace(host="192.0.2.1", port=22, status="closed"),
        SimpleNamespace(host="192.0.2.1", port=80, status="open"),
    ]

    records = _scan_results_to_frontend_records(results, method="connect", lang="zh")

    assert records == [
        {
            "ip": "192.0.2.1",
            "host_status": "在线",
            "method": "TCP Connect",
            "port": 22,
            "port_status": "关闭",
            "service": None,
        },
        {
            "ip": "192.0.2.1",
            "host_status": "在线",
            "method": "TCP Connect",
            "port": 80,
            "port_status": "开放",
            "service": None,
        },
    ]


def test_scan_results_to_frontend_records_maps_udp_method():
    results = [
        SimpleNamespace(host="192.0.2.1", port=53, status="open|filtered"),
    ]

    records = _scan_results_to_frontend_records(results, method="udp", lang="zh")

    assert records == [
        {
            "ip": "192.0.2.1",
            "host_status": "未知",
            "method": "UDP",
            "port": 53,
            "port_status": "开放或被过滤",
            "service": None,
        },
    ]


def test_fingerprint_records_preserve_unknown_service_as_none():
    results = [
        SimpleNamespace(host="192.0.2.1", port=443, open=True, service="https"),
        SimpleNamespace(host="192.0.2.1", port=8080, open=False, service=None),
    ]

    records = _fingerprint_results_to_frontend_records(results, lang="en")

    assert records[0]["host_status"] == "online"
    assert records[0]["service"] == "HTTPS"
    assert records[1]["port_status"] == "closed"
    assert records[1]["service"] is None


def test_render_json_and_export_filename_are_frontend_safe():
    assert '"端口"' in _render_json([{"name": "端口"}])
    assert _build_export_filename("scan", "../bad host", mode="tcp syn", use_json=True) == "scan_bad_host_tcp_syn.json"
