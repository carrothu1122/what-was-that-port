from scanner_adapter import convert_status, get_service_name, make_error_row, make_row


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


def test_make_row_and_error_row_have_stable_frontend_shape():
    assert make_row("192.0.2.1", "在线", "TCP Connect", 80, "开放") == {
        "ip": "192.0.2.1",
        "host_status": "在线",
        "method": "TCP Connect",
        "port": 80,
        "port_status": "开放",
        "service": "HTTP",
    }

    assert make_error_row("192.0.2.1", "未知", "TCP SYN", "需要 root") == {
        "ip": "192.0.2.1",
        "host_status": "未知",
        "method": "TCP SYN",
        "port": "-",
        "port_status": "错误：需要 root",
        "service": "-",
    }
