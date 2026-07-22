import csv
import io

from csv_export import (
    RESULT_COLUMN_HEADERS,
    RESULT_COLUMNS,
    RESULT_FIELDNAMES,
    write_csv_rows,
)


def test_write_csv_rows_exports_gui_fields_only():
    output = io.StringIO(newline="")
    populated_result = {
        "ip": "192.0.2.1",
        "host_status": "在线",
        "method": "TCP SYN",
        "port": 443,
        "port_status": "开放",
        "service": "HTTPS",
        "response_flags": "SA",
        "error_message": "收到 SYN/ACK",
        "detail": "Flags: SA；端口正常响应连接请求",
        "elapsed_ms": 12.34,
        "error_reason": "",
    }
    empty_result = {
        "ip": "192.0.2.2",
        "host_status": "在线",
        "method": "ICMP",
        "port": "-",
        "port_status": "-",
        "service": "-",
        "response_flags": None,
        "error_message": None,
        "detail": "-",
        "elapsed_ms": None,
        "error_reason": "",
    }

    write_csv_rows(output, [populated_result, empty_result])

    rows = list(csv.DictReader(io.StringIO(output.getvalue())))
    assert tuple(rows[0]) == RESULT_FIELDNAMES
    assert rows[0]["ip"] == "192.0.2.1"
    assert rows[0]["detail"] == "Flags: SA；端口正常响应连接请求"
    assert "response_flags" not in rows[0]
    assert "error_message" not in rows[0]
    assert rows[1]["elapsed_ms"] == ""


def test_result_fields_and_gui_headers_come_from_the_same_column_config():
    assert RESULT_FIELDNAMES == tuple(field for field, _ in RESULT_COLUMNS)
    assert RESULT_COLUMN_HEADERS == tuple(header for _, header in RESULT_COLUMNS)
    assert len(RESULT_FIELDNAMES) == len(RESULT_COLUMN_HEADERS) == 9
