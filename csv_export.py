import csv
from typing import TextIO


RESULT_COLUMNS = (
    ("ip", "目标 IP"),
    ("host_status", "主机状态"),
    ("method", "扫描方式"),
    ("port", "端口号"),
    ("port_status", "端口状态"),
    ("service", "服务名称"),
    ("detail", "详情"),
    ("elapsed_ms", "耗时"),
    ("error_reason", "错误原因"),
)

RESULT_FIELDNAMES = tuple(field for field, _ in RESULT_COLUMNS)
RESULT_COLUMN_HEADERS = tuple(header for _, header in RESULT_COLUMNS)


def write_csv_rows(file_obj: TextIO, results: list[dict]) -> None:
    """Write the same result columns shown by the GUI."""
    writer = csv.DictWriter(file_obj, fieldnames=RESULT_FIELDNAMES)
    writer.writeheader()
    writer.writerows(
        {field: result.get(field, "") for field in RESULT_FIELDNAMES}
        for result in results
    )
