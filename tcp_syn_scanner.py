#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
模块名称：tcp_syn_scanner.py

功能：
    实现 TCP SYN 端口扫描功能。

扫描原理：
    TCP SYN 扫描也叫“半开放扫描”。
    程序向目标端口发送 SYN 数据包。

判断规则：
    1. 如果目标端口开放：
        目标主机返回 SYN/ACK（TCP flags & 0x12 == 0x12）

    2. 如果目标端口关闭：
        目标主机返回 RST（TCP flags & 0x04 == 0x04）

    3. 如果没有响应或 ICMP 管理禁止：
        记为 filtered

    4. 如果收到 ICMP 网络/主机/协议不可达：
        记为 unreachable

    5. 如果收到非预期 TCP Flags 或无法解释的响应：
        记为 unknown

主机在线状态：
    主机初始在线状态由 ICMP 模块（host_discovery.py）提供。
    最终主机状态由 ICMP 与 TCP SYN 响应综合判断：
    TCP 出现 open 或 closed（RST）时，主机确定在线。

注意：
    本模块只判断端口状态，不判断端口运行的具体服务。
    Linux 下通常需要 sudo 权限运行。
    sudo python3 tcp_syn_scanner.py
"""

from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Dict, List, Optional

try:
    from .models import TCPSYNScanResult
    from .utils import parse_ports
except ImportError:  # 兼容直接运行本文件：python tcp_syn_scanner.py
    from models import TCPSYNScanResult
    from utils import parse_ports

try:
    from scapy.all import IP, TCP, ICMP, sr1, send, RandShort, conf
except ImportError:
    raise ImportError("请先安装 scapy：pip install scapy")


# ============================================================================
# ICMP 不可达 Code → 含义映射
# ============================================================================

_ICMP_UNREACHABLE_MAP: Dict[int, str] = {
    0:  "network unreachable",
    1:  "host unreachable",
    2:  "protocol unreachable",
    9:  "network administratively prohibited",
    10: "host administratively prohibited",
    13: "communication administratively prohibited",
}

# 归类为 unreachable 的 ICMP Code（非管理策略导致的不可达）
_UNREACHABLE_CODES: set = {0, 1, 2}

# 归类为 filtered 的 ICMP Code（管理策略导致）
_FILTERED_ICMP_CODES: set = {9, 10, 13}


class TCPSYNScanner:
    """
    TCP SYN 扫描器类
    """

    def __init__(self, timeout: float = 2.0):
        """
        初始化扫描器

        Args:
            timeout: 等待目标响应的超时时间，单位为秒
        """
        self.timeout = timeout
        conf.verb = 0

    def scan_port(self, host: str, port: int) -> TCPSYNScanResult:
        """
        扫描单个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            port: 目标端口号

        Returns:
            TCPSYNScanResult: 扫描结果对象
        """

        if port < 1 or port > 65535:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message="Invalid port number"
            )

        try:
            source_port = int(RandShort())

            syn_packet = IP(dst=host) / TCP(
                sport=source_port,
                dport=port,
                flags="S",
                seq=1000
            )

            response = sr1(
                syn_packet,
                timeout=self.timeout,
                verbose=False
            )

            if response is None:
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    response_flags=None,
                    error_message="No response"
                )

            if response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                flags_value = int(tcp_flags)

                # SYN/ACK = 0x12，表示端口开放
                if flags_value & 0x12 == 0x12:
                    rst_packet = IP(dst=host) / TCP(
                        sport=source_port,
                        dport=port,
                        flags="R",
                        seq=response.getlayer(TCP).ack
                    )

                    send(rst_packet, verbose=False)

                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="open",
                        response_flags=str(tcp_flags),
                        error_message="收到SYN/ACK → 端口开放"
                    )

                # RST = 0x14 或 0x04，表示端口关闭
                elif flags_value & 0x04 == 0x04:
                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="closed",
                        response_flags=str(tcp_flags),
                        error_message="收到RST → 端口关闭"
                    )

                else:
                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="unknown",
                        response_flags=str(tcp_flags),
                        error_message="Unexpected TCP response"
                    )

            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                icmp_type = int(icmp_layer.type)
                icmp_code = int(icmp_layer.code)

                # 只处理 ICMP Destination Unreachable (Type 3)
                if icmp_type == 3:
                    description = _ICMP_UNREACHABLE_MAP.get(
                        icmp_code,
                        f"ICMP unreachable (code={icmp_code})"
                    )
                    full_message = (
                        f"ICMP unreachable: type={icmp_type}, "
                        f"code={icmp_code}, {description}"
                    )

                    if icmp_code in _FILTERED_ICMP_CODES:
                        return TCPSYNScanResult(
                            host=host,
                            port=port,
                            status="filtered",
                            response_flags=None,
                            error_message=full_message,
                        )

                    if icmp_code in _UNREACHABLE_CODES:
                        return TCPSYNScanResult(
                            host=host,
                            port=port,
                            status="unreachable",
                            response_flags=None,
                            error_message=full_message,
                        )

                    # 其他 ICMP Type 3 Code → unknown
                    return TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="unknown",
                        response_flags=None,
                        error_message=full_message,
                    )

                # 非 Type 3 的 ICMP → unknown
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="unknown",
                    response_flags=None,
                    error_message=(
                        f"Unexpected ICMP: type={icmp_type}, code={icmp_code}"
                    ),
                )

            else:
                return TCPSYNScanResult(
                    host=host,
                    port=port,
                    status="unknown",
                    response_flags=None,
                    error_message="Unknown response"
                )

        except PermissionError as e:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message=f"Permission error: {e}"
            )

        except Exception as e:
            return TCPSYNScanResult(
                host=host,
                port=port,
                status="error",
                response_flags=None,
                error_message=str(e)
            )

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        max_workers: int = 50
    ) -> List[TCPSYNScanResult]:
        """
        扫描多个 TCP 端口

        Args:
            host: 目标主机 IP 或域名
            ports: 端口列表
            max_workers: 最大线程数

        Returns:
            List[TCPSYNScanResult]: 扫描结果列表
        """

        results: List[TCPSYNScanResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port: Dict[Future, int] = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    results.append(TCPSYNScanResult(
                        host=host,
                        port=port,
                        status="error",
                        response_flags=None,
                        error_message=str(exc),
                    ))

        results.sort(key=lambda item: item.port)
        return results


def print_scan_results(results: List[TCPSYNScanResult]) -> None:
    """
    打印扫描结果，方便调试
    """

    print("-" * 100)
    print(f"{'Host':<18}{'Port':<10}{'Status':<12}{'Flags':<12}{'Message'}")
    print("-" * 100)

    for result in results:
        print(
            f"{result.host:<18}"
            f"{result.port:<10}"
            f"{result.status:<12}"
            f"{str(result.response_flags):<12}"
            f"{result.error_message}"
        )

    print("-" * 100)


def print_fingerprint_debug_results(
    host: str,
    open_ports: List[int],
    timeout: float = 3.0,
) -> None:
    """仅用于 __main__ 调试联动，不写入 SYN 扫描器正式实现。"""
    unique_open_ports = sorted(set(open_ports))

    print()
    print("【Fingerprint 调试验证】")

    if not unique_open_ports:
        print("  未发现开放端口，跳过服务指纹识别。")
        return

    try:
        from .service_fingerprint import scan_services
    except ImportError:
        from service_fingerprint import scan_services

    print(f"  对开放端口做额外指纹识别验证：{unique_open_ports}")

    try:
        fingerprint_results = scan_services(host, unique_open_ports, timeout=timeout)
    except Exception as exc:
        print(f"  服务指纹识别失败：{exc}")
        return

    print("-" * 110)
    print(
        f"{'Host':<18}{'Port':<8}{'Open':<8}"
        f"{'Service':<18}{'Version':<20}{'Probe':<16}{'Detail'}"
    )
    print("-" * 110)

    for item in fingerprint_results:
        service = item.service or "未知"
        version = item.version or "-"
        probe = item.probe or "-"
        detail = item.detail or ""
        print(
            f"{item.host:<18}{item.port:<8}{str(item.open):<8}"
            f"{service:<18}{version:<20}{probe:<16}{detail}"
        )

    print("-" * 110)


if __name__ == "__main__":
    """
    单独运行本文件时，用于调试。
    被其他模块 import 时，不会执行这里。

    推荐调用流程：
        1. ICMP 探测 → icmp_status_code (online/offline)
        2. TCP SYN 扫描 → raw_results
        3. 综合判断 → resolve_final_host_status(icmp_status_code, raw_results)
    """

    # ===== 调试参数（以SSH/FTP端口扫描为例） =====
    target_host = "10.181.211.172"   # 请改为实际目标 IP
    port_input = "21,22,8080"             # FTP(21) + SSH(22)
    timeout = 2.0
    max_workers = 20

    print("TCP SYN 扫描 —— 以 SSH(22) / FTP(21) 为例")
    print(f"目标主机：{target_host}")
    print(f"扫描端口：{port_input}")
    print()

    # ================================================================
    # 以下 ICMP 联调代码仅用于临时调试和模块联调。
    # 正式的综合扫描流程应放在项目的 main.py 或 ScanManager 中。
    # TCPSYNScanner 类本身只负责端口状态判断，不调用 ICMP 主机探测。
    # ================================================================

    # ----- ICMP 主机探测（临时联调） -----
    icmp_status_code: str = "offline"
    try:
        from .host_discovery import is_host_alive
    except ImportError:
        from host_discovery import is_host_alive
    try:
        print("  [ICMP] 正在探测主机是否在线 ...")
        alive = is_host_alive(target_host, timeout_ms=1000)
        icmp_status_code = "online" if alive else "offline"
        icmp_display = "在线" if alive else "离线"
        print(f"  [ICMP] 探测结果：{icmp_display}")
    except Exception as exc:
        print(f"  [ICMP] 探测异常：{exc}，ICMP 初始状态设为 offline")
    print()

    try:
        ports = parse_ports(port_input)

        scanner = TCPSYNScanner(timeout=timeout)
        scan_results = scanner.scan_ports(
            host=target_host,
            ports=ports,
            max_workers=max_workers
        )

        print_scan_results(scan_results)

        # 仅在调试时联动 fingerprint，便于核对开放端口上的服务识别结果。
        # 仅在调试时联动 fingerprint，便于核对开放端口上的服务识别结果。
        open_ports = [result.port for result in scan_results if result.status == "open"]
        open_ports = [result.port for result in scan_results if result.status == "open"]
        print_fingerprint_debug_results(
            host=target_host,
            open_ports=open_ports,
            timeout=timeout,
        )

        # 综合判断主机状态
        has_response = any(
            r.status in ("open", "closed") for r in scan_results
        )
        if icmp_status_code == "offline" and has_response:
            print("  [TCP] 检测到目标主机有明确响应（ICMP 失败但 TCP 可达）")
        final_code = "online" if (icmp_status_code == "online" or has_response) else "offline"
        print(f"  最终主机状态：{'在线' if final_code == 'online' else '离线'}")
        print()

    except ValueError as e:
        print(f"端口输入错误：{e}")

    except KeyboardInterrupt:
        print("\n扫描已手动终止")
