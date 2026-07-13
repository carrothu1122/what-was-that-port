#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
integration_demo.py — 三种 TCP 扫描器整合示例

演示如何在自己的模块中统一导入并调用三种扫描器。

注意：syn / fin 模式需要 root/sudo 权限。
"""

from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor

# ---------- 导入三种扫描器 ----------
from tcp_scanner.models import TCPConnectScanResult, TCPFINScanResult, TCPSYNScanResult
from tcp_scanner.tcp_connect_scanner import TCPConnectScanner
from tcp_scanner.tcp_fin_scanner import fin_scan_port, scan_ports as fin_scan_ports
from tcp_scanner.tcp_syn_scanner import TCPSYNScanner


# =============================================
# 方案一：分别调用，各自获取结果
# =============================================

def demo_separate_scans(target_host: str, port_list: List[int]):
    """分别调用三种扫描器，返回各自的原始结果"""

    # 1. TCP Connect 扫描（无权限要求）
    connect_scanner = TCPConnectScanner(timeout=1.0)
    connect_results: List[TCPConnectScanResult] = connect_scanner.scan_ports(
        host=target_host, ports=port_list, max_workers=50
    )

    # 2. TCP SYN 扫描（需 root/sudo）
    syn_scanner = TCPSYNScanner(timeout=2.0)
    syn_results: List[TCPSYNScanResult] = syn_scanner.scan_ports(
        host=target_host, ports=port_list, max_workers=50
    )

    # 3. TCP FIN 扫描（需 root/sudo）
    fin_results: List[TCPFINScanResult] = fin_scan_ports(
        target=target_host, ports=port_list, timeout=1.0, retries=1, delay=0.05
    )

    return connect_results, syn_results, fin_results


# =============================================
# 方案二：统一扫描接口（推荐整合方式）
# =============================================

ScanMode = str  # "connect" | "syn" | "fin"

def unified_scan(
    target_host: str,
    ports: List[int],
    mode: ScanMode = "connect",
    timeout: float = 1.0,
    max_workers: int = 50
) -> List:
    """
    统一扫描接口，通过 mode 切换扫描方式。

    Args:
        target_host: 目标主机
        ports: 端口列表
        mode: "connect" / "syn" / "fin"
        timeout: 超时时间（秒）
        max_workers: 最大并发数（仅 connect 和 syn 有效）

    Returns:
        扫描结果列表（TCPConnectScanResult / TCPSYNScanResult / TCPFINScanResult）
    """

    if mode == "connect":
        scanner = TCPConnectScanner(timeout=timeout)
        return scanner.scan_ports(target_host, ports, max_workers)

    elif mode == "syn":
        scanner = TCPSYNScanner(timeout=timeout)
        return scanner.scan_ports(target_host, ports, max_workers)

    elif mode == "fin":
        return fin_scan_ports(target_host, ports, timeout=timeout, retries=1, delay=0.05)

    else:
        raise ValueError(f"不支持的扫描模式: {mode}")


# =============================================
# 方案三：多模式对比扫描
# =============================================

def compare_scan(
    target_host: str,
    ports: List[int],
    timeout: float = 1.0
) -> Dict[int, Dict[str, str]]:
    """
    对同一批端口同时执行三种扫描，汇总对比结果。

    返回格式：
        {
            22:  {"connect": "open",       "syn": "open",       "fin": "打开(丢弃)"},
            80:  {"connect": "closed",     "syn": "closed",     "fin": "关闭(RST)"},
            443: {"connect": "filtered",   "syn": "filtered",   "fin": "打开(丢弃)"},
        }
    """

    connect_scanner = TCPConnectScanner(timeout=timeout)

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_connect = executor.submit(
            connect_scanner.scan_ports, target_host, ports, 50
        )
        future_syn = executor.submit(
            TCPSYNScanner(timeout=timeout).scan_ports, target_host, ports, 50
        )

    connect_results = future_connect.result()
    syn_results     = future_syn.result()

    # FIN 扫描
    fin_results = fin_scan_ports(target_host, ports, timeout=timeout, retries=1, delay=0.05)

    # 安全组装对比字典（使用 setdefault 避免 KeyError）
    comparison: Dict[int, Dict[str, str]] = {}

    for cr in connect_results:
        comparison.setdefault(cr.port, {})
        comparison[cr.port]["connect"] = cr.status

    for sr in syn_results:
        comparison.setdefault(sr.port, {})
        comparison[sr.port]["syn"] = sr.status

    for fr in fin_results:
        comparison.setdefault(fr.port, {})
        comparison[fr.port]["fin"] = fr.status

    return comparison


# =============================================
# 方案四：异常安全包装（统一输出为 dict）
# =============================================

def safe_scan(
    target_host: str,
    ports: List[int],
    mode: ScanMode = "connect",
    timeout: float = 1.0
) -> List[dict]:
    """
    带异常捕获的安全扫描包装，统一输出为 dict 列表。

    返回格式：
        [{"host": ..., "port": ..., "status": ..., "detail": ...}, ...]
    """

    unified_results = []

    try:
        if mode == "connect":
            scanner = TCPConnectScanner(timeout=timeout)
            results = scanner.scan_ports(target_host, ports)
            for r in results:
                unified_results.append({
                    "host": r.host,
                    "port": r.port,
                    "status": r.status,
                    "detail": r.error_message,
                })

        elif mode == "syn":
            scanner = TCPSYNScanner(timeout=timeout)
            results = scanner.scan_ports(target_host, ports)
            for r in results:
                unified_results.append({
                    "host": r.host,
                    "port": r.port,
                    "status": r.status,
                    "detail": r.error_message,
                })

        elif mode == "fin":
            results = fin_scan_ports(target_host, ports, timeout=timeout, retries=1, delay=0.05)
            for r in results:
                unified_results.append({
                    "host": r.host,
                    "port": r.port,
                    "status": r.status,
                    "detail": r.error_message,
                })

    except PermissionError:
        print(f"[{mode}] 权限不足，请使用 root/sudo 运行")
    except Exception as e:
        print(f"[{mode}] 扫描异常: {e}")

    return sorted(unified_results, key=lambda x: x["port"])


# =============================================
# 使用示例
# =============================================

if __name__ == "__main__":

    TARGET = "192.168.1.1"
    PORTS  = [22, 80, 443]

    # 分别扫描
    c_res, s_res, f_res = demo_separate_scans(TARGET, PORTS)
    print(f"Connect 扫描到 {len(c_res)} 个端口")
    print(f"SYN     扫描到 {len(s_res)} 个端口")
    print(f"FIN     扫描到 {len(f_res)} 个端口")

    # 统一扫描
    results = unified_scan(TARGET, PORTS, mode="connect", timeout=2.0)
    print(f"\n统一扫描完成，共 {len(results)} 条结果")

    # 对比扫描
    comparison = compare_scan(TARGET, PORTS, timeout=2.0)
    for port, states in comparison.items():
        print(f"Port {port}: {states}")

    # 异常安全扫描
    safe_results = safe_scan(TARGET, PORTS, mode="connect")
    for r in safe_results:
        print(f"{r['host']}:{r['port']} -> {r['status']} ({r['detail']})")
