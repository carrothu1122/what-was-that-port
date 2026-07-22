#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
公共数据模型模块

定义 TCP Connect / TCP SYN / TCP FIN / UDP 扫描器的统一返回数据结构。

统一字段语义：
    host           — 目标主机 IP
    port           — 目标端口号
    status         — 端口状态：
                      Connect: open / closed / filtered / error
                      SYN:     open / closed / filtered / error
                      FIN:     closed / open|filtered / filtered / unreachable / unknown / error
                      UDP:     open / closed / open|filtered / filtered / unreachable / unknown / error
    response_flags — 目标返回的 TCP 标志位或 UDP/ICMP 响应标记，无则为 None
    error_code     — 错误码，Connect 成功时为 0（即 connect()返回0），不适用时为 None
    error_message  — 详细描述信息
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class TCPConnectScanResult:
    """
    TCP Connect 扫描结果

    Attributes:
        host: 目标主机 IP
        port: 目标端口号
        status: open / closed / filtered / error / cancelled
        error_code: socket 错误码，成功时为 0，不适用时为 None
        error_message: 详细描述信息
        response_time_ms: 响应时间（毫秒），无则为 None
    """
    host: str
    port: int
    status: str
    error_code: Optional[int]
    error_message: str
    response_time_ms: Optional[float] = None


@dataclass
class TCPSYNScanResult:
    """
    TCP SYN 扫描结果

    Attributes:
        host: 目标主机 IP
        port: 目标端口号
        status: open / closed / filtered / error
        response_flags: TCP 标志位（如 SA / RA），无则为 None
        error_message: 详细描述信息
    """
    host: str
    port: int
    status: str
    response_flags: Optional[str]
    error_message: str


@dataclass
class TCPFINScanResult:
    """
    TCP FIN 扫描结果

    判断规则：
        RST                    → status="closed"
        无响应                  → status="open|filtered"
        ICMP(3,9/10/13)       → status="filtered"
        ICMP(3,0/1/2)         → status="unreachable"
        其他无法判断的响应       → status="unknown"
        本地异常                → status="error"

    Attributes:
        host: 目标主机 IP
        port: 目标端口号
        status: closed / open|filtered / filtered / unreachable / unknown / error
        response_flags: TCP 标志位，无则为 None
        error_message: 详细描述信息
    """
    host: str
    port: int
    status: str
    response_flags: Optional[str]
    error_message: str


@dataclass
class UDPScanResult:
    """
    UDP 扫描结果

    判断规则：
        收到 UDP 响应             → status="open"
        ICMP(3,3) Port Unreachable → status="closed"
        无响应                    → status="open|filtered"
        ICMP(3,9/10/13)          → status="filtered"
        ICMP(3,0/1/2)            → status="unreachable"
        其他无法判断的响应         → status="unknown"
        本地异常                  → status="error"

    Attributes:
        host: 目标主机 IP
        port: 目标端口号
        status: open / closed / open|filtered / filtered / unreachable / unknown / error
        response_flags: UDP 无 TCP 标志位；收到 UDP 响应时为 "UDP"，收到 ICMP 时为 "ICMP"
        error_message: 详细描述信息
    """
    host: str
    port: int
    status: str
    response_flags: Optional[str]
    error_message: str
