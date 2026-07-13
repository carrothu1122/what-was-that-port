#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
公共数据模型模块

定义三种 TCP 扫描器的统一返回数据结构。

统一字段语义：
    host           — 目标主机 IP
    port           — 目标端口号
    status         — 端口状态：
                      Connect: open / closed / filtered / error
                      SYN:     open / closed / filtered / error
                      FIN:     打开(丢弃) / 关闭(RST) / 有连接(ACK) / filtered / unknown / error
    response_flags — 目标返回的 TCP 标志位（如 SA / RA / A），无则为 None
    error_code     — 错误码，Connect 成功时为 0（即 connect()返回0），不适用时为 None
    error_message  — 详细描述信息（使用 PPT 术语）
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
        status: open / closed / filtered / error
        error_code: socket 错误码，成功时为 0
        error_message: 详细描述信息
    """
    host: str
    port: int
    status: str
    error_code: Optional[int]
    error_message: str


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

    PPT 对应：
        若对应一个连接 → 返回ACK         → status="有连接(ACK)"
        若端口打开，且没连接 → 直接丢弃   → status="打开(丢弃)"
        若端口关闭 → 返回RST             → status="关闭(RST)"

    Attributes:
        host: 目标主机 IP
        port: 目标端口号
        status: 打开(丢弃) / 关闭(RST) / 有连接(ACK) / filtered / unknown / error
        response_flags: TCP 标志位，无则为 None
        error_message: 详细描述信息
    """
    host: str
    port: int
    status: str
    response_flags: Optional[str]
    error_message: str
