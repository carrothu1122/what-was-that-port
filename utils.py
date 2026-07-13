#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
公共工具模块

提供所有扫描器共用的工具函数。
"""

import ipaddress
from typing import List


def validate_target(target: str) -> str:
    """
    验证并规范化目标 IPv4 地址。

    Args:
        target: 目标 IP 地址字符串

    Returns:
        规范化后的 IPv4 地址字符串

    Raises:
        ValueError: 非法的 IP 地址或非 IPv4 地址
    """

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(f"无效的 IP 地址：{target}")

    if address.version != 4:
        raise ValueError("当前程序只支持 IPv4")

    return str(address)


def parse_ports(port_text: str) -> List[int]:
    """
    解析端口参数字符串。

    支持格式：
        "80"
        "21,22,80,443"
        "1-1024"
        "21,22,80-90"

    Args:
        port_text: 端口参数字符串

    Returns:
        排序后的端口列表

    Raises:
        ValueError: 端口格式无效或超出范围
    """

    ports = set()

    for item in port_text.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", 1)

            try:
                start_port = int(start_text)
                end_port = int(end_text)
            except ValueError:
                raise ValueError(f"无效端口范围：{item}")

            if start_port > end_port:
                start_port, end_port = end_port, start_port

            if start_port < 1 or end_port > 65535:
                raise ValueError("端口必须在 1 到 65535 之间")

            ports.update(range(start_port, end_port + 1))

        else:
            try:
                port = int(item)
            except ValueError:
                raise ValueError(f"无效端口：{item}")

            if port < 1 or port > 65535:
                raise ValueError("端口必须在 1 到 65535 之间")

            ports.add(port)

    if not ports:
        raise ValueError("至少需要指定一个端口")

    return sorted(ports)
