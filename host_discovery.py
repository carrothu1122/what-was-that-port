#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主机存活探测模块。

当前实现使用 ICMP Echo Request。Linux/macOS 下通常需要 root/sudo 或 raw socket
能力；无权限时返回不可达，并在 reason 中说明原因。
"""

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class HostDiscoveryResult:
    host: str
    resolved_ip: Optional[str]
    alive: bool
    rtt_ms: Optional[float]
    reason: str


def _resolve_ipv4(host: str) -> Optional[str]:
    try:
        info = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if not info:
            return None
        return info[0][4][0]
    except socket.gaierror:
        return None


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    checksum = 0
    for index in range(0, len(data), 2):
        checksum += (data[index] << 8) + data[index + 1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF


def icmp_probe(
    host: str,
    timeout_ms: int = 1000,
    ttl: int = 64,
    payload_size: int = 32,
) -> HostDiscoveryResult:
    """
    使用 ICMP Echo Request 探测主机是否存活。
    """

    dest_ip = _resolve_ipv4(host)
    if dest_ip is None:
        return HostDiscoveryResult(host, None, False, None, "无法解析 IPv4 地址")

    payload = b"7" * max(payload_size, 0)
    identifier = os.getpid() & 0xFFFF
    sequence = 1

    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    packet_checksum = _checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, packet_checksum, identifier, sequence)
    packet = header + payload

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
            except OSError:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            started_at = time.time()
            deadline = started_at + timeout_ms / 1000.0
            sock.sendto(packet, (dest_ip, 0))

            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return HostDiscoveryResult(host, dest_ip, False, None, "ICMP 请求超时")

                sock.settimeout(remaining)
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    return HostDiscoveryResult(host, dest_ip, False, None, "ICMP 请求超时")

                if addr and addr[0] != dest_ip:
                    continue
                if len(data) < 20:
                    continue

                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 8:
                    continue

                icmp_segment = data[ihl:]
                r_type, r_code, _r_checksum, r_id, r_seq = struct.unpack(
                    "!BBHHH", icmp_segment[:8]
                )

                if r_type == 0 and r_code == 0 and r_id == identifier and r_seq == sequence:
                    rtt_ms = (time.time() - started_at) * 1000
                    return HostDiscoveryResult(host, dest_ip, True, rtt_ms, "收到 ICMP Echo Reply")

    except PermissionError:
        return HostDiscoveryResult(host, dest_ip, False, None, "权限不足：ICMP raw socket 需要 root/sudo")
    except OSError as error:
        return HostDiscoveryResult(host, dest_ip, False, None, f"ICMP 探测失败：{error}")


def is_host_alive(host: str, timeout_ms: int = 1000) -> bool:
    """兼容旧代码的布尔接口。"""

    return icmp_probe(host, timeout_ms=timeout_ms).alive
