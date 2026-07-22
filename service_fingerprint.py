#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP 服务指纹识别模块。

先确认端口可建立 TCP 连接，再按端口优先级发送探针并匹配响应。
"""

import os
import re
import socket
import ssl
import sys as _sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

# 确保当前目录在 sys.path 中，以便绝对导入 fingerprints 总能成功
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in _sys.path:
    _sys.path.insert(0, _dir)

try:
    from .fingerprints import DEFAULT_PRIORITY, FINGERPRINTS, PORT_PRIORITY
except ImportError:
    from fingerprints import DEFAULT_PRIORITY, FINGERPRINTS, PORT_PRIORITY


@dataclass
class ServiceFingerprintResult:
    host: str
    port: int
    open: bool
    service: Optional[str]
    version: Optional[str]
    probe: Optional[str]
    detail: str


def _build_probe(probe: bytes, host: str) -> bytes:
    if b"%s" in probe:
        return probe.replace(b"%s", host.encode())
    return probe


def _connect(host: str, port: int, timeout: float = 3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def is_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        sock = _connect(host, port, timeout)
    except OSError:
        return False
    else:
        sock.close()
        return True


def send_probe(
    host: str,
    port: int,
    probe: bytes,
    tls: bool = False,
    timeout: float = 3.0,
) -> Optional[bytes]:
    sock = None
    try:
        sock = _connect(host, port, timeout)
        if tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        payload = _build_probe(probe, host)
        if payload:
            sock.sendall(payload)

        return sock.recv(4096)
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()


def match_fingerprint(response: bytes, fingerprints: Iterable[dict]) -> Tuple[Optional[str], Optional[str]]:
    text = response.decode(errors="ignore")
    for fingerprint in fingerprints:
        match = re.search(fingerprint["match_regex"], text)
        if match:
            version_info = fingerprint["version_template"].format(*match.groups())
            return fingerprint["service"], version_info
    return None, None


def _fingerprint_by_name(name: str) -> List[dict]:
    return [fingerprint for fingerprint in FINGERPRINTS if fingerprint["name"] == name]


def scan_service(host: str, port: int, timeout: float = 3.0) -> ServiceFingerprintResult:
    if port < 1 or port > 65535:
        return ServiceFingerprintResult(host, port, False, None, None, None, "Invalid port number")

    if not is_open(host, port, timeout=timeout):
        return ServiceFingerprintResult(host, port, False, None, None, None, "端口未开放或连接失败")

    probe_names = PORT_PRIORITY.get(port, DEFAULT_PRIORITY)
    tried = set()

    for probe_name in probe_names + DEFAULT_PRIORITY:
        if probe_name in tried:
            continue
        tried.add(probe_name)

        candidates = _fingerprint_by_name(probe_name)
        for fingerprint in candidates:
            response = send_probe(
                host,
                port,
                fingerprint["probe"],
                tls=fingerprint.get("tls", False),
                timeout=timeout,
            )
            if not response:
                continue

            service, version = match_fingerprint(response, [fingerprint])
            if service:
                return ServiceFingerprintResult(
                    host=host,
                    port=port,
                    open=True,
                    service=service,
                    version=version,
                    probe=fingerprint["name"],
                    detail="指纹匹配成功",
                )

    return ServiceFingerprintResult(host, port, True, None, None, None, "端口开放，但未匹配到服务指纹")


def scan_services(host: str, ports: List[int], timeout: float = 3.0) -> List[ServiceFingerprintResult]:
    results = [scan_service(host, port, timeout=timeout) for port in ports]
    return sorted(results, key=lambda result: result.port)

