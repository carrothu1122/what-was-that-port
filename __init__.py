#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcp_scanner package

基础用法：
    python -m tcp_scanner scan 127.0.0.1 -p 22,80 --mode connect
"""

try:
    from .models import TCPConnectScanResult, TCPFINScanResult, TCPSYNScanResult
    from .service_fingerprint import ServiceFingerprintResult, scan_service, scan_services
    from .tcp_connect_scanner import TCPConnectScanner
    from .utils import parse_ports, validate_target
except ImportError:
    # pytest may import this root-level __init__.py as a standalone module when
    # the project directory is not installed as an importable package.
    from models import TCPConnectScanResult, TCPFINScanResult, TCPSYNScanResult
    from service_fingerprint import ServiceFingerprintResult, scan_service, scan_services
    from tcp_connect_scanner import TCPConnectScanner
    from utils import parse_ports, validate_target

__all__ = [
    "TCPConnectScanner",
    "TCPConnectScanResult",
    "TCPSYNScanResult",
    "TCPFINScanResult",
    "ServiceFingerprintResult",
    "parse_ports",
    "scan_service",
    "scan_services",
    "validate_target",
]
