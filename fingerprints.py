#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务识别指纹库。
"""

FINGERPRINTS = [
    {
        "name": "null",
        "probe": b"",
        "match_regex": r"^SSH-([\d.]+)-(.+)",
        "service": "ssh",
        "version_template": "SSH-{} - {}",
    },
    {
        "name": "null",
        "probe": b"",
        "match_regex": r"^220[\s-]+(.+)",
        "service": "ftp/smtp",
        "version_template": "{}",
    },
    {
        "name": "null",
        "probe": b"",
        "match_regex": r"^\+OK",
        "service": "pop3",
        "version_template": "POP3 Ready",
    },
    {
        "name": "http",
        "probe": b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
        "match_regex": r"Server:\s*([^\r\n]+)",
        "service": "http",
        "version_template": "{}",
    },
    {
        "name": "https",
        "probe": b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
        "match_regex": r"Server:\s*([^\r\n]+)",
        "service": "https",
        "version_template": "{}",
        "tls": True,
    },
    {
        "name": "smtp",
        "probe": b"HELO localhost\r\n",
        "match_regex": r"^250[\s-]+(.+)",
        "service": "smtp",
        "version_template": "SMTP: {}",
    },
    {
        "name": "ftp",
        "probe": b"SYST\r\n",
        "match_regex": r"^215[\s-]+(.+)",
        "service": "ftp",
        "version_template": "FTP: {}",
    },
    {
        "name": "mysql",
        "probe": b"\x00\x00\x00\x00\x01\x00\x00\x00\x00",
        "match_regex": r"(.+?)\x00",
        "service": "mysql",
        "version_template": "MySQL: {}",
    },
    {
        "name": "redis",
        "probe": b"PING\r\n",
        "match_regex": r"^\+PONG",
        "service": "redis",
        "version_template": "Redis (PONG)",
    },
]

PORT_PRIORITY = {
    80: ["null", "http"],
    443: ["https", "null"],
    22: ["null"],
    21: ["null", "ftp"],
    25: ["null", "smtp"],
    3306: ["mysql"],
    6379: ["redis"],
    8080: ["null", "http"],
    8443: ["https", "null"],
    465: ["https", "null"],
    993: ["https", "null"],
    995: ["null"],
}

DEFAULT_PRIORITY = ["null", "http", "https", "smtp", "ftp", "mysql", "redis"]
