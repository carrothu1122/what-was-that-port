import socket
import threading
import time

import pytest

from service_fingerprint import scan_service
from tcp_connect_scanner import TCPConnectScanner


HOST = "127.0.0.1"


pytestmark = pytest.mark.network


def create_tcp_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as exc:
        pytest.skip(f"当前环境不允许创建本机 socket：{exc}")


class LocalTCPServer:
    def __init__(self, response: bytes):
        self.response = response
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._sock = create_tcp_socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((HOST, 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        assert self._ready.wait(timeout=1.0)
        return self

    def close(self):
        self._stop.set()
        try:
            with socket.create_connection((HOST, self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self._thread.join(timeout=1.0)
        self._sock.close()

    def _serve(self):
        self._sock.listen()
        self._sock.settimeout(0.1)
        self._ready.set()

        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            with conn:
                conn.settimeout(0.1)
                try:
                    conn.recv(4096)
                except (TimeoutError, OSError):
                    pass
                try:
                    conn.sendall(self.response)
                except OSError:
                    pass


def get_unused_local_port():
    with create_tcp_socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def test_tcp_connect_scanner_detects_local_open_and_closed_ports():
    server = LocalTCPServer(b"hello\r\n").start()
    closed_port = get_unused_local_port()

    try:
        scanner = TCPConnectScanner(timeout=0.5)

        open_result = scanner.scan_port(HOST, server.port)
        closed_result = scanner.scan_port(HOST, closed_port)

        assert open_result.status == "open"
        assert open_result.error_code == 0
        assert open_result.response_time_ms is not None

        assert closed_result.status == "closed"
    finally:
        server.close()


def test_tcp_connect_scanner_batch_scan_local_ports_sorted():
    server = LocalTCPServer(b"hello\r\n").start()
    closed_port = get_unused_local_port()

    try:
        scanner = TCPConnectScanner(timeout=0.5)
        results = scanner.scan_ports(HOST, [server.port, closed_port], max_workers=2)

        assert [result.port for result in results] == sorted([server.port, closed_port])
        assert {result.port: result.status for result in results} == {
            server.port: "open",
            closed_port: "closed",
        }
    finally:
        server.close()


def test_service_fingerprint_detects_local_http_banner():
    server = LocalTCPServer(
        b"HTTP/1.0 200 OK\r\n"
        b"Server: LocalTestServer/1.0\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    ).start()

    try:
        result = scan_service(HOST, server.port, timeout=0.5)

        assert result.open is True
        assert result.service == "http"
        assert result.version == "LocalTestServer/1.0"
        assert result.probe == "http"
    finally:
        server.close()


def test_service_fingerprint_reports_closed_local_port():
    closed_port = get_unused_local_port()
    time.sleep(0.01)

    result = scan_service(HOST, closed_port, timeout=0.2)

    assert result.open is False
    assert result.service is None
    assert "端口未开放" in result.detail
