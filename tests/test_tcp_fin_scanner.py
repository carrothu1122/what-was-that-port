import pytest

from tcp_fin_scanner import ICMP, TCP, classify_response, scan_ports


class FakeLayer:
    def __init__(self, *, flags=None, type=None, code=None, flag_text=""):
        self.flags = flags
        self.type = type
        self.code = code
        self._flag_text = flag_text

    def sprintf(self, _format):
        return self._flag_text


class FakeResponse:
    def __init__(self, layers):
        self._layers = layers

    def haslayer(self, layer):
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]


def test_classify_fin_no_response_is_open_filtered():
    state, reason = classify_response(None)

    assert state == "open|filtered"
    assert "无响应" in reason


def test_classify_fin_tcp_rst_is_closed():
    response = FakeResponse({TCP: FakeLayer(flags=0x04, flag_text="R")})

    assert classify_response(response)[0] == "closed"


def test_classify_fin_tcp_non_rst_is_unknown():
    response = FakeResponse({TCP: FakeLayer(flags=0x10, flag_text="A")})

    state, reason = classify_response(response)

    assert state == "unknown"
    assert "A" in reason


@pytest.mark.parametrize(
    ("code", "expected"),
    [(9, "filtered"), (10, "filtered"), (13, "filtered"), (0, "unreachable"), (1, "unreachable"), (2, "unreachable"), (3, "unknown")],
)
def test_classify_fin_icmp_destination_unreachable_codes(code, expected):
    response = FakeResponse({ICMP: FakeLayer(type=3, code=code)})

    assert classify_response(response)[0] == expected


def test_scan_ports_validates_workers_and_sorts_results(monkeypatch):
    def fake_fin_scan_port(target, port, timeout, retries):
        from models import TCPFINScanResult

        return TCPFINScanResult(
            host=target,
            port=port,
            status="closed",
            response_flags="R",
            error_message=f"port {port}",
        )

    monkeypatch.setattr("tcp_fin_scanner.fin_scan_port", fake_fin_scan_port)

    results = scan_ports("192.0.2.1", [443, 22, 80], max_workers=2)

    assert [result.port for result in results] == [22, 80, 443]

    with pytest.raises(ValueError):
        scan_ports("192.0.2.1", [80], max_workers=0)
