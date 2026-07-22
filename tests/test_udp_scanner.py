import pytest

from udp_scanner import ICMP, UDP, classify_response, scan_ports


class FakeLayer:
    def __init__(self, *, type=None, code=None):
        self.type = type
        self.code = code


class FakeResponse:
    def __init__(self, layers):
        self._layers = layers

    def haslayer(self, layer):
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]


def test_classify_udp_no_response_is_open_filtered():
    state, marker, reason = classify_response(None)

    assert state == "open|filtered"
    assert marker is None
    assert "无响应" in reason


def test_classify_udp_response_is_open():
    response = FakeResponse({UDP: FakeLayer()})

    state, marker, reason = classify_response(response)

    assert state == "open"
    assert marker == "UDP"
    assert "开放" in reason


def test_classify_udp_icmp_port_unreachable_is_closed():
    response = FakeResponse({ICMP: FakeLayer(type=3, code=3)})

    state, marker, reason = classify_response(response)

    assert state == "closed"
    assert marker == "ICMP"
    assert "Port Unreachable" in reason


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (9, "filtered"),
        (10, "filtered"),
        (13, "filtered"),
        (0, "unreachable"),
        (1, "unreachable"),
        (2, "unreachable"),
        (8, "unknown"),
    ],
)
def test_classify_udp_icmp_destination_unreachable_codes(code, expected):
    response = FakeResponse({ICMP: FakeLayer(type=3, code=code)})

    assert classify_response(response)[0] == expected


def test_scan_ports_validates_workers_and_sorts_results(monkeypatch):
    def fake_udp_scan_port(target, port, timeout, retries):
        from models import UDPScanResult

        return UDPScanResult(
            host=target,
            port=port,
            status="open|filtered",
            response_flags=None,
            error_message=f"port {port}",
        )

    monkeypatch.setattr("udp_scanner.udp_scan_port", fake_udp_scan_port)

    results = scan_ports("192.0.2.1", [123, 53, 161], max_workers=2)

    assert [result.port for result in results] == [53, 123, 161]

    with pytest.raises(ValueError):
        scan_ports("192.0.2.1", [53], max_workers=0)
