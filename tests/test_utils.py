import pytest

from utils import parse_ports, validate_target


def test_parse_ports_sorts_deduplicates_and_expands_ranges():
    assert parse_ports("80,22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


@pytest.mark.parametrize("port_text", ["", "abc", "0", "65536", "22-abc", "1-65536"])
def test_parse_ports_rejects_invalid_input(port_text):
    with pytest.raises(ValueError):
        parse_ports(port_text)


def test_validate_target_accepts_ipv4_and_rejects_non_ipv4():
    assert validate_target("127.0.0.1") == "127.0.0.1"

    with pytest.raises(ValueError):
        validate_target("::1")

    with pytest.raises(ValueError):
        validate_target("127.000.000.001")

    with pytest.raises(ValueError):
        validate_target("not-an-ip")
