"""Link-layer decoders of the Linux backend — pure parsing, no root needed."""
import dpkt
import pytest

from nad.capture.base import Direction
from nad.capture.linux_libpcap import (
    _decode_ethernet,
    _decode_null,
    _decode_raw,
    _decode_sll,
    _decode_sll2,
    _direction_from_pkttype,
)


def _ip_bytes() -> bytes:
    tcp = dpkt.tcp.TCP(sport=44321, dport=443, data=b"hello")
    ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x08\x08\x08\x08",
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    return bytes(ip)


def _check_ip(ip) -> None:
    import socket
    assert socket.inet_ntoa(ip.src) == "10.0.0.1"
    assert socket.inet_ntoa(ip.dst) == "8.8.8.8"
    assert int(ip.p) == 6
    assert int(ip.data.dport) == 443


def test_decode_ethernet():
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=_ip_bytes())
    result = _decode_ethernet(bytes(eth))
    assert result is not None
    ip, direction = result
    _check_ip(ip)
    assert direction is Direction.UNKNOWN


def test_decode_ethernet_non_ip():
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28)
    assert _decode_ethernet(bytes(eth)) is None


@pytest.mark.parametrize("pkttype,expected", [
    (0, Direction.INGRESS),   # PACKET_HOST
    (1, Direction.INGRESS),   # PACKET_BROADCAST
    (2, Direction.INGRESS),   # PACKET_MULTICAST
    (3, Direction.UNKNOWN),   # PACKET_OTHERHOST
    (4, Direction.EGRESS),    # PACKET_OUTGOING
])
def test_direction_from_pkttype(pkttype, expected):
    assert _direction_from_pkttype(pkttype) is expected


def _sll_frame(pkttype: int) -> bytes:
    # pkttype(2) hatype(2) halen(2) addr(8) proto(2)
    return (pkttype.to_bytes(2, "big") + (1).to_bytes(2, "big")
            + (6).to_bytes(2, "big") + b"\x00" * 8
            + (0x0800).to_bytes(2, "big") + _ip_bytes())


def test_decode_sll_outgoing():
    result = _decode_sll(_sll_frame(pkttype=4))
    assert result is not None
    ip, direction = result
    _check_ip(ip)
    assert direction is Direction.EGRESS


def test_decode_sll_incoming():
    result = _decode_sll(_sll_frame(pkttype=0))
    assert result is not None
    _, direction = result
    assert direction is Direction.INGRESS


def test_decode_sll_non_ip():
    frame = ((0).to_bytes(2, "big") + (1).to_bytes(2, "big")
             + (6).to_bytes(2, "big") + b"\x00" * 8
             + (0x0806).to_bytes(2, "big") + b"\x00" * 28)  # ARP
    assert _decode_sll(frame) is None


def _sll2_frame(pkttype: int) -> bytes:
    # proto(2) rsvd(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8)
    return ((0x0800).to_bytes(2, "big") + b"\x00\x00"
            + (2).to_bytes(4, "big") + (1).to_bytes(2, "big")
            + bytes([pkttype, 6]) + b"\x00" * 8 + _ip_bytes())


def test_decode_sll2_outgoing():
    result = _decode_sll2(_sll2_frame(pkttype=4))
    assert result is not None
    ip, direction = result
    _check_ip(ip)
    assert direction is Direction.EGRESS


def test_decode_sll2_incoming():
    result = _decode_sll2(_sll2_frame(pkttype=0))
    assert result is not None
    _, direction = result
    assert direction is Direction.INGRESS


def test_decode_raw():
    result = _decode_raw(_ip_bytes())
    assert result is not None
    ip, direction = result
    _check_ip(ip)
    assert direction is Direction.UNKNOWN


def test_decode_null():
    frame = (2).to_bytes(4, "little") + _ip_bytes()  # AF_INET, host order
    result = _decode_null(frame)
    assert result is not None
    ip, _ = result
    _check_ip(ip)


def test_decode_truncated_frames_return_none():
    assert _decode_sll(b"\x00\x04") is None
    assert _decode_sll2(b"\x08\x00") is None
    assert _decode_null(b"\x02") is None
    assert _decode_raw(b"\x45") is None
