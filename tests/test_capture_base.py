import dataclasses

import pytest

from nad.capture.base import Direction, Packet


def _make_packet(**overrides) -> Packet:
    defaults = dict(
        timestamp_ns=1_700_000_000_000_000_000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol=6,
        direction=Direction.EGRESS,
        payload=b"GET / HTTP/1.1\r\n",
        total_len=80,
    )
    defaults.update(overrides)
    return Packet(**defaults)


def test_packet_fields_round_trip():
    pkt = _make_packet()
    assert pkt.src_port == 12345
    assert pkt.protocol == 6
    assert pkt.direction is Direction.EGRESS
    assert pkt.payload.startswith(b"GET")


def test_packet_is_frozen():
    pkt = _make_packet()
    with pytest.raises(dataclasses.FrozenInstanceError):
        pkt.src_port = 999  # type: ignore[misc]


def test_direction_values():
    assert int(Direction.INGRESS) == 0
    assert int(Direction.EGRESS) == 1
    assert int(Direction.UNKNOWN) == 2
