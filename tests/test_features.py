from __future__ import annotations

from nad.capture.base import Direction, Packet
from nad.features import WindowAggregator


def _pkt(ts_ns: int, src="10.0.0.1", dst="10.0.0.2", sp=1234, dp=80, proto=6, plen=64, total=120):
    return Packet(
        timestamp_ns=ts_ns, src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp,
        protocol=proto, direction=Direction.UNKNOWN, payload=b"\x00" * plen, total_len=total,
    )


def test_window_emits_when_boundary_crosses():
    agg = WindowAggregator(window_seconds=1.0)
    base = 1_000_000_000
    assert agg.add(_pkt(base + 0)) is None
    assert agg.add(_pkt(base + 500_000_000)) is None
    # crosses into next 1s window
    out = agg.add(_pkt(base + 1_000_000_000))
    assert out is not None
    assert out.packet_count == 2
    assert out.bytes_total == 240
    assert out.tcp_count == 2
    assert out.unique_src_ips == 1


def test_window_top_k_counts():
    agg = WindowAggregator(window_seconds=1.0, top_k=3)
    base = 2_000_000_000
    for i in range(5):
        agg.add(_pkt(base + i * 1_000_000, dst=f"10.0.0.{i}"))
    out = agg.flush()
    assert out is not None
    assert out.unique_dst_ips == 5
    assert len(out.top_dst_ips) == 3


def test_protocol_buckets():
    agg = WindowAggregator(window_seconds=1.0)
    base = 3_000_000_000
    agg.add(_pkt(base, proto=6))     # tcp
    agg.add(_pkt(base, proto=17))    # udp
    agg.add(_pkt(base, proto=1))     # icmp
    agg.add(_pkt(base, proto=47))    # other
    out = agg.flush()
    assert out is not None
    assert out.tcp_count == 1
    assert out.udp_count == 1
    assert out.icmp_count == 1
    assert out.other_count == 1


def test_flush_returns_none_on_empty():
    agg = WindowAggregator(window_seconds=1.0)
    assert agg.flush() is None
