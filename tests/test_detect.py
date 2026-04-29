from __future__ import annotations

from nad.detect import BaselineDetector
from nad.features import WindowFeatures


def _w(packet_count: int, ts: int = 0) -> WindowFeatures:
    return WindowFeatures(
        window_start_ns=ts, window_end_ns=ts + 1_000_000_000, duration_s=1.0,
        packet_count=packet_count, bytes_total=packet_count * 100,
        avg_payload_size=64.0,
        unique_src_ips=1, unique_dst_ips=1, unique_dst_ports=1,
        tcp_count=packet_count, udp_count=0, icmp_count=0, other_count=0,
        top_src_ips={"10.0.0.1": packet_count},
        top_dst_ips={"10.0.0.2": packet_count},
        top_dst_ports={80: packet_count},
    )


def test_no_alerts_during_warmup():
    det = BaselineDetector(z_threshold=3.0, warmup_windows=10, confirm_windows=1)
    for i in range(10):
        # even with a huge spike, no alerts before warmup completes
        alerts = det.update(_w(packet_count=10_000 if i == 5 else 10))
        assert alerts == []


def test_single_spike_does_not_fire_with_confirm():
    """A 1-window blip should be filtered out when confirm_windows=3."""
    det = BaselineDetector(
        z_threshold=3.0, warmup_windows=10, confirm_windows=3, cooldown_windows=0,
    )
    for _ in range(15):
        det.update(_w(packet_count=10))
    # single spike, then back to normal
    spike_alerts = det.update(_w(packet_count=10_000))
    after_alerts  = det.update(_w(packet_count=10))
    assert all(a.feature != "packet_count" for a in spike_alerts)
    assert all(a.feature != "packet_count" for a in after_alerts)


def test_sustained_spike_fires_after_confirm():
    det = BaselineDetector(
        z_threshold=3.0, warmup_windows=10, confirm_windows=3, cooldown_windows=0,
    )
    for _ in range(15):
        det.update(_w(packet_count=10))
    # spike that lasts 3 windows in a row
    a1 = det.update(_w(packet_count=10_000))
    a2 = det.update(_w(packet_count=10_000))
    a3 = det.update(_w(packet_count=10_000))
    assert all(a.feature != "packet_count" for a in a1)
    assert all(a.feature != "packet_count" for a in a2)
    fired = [a for a in a3 if a.feature == "packet_count"]
    assert len(fired) == 1
    assert fired[0].direction == "above"
    assert fired[0].z_score > 3.0


def test_cooldown_suppresses_consecutive_alerts():
    det = BaselineDetector(
        z_threshold=3.0, warmup_windows=5, cooldown_windows=10, confirm_windows=1,
    )
    for _ in range(10):
        det.update(_w(packet_count=10))
    first = det.update(_w(packet_count=10_000))
    assert any(a.feature == "packet_count" for a in first)
    # next big window — packet_count should still be in cooldown
    second = det.update(_w(packet_count=10_000))
    assert not any(a.feature == "packet_count" for a in second)
