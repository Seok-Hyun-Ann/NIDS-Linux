from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

from nad.behavioral import FirstSeenDetector, is_external
from nad.features import WindowFeatures
from nad.storage import DestinationStore

_TS = int(datetime(2026, 6, 1, 12, tzinfo=timezone.utc).timestamp() * 1e9)


def _w(dsts: dict[str, int]) -> WindowFeatures:
    return WindowFeatures(
        window_start_ns=_TS, window_end_ns=_TS, duration_s=1.0,
        packet_count=sum(dsts.values()), bytes_total=0, avg_payload_size=0.0,
        unique_src_ips=1, unique_dst_ips=len(dsts), unique_dst_ports=1,
        tcp_count=0, udp_count=0, icmp_count=0, other_count=0,
        all_dst_ips=dict(dsts),
    )


def test_is_external_classification():
    assert is_external("8.8.8.8")
    assert not is_external("192.168.0.10")
    assert not is_external("10.0.0.5")
    assert not is_external("127.0.0.1")
    assert not is_external("224.0.0.1")       # multicast
    assert not is_external("not-an-ip")


def test_sustained_new_external_fires_after_consecutive():
    det = FirstSeenDetector(store=None, learning_windows=2,
                            min_consecutive=3, min_packets=1)
    det.update(_w({"8.8.8.8": 5}))            # learning window 1
    det.update(_w({"8.8.8.8": 5}))            # learning window 2
    a1 = det.update(_w({"1.2.3.4": 5}))       # watch=1
    a2 = det.update(_w({"1.2.3.4": 5}))       # watch=2
    a3 = det.update(_w({"1.2.3.4": 5}))       # watch=3 -> alert
    assert not a1 and not a2
    assert len(a3) == 1
    assert a3[0].category == "처음 보는 외부 연결"
    assert a3[0].context["new_destination"] == "1.2.3.4"
    assert a3[0].severity in ("주의", "경고")


def test_private_destinations_ignored():
    det = FirstSeenDetector(store=None, learning_windows=0,
                            min_consecutive=1, min_packets=1)
    assert det.update(_w({"192.168.0.5": 10, "10.0.0.9": 10})) == []


def test_single_window_new_destination_is_transient():
    det = FirstSeenDetector(store=None, learning_windows=0,
                            min_consecutive=3, min_packets=1)
    a = det.update(_w({"8.8.8.8": 5}))        # appears once
    b = det.update(_w({"9.9.9.9": 5}))        # 8.8.8.8 gone -> learned as benign
    c = det.update(_w({"8.8.8.8": 5}))        # now known -> never alerts
    assert not a and not b and not c


def test_destination_known_from_learning_never_alerts():
    det = FirstSeenDetector(store=None, learning_windows=3,
                            min_consecutive=1, min_packets=1)
    for _ in range(3):
        det.update(_w({"8.8.8.8": 5}))        # learned silently
    assert det.update(_w({"8.8.8.8": 5})) == []


def test_min_packets_filters_stray_single_packet():
    det = FirstSeenDetector(store=None, learning_windows=0,
                            min_consecutive=1, min_packets=3)
    assert det.update(_w({"8.8.8.8": 1})) == []   # below min_packets


def test_destination_store_persists_across_reopen():
    path = os.path.join(tempfile.gettempdir(), "nad_dest_test.db")
    if os.path.exists(path):
        os.remove(path)
    s = DestinationStore(path)
    s.upsert_many(["8.8.8.8", "1.1.1.1"], _TS)
    s.close()

    s2 = DestinationStore(path)
    known = s2.load()
    assert "8.8.8.8" in known and "1.1.1.1" in known
    # a detector loading this store treats them as already-known
    det = FirstSeenDetector(store=s2, learning_windows=0,
                            min_consecutive=1, min_packets=1)
    assert det.update(_w({"8.8.8.8": 5})) == []
    s2.close()
    os.remove(path)
