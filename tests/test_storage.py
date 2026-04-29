from __future__ import annotations

from nad.detect import Alert
from nad.storage import AlertStore


def test_save_and_recent_roundtrip(tmp_path):
    store = AlertStore(tmp_path / "test.db")
    a = Alert(
        timestamp_ns=1_700_000_000_000_000_000,
        feature="packet_count",
        value=12345.0,
        baseline_mean=100.0,
        baseline_std=10.0,
        z_score=4.2,
        direction="above",
        explanation="패킷 수가 평소 대비 4.2σ 초과.",
        context={"top_src_ips": {"10.0.0.1": 9000}},
    )
    rid = store.save_alert(a)
    assert rid > 0
    rows = store.recent_alerts()
    assert len(rows) == 1
    r = rows[0]
    assert r["feature"] == "packet_count"
    assert r["z_score"] == 4.2
    assert r["context"]["top_src_ips"]["10.0.0.1"] == 9000
    store.close()


def test_total_alerts(tmp_path):
    store = AlertStore(tmp_path / "test.db")
    assert store.total_alerts() == 0
    for i in range(3):
        store.save_alert(Alert(
            timestamp_ns=i, feature="x", value=1.0, baseline_mean=0.0, baseline_std=1.0,
            z_score=3.0 + i, direction="above", explanation="", context={},
        ))
    assert store.total_alerts() == 3
    store.close()
