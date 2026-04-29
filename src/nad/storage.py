"""SQLite-backed alert store. One file, append-only writes, no migrations yet."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .detect import Alert


_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns  INTEGER NOT NULL,
    feature       TEXT    NOT NULL,
    value         REAL    NOT NULL,
    baseline_mean REAL    NOT NULL,
    baseline_std  REAL    NOT NULL,
    z_score       REAL    NOT NULL,
    direction     TEXT    NOT NULL,
    explanation   TEXT    NOT NULL,
    context_json  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp_ns DESC);
"""


class AlertStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def save_alert(self, alert: Alert) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (timestamp_ns, feature, value, baseline_mean, "
                "baseline_std, z_score, direction, explanation, context_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.timestamp_ns,
                    alert.feature,
                    alert.value,
                    alert.baseline_mean,
                    alert.baseline_std,
                    alert.z_score,
                    alert.direction,
                    alert.explanation,
                    json.dumps(alert.context, default=str),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, timestamp_ns, feature, value, baseline_mean, baseline_std, "
                "z_score, direction, explanation, context_json "
                "FROM alerts ORDER BY id DESC LIMIT ?",
                (int(limit),),
            )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0],
                "timestamp_ns": r[1],
                "feature": r[2],
                "value": r[3],
                "baseline_mean": r[4],
                "baseline_std": r[5],
                "z_score": r[6],
                "direction": r[7],
                "explanation": r[8],
                "context": json.loads(r[9]),
            })
        return out

    def total_alerts(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM alerts")
            return int(cur.fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
