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
    context_json  TEXT    NOT NULL,
    category       TEXT   NOT NULL DEFAULT '',
    severity       TEXT   NOT NULL DEFAULT '',
    summary        TEXT   NOT NULL DEFAULT '',
    recommendation TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp_ns DESC);
"""

# Columns added after the initial release; ALTER-in for pre-existing databases.
_ADDED_COLUMNS = ("category", "severity", "summary", "recommendation")


class AlertStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(alerts)")}
        for name in _ADDED_COLUMNS:
            if name not in cols:
                self._conn.execute(
                    f"ALTER TABLE alerts ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")

    def save_alert(self, alert: Alert) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (timestamp_ns, feature, value, baseline_mean, "
                "baseline_std, z_score, direction, explanation, context_json, "
                "category, severity, summary, recommendation) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    alert.category,
                    alert.severity,
                    alert.summary,
                    alert.recommendation,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, timestamp_ns, feature, value, baseline_mean, baseline_std, "
                "z_score, direction, explanation, context_json, "
                "category, severity, summary, recommendation "
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
                "category": r[10],
                "severity": r[11],
                "summary": r[12],
                "recommendation": r[13],
            })
        return out

    def total_alerts(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM alerts")
            return int(cur.fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_DEST_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_destinations (
    ip            TEXT    PRIMARY KEY,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns  INTEGER NOT NULL,
    count         INTEGER NOT NULL
);
"""


class DestinationStore:
    """Persistent memory of which destinations this host has talked to.

    The first-seen detector loads the whole table into memory on start (cheap —
    one row per distinct IP ever seen) and writes through new/updated rows. This
    is what lets "never-contacted-before destination" survive restarts.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(_DEST_SCHEMA)
        self._conn.commit()

    def load(self) -> dict[str, tuple[int, int, int]]:
        """Return {ip: (first_seen_ns, last_seen_ns, count)}."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT ip, first_seen_ns, last_seen_ns, count FROM known_destinations")
            return {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}

    def upsert(self, ip: str, ts_ns: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO known_destinations (ip, first_seen_ns, last_seen_ns, count) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen_ns=excluded.last_seen_ns, "
                "count=count+1",
                (ip, ts_ns, ts_ns),
            )
            self._conn.commit()

    def upsert_many(self, ips: list[str], ts_ns: int) -> None:
        if not ips:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO known_destinations (ip, first_seen_ns, last_seen_ns, count) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen_ns=excluded.last_seen_ns, "
                "count=count+1",
                [(ip, ts_ns, ts_ns) for ip in ips],
            )
            self._conn.commit()

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM known_destinations").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
