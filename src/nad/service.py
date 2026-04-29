"""Capture → features → detect → store, on a single background thread.

The FastAPI process owns one `MonitorService`. Read paths (`current_stats`,
`recent_windows`, `recent_alerts`) are thread-safe; the writer is the capture
thread itself.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .capture.factory import make_capture
from .detect import Alert, BaselineDetector
from .features import WindowAggregator, WindowFeatures
from .storage import AlertStore


log = logging.getLogger(__name__)


class MonitorService:
    def __init__(
        self,
        interface: str,
        bpf_filter: str = "ip",
        db_path: str | Path = "nad.db",
        window_seconds: float = 1.0,
        z_threshold: float = 3.0,
        warmup_windows: int = 30,
        confirm_windows: int = 3,
        cooldown_windows: int = 10,
        history_size: int = 300,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.window_seconds = window_seconds
        self.aggregator = WindowAggregator(window_seconds=window_seconds)
        self.detector = BaselineDetector(
            z_threshold=z_threshold,
            warmup_windows=warmup_windows,
            confirm_windows=confirm_windows,
            cooldown_windows=cooldown_windows,
        )
        self.store = AlertStore(db_path)
        self.history_size = history_size

        self._lock = threading.Lock()
        self._windows: deque[WindowFeatures] = deque(maxlen=history_size)
        self._recent_alerts: deque[Alert] = deque(maxlen=200)
        self._packets_seen = 0
        self._started_at: Optional[float] = None
        self._last_packet_at: Optional[float] = None
        self._last_error: Optional[str] = None

        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_evt.clear()
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._run, name="nad-capture", daemon=True
        )
        self._thread.start()
        log.info("MonitorService started on interface=%s", self.interface)

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
        self.store.close()

    def _run(self) -> None:
        try:
            cap = make_capture(interface=self.interface, bpf_filter=self.bpf_filter)
            with cap as stream:
                for pkt in stream:
                    if self._stop_evt.is_set():
                        break
                    self._packets_seen += 1
                    self._last_packet_at = time.time()
                    closed = self.aggregator.add(pkt)
                    if closed is not None:
                        self._handle_window(closed)
        except Exception as e:                       # noqa: BLE001
            self._last_error = f"{type(e).__name__}: {e}"
            log.exception("capture loop crashed")

    def _handle_window(self, window: WindowFeatures) -> None:
        with self._lock:
            self._windows.append(window)
        for alert in self.detector.update(window):
            self.store.save_alert(alert)
            with self._lock:
                self._recent_alerts.append(alert)
            log.info("ALERT %s z=%.2f val=%.2f", alert.feature, alert.z_score, alert.value)

    # ----- read paths used by the dashboard -----

    def status(self) -> dict:
        with self._lock:
            uptime = (time.time() - self._started_at) if self._started_at else 0.0
            last_window = self._windows[-1] if self._windows else None
            return {
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
                "window_seconds": self.window_seconds,
                "uptime_s": uptime,
                "packets_seen": self._packets_seen,
                "windows_seen": len(self._windows),
                "last_packet_at": self._last_packet_at,
                "last_error": self._last_error,
                "running": self._thread is not None and self._thread.is_alive(),
                "warmup_remaining": max(
                    0,
                    self.detector.warmup_windows - (len(self._windows)),
                ),
                "current_window": _window_to_dict(last_window) if last_window else None,
                "alert_total": self.store.total_alerts(),
            }

    def windows(self, limit: int = 60) -> list[dict]:
        with self._lock:
            items = list(self._windows)[-limit:]
        return [_window_to_dict(w) for w in items]

    def baseline(self) -> dict:
        return self.detector.state_snapshot()

    def alerts(self, limit: int = 50) -> list[dict]:
        return self.store.recent_alerts(limit=limit)


def _window_to_dict(w: WindowFeatures) -> dict:
    d = asdict(w)
    return d
