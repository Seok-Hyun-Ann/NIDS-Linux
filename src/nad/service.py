"""Capture → features → detect → store, on a single background thread.

The FastAPI process owns one `MonitorService`. Read paths (`current_stats`,
`recent_windows`, `recent_alerts`) are thread-safe; the writer is the capture
thread itself.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .adaptive import AdaptiveDetector
from .behavioral import FirstSeenDetector
from .capture.factory import make_capture
from .detect import Alert, BaselineDetector
from .features import WindowAggregator, WindowFeatures
from .storage import AlertStore, DestinationStore


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
        detector_kind: str = "baseline",     # "baseline" | "adaptive"
        bucketing: str = "weekend_hour",
        threshold_mode: str = "combined",
        target_rate: float = 0.005,
        robust_k: float = 3.5,
        bucket_warmup: int = 200,
        behavioral: bool = True,
        firstseen_learning: int = 3600,
        firstseen_consecutive: int = 5,
        baseline_save_interval: int = 300,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.window_seconds = window_seconds
        self.detector_kind = detector_kind
        self.aggregator = WindowAggregator(window_seconds=window_seconds)
        if detector_kind == "adaptive":
            self.detector = AdaptiveDetector(
                bucketing=bucketing,
                threshold_mode=threshold_mode,
                target_rate=target_rate,
                robust_k=robust_k,
                warmup_windows=bucket_warmup,
                global_warmup=warmup_windows,
                confirm_windows=confirm_windows,
                cooldown_windows=cooldown_windows,
            )
        else:
            self.detector = BaselineDetector(
                z_threshold=z_threshold,
                warmup_windows=warmup_windows,
                confirm_windows=confirm_windows,
                cooldown_windows=cooldown_windows,
            )
        self.store = AlertStore(db_path)
        self.history_size = history_size

        # Restore learned baselines so a restart doesn't discard days of learning.
        self.baseline_save_interval = max(1, baseline_save_interval)
        self._windows_since_save = 0
        if hasattr(self.detector, "restore"):
            raw = self.store.load_detector_state()
            if raw:
                try:
                    if self.detector.restore(json.loads(raw)):
                        log.info("restored detector baselines from store")
                except (ValueError, TypeError):
                    log.warning("could not parse saved detector state; cold start")

        # Behavioural axis (component A): never-before-seen external destinations.
        self.dest_store: Optional[DestinationStore] = None
        self.behavioral: Optional[FirstSeenDetector] = None
        if behavioral:
            self.dest_store = DestinationStore(db_path)
            self.behavioral = FirstSeenDetector(
                store=self.dest_store,
                learning_windows=firstseen_learning,
                min_consecutive=firstseen_consecutive,
            )

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
        self._save_detector_state()       # final flush so nothing is lost on exit
        self.store.close()
        if self.dest_store is not None:
            self.dest_store.close()

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
        alerts = list(self.detector.update(window))
        if self.behavioral is not None:
            alerts.extend(self.behavioral.update(window))
        for alert in alerts:
            self.store.save_alert(alert)
            with self._lock:
                self._recent_alerts.append(alert)
            log.info("ALERT %s z=%.2f val=%.2f", alert.feature, alert.z_score, alert.value)

        self._windows_since_save += 1
        if self._windows_since_save >= self.baseline_save_interval:
            self._windows_since_save = 0
            self._save_detector_state()

    def _save_detector_state(self) -> None:
        if not hasattr(self.detector, "serialize"):
            return
        try:
            self.store.save_detector_state(
                json.dumps(self.detector.serialize()), time.time_ns())
        except Exception:                                # noqa: BLE001
            log.exception("failed to persist detector state")

    # ----- read paths used by the dashboard -----

    def status(self) -> dict:
        with self._lock:
            uptime = (time.time() - self._started_at) if self._started_at else 0.0
            last_window = self._windows[-1] if self._windows else None
            # For the adaptive detector, alerting begins once the fast global
            # fallback is warm (global_warmup); per-bucket baselines sharpen later.
            warmup_base = getattr(
                self.detector, "global_warmup", self.detector.warmup_windows
            )
            return {
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
                "window_seconds": self.window_seconds,
                "detector": self.detector_kind,
                "uptime_s": uptime,
                "packets_seen": self._packets_seen,
                "windows_seen": len(self._windows),
                "last_packet_at": self._last_packet_at,
                "last_error": self._last_error,
                "running": self._thread is not None and self._thread.is_alive(),
                "warmup_remaining": max(0, warmup_base - len(self._windows)),
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
    d.pop("all_dst_ips", None)   # full destination list is for the detector, not the UI
    return d
