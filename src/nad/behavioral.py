"""Behavioural detection axis: catch what volume thresholds miss.

The statistical detectors (:mod:`nad.detect`, :mod:`nad.adaptive`) reason about
*how much* traffic there is. Some attacks deliberately stay small — exfiltration
to an attacker's server, a quiet C2 channel — and slip under any volume
threshold. This module adds an *identity* signal:

    :class:`FirstSeenDetector` — flags a sustained connection to an external
    destination this host has **never contacted before**. Mimicry and exfil
    almost always involve a brand-new server, so novelty itself is the tell,
    regardless of byte count.

Knowledge of "what we've seen before" is persisted (``DestinationStore``) so it
survives restarts. This is component **A** of the hidden-attack plan; CUSUM and
beacon detection are separate, later components.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, tzinfo
from typing import Iterable, Optional

from .detect import Alert
from .features import WindowFeatures
from .storage import DestinationStore


def is_external(ip: str) -> bool:
    """True for a globally-routable (public) address — skips private, loopback,
    link-local, multicast and reserved ranges."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def _is_night(ts_ns: int, tz: tzinfo | None) -> bool:
    h = datetime.fromtimestamp(ts_ns / 1_000_000_000, tz).hour
    return h < 6 or h >= 23


class FirstSeenDetector:
    """Flag sustained traffic to never-before-seen external destinations.

    Logic per window:
      * Consider external destinations carrying at least ``min_packets`` packets.
      * A destination already in the known set is ignored.
      * A brand-new one is *watched*; if it persists for ``min_consecutive``
        consecutive windows it raises one alert, then joins the known set.
      * A new destination that vanishes before confirming is treated as a benign
        one-off (DNS lookup, ad) and quietly learned.
      * During the initial ``learning_windows`` everything is learned silently —
        on a fresh install almost every destination is "new".
    """

    def __init__(
        self,
        store: Optional[DestinationStore] = None,
        learning_windows: int = 3600,      # ~1h at 1s windows: learn the regulars first
        min_consecutive: int = 5,
        min_packets: int = 3,
        cooldown_windows: int = 30,
        allowlist: Iterable[str] | None = None,
        tz: tzinfo | None = None,
    ) -> None:
        self._store = store
        self._known: set[str] = set(store.load()) if store else set()
        self._watch: dict[str, int] = {}
        self._cooldown: dict[str, int] = {}
        self.learning_windows = learning_windows
        self.min_consecutive = max(1, min_consecutive)
        self.min_packets = max(1, min_packets)
        self.cooldown_windows = cooldown_windows
        self.allowlist = set(allowlist or ())
        self.tz = tz
        self._windows_seen = 0

    def update(self, window: WindowFeatures) -> list[Alert]:
        self._windows_seen += 1
        ts = window.window_end_ns
        learning = self._windows_seen <= self.learning_windows

        for ip in list(self._cooldown):
            self._cooldown[ip] -= 1
            if self._cooldown[ip] <= 0:
                del self._cooldown[ip]

        externals = {
            ip: cnt for ip, cnt in window.all_dst_ips.items()
            if cnt >= self.min_packets and ip not in self.allowlist and is_external(ip)
        }
        current = set(externals)

        alerts: list[Alert] = []
        learn: list[str] = []

        for ip, cnt in externals.items():
            if ip in self._known:
                continue
            if learning:
                self._known.add(ip)
                learn.append(ip)
                continue
            self._watch[ip] = self._watch.get(ip, 0) + 1
            if self._watch[ip] >= self.min_consecutive and ip not in self._cooldown:
                alerts.append(self._build_alert(ip, cnt, self._watch[ip], window))
                self._known.add(ip)
                learn.append(ip)
                self._cooldown[ip] = self.cooldown_windows
                self._watch.pop(ip, None)

        # Watched candidates that disappeared were transient — learn and forget.
        for ip in list(self._watch):
            if ip not in current:
                self._known.add(ip)
                learn.append(ip)
                self._watch.pop(ip, None)

        if self._store and learn:
            self._store.upsert_many(learn, ts)
        return alerts

    def _build_alert(self, ip: str, pkts: int, consecutive: int,
                     window: WindowFeatures) -> Alert:
        night = _is_night(window.window_end_ns, self.tz)
        severity = "경고" if night else "주의"
        when = "평소 한가한 심야 시간대에 " if night else ""
        summary = (
            f"{when}이전에 한 번도 통신한 적 없는 외부 서버({ip})와 "
            f"{consecutive}회 연속으로 통신이 이어지고 있습니다. 새 웹사이트나 앱이라면 "
            f"정상일 수 있지만, 예상치 못한 연결이라면 정보 유출이나 외부 원격 제어(C2)일 "
            f"수 있습니다."
        )
        ctx = {
            "new_destination": ip,
            "consecutive_windows": consecutive,
            "packets": pkts,
            "window_start_ns": window.window_start_ns,
            "top_dst_ports": window.top_dst_ports,
        }
        return Alert(
            timestamp_ns=window.window_end_ns,
            feature="new_destination",
            value=float(pkts),
            baseline_mean=0.0,
            baseline_std=0.0,           # 0/0 marks a non-statistical (behavioural) alert
            z_score=0.0,
            direction="above",
            explanation=(f"new external destination {ip} sustained {consecutive} "
                         f"windows (pkts={pkts})"),
            context=ctx,
            category="처음 보는 외부 연결",
            severity=severity,
            summary=summary,
            recommendation="이 주소로 통신할 이유가 없다면 연결을 차단하고 점검하세요.",
        )

    def state_snapshot(self) -> dict:
        return {
            "known_destinations": len(self._known),
            "watching": len(self._watch),
            "windows_seen": self._windows_seen,
            "learning": self._windows_seen <= self.learning_windows,
        }
