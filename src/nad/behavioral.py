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
from collections import deque
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
        ttl_seconds: float = 30 * 86_400,  # forget a destination unseen for 30 days
        max_known: int = 100_000,          # hard cap on remembered destinations
        prune_interval: int = 3600,        # windows between TTL/cap sweeps
        allowlist: Iterable[str] | None = None,
        tz: tzinfo | None = None,
    ) -> None:
        self._store = store
        self.max_known = max(1, max_known)
        # ip -> last_seen_ns. Bounded by TTL + max_known so it can't grow forever.
        self._known: dict[str, int] = (
            {ip: last for ip, (_first, last, _c) in store.load(self.max_known).items()}
            if store else {}
        )
        self._watch: dict[str, int] = {}
        self._cooldown: dict[str, int] = {}
        self._seen_since_prune: set[str] = set()
        self.learning_windows = learning_windows
        self.min_consecutive = max(1, min_consecutive)
        self.min_packets = max(1, min_packets)
        self.cooldown_windows = cooldown_windows
        self.ttl_ns = int(ttl_seconds * 1_000_000_000)
        self.prune_interval = max(1, prune_interval)
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
                self._known[ip] = ts                 # refresh recency for TTL
                self._seen_since_prune.add(ip)
                continue
            if learning:
                self._known[ip] = ts
                learn.append(ip)
                continue
            self._watch[ip] = self._watch.get(ip, 0) + 1
            if self._watch[ip] >= self.min_consecutive and ip not in self._cooldown:
                alerts.append(self._build_alert(ip, cnt, self._watch[ip], window))
                self._known[ip] = ts
                learn.append(ip)
                self._cooldown[ip] = self.cooldown_windows
                self._watch.pop(ip, None)

        # Watched candidates that disappeared were transient — learn and forget.
        for ip in list(self._watch):
            if ip not in current:
                self._known[ip] = ts
                learn.append(ip)
                self._watch.pop(ip, None)

        if self._store and learn:
            self._store.upsert_many(learn, ts)
        if self._windows_seen % self.prune_interval == 0:
            self._prune(ts)
        return alerts

    def _prune(self, now_ns: int) -> None:
        """Bound memory and the DB: refresh recency of recently-seen IPs, then
        forget anything past its TTL, then enforce the hard cap (drop oldest)."""
        if self._store and self._seen_since_prune:
            self._store.touch_many(list(self._seen_since_prune), now_ns)
        self._seen_since_prune.clear()

        cutoff = now_ns - self.ttl_ns
        expired = [ip for ip, last in self._known.items() if last < cutoff]
        for ip in expired:
            del self._known[ip]
        if self._store:
            self._store.prune(cutoff)

        if len(self._known) > self.max_known:
            # LRU backstop: keep the most-recently-seen max_known.
            ordered = sorted(self._known.items(), key=lambda kv: kv[1], reverse=True)
            drop = [ip for ip, _ in ordered[self.max_known:]]
            for ip in drop:
                del self._known[ip]
            if self._store:
                self._store.delete_many(drop)

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


class BeaconDetector:
    """Flag periodic, low-jitter communication to an external destination — the
    timing signature of a C2 beacon, which stays small enough to slip under any
    volume threshold.

    For each external destination it records the timestamps of the windows it was
    active in. Once a destination has at least ``min_events`` contacts whose
    inter-contact intervals are tight (coefficient of variation ``<= max_cv``)
    and whose period sits between ``min_period_s`` and ``max_period_s``, it
    raises one alert, then mutes that destination for ``cooldown_windows``.

    Conservative by design — legitimately periodic traffic (NTP, keepalives,
    polling) can look beaconish, so use the allowlist and tight thresholds.
    """

    def __init__(
        self,
        min_events: int = 8,
        max_cv: float = 0.15,
        min_period_s: float = 10.0,
        max_period_s: float = 3600.0,
        history: int = 24,
        cooldown_windows: int = 600,
        max_tracked: int = 2000,
        allowlist: Iterable[str] | None = None,
        tz: tzinfo | None = None,
    ) -> None:
        self.min_events = max(3, min_events)
        self.max_cv = max_cv
        self.min_period_ns = min_period_s * 1e9
        self.max_period_ns = max_period_s * 1e9
        self.history = max(self.min_events, history)
        self.cooldown_windows = cooldown_windows
        self.max_tracked = max(1, max_tracked)
        self.allowlist = set(allowlist or ())
        self.tz = tz
        self._hist: dict[str, deque[int]] = {}
        self._seen_count: dict[str, int] = {}   # for LRU eviction
        self._cooldown: dict[str, int] = {}
        self._windows_seen = 0

    def update(self, window: WindowFeatures) -> list[Alert]:
        self._windows_seen += 1
        ts = window.window_end_ns
        for ip in list(self._cooldown):
            self._cooldown[ip] -= 1
            if self._cooldown[ip] <= 0:
                del self._cooldown[ip]

        alerts: list[Alert] = []
        for ip in window.all_dst_ips:
            if ip in self.allowlist or not is_external(ip):
                continue
            dq = self._hist.get(ip)
            if dq is None:
                dq = self._hist[ip] = deque(maxlen=self.history)
            if not dq or dq[-1] != ts:
                dq.append(ts)
            self._seen_count[ip] = self._windows_seen

            if len(dq) >= self.min_events and ip not in self._cooldown:
                hit = self._evaluate(ip, dq, window)
                if hit is not None:
                    alerts.append(hit)
                    self._cooldown[ip] = self.cooldown_windows

        if len(self._hist) > self.max_tracked:
            self._evict()
        return alerts

    def _evaluate(self, ip: str, dq: "deque[int]", window: WindowFeatures):
        intervals = [dq[i + 1] - dq[i] for i in range(len(dq) - 1)]
        mean = sum(intervals) / len(intervals)
        if mean <= 0 or not (self.min_period_ns <= mean <= self.max_period_ns):
            return None   # too frequent (continuous) or too sparse to be a beacon
        var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = (var ** 0.5) / mean
        if cv > self.max_cv:
            return None   # irregular timing — not a beacon
        period_s = mean / 1e9
        summary = (
            f"외부 서버({ip})와 약 {period_s:.0f}초 간격으로 매우 규칙적인 통신이 "
            f"{len(dq)}회 반복됐습니다(간격 편차 거의 없음). 자동 업데이트·동기화일 "
            f"수도 있지만, 악성코드가 주기적으로 신호를 보내는 C2 비콘일 수 있습니다."
        )
        return Alert(
            timestamp_ns=window.window_end_ns,
            feature="beacon",
            value=float(len(dq)),
            baseline_mean=0.0,
            baseline_std=0.0,         # 0/0 marks a non-statistical (behavioural) alert
            z_score=0.0,
            direction="above",
            explanation=(f"periodic contact to {ip}: period~{period_s:.1f}s, "
                         f"cv={cv:.3f}, events={len(dq)}"),
            context={"destination": ip, "period_seconds": period_s,
                     "interval_cv": cv, "events": len(dq),
                     "window_start_ns": window.window_start_ns},
            category="주기적 통신(비콘) 의심",
            severity="경고",
            summary=summary,
            recommendation="이 주소로 주기적으로 통신할 이유가 없다면 차단하고 점검하세요.",
        )

    def _evict(self) -> None:
        # Drop the least-recently-active destinations down to the cap.
        ordered = sorted(self._seen_count.items(), key=lambda kv: kv[1])
        for ip, _ in ordered[: len(self._hist) - self.max_tracked]:
            self._hist.pop(ip, None)
            self._seen_count.pop(ip, None)

    def state_snapshot(self) -> dict:
        return {"tracked_destinations": len(self._hist),
                "windows_seen": self._windows_seen}
