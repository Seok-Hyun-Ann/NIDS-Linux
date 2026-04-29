"""Time-window aggregation: packet stream → numeric feature vectors.

Higher layers (detection, dashboard) consume `WindowFeatures`. The aggregator
is allocation-light and single-threaded — wrap it from outside if you need
concurrency.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .capture.base import Packet


@dataclass(slots=True)
class WindowFeatures:
    window_start_ns: int
    window_end_ns: int
    duration_s: float
    packet_count: int
    bytes_total: int
    avg_payload_size: float
    unique_src_ips: int
    unique_dst_ips: int
    unique_dst_ports: int
    tcp_count: int
    udp_count: int
    icmp_count: int
    other_count: int
    top_src_ips: dict[str, int] = field(default_factory=dict)
    top_dst_ips: dict[str, int] = field(default_factory=dict)
    top_dst_ports: dict[int, int] = field(default_factory=dict)

    def numeric(self) -> dict[str, float]:
        """Subset of fields the detector treats as time-series signals."""
        return {
            "packet_count": float(self.packet_count),
            "bytes_total": float(self.bytes_total),
            "avg_payload_size": float(self.avg_payload_size),
            "unique_src_ips": float(self.unique_src_ips),
            "unique_dst_ips": float(self.unique_dst_ips),
            "unique_dst_ports": float(self.unique_dst_ports),
            "tcp_count": float(self.tcp_count),
            "udp_count": float(self.udp_count),
            "icmp_count": float(self.icmp_count),
        }


class WindowAggregator:
    """Buckets packets into fixed-duration windows.

    `add(packet)` returns a `WindowFeatures` exactly when a packet's timestamp
    crosses into the next window — at most one closed window per call. Call
    `flush()` to drain the in-progress window (e.g. on shutdown).
    """

    def __init__(self, window_seconds: float = 1.0, top_k: int = 5) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_ns = int(window_seconds * 1_000_000_000)
        self.top_k = top_k
        self._window_start_ns: Optional[int] = None
        self._reset_buckets()

    def _reset_buckets(self) -> None:
        self._packet_count = 0
        self._bytes_total = 0
        self._payload_total = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0
        self._other = 0
        self._src_ips: Counter[str] = Counter()
        self._dst_ips: Counter[str] = Counter()
        self._dst_ports: Counter[int] = Counter()

    def _emit(self) -> WindowFeatures:
        assert self._window_start_ns is not None
        n = self._packet_count
        avg_payload = (self._payload_total / n) if n else 0.0
        feats = WindowFeatures(
            window_start_ns=self._window_start_ns,
            window_end_ns=self._window_start_ns + self.window_ns,
            duration_s=self.window_ns / 1_000_000_000,
            packet_count=n,
            bytes_total=self._bytes_total,
            avg_payload_size=avg_payload,
            unique_src_ips=len(self._src_ips),
            unique_dst_ips=len(self._dst_ips),
            unique_dst_ports=len(self._dst_ports),
            tcp_count=self._tcp,
            udp_count=self._udp,
            icmp_count=self._icmp,
            other_count=self._other,
            top_src_ips=dict(self._src_ips.most_common(self.top_k)),
            top_dst_ips=dict(self._dst_ips.most_common(self.top_k)),
            top_dst_ports=dict(self._dst_ports.most_common(self.top_k)),
        )
        self._reset_buckets()
        return feats

    def add(self, packet: Packet) -> Optional[WindowFeatures]:
        ts = packet.timestamp_ns
        if self._window_start_ns is None:
            self._window_start_ns = ts - (ts % self.window_ns)

        emitted: Optional[WindowFeatures] = None
        if ts >= self._window_start_ns + self.window_ns:
            if self._packet_count > 0:
                emitted = self._emit()
            self._window_start_ns = ts - (ts % self.window_ns)

        self._packet_count += 1
        self._bytes_total += packet.total_len
        self._payload_total += len(packet.payload)
        proto = packet.protocol
        if proto == 6:
            self._tcp += 1
        elif proto == 17:
            self._udp += 1
        elif proto == 1:
            self._icmp += 1
        else:
            self._other += 1
        self._src_ips[packet.src_ip] += 1
        self._dst_ips[packet.dst_ip] += 1
        if packet.dst_port:
            self._dst_ports[packet.dst_port] += 1
        return emitted

    def flush(self) -> Optional[WindowFeatures]:
        if self._window_start_ns is None or self._packet_count == 0:
            return None
        feats = self._emit()
        self._window_start_ns = None
        return feats
