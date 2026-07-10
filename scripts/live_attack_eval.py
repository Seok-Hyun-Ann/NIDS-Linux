"""Live attack-reproduction benchmark — real packets through the real pipeline.

`evaluate.py` scores detectors on *synthetic* WindowFeatures; this script closes
the other half of the question: do real attack packets, captured off the wire by
the libpcap backend and aggregated into windows, actually get detected — and how
fast?

It is **loopback-locked by design**. Every attack targets 127.0.0.1 and a set of
dedicated high ports opened by this process; nothing ever leaves the machine, and
no other service is touched. Rates are deliberately low — the goal is to measure
detection, not to stress anything. Running it is no more dangerous than
`curl localhost` or `nmap localhost`.

    sudo .venv/bin/python scripts/live_attack_eval.py        # needs root for lo capture

Phases (all on loopback):
    1. warmup      — steady benign TCP+UDP baseline so per-bucket stats settle
    2. port_scan   — connect to many distinct closed ports (unique_dst_ports ↑)
    3. syn_flood   — hammer SYNs at one closed port          (syn_count ↑)
    4. volume_spike— blast bytes over a live connection       (bytes_total ↑)

Then it reads the alerts the detector produced and prints, per attack:
detected? · latency (windows) · plus the post-warmup false-alarm count.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nad.adaptive import AdaptiveDetector          # noqa: E402
from nad.capture.factory import make_capture       # noqa: E402
from nad.features import WindowAggregator           # noqa: E402

HOST = "127.0.0.1"
LISTEN_PORT = 54321                 # our benign "server"
SCAN_LO, SCAN_HI = 40000, 40120     # closed-port range the scans hit
BPF = f"tcp and (port {LISTEN_PORT} or portrange {SCAN_LO}-{SCAN_HI}) or udp port {LISTEN_PORT}"


# --------------------------------------------------------------------------- #
# Benign listener + baseline traffic                                          #
# --------------------------------------------------------------------------- #

class Listener:
    """A loopback TCP acceptor + UDP sink that just drains whatever arrives."""

    def __init__(self) -> None:
        self._stop = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((HOST, LISTEN_PORT))
        tcp.listen(64)
        tcp.settimeout(0.5)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((HOST, LISTEN_PORT))
        udp.settimeout(0.5)
        self._tcp, self._udp = tcp, udp
        for target in (self._accept_loop, self._udp_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._drain, args=(conn,), daemon=True).start()

    def _drain(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        with conn:
            while not self._stop:
                try:
                    if not conn.recv(65536):
                        break
                except (socket.timeout, OSError):
                    if self._stop:
                        break

    def _udp_loop(self) -> None:
        while not self._stop:
            try:
                self._udp.recvfrom(65536)
            except (socket.timeout, OSError):
                continue

    def stop(self) -> None:
        self._stop = True
        for s in (self._tcp, self._udp):
            try:
                s.close()
            except OSError:
                pass


def baseline_traffic(stop_evt: threading.Event) -> None:
    """Steady, unremarkable TCP+UDP chatter to the listener until told to stop."""
    conns: list[socket.socket] = []
    for _ in range(4):                       # a few persistent TCP flows
        try:
            c = socket.create_connection((HOST, LISTEN_PORT), timeout=1.0)
            conns.append(c)
        except OSError:
            pass
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not stop_evt.is_set():
        for c in conns:
            try:
                c.sendall(b"x" * 200)        # small, steady payloads
            except OSError:
                pass
        try:
            udp.sendto(b"u" * 120, (HOST, LISTEN_PORT))
        except OSError:
            pass
        time.sleep(0.05)                     # ~20 rounds/s → windows keep emitting
    for c in conns:
        c.close()
    udp.close()


# --------------------------------------------------------------------------- #
# Attacks (loopback only)                                                      #
# --------------------------------------------------------------------------- #

def attack_port_scan(seconds: float) -> None:
    """Sweep many distinct closed ports on the host — a vertical scan, sustained
    over the measurement window so it forms a proper multi-window episode."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for port in range(SCAN_LO, SCAN_HI):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            try:
                s.connect((HOST, port))      # closed → immediate RST
            except OSError:
                pass
            finally:
                s.close()


def attack_syn_flood(seconds: float) -> None:
    """Repeatedly open connections to one closed port — a SYN/RST burst."""
    end = time.monotonic() + seconds
    port = SCAN_LO                            # single target port
    while time.monotonic() < end:
        for _ in range(40):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)
            try:
                s.connect((HOST, port))
            except OSError:
                pass
            finally:
                s.close()
        time.sleep(0.02)


def attack_volume_spike(seconds: float) -> None:
    """Blast large payloads over a live connection — a volume/bytes spike."""
    try:
        c = socket.create_connection((HOST, LISTEN_PORT), timeout=1.0)
    except OSError:
        return
    end = time.monotonic() + seconds
    chunk = b"A" * 60000
    with c:
        while time.monotonic() < end:
            try:
                c.sendall(chunk)
            except OSError:
                break


# --------------------------------------------------------------------------- #
# Capture + detect on a background thread                                      #
# --------------------------------------------------------------------------- #

@dataclass
class Fired:
    at: float          # wall-clock time the alert was produced
    feature: str
    category: str
    severity: str
    direction: str     # "above" | "below"


class Monitor:
    def __init__(self, interface: str, warmup: int, confirm: int) -> None:
        self.agg = WindowAggregator(window_seconds=1.0)
        self.det = AdaptiveDetector(
            bucketing="hour", threshold_mode="combined",
            warmup_windows=warmup, global_warmup=max(6, warmup // 2),
            confirm_windows=confirm, cooldown_windows=2, robust_k=3.5,
        )
        self.cap = make_capture(interface=interface, bpf_filter=BPF)
        self.alerts: list[Fired] = []
        self.windows_seen = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        with self.cap as stream:
            for pkt in stream:
                win = self.agg.add(pkt)
                if win is None:
                    continue
                self.windows_seen += 1
                for a in self.det.update(win):
                    self.alerts.append(
                        Fired(time.time(), a.feature, a.category, a.severity, a.direction))

    def stop(self) -> None:
        self.cap._stop = True                # loop notices within the read timeout
        if self._thread:
            self._thread.join(timeout=2.0)


# --------------------------------------------------------------------------- #
# Orchestration + scoring                                                      #
# --------------------------------------------------------------------------- #

@dataclass
class Episode:
    kind: str
    features: tuple[str, ...]       # features that should light up
    start: float
    end: float


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interface", "-i", default="lo",
                    help="capture interface (loopback by default; keep it that way)")
    ap.add_argument("--warmup", type=int, default=20, help="baseline windows before scoring")
    ap.add_argument("--confirm", type=int, default=2, help="consecutive windows to confirm")
    ap.add_argument("--attack-seconds", type=float, default=6.0)
    ap.add_argument("--tolerance", type=int, default=4, help="grace windows after an episode")
    args = ap.parse_args()

    print(f"Live attack reproduction on {args.interface} (loopback-locked).")
    print(f"BPF: {BPF}\n")

    listener = Listener()
    listener.start()
    time.sleep(0.3)

    mon = Monitor(args.interface, args.warmup, args.confirm)
    mon.start()

    stop_base = threading.Event()
    base_thread = threading.Thread(target=baseline_traffic, args=(stop_base,), daemon=True)
    base_thread.start()

    def wait(seconds: float) -> None:
        time.sleep(seconds)

    print(f"warmup: {args.warmup + 6}s of benign baseline…")
    wait(args.warmup + 6)

    episodes: list[Episode] = []

    def run_attack(kind, features, fn):
        gap = 8.0                                    # let the drop-back settle
        start = time.time()
        fn()
        end = time.time()
        episodes.append(Episode(kind, features, start, end))
        print(f"  {kind:<13} injected ({end - start:.1f}s), settling {gap:.0f}s…")
        wait(gap)

    print("attacks:")
    run_attack("port_scan", ("unique_dst_ports", "max_ports_per_dst"),
               lambda: attack_port_scan(args.attack_seconds))
    run_attack("syn_flood", ("syn_count", "rst_count"),
               lambda: attack_syn_flood(args.attack_seconds))
    run_attack("volume_spike", ("bytes_total", "avg_payload_size"),
               lambda: attack_volume_spike(args.attack_seconds))

    wait(3)
    stop_base.set()
    mon.stop()
    listener.stop()

    # ---- score ----
    # An attack is DETECTED if an "above" alert on one of its features fires
    # inside its window (+ a few grace windows for aggregation/confirm latency).
    warmup_end = episodes[0].start if episodes else None

    def attributable(a: Fired) -> Episode | None:
        for ep in episodes:
            if ep.start - 1.0 <= a.at <= ep.end + args.tolerance:
                return ep
        return None

    def matches(a: Fired, ep: Episode) -> bool:
        return (a.direction == "above" and a.feature in ep.features
                and ep.start - 1.0 <= a.at <= ep.end + args.tolerance)

    print(f"\nwindows scored: {mon.windows_seen}, alerts fired: {len(mon.alerts)}\n")
    print(f"{'attack':<14}{'detected':<10}{'latency(win)':<14}{'category (as shown to user)'}")
    print("-" * 72)
    detected_n = 0
    for ep in episodes:
        hits = sorted((a for a in mon.alerts if matches(a, ep)), key=lambda x: x.at)
        if hits:
            detected_n += 1
            lat = round(hits[0].at - ep.start)
            print(f"{ep.kind:<14}{'YES':<10}{f'~{lat}':<14}{hits[0].category}")
        else:
            print(f"{ep.kind:<14}{'MISS':<10}{'-':<14}")

    # False positives: "above" alerts after warmup that belong to no attack.
    # (A "below" alert is just traffic returning to baseline once an attack ends,
    #  and any alert during another attack's window is that attack's, not noise.)
    false_alarms = [
        a for a in mon.alerts
        if a.direction == "above" and warmup_end and a.at >= warmup_end
        and attributable(a) is None
    ]
    drops = sum(1 for a in mon.alerts if a.direction == "below" and warmup_end and a.at >= warmup_end)

    print(f"\ndetection: {detected_n}/{len(episodes)} attacks")
    print(f"false alarms (post-warmup 'above', unattributed): {len(false_alarms)}")
    for a in false_alarms[:10]:
        print(f"    {a.feature:<20} {a.category}")
    print(f"return-to-baseline drops (expected after each attack, not FPs): {drops}")


if __name__ == "__main__":
    main()
