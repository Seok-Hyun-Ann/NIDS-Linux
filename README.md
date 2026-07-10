# NIDS-Linux(네트워크 침입 탐지 시스템-리눅스용) — Network Anomaly Detector for Linux

[![CI](https://github.com/Seok-Hyun-Ann/NIDS-Linux/actions/workflows/ci.yml/badge.svg)](https://github.com/Seok-Hyun-Ann/NIDS-Linux/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux-orange)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> A host-resident network anomaly detector for Linux that learns what *your*
> machine's traffic looks like **at each time of day**, flags deviations, and
> explains every alert in plain language.

It captures live traffic on a chosen interface, builds a self-tuning baseline,
and raises alerts with both an everyday-Korean verdict and the exact statistics
behind it. Everything runs on the machine — no telemetry, no cloud, no ML model
in the detection path. Pure standard-library statistics.

**At a glance**

- **Time-of-day baselines** — "9pm gaming" is normal at 9pm but suspicious at 3am.
- **Self-tuning threshold** — the cutoff is set from the data, no magic sigma to pick.
- **Two detection axes** — volume/statistics *and* behaviour (new servers, beacons).
- **Explained twice** — a plain-language verdict for anyone, the raw stats for analysts.
- **On-device & inspectable** — the whole detection path is readable Python.

## Platform support

This is the Linux port of [NIDS-Win](https://github.com/Seok-Hyun-Ann/NIDS-Win):
the detection engine is identical (it is OS-independent, pure-stdlib Python);
only the packet-capture layer is per-OS. The capture factory
(`src/nad/capture/factory.py`) detects the running OS and loads the matching
backend — the other backend's code is never imported.

| OS | Capture backend | Status | Instructions |
|---|---|---|---|
| **Linux** | `libpcap.so` via ctypes (`linux_libpcap.py`) | **primary target of this repo** | this README |
| Windows 10/11 | Npcap `wpcap.dll` via ctypes (`windows_npcap.py`) | retained, works unchanged | [NIDS-Win README](https://github.com/Seok-Hyun-Ann/NIDS-Win#readme) |
| macOS / BSD | — | not implemented | — |

So this one codebase runs on both OSes; if you are on Windows, follow the
NIDS-Win install steps (Npcap, Administrator terminal) — everything else,
including the dashboard and all `nad serve` options, is the same.

## Contents

- [Platform support](#platform-support)
- [Why NIDS-Linux?](#why-nids-linux)
- [What it detects](#what-it-detects)
- [Getting started](#getting-started)
- [The dashboard](#the-dashboard)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Status and roadmap](#status-and-roadmap)
- [Privacy](#privacy)

## Why NIDS-Linux?

Most consumer IDS/EDR tools tell you "we noticed something" — rarely *why*, and a
single fixed threshold either floods you with false alarms or misses real attacks,
because nobody uses a computer the same way every day. NIDS-Linux does the opposite:

- **Per-time-of-day baselines** — a separate baseline per hour bucket.
- **The threshold tunes itself** — set from the data to hit a target false-alarm *rate*.
- **Robust to evasion** — median/MAD stats, so a burst can't inflate the baseline and blind the next detection.
- **Every alert explained twice** — `데이터 유출 의심 — 평소의 약 18배` for anyone, exact statistics for analysts.
- **On-device** — readable Python; nothing leaves the machine.

## What it detects

Two complementary axes, so an attack that hides from one is caught by the other:

| Attack pattern | How it's caught | Component |
|---|---|---|
| Sudden spike (port scan, volumetric exfil, DDoS) | per-time-bucket robust Z-score | `AdaptiveDetector` |
| Low-and-slow drift (gradual exfil, baseline poisoning) | cumulative-sum control chart | CUSUM (visit-anchored) |
| Burst-then-hide (masking) | median/MAD scale isn't inflated by the burst | robust statistics |
| Volume-normal but structurally off (one-directional exfil, fan-out) | shape features scored directly | `egress_ratio`, `fan_out` |
| Vertical port scan (many ports, one host) | per-destination port tracking | `max_ports_per_dst` |
| SYN flood / half-open scan | connection-open (SYN) rate against a low baseline | `syn_count` |
| Connection resets (scan rejections, reset attacks) | RST rate | `rst_count` |
| Never-before-seen external server (quiet C2 / exfil) | persistent identity memory | `FirstSeenDetector` |
| Periodic C2 beacon (small, regular timing) | inter-contact interval regularity | `BeaconDetector` |
| Off-hours activity | the hour has its own baseline | time-of-day buckets |

## Getting started

**Requirements**

- Linux (kernel with `AF_PACKET`; any mainstream distro) — for live capture
- Python 3.11+
- `libpcap` — `sudo apt install libpcap0.8` (Debian/Ubuntu) or `sudo dnf install libpcap` (Fedora/RHEL)
- root (`sudo`) or `CAP_NET_RAW` to capture packets

No compiler or dev headers needed — capture talks to `libpcap.so` directly
through `ctypes`. (The [offline evaluation](#development) scripts need none of
this and run on any OS.)

**Install**

```bash
git clone https://github.com/Seok-Hyun-Ann/NIDS-Linux.git
cd NIDS-Linux
python3 -m venv .venv          # fails with "ensurepip is not available"?
                               #   → sudo apt install python3-venv, then retry
source .venv/bin/activate
pip install -e ".[dev]"
```

**Run the dashboard**

```bash
nad list-interfaces                    # eth0, wlan0, any, lo, ...
sudo .venv/bin/nad serve -i any --detector adaptive
#   → http://127.0.0.1:8000
```

The first ~30 seconds are a warmup. Leave it running for hours/days so the
per-hour baselines settle — they are persisted, so a restart does **not** reset
the learning.

> **Which interface?** Plain interface names (`ip link` shows them). The `any`
> pseudo-device captures every interface at once *and* lets the kernel tag each
> packet as inbound/outbound, which makes the `egress_ratio` (exfiltration
> direction) feature fully live — on a single Ethernet interface direction is
> inferred less directly. `any` is the recommended default.

> **Running without sudo:** grant the capture capability to your venv's Python
> once, then `nad` works as a normal user:
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)
> ```

## The dashboard

A single page at `http://127.0.0.1:8000`, five sections on one screen:

| Section | What it shows |
|---|---|
| **Status pill** | `정상 감시중` / `워밍업 N` / `오류`, plus interface and uptime |
| **KPI strip** | alert counts (1h / 24h / total), top feature, current packets/sec |
| **Alert timeline** | 60-minute histogram of alert density, coloured by severity |
| **Detected anomalies** | table of named verdicts + severity; click a row for the plain-language summary, recommended action, top talkers, and raw stats |
| **Live network activity** | top talkers and TCP/UDP/ICMP/OTHER mix for the current 1-second window |

Each alert leads with a plain-language verdict; the jargon stays in a collapsible
technical-detail section:

```text
[심각] 분산 공격(DDoS)/출발지 위조 의심
  갑자기 매우 많은 서로 다른 출발지에서 트래픽이 쏟아지고 있습니다
  (565곳, 평소의 약 185배). DDoS 공격이나 출발지 위조(spoofing)일 수 있습니다.
  → 권장: 지속되면 인터넷 연결을 차단하고 네트워크 관리자에게 알리세요.
  (기술 상세: unique_src_ips — 평소 대비 185배 ↑ ...)
```

## How it works

```
┌────────────┐  packets  ┌────────────┐ features ┌────────────────────────┐
│ libpcap    │ ────────▶ │ Window     │ ───────▶ │ AdaptiveDetector       │
│  (ctypes)  │           │ Aggregator │          │  robust Z per bucket   │─┐
└────────────┘           │ (1s)       │          │  + auto threshold      │ │
                         └─────┬──────┘          │  + CUSUM (slow drift)  │ │ alerts
                               │                 ├────────────────────────┤ ├─▶ classify ─▶ SQLite ─▶ dashboard
                               └────────────────▶│ FirstSeen + Beacon     │ │
                                                 │  (behavioural axis)    │─┘
                                                 └────────────────────────┘
```

- **Capture** — direct `ctypes` calls into the platform's libpcap, chosen at
  runtime by the capture factory: `libpcap.so` on Linux (packets come from the
  kernel's `AF_PACKET` socket), Npcap's `wpcap.dll` on Windows. Either way the
  BPF filter (`-f`, default `ip`) is compiled and run **below Python** (in the
  kernel / the Npcap driver), so uninteresting traffic never crosses into the
  process. On Linux the link layer is detected at open time via
  `pcap_datalink()` and decoded accordingly: Ethernet (`eth0`, `wlan0`, …),
  *cooked* `SLL`/`SLL2` (the `any` pseudo-device), raw IP, and loopback;
  Windows interfaces are Ethernet.
- **Direction** — on Linux cooked captures (`-i any`) every packet carries the
  kernel's own incoming/outgoing tag (`sll_pkttype`), so ingress/egress is exact.
  On a plain Ethernet interface (`-i eth0`) libpcap gives no tag, so the Linux
  backend **infers** it: it snapshots the host's own IPv4 addresses at open time
  and marks a packet EGRESS if its source is local, INGRESS if its destination
  is (loopback and pass-through traffic stay neutral). Either way `egress_ratio`
  — the exfiltration-direction feature — is live. Windows captures get no tag and
  no inference yet, so there `egress_ratio` sits at its neutral 50.
- **Features** — each 1-second window yields volume/count signals (packets,
  bytes, payload size, unique src/dst IPs, dst ports, TCP/UDP/ICMP, plus
  `syn_count`/`rst_count` TCP-flag tallies that separate a SYN flood or scan
  from ordinary traffic) plus 3 *shape* signals: `egress_ratio` (% outbound),
  `fan_out` (dsts per src), and `max_ports_per_dst` (most ports on one host —
  exposes a vertical scan). Any new key added here is picked up and baselined by
  every detector automatically.
- **Adaptive detector** — a robust **EWMA median + MAD** per `(time-bucket,
  feature)`, so outliers can't inflate the scale. The threshold self-tunes: a
  robust floor raised by a P²-tracked high quantile of recent scores, targeting a
  false-alarm *rate*. Cold buckets fall back to a fast global baseline.
- **CUSUM** — a control chart, re-anchored on entering each bucket and scaled by
  the within-visit spread, accumulates sustained sub-threshold drift (low-and-slow)
  without firing on normal day-to-day regime shifts.
- **Behavioural axis** — **first-seen** flags sustained traffic to a brand-new
  public server (persistent, TTL/LRU-bounded); **beacon** flags periodic,
  low-jitter contact — the timing signature of C2 that stays under volume radar.
- **Classifier** — maps the deviation + context (direction, protocol, time, top
  talkers) to a named hypothesis, a severity (관심 / 주의 / 경고 / 심각), an
  everyday-Korean summary, and a recommended action.
- **Persistence** — every baseline and rate-cutoff estimator is saved to SQLite
  and restored on start, so a restart never throws away days of learning.

## Configuration

`--detector adaptive` is the recommended engine; `baseline` is the original
fixed-threshold EWMA detector, kept for comparison.

**Tuning false positives**

| Knob | Range | Effect |
|---|---|---|
| `--robust-k` | 3.0 – 5.0 | higher = fewer alerts, may miss subtle signals |
| `--target-rate` | 0.001 – 0.02 | lower = stricter auto-cutoff, fewer alerts |
| `--confirm` | 1 – 10 | higher = ignore transient bursts, slower to react |
| `--cooldown` | 0 – 30 | higher = less alert spam |
| `--no-behavioral` | — | disable first-seen / beacon (noisy on short runs) |

<details>
<summary><b>Full <code>nad serve</code> options</b></summary>

```text
# core
  -i, --interface     interface name (eth0, wlan0, any…)  (required)
  -f, --filter        BPF filter                         [default: ip]
  -p, --port          HTTP port                          [default: 8000]
      --window-seconds  aggregation window (s)           [default: 1.0]
      --warmup        windows before alerting            [default: 30]
      --confirm       consecutive windows to confirm     [default: 3]
      --cooldown      windows muted after an alert        [default: 10]

# detector selection
      --detector      baseline | adaptive                [default: baseline]
      --bucketing     hour | weekend_hour | dow_hour     [default: weekend_hour]
      --threshold-mode  combined | robust | rate         [default: combined]
      --target-rate   target false-alarm fraction        [default: 0.005]
      --robust-k      robust-Z floor (~sigma)            [default: 3.5]
      --bucket-warmup windows before a bucket scores     [default: 200]

# behavioural axis
      --behavioral / --no-behavioral                     [default: on]
      --firstseen-learning      windows to learn first   [default: 3600]
      --firstseen-consecutive   windows to confirm new   [default: 5]
```
</details>

## Development

**Tests** (no elevation needed):

```bash
pytest                          # full suite
pytest tests/test_adaptive.py   # one module
pytest -k "cusum"               # by name
```

**Try it without capturing** — the evaluation scripts need no libpcap or root.

```bash
python scripts/evaluate.py              # synthetic benchmark: attacks vs detector stacks
python scripts/evaluate.py --sweep      # low-and-slow detection across ramp speeds
python scripts/replay_pcap.py a.pcap b.pcap   # replay real pcaps through the pipeline
python scripts/eval_unsw.py             # unsupervised separability on UNSW-NB15
```

> Datasets and pcaps are **not** in the repo (too large, gitignored). Pcaps are
> read via `dpkt`; UNSW-NB15 / CIC-IoT-2023 CSVs go in `Data/`.

**Live end-to-end benchmark** — `evaluate.py` scores detectors on *synthetic*
windows; this one drives real attack packets through the actual libpcap capture
path and measures what gets detected. It is **loopback-locked**: every attack
targets `127.0.0.1` and dedicated high ports this process opens itself, so
nothing leaves the machine and no other service is touched (no more dangerous
than `nmap localhost`). Needs root, only to capture on `lo`:

```bash
sudo .venv/bin/python scripts/live_attack_eval.py
```

It runs a benign baseline, then injects a port scan, a SYN/RST burst, and a
volume spike, and prints per-attack detection, latency, and the post-warmup
false-alarm count. A typical run detects 3/3 with 0 false alarms.

**Project layout**

```
src/nad/
├── capture/      # libpcap binding (ctypes → libpcap.so / wpcap.dll) + Packet/Capture types
│                 #   netlocal.py: host-IP discovery + direction inference
├── features.py   # WindowAggregator → WindowFeatures (volume + shape features)
├── stats.py      # RobustEwmaStat, P2Quantile, Cusum  (streaming, stdlib)
├── detect.py     # BaselineDetector (original fixed-threshold EWMA)
├── adaptive.py   # AdaptiveDetector: time buckets + auto-threshold + CUSUM
├── behavioral.py # FirstSeenDetector + BeaconDetector (behavioural axis)
├── classify.py   # anomaly → category / severity / plain-language / action
├── storage.py    # SQLite AlertStore + DestinationStore (WAL, persistent memory)
├── service.py    # capture → features → detect(+behavioural) → store loop
├── web/          # FastAPI app + dashboard
└── cli.py        # `nad` console script
scripts/          # evaluate.py (synthetic), live_attack_eval.py (loopback e2e),
                  #   replay_pcap.py, eval_unsw.py
docs/             # adaptive-detection-design.md
tests/
```

The Windows/Npcap backend (`capture/windows_npcap.py`) is kept intact — the
capture factory picks the right backend per OS, so the same codebase still runs
on Windows.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `libpcap not found` | Install it: `sudo apt install libpcap0.8` / `sudo dnf install libpcap`. |
| `ensurepip is not available` on `python3 -m venv` | Debian/Ubuntu ships venv separately: `sudo apt install python3-venv`. |
| `pcap_open_live failed … Operation not permitted` | Not running as root — use `sudo` or `setcap cap_net_raw,cap_net_admin=eip` on the venv's `python3`. |
| `sudo: nad: command not found` | `sudo` doesn't see the venv — use the full path: `sudo .venv/bin/nad …`. |
| `nad` runs old code | `nad` points at another editable install — run `pip install -e .` in *this* folder. |
| `egress_ratio` stuck at 50 | Neither end of the traffic is a host-local IP (loopback, or pass-through seen in promiscuous mode), so no direction can be inferred — expected for `-i lo`. |
| Many `처음 보는 외부 연결` early on | First-seen has no history yet (expected on short runs) — use `--no-behavioral` or let it learn. |
| Alerts spam | Raise `--confirm` / `--robust-k`, or lower `--target-rate`. |

## Status and roadmap

**Done**

- [x] Linux packet capture (libpcap via `ctypes` → `libpcap.so`) — Ethernet, cooked `any` (SLL/SLL2), raw, loopback
- [x] Kernel-tagged ingress/egress direction on cooked captures; host-IP inference on plain Ethernet interfaces
- [x] TCP-flag features (`syn_count`, `rst_count`) — SYN flood / scan / reset detection
- [x] Adaptive per-time-bucket baselines with self-tuning threshold
- [x] CUSUM low-and-slow drift detection
- [x] Shape features (egress ratio, fan-out, per-host port scan)
- [x] First-seen + beacon behavioural axis
- [x] Plain-language alert classifier
- [x] Baseline persistence across restarts (no re-warmup); SQLite WAL storage
- [x] FastAPI live dashboard
- [x] PCAP replay mode for repeatable testing
- [x] Windows backend retained (cross-platform capture factory)

**Planned**

- [ ] systemd unit (run as a service, start on boot)
- [ ] Optional auth / TLS for remote dashboard access
- [ ] IPv6 capture path

## Privacy

NIDS-Linux never connects out (the evaluation scripts download only datasets you
choose). Packet headers, capped 256-byte payload prefixes, alerts, and the
learned destination memory stay in the local SQLite file you point `--db` at.
Delete the file to wipe history.

## License

[MIT](LICENSE).
