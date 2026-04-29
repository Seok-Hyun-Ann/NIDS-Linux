# NIDS-Win — Network Anomaly Detector for Windows

[![CI](https://github.com/Seok-Hyun-Ann/NIDS-Win/actions/workflows/ci.yml/badge.svg)](https://github.com/Seok-Hyun-Ann/NIDS-Win/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Host-resident network anomaly detector for Windows with **explainable alerts**.
Captures live traffic on a chosen interface, learns a per-feature baseline of
normal behavior, flags anomalies, and ships every alert with the statistical
reasons that triggered it. Runs entirely on your machine — no telemetry, no
external services, no LLMs in the detection path.

A live web dashboard (FastAPI + vanilla JS) shows current throughput, an alert
timeline, top talkers, and click-to-expand details for each alert.

## Why this project?

Most consumer-grade IDS/EDR tools give you alerts that boil down to "we noticed
something." They rarely tell you *why*, and when they do, the reason is hidden
behind a model you can't inspect. NAD is the opposite:

- **Every alert is reproducible** — the math is `(value − EWMA mean) / EWMA std`,
  per feature, per time window. You can read the code in 200 lines.
- **Every alert lists its evidence** — the top source IPs, destination IPs, and
  destination ports for the offending window are shown alongside the Z-score.
- **Tunable from the command line** — change `--z-threshold`, `--confirm`, and
  `--cooldown` until the signal-to-noise ratio fits your environment.

## What you see

The dashboard is a single page served at `http://127.0.0.1:8000`. Five
sections, all on one screen:

| Section | What it shows |
|---|---|
| **Status pill** | `정상 감시중` (green) / `워밍업 N` (yellow) / `오류` (red), plus interface name and uptime |
| **KPI strip** | Alert counts (1h / 24h / total), top affected feature in the last hour, current packets-per-second |
| **Alert timeline** | 60-minute histogram of alert density. Bar colour = severity (LOW / MED / HIGH based on \|Z-score\|) |
| **Detected anomalies** | Sortable table of alerts. Click a row to expand: Korean explanation, top 5 source IPs, top 5 destination IPs, top 5 destination ports, raw stats (current vs baseline, Z-score, direction) |
| **Live network activity** | Top talkers (source IPs / destination IPs / destination ports) and TCP / UDP / ICMP / OTHER protocol mix for the *current* 1-second window |

Every alert carries a deterministic, one-line explanation built straight from
the EWMA statistics — no LLM, no template randomisation:

```text
unique_dst_ips — 평소 대비 4.2σ 초과 (현재 30.0 IPs, 기준 11.6 ±2.5).
주요 출발지: 172.23.14.16(150), 151.106.247.9(77), 64.233.185.95(15).
주요 목적지 포트: 7338(106), 55544(77), 443(40).
```

## Status

| Component | State |
|---|---|
| Windows packet capture (Npcap via direct ctypes → `wpcap.dll`) | ✅ verified on Windows 11 |
| Time-window feature aggregation | ✅ |
| Statistical anomaly detection (EWMA + Z-score with N-window confirm) | ✅ |
| SQLite alert storage | ✅ |
| FastAPI live dashboard with SIEM-style UI | ✅ |
| Two-stage detection (Isolation Forest) | ⏳ planned |
| SHAP-backed feature attribution | ⏳ planned |
| Windows Service installer | ⏳ planned |

## Requirements

- **Windows 10 or 11** (64-bit)
- **Python 3.11 or newer**
- **[Npcap](https://npcap.com/)**, installed with **"Install Npcap in WinPcap
  API-compatible Mode"** checked (default in modern installers)
- **Administrator privileges** when running the capture commands — Windows
  requires elevation for raw packet capture

You do **not** need MSVC Build Tools, the Windows SDK, or Visual Studio. The
package talks to Npcap's `wpcap.dll` directly through `ctypes` — no native
Python wheels to compile.

## Installation

```powershell
git clone https://github.com/Seok-Hyun-Ann/NIDS-Win.git
cd NIDS-Win

python -m venv .venv
.venv\Scripts\activate

pip install -e ".[dev]"
```

## Quick start

Open a terminal **as Administrator**, then:

```powershell
# 1. List available interfaces
nad list-interfaces
# →  \Device\NPF_{F2EF76A2-...}        (VMware VMnet1)
#    \Device\NPF_{A5CB34C2-...}        (Realtek PCIe GbE)
#    \Device\NPF_{500A84C1-...}        (VMware VMnet8)

# 2. Smoke-test capture (10 packets from your physical NIC)
nad capture --interface "\Device\NPF_{A5CB34C2-...}" --limit 10

# 3. Launch the live dashboard
nad serve --interface "\Device\NPF_{A5CB34C2-...}"
#   → http://127.0.0.1:8000
```

Open the URL in your browser and you'll see the dashboard. The first ~30
seconds are a warmup phase where the baseline learns your normal traffic; no
alerts fire during that window.

> **Tip — finding your interface:** the `\Device\NPF_{...}` strings are GUIDs.
> Match them against `Get-NetAdapter` in PowerShell to find which one is your
> physical NIC vs. virtual adapters.

## How it works

```
┌──────────────┐    packets     ┌──────────────┐   features   ┌──────────────┐
│ Npcap        │ ─────────────▶ │ Window       │ ───────────▶ │ EWMA Z-score │
│ (wpcap.dll)  │                │ Aggregator   │              │ Detector     │
└──────────────┘                │ (1s buckets) │              └──────┬───────┘
                                └──────────────┘                     │ alerts
                                                                     ▼
                                ┌──────────────┐              ┌──────────────┐
                                │ FastAPI app  │ ◀─── reads ─ │ SQLite store │
                                │ + dashboard  │              └──────────────┘
                                └──────────────┘
```

For each 1-second window the aggregator computes 9 numeric features (packet
count, byte total, average payload size, unique source/destination IPs,
unique destination ports, TCP/UDP/ICMP counts) plus the top-K source IPs,
destination IPs, and destination ports for context.

The detector keeps an online EWMA mean and variance per feature. When a
feature's value is more than `--z-threshold` standard deviations from its
baseline for `--confirm` consecutive windows, an alert fires. After firing,
that feature is muted for `--cooldown` windows while the EWMA absorbs any
sustained legitimate change (e.g., you started a download).

The explanation is rendered from a fixed Korean template that includes the
deviation magnitude, current vs. baseline values, and the top contributing
sources for the offending window — no LLM, no free-form generation.

## CLI reference

```text
nad list-interfaces                    # print Npcap device names
nad capture   --interface <dev> [opts] # raw packet print (debug)
nad serve     --interface <dev> [opts] # live dashboard

# Common options for `serve`:
  --interface, -i   Npcap device string (required)
  --filter, -f      BPF filter expression           [default: ip]
  --host            Bind address                    [default: 127.0.0.1]
  --port, -p        HTTP port                       [default: 8000]
  --db              SQLite alert path               [default: nad.db]
  --window-seconds  Aggregation window in seconds   [default: 1.0]
  --z-threshold     Sigma threshold per feature     [default: 3.0]
  --warmup          Windows before alerting starts  [default: 30]
  --confirm         Consecutive anomalous windows
                    required before firing          [default: 3]
  --cooldown        Windows muted per feature
                    after each alert                [default: 10]
```

### Tuning false positives

If the dashboard fires on every Chrome tab burst, raise `--confirm` (e.g. `5`)
or `--z-threshold` (e.g. `4.0`). If real anomalies sneak through, lower them.
Sensible ranges:

| Knob | Range | Effect |
|---|---|---|
| `--z-threshold` | 2.5 – 5.0 | higher = fewer alerts, miss subtle signals |
| `--confirm`     | 1 – 10    | higher = transient bursts ignored, slower to react |
| `--cooldown`    | 0 – 30    | higher = less alert spam, possible miss-after-alert |
| `--window-seconds` | 0.5 – 5 | smaller = more reactive, noisier features |

## Tests

```powershell
pytest                               # full suite
pytest tests/test_detect.py          # one file
pytest -k "spike"                    # by name
```

The unit tests cover the OS-independent layers (features, detector, storage)
and run on any Windows machine without elevation. The capture path is
verified by manual smoke-test (`nad capture --limit ...`).

## Project layout

```
src/nad/
├── capture/
│   ├── base.py           # Capture ABC + Packet dataclass
│   ├── factory.py        # Windows-only factory
│   └── windows_npcap.py  # ctypes binding to wpcap.dll
├── features.py           # WindowAggregator
├── detect.py             # BaselineDetector (EWMA Z-score + N-window confirm)
├── storage.py            # SQLite AlertStore
├── service.py            # capture → features → detect → store loop
├── web/
│   ├── app.py            # FastAPI app
│   └── static/           # index.html + style.css + app.js
└── cli.py                # `nad` console script
tests/
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `RuntimeError: wpcap.dll not found` | Npcap not installed, or installed without WinPcap-compatible mode. Re-run the Npcap installer with that option enabled. |
| `pcap_open_live failed` for a valid interface | Terminal not running as Administrator. |
| Dashboard reaches 워밍업 0, but no alerts | Working as intended — your traffic is well-behaved. Lower `--z-threshold` or `--confirm` to make it more sensitive. |
| Alerts spam every minute | Raise `--z-threshold` to 4.0 or `--confirm` to 5. |
| `nad list-interfaces` shows only `\Device\NPF_*` GUIDs | Match them against PowerShell's `Get-NetAdapter \| Select Name, InterfaceGuid` to identify which is which. |

## Roadmap

- [ ] Stage-2 anomaly scoring with Isolation Forest (gates only the windows
      flagged by the statistical baseline).
- [ ] SHAP feature attribution rendered into the existing alert templates.
- [ ] Windows Service installer (so the daemon can run without an open
      Administrator terminal).
- [ ] Optional auth / TLS for remote dashboard access.
- [ ] PCAP replay mode for repeatable testing.

## Privacy

NAD never connects out. All packet headers, payload prefixes (capped at 256
bytes), and alerts stay in the SQLite file you point `--db` at. Delete the
file to wipe history.

## License

[MIT](LICENSE).
