from __future__ import annotations

import click

from .capture import list_interfaces, make_capture


@click.group()
def main() -> None:
    """Network anomaly detector — CLI for capture, training, and serving."""


@main.command("list-interfaces")
def list_interfaces_cmd() -> None:
    """Print available network interfaces."""
    for name in list_interfaces():
        click.echo(name)


@main.command("capture")
@click.option("--interface", "-i", required=True, help="Interface to capture on.")
@click.option("--filter", "-f", "bpf_filter", default="ip", show_default=True,
              help="BPF filter expression.")
@click.option("--limit", "-n", type=int, default=10, show_default=True,
              help="Stop after N packets (0 = unlimited).")
def capture_cmd(interface: str, bpf_filter: str, limit: int) -> None:
    """Print captured packets to stdout. Requires Administrator."""
    cap = make_capture(interface=interface, bpf_filter=bpf_filter)
    with cap as stream:
        for i, pkt in enumerate(stream, start=1):
            click.echo(
                f"{pkt.timestamp_ns} {pkt.direction.name:7} "
                f"{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port} "
                f"proto={pkt.protocol} len={pkt.total_len} payload={len(pkt.payload)}B"
            )
            if limit and i >= limit:
                break


@main.command("serve")
@click.option("--interface", "-i", required=True, help="Interface to monitor.")
@click.option("--filter", "-f", "bpf_filter", default="ip", show_default=True,
              help="BPF filter expression.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address for the dashboard.")
@click.option("--port", "-p", type=int, default=8000, show_default=True,
              help="HTTP port for the dashboard.")
@click.option("--db", "db_path", default="nad.db", show_default=True,
              help="SQLite path for alerts.")
@click.option("--window-seconds", type=float, default=1.0, show_default=True,
              help="Aggregation window in seconds.")
@click.option("--z-threshold", type=float, default=3.0, show_default=True,
              help="Z-score above which a window triggers an alert.")
@click.option("--warmup", type=int, default=30, show_default=True,
              help="Number of windows to learn the baseline before alerting.")
@click.option("--confirm", type=int, default=3, show_default=True,
              help="Consecutive anomalous windows required before firing an alert.")
@click.option("--cooldown", type=int, default=10, show_default=True,
              help="Windows muted per feature after an alert.")
@click.option("--detector", type=click.Choice(["baseline", "adaptive"]),
              default="baseline", show_default=True,
              help="Detection engine. 'adaptive' self-tunes the threshold and "
                   "learns a separate baseline per time-of-day bucket.")
@click.option("--bucketing", type=click.Choice(["hour", "weekend_hour", "dow_hour"]),
              default="weekend_hour", show_default=True,
              help="[adaptive] Time bucket granularity for per-period baselines.")
@click.option("--threshold-mode", type=click.Choice(["combined", "robust", "rate"]),
              default="combined", show_default=True,
              help="[adaptive] Threshold policy: robust floor, rate-targeting, or both.")
@click.option("--target-rate", type=float, default=0.005, show_default=True,
              help="[adaptive] Target fraction of windows allowed to alert (rate tuning).")
@click.option("--robust-k", type=float, default=3.5, show_default=True,
              help="[adaptive] Robust Z floor (~sigma multiplier) for the threshold.")
@click.option("--bucket-warmup", type=int, default=200, show_default=True,
              help="[adaptive] Windows a time bucket must see before it scores.")
@click.option("--behavioral/--no-behavioral", default=True, show_default=True,
              help="Flag sustained traffic to never-before-seen external destinations.")
@click.option("--firstseen-learning", type=int, default=3600, show_default=True,
              help="Windows to silently learn known destinations before alerting.")
@click.option("--firstseen-consecutive", type=int, default=5, show_default=True,
              help="Consecutive windows a new destination must persist to alert.")
def serve_cmd(interface: str, bpf_filter: str, host: str, port: int,
              db_path: str, window_seconds: float, z_threshold: float, warmup: int,
              confirm: int, cooldown: int, detector: str, bucketing: str,
              threshold_mode: str, target_rate: float, robust_k: float,
              bucket_warmup: int, behavioral: bool, firstseen_learning: int,
              firstseen_consecutive: int) -> None:
    """Run the live dashboard. Requires Administrator (for packet capture)."""
    import logging
    import uvicorn

    from .service import MonitorService
    from .web.app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    service = MonitorService(
        interface=interface,
        bpf_filter=bpf_filter,
        db_path=db_path,
        window_seconds=window_seconds,
        z_threshold=z_threshold,
        warmup_windows=warmup,
        confirm_windows=confirm,
        cooldown_windows=cooldown,
        detector_kind=detector,
        bucketing=bucketing,
        threshold_mode=threshold_mode,
        target_rate=target_rate,
        robust_k=robust_k,
        bucket_warmup=bucket_warmup,
        behavioral=behavioral,
        firstseen_learning=firstseen_learning,
        firstseen_consecutive=firstseen_consecutive,
    )
    app = create_app(service)
    click.echo(f"  → http://{host}:{port}  (interface={interface}, "
               f"filter={bpf_filter!r}, detector={detector})")
    uvicorn.run(app, host=host, port=port, log_level="warning")
