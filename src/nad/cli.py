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
def serve_cmd(interface: str, bpf_filter: str, host: str, port: int,
              db_path: str, window_seconds: float, z_threshold: float, warmup: int,
              confirm: int, cooldown: int) -> None:
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
    )
    app = create_app(service)
    click.echo(f"  → http://{host}:{port}  (interface={interface}, filter={bpf_filter!r})")
    uvicorn.run(app, host=host, port=port, log_level="warning")
