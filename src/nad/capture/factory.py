"""Capture factory — Windows / Npcap only."""
from __future__ import annotations

import sys

from .base import Capture


def _require_windows() -> None:
    if sys.platform != "win32":
        raise NotImplementedError(
            f"This package only supports Windows (sys.platform={sys.platform!r})."
        )


def make_capture(interface: str, snaplen: int = 65535, bpf_filter: str = "ip") -> Capture:
    _require_windows()
    from .windows_npcap import WindowsNpcapCapture
    return WindowsNpcapCapture(interface=interface, snaplen=snaplen, bpf_filter=bpf_filter)


def list_interfaces() -> list[str]:
    _require_windows()
    from .windows_npcap import list_devices
    return list_devices()
