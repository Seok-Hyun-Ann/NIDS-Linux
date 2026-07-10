"""Capture factory — picks the libpcap backend for the current OS."""
from __future__ import annotations

import sys

from .base import Capture


def make_capture(interface: str, snaplen: int = 65535, bpf_filter: str = "ip") -> Capture:
    if sys.platform.startswith("linux"):
        from .linux_libpcap import LinuxLibpcapCapture
        return LinuxLibpcapCapture(interface=interface, snaplen=snaplen, bpf_filter=bpf_filter)
    if sys.platform == "win32":
        from .windows_npcap import WindowsNpcapCapture
        return WindowsNpcapCapture(interface=interface, snaplen=snaplen, bpf_filter=bpf_filter)
    raise NotImplementedError(
        f"No capture backend for this OS (sys.platform={sys.platform!r}); "
        "supported: Linux (libpcap), Windows (Npcap)."
    )


def list_interfaces() -> list[str]:
    if sys.platform.startswith("linux"):
        from .linux_libpcap import list_devices
        return list_devices()
    if sys.platform == "win32":
        from .windows_npcap import list_devices
        return list_devices()
    raise NotImplementedError(
        f"No capture backend for this OS (sys.platform={sys.platform!r}); "
        "supported: Linux (libpcap), Windows (Npcap)."
    )
