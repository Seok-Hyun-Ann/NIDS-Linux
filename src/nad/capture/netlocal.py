"""Host-local IPv4 discovery and direction inference.

The kernel tags packet direction only on Linux *cooked* captures (`-i any`).
On a plain Ethernet interface — and on Windows — libpcap reports no direction,
so the whole `egress_ratio` (exfiltration) axis goes dark. This module recovers
it the way `capture/base.py` always intended: compare each packet's addresses
against the set of the host's own IPv4 addresses.
"""
from __future__ import annotations

import socket
import sys

from .base import Direction

_SIOCGIFADDR = 0x8915  # linux/sockios.h — get an interface's IPv4 address


def _linux_ioctl_ipv4s() -> set[str]:
    import fcntl
    import struct

    ips: set[str] = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _idx, name in socket.if_nameindex():
            try:
                packed = fcntl.ioctl(
                    sock.fileno(),
                    _SIOCGIFADDR,
                    struct.pack("256s", name.encode("utf-8")[:15]),
                )
            except OSError:
                continue  # interface has no IPv4 bound
            ips.add(socket.inet_ntoa(packed[20:24]))
    finally:
        sock.close()
    return ips


def local_ipv4s() -> set[str]:
    """Every IPv4 address that belongs to this host (loopback included).

    Linux uses a per-interface ioctl for the complete set; other platforms fall
    back to resolving the hostname. Always returns at least ``127.0.0.1`` so the
    result is never empty.
    """
    ips: set[str] = {"127.0.0.1"}
    if sys.platform.startswith("linux"):
        try:
            ips |= _linux_ioctl_ipv4s()
        except OSError:
            pass
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.add(info[4][0])
    except (OSError, socket.gaierror):
        pass
    return ips


def infer_direction(src_ip: str, dst_ip: str, local_ips: set[str]) -> Direction:
    """EGRESS if it leaves us, INGRESS if it arrives, UNKNOWN otherwise.

    UNKNOWN covers loopback (both ends local) and transit traffic seen in
    promiscuous mode (neither end local) — in both cases a direction would be
    meaningless, so the neutral value keeps `egress_ratio` from firing falsely.
    """
    src_local = src_ip in local_ips
    dst_local = dst_ip in local_ips
    if src_local and not dst_local:
        return Direction.EGRESS
    if dst_local and not src_local:
        return Direction.INGRESS
    return Direction.UNKNOWN
