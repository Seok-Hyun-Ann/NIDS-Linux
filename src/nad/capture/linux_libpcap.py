"""Linux packet capture via libpcap, using direct ctypes calls into libpcap.so.

Mirrors the Windows/Npcap binding: same pcap API, same `Packet` output. Two
Linux-specific differences:

  * The link layer is not always Ethernet. `pcap_datalink()` is consulted once
    at open time and the matching decoder is used (Ethernet, Linux cooked
    SLL/SLL2 for the ``any`` pseudo-device, raw IP, and BSD-style null/loop).
  * On the cooked link types the kernel tags each packet as incoming or
    outgoing, so `Packet.direction` is real INGRESS/EGRESS there. On plain
    Ethernet interfaces it stays UNKNOWN, exactly like the Windows backend.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import socket
from collections.abc import Iterator
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char_p,
    c_int,
    c_long,
    c_ubyte,
    c_uint,
    c_void_p,
    create_string_buffer,
)

from .base import Capture, Direction, Packet


PCAP_ERRBUF_SIZE = 256
_PAYLOAD_CAP = 256

# pcap_datalink() values (from pcap/dlt.h).
DLT_NULL = 0          # BSD loopback: 4-byte address-family header
DLT_EN10MB = 1        # Ethernet
DLT_RAW = 12          # raw IP, no link header
DLT_LOOP = 108        # OpenBSD loopback (network-order AF header)
DLT_LINUX_SLL = 113   # Linux "cooked" v1 — the `any` device on older libpcap
DLT_LINUX_SLL2 = 276  # Linux "cooked" v2 — the `any` device on libpcap >= 1.10

# sll_pkttype values (from linux/if_packet.h).
_PACKET_HOST = 0       # addressed to us
_PACKET_BROADCAST = 1
_PACKET_MULTICAST = 2
_PACKET_OTHERHOST = 3  # promiscuous catch, neither ours nor from us
_PACKET_OUTGOING = 4


class _timeval(Structure):
    # Native C `long`: 64-bit on 64-bit Linux, so no 2038 wrap here.
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class _pcap_pkthdr(Structure):
    _fields_ = [
        ("ts", _timeval),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


class _pcap_if(Structure):
    pass


_pcap_if._fields_ = [
    ("next", POINTER(_pcap_if)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", c_void_p),
    ("flags", c_uint),
]


class _bpf_program(Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", c_void_p),
    ]


_lib: ctypes.CDLL | None = None


def _load_libpcap() -> ctypes.CDLL:
    candidates = ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
    found = ctypes.util.find_library("pcap")
    if found:
        candidates.insert(0, found)
    last_err: OSError | None = None
    for path in candidates:
        try:
            return ctypes.CDLL(path)
        except OSError as e:
            last_err = e
    raise RuntimeError(
        "libpcap not found. Install it with your package manager, e.g. "
        "`sudo apt install libpcap0.8` (Debian/Ubuntu) or "
        "`sudo dnf install libpcap` (Fedora/RHEL)."
    ) from last_err


def _libpcap() -> ctypes.CDLL:
    global _lib
    if _lib is not None:
        return _lib
    lib = _load_libpcap()

    lib.pcap_open_live.restype = c_void_p
    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

    lib.pcap_findalldevs.restype = c_int
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(_pcap_if)), c_char_p]

    lib.pcap_freealldevs.restype = None
    lib.pcap_freealldevs.argtypes = [POINTER(_pcap_if)]

    lib.pcap_compile.restype = c_int
    lib.pcap_compile.argtypes = [c_void_p, POINTER(_bpf_program), c_char_p, c_int, c_uint]

    lib.pcap_setfilter.restype = c_int
    lib.pcap_setfilter.argtypes = [c_void_p, POINTER(_bpf_program)]

    lib.pcap_freecode.restype = None
    lib.pcap_freecode.argtypes = [POINTER(_bpf_program)]

    lib.pcap_next_ex.restype = c_int
    lib.pcap_next_ex.argtypes = [
        c_void_p,
        POINTER(POINTER(_pcap_pkthdr)),
        POINTER(POINTER(c_ubyte)),
    ]

    lib.pcap_close.restype = None
    lib.pcap_close.argtypes = [c_void_p]

    lib.pcap_geterr.restype = c_char_p
    lib.pcap_geterr.argtypes = [c_void_p]

    lib.pcap_datalink.restype = c_int
    lib.pcap_datalink.argtypes = [c_void_p]

    _lib = lib
    return lib


def list_devices() -> list[str]:
    lib = _libpcap()
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    head = POINTER(_pcap_if)()
    if lib.pcap_findalldevs(byref(head), errbuf) != 0:
        raise RuntimeError(
            f"pcap_findalldevs failed: {errbuf.value.decode(errors='replace')}"
        )
    names: list[str] = []
    cur = head
    while cur:
        name = cur.contents.name
        if name:
            names.append(name.decode(errors="replace"))
        cur = cur.contents.next
    lib.pcap_freealldevs(head)
    return names


def _direction_from_pkttype(pkttype: int) -> Direction:
    if pkttype == _PACKET_OUTGOING:
        return Direction.EGRESS
    if pkttype in (_PACKET_HOST, _PACKET_BROADCAST, _PACKET_MULTICAST):
        return Direction.INGRESS
    return Direction.UNKNOWN  # PACKET_OTHERHOST: promiscuous bystander traffic


def _decode_ethernet(data: bytes):
    import dpkt

    try:
        eth = dpkt.ethernet.Ethernet(data)
    except dpkt.UnpackError:
        return None
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None
    return ip, Direction.UNKNOWN


def _decode_sll(data: bytes):
    # v1 cooked header, 16 bytes: pkttype(2) hatype(2) halen(2) addr(8) proto(2)
    import dpkt

    if len(data) < 16:
        return None
    pkttype = int.from_bytes(data[0:2], "big")
    proto = int.from_bytes(data[14:16], "big")
    if proto != dpkt.ethernet.ETH_TYPE_IP:
        return None
    try:
        ip = dpkt.ip.IP(data[16:])
    except dpkt.UnpackError:
        return None
    return ip, _direction_from_pkttype(pkttype)


def _decode_sll2(data: bytes):
    # v2 cooked header, 20 bytes: proto(2) rsvd(2) ifindex(4) hatype(2)
    #                             pkttype(1) halen(1) addr(8)
    import dpkt

    if len(data) < 20:
        return None
    proto = int.from_bytes(data[0:2], "big")
    pkttype = data[10]
    if proto != dpkt.ethernet.ETH_TYPE_IP:
        return None
    try:
        ip = dpkt.ip.IP(data[20:])
    except dpkt.UnpackError:
        return None
    return ip, _direction_from_pkttype(pkttype)


def _decode_raw(data: bytes):
    import dpkt

    try:
        ip = dpkt.ip.IP(data)
    except dpkt.UnpackError:
        return None
    return ip, Direction.UNKNOWN


def _decode_null(data: bytes):
    # 4-byte address-family header; AF_INET=2 in either byte order.
    import dpkt

    if len(data) < 4:
        return None
    family = int.from_bytes(data[0:4], "little")
    if family not in (socket.AF_INET, socket.AF_INET << 24):
        return None
    try:
        ip = dpkt.ip.IP(data[4:])
    except dpkt.UnpackError:
        return None
    return ip, Direction.UNKNOWN


_DECODERS = {
    DLT_EN10MB: _decode_ethernet,
    DLT_LINUX_SLL: _decode_sll,
    DLT_LINUX_SLL2: _decode_sll2,
    DLT_RAW: _decode_raw,
    DLT_NULL: _decode_null,
    DLT_LOOP: _decode_null,
}


class LinuxLibpcapCapture(Capture):
    def __init__(self, interface: str, snaplen: int = 65535, bpf_filter: str = "ip") -> None:
        self.interface = interface
        self.snaplen = snaplen
        self.bpf_filter = bpf_filter
        self._handle: int | None = None
        self._decode = None
        self._stop = False

    def __enter__(self) -> "LinuxLibpcapCapture":
        lib = _libpcap()
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_open_live(
            self.interface.encode("utf-8"),
            self.snaplen,
            1,        # promisc
            100,      # read timeout (ms)
            errbuf,
        )
        if not handle:
            raise RuntimeError(
                f"pcap_open_live failed for {self.interface!r}: "
                f"{errbuf.value.decode(errors='replace')} "
                "(capture needs root, or CAP_NET_RAW on the Python binary)"
            )
        self._handle = handle

        dlt = lib.pcap_datalink(handle)
        self._decode = _DECODERS.get(dlt)
        if self._decode is None:
            lib.pcap_close(handle)
            self._handle = None
            raise RuntimeError(
                f"unsupported link type {dlt} on {self.interface!r} "
                f"(supported: {sorted(_DECODERS)})"
            )

        if self.bpf_filter:
            prog = _bpf_program()
            if lib.pcap_compile(
                handle, byref(prog), self.bpf_filter.encode("utf-8"), 1, 0xFFFFFFFF
            ) != 0:
                err = lib.pcap_geterr(handle).decode(errors="replace")
                lib.pcap_close(handle)
                self._handle = None
                raise RuntimeError(f"pcap_compile failed: {err}")
            if lib.pcap_setfilter(handle, byref(prog)) != 0:
                err = lib.pcap_geterr(handle).decode(errors="replace")
                lib.pcap_freecode(byref(prog))
                lib.pcap_close(handle)
                self._handle = None
                raise RuntimeError(f"pcap_setfilter failed: {err}")
            lib.pcap_freecode(byref(prog))
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop = True
        if self._handle is not None:
            _libpcap().pcap_close(self._handle)
            self._handle = None

    def __iter__(self) -> Iterator[Packet]:
        import dpkt

        lib = _libpcap()
        hdr_p = POINTER(_pcap_pkthdr)()
        data_p = POINTER(c_ubyte)()

        while not self._stop:
            rc = lib.pcap_next_ex(self._handle, byref(hdr_p), byref(data_p))
            if rc == 0:
                continue  # read timed out, no packet ready
            if rc < 0:
                err = lib.pcap_geterr(self._handle).decode(errors="replace")
                raise RuntimeError(f"pcap_next_ex failed: {err}")

            hdr = hdr_p.contents
            ts_ns = hdr.ts.tv_sec * 1_000_000_000 + hdr.ts.tv_usec * 1_000
            caplen = int(hdr.caplen)
            data = ctypes.string_at(data_p, caplen)

            decoded = self._decode(data)
            if decoded is None:
                continue
            ip, direction = decoded

            src_port = dst_port = 0
            payload = b""
            if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                src_port = int(ip.data.sport)
                dst_port = int(ip.data.dport)
                payload = bytes(ip.data.data)[:_PAYLOAD_CAP]

            yield Packet(
                timestamp_ns=ts_ns,
                src_ip=socket.inet_ntoa(ip.src),
                dst_ip=socket.inet_ntoa(ip.dst),
                src_port=src_port,
                dst_port=dst_port,
                protocol=int(ip.p),
                direction=direction,
                payload=payload,
                total_len=int(ip.len),
            )
