"""Windows packet capture via Npcap, using direct ctypes calls into wpcap.dll.

Direction (ingress/egress) is reported as UNKNOWN; higher layers can infer
it by comparing src_ip against the host's local interfaces.
"""
from __future__ import annotations

import ctypes
import os
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


class _timeval(Structure):
    # 64-bit Windows keeps C `long` 32-bit; libpcap's pcap_pkthdr uses that.
    # tv_sec therefore wraps in 2038 — a libpcap-on-Windows limit, not ours.
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


_lib: ctypes.WinDLL | None = None


def _load_wpcap() -> ctypes.WinDLL:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        "wpcap.dll",  # works when Npcap was installed in WinPcap-compatible mode
        os.path.join(sysroot, "System32", "Npcap", "wpcap.dll"),
        os.path.join(sysroot, "SysWOW64", "Npcap", "wpcap.dll"),
    ]
    last_err: OSError | None = None
    for path in candidates:
        try:
            return ctypes.WinDLL(path)
        except OSError as e:
            last_err = e
    raise RuntimeError(
        "wpcap.dll not found. Install Npcap from https://npcap.com/ — during "
        "install, leave 'Install Npcap in WinPcap API-compatible Mode' checked."
    ) from last_err


def _libpcap() -> ctypes.WinDLL:
    global _lib
    if _lib is not None:
        return _lib
    lib = _load_wpcap()

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


class WindowsNpcapCapture(Capture):
    def __init__(self, interface: str, snaplen: int = 65535, bpf_filter: str = "ip") -> None:
        self.interface = interface
        self.snaplen = snaplen
        self.bpf_filter = bpf_filter
        self._handle: int | None = None
        self._stop = False

    def __enter__(self) -> "WindowsNpcapCapture":
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
                f"{errbuf.value.decode(errors='replace')}"
            )
        self._handle = handle

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

            try:
                eth = dpkt.ethernet.Ethernet(data)
            except dpkt.UnpackError:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue

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
                direction=Direction.UNKNOWN,
                payload=payload,
                total_len=int(ip.len),
            )
