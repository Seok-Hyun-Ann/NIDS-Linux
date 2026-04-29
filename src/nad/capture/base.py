"""Packet capture interface and shared types."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum


class Direction(IntEnum):
    INGRESS = 0
    EGRESS = 1
    UNKNOWN = 2


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp_ns: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int          # IANA protocol number; 6=TCP, 17=UDP, 1=ICMP
    direction: Direction
    payload: bytes         # truncated to the implementation's snap length
    total_len: int         # full IP datagram length, regardless of payload truncation


class Capture(ABC):
    """Context-managed iterator of `Packet` records."""

    @abstractmethod
    def __enter__(self) -> "Capture": ...

    @abstractmethod
    def __exit__(self, exc_type, exc, tb) -> None: ...

    @abstractmethod
    def __iter__(self) -> Iterator[Packet]: ...
