"""Deterministic binary encoding primitives.

All integers are little-endian fixed width except where noted. Variable-length
counts use Bitcoin's CompactSize encoding, but we additionally require the
*minimal* encoding so that every object has exactly one serialization.
"""
from __future__ import annotations

import struct


class DecodeError(ValueError):
    """Raised for malformed or non-canonical serialized data."""


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


def u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b: bytes) -> bytes:
    return varint(len(b)) + b


class Reader:
    """Bounds-checked cursor over a byte string."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise DecodeError("unexpected end of data")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def varint(self) -> int:
        first = self.read(1)[0]
        if first < 0xFD:
            return first
        if first == 0xFD:
            n, minimum = struct.unpack("<H", self.read(2))[0], 0xFD
        elif first == 0xFE:
            n, minimum = struct.unpack("<I", self.read(4))[0], 0x10000
        else:
            n, minimum = struct.unpack("<Q", self.read(8))[0], 0x100000000
        if n < minimum:
            raise DecodeError("non-canonical varint")
        return n

    def varbytes(self, max_len: int) -> bytes:
        n = self.varint()
        if n > max_len:
            raise DecodeError(f"byte string length {n} exceeds limit {max_len}")
        return self.read(n)

    def count(self, max_count: int, min_item_bytes: int) -> int:
        """Read an element count, rejecting counts that cannot fit in the remaining data."""
        n = self.varint()
        if n > max_count:
            raise DecodeError(f"count {n} exceeds limit {max_count}")
        if n * min_item_bytes > self.remaining():
            raise DecodeError("count exceeds remaining data")
        return n

    def finish(self) -> None:
        if self.remaining():
            raise DecodeError(f"{self.remaining()} trailing bytes")
