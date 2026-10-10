"""Base58Check addresses.

address = Base58( version_byte || h20 || checksum4 )
  h20       = SHA-256d(compressed_pubkey)[:20]
  checksum4 = SHA-256d(version_byte || h20)[:4]
"""
from __future__ import annotations

from .hashing import hash20, sha256d

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


class AddressError(ValueError):
    pass


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, rem = divmod(n, 58)
        out.append(_ALPHABET[rem])
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _INDEX:
            raise AddressError(f"invalid base58 character {c!r}")
        n = n * 58 + _INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


def encode_address(h20: bytes, version: int) -> str:
    if len(h20) != 20:
        raise AddressError("address hash must be 20 bytes")
    payload = bytes([version]) + h20
    return b58encode(payload + sha256d(payload)[:4])


def decode_address(addr: str, version: int) -> bytes:
    if not (20 <= len(addr) <= 40):
        raise AddressError("address has invalid length")
    raw = b58decode(addr)
    if len(raw) != 25:
        raise AddressError("address payload has invalid length")
    payload, checksum = raw[:21], raw[21:]
    if sha256d(payload)[:4] != checksum:
        raise AddressError("address checksum mismatch")
    if payload[0] != version:
        raise AddressError("address belongs to a different network")
    return payload[1:]


def pubkey_to_address(pubkey: bytes, version: int) -> str:
    return encode_address(hash20(pubkey), version)
