"""Hash constructions used by the protocol (all SHA-256 based)."""
from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double SHA-256, as used by Bitcoin for block and transaction identifiers."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash20(pubkey: bytes) -> bytes:
    """20-byte public-key hash used inside addresses: SHA-256d(pubkey)[:20]."""
    return sha256d(pubkey)[:20]


def work_from_target(target: int) -> int:
    """Expected number of hashes to find a block at this target: floor(2^256 / (target+1))."""
    return (1 << 256) // (target + 1)


def hash_to_int(h: bytes) -> int:
    """Interpret a 32-byte hash as a big-endian unsigned integer (no byte reversal)."""
    return int.from_bytes(h, "big")
