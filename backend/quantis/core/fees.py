"""Fee rules.

Two layers, deliberately separated:

1. Consensus floor (every node, every block): fee >= size_bytes * min_fee_per_byte.

2. Relay policy (local, not consensus). A node's mempool admits a transaction only
   if its fee rate meets
        rate(B) = r_base + floor(r_base * (M - 1) * min(B, B*) / B*)
   where B is the current mempool size in bytes and B* the configured target.
   The multiplier rate/r_base is therefore bounded to [1, M]: it rises linearly
   with congestion and saturates once the mempool reaches its target size.

The fee a user *offers* is independent of the minimum: the wallet shows both.
All arithmetic is on Python integers (no overflow) and is checked to be >= 0.
"""
from __future__ import annotations

from dataclasses import dataclass


def fee_burn(fees: int, p) -> int:
    """Quanta of a block's fees that are burned: fee_burn_percent of them, rounded up."""
    return -(-fees * p.fee_burn_percent // 100)


@dataclass(frozen=True)
class FeePolicy:
    base_rate: int = 10  # quanta per byte when the mempool is empty
    max_multiplier: int = 8  # M
    target_bytes: int = 64_000  # B*

    def __post_init__(self) -> None:
        if self.base_rate < 0 or self.max_multiplier < 1 or self.target_bytes < 1:
            raise ValueError("invalid fee policy")

    def rate(self, mempool_bytes: int) -> int:
        b = min(max(mempool_bytes, 0), self.target_bytes)
        return self.base_rate + (self.base_rate * (self.max_multiplier - 1) * b) // self.target_bytes

    def min_fee(self, size_bytes: int, mempool_bytes: int) -> int:
        if size_bytes < 0:
            raise ValueError("size must be non-negative")
        return size_bytes * self.rate(mempool_bytes)


def consensus_min_fee(size_bytes: int, min_fee_per_byte: int) -> int:
    return size_bytes * min_fee_per_byte


def feerate_key(fee: int, size: int, txid: bytes) -> tuple:
    """Sort key: higher fee per byte first, then ascending txid. Uses exact rationals."""
    from fractions import Fraction

    return (-Fraction(fee, size), txid)
