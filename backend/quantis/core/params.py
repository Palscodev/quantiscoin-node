"""Consensus parameters.

Everything in NetworkParams is consensus-critical: two nodes with different values
are on different networks. The network "magic" is derived from a canonical
serialization of these values, so a mismatch is detected at the P2P handshake and
signatures made for one network are invalid on another (see sighash in tx.py).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

COIN = 100_000_000  # 1 QTS = 10^8 quanta (the atomic unit)
TICKER = "QTS"
PROTOCOL_VERSION = 1
SOFTWARE_VERSION = "0.3.0"


@dataclass(frozen=True)
class NetworkParams:
    name: str
    # --- monetary policy -------------------------------------------------
    initial_reward: int = 25 * COIN  # R_0 in quanta (25 QTS)
    halving_interval: int = 200_000  # H, blocks per reward era (about 139 days at 60 s)
    coinbase_maturity: int = 10  # confirmations before a coinbase output is spendable
    # --- proof of work / difficulty -------------------------------------
    target_block_time: int = 60  # T, seconds
    retarget_window: int = 10  # W, blocks
    damping: int = 2  # d, controller damping factor
    clamp_factor: int = 4  # observed window time is clamped to [E/c, E*c]
    pow_limit: int = 1 << 236  # easiest permitted target (~1 million hashes: a lone Raspberry Pi can always mine)
    initial_target: int = 1 << 229  # target until the first retarget (~134 million hashes per block)
    mtp_span: int = 11  # blocks in the median-time-past
    max_future_drift: int = 120  # seconds a timestamp may lead the validating node's clock
    # --- resource limits --------------------------------------------------
    max_block_bytes: int = 64_000
    max_tx_bytes: int = 16_000
    max_tx_inputs: int = 64
    max_tx_outputs: int = 64
    min_fee_per_byte: int = 1  # consensus fee floor, quanta per serialized byte
    # --- identity -----------------------------------------------------------
    genesis_timestamp: int = 1767225600  # 2026-01-01T00:00:00Z
    genesis_message: str = "QuantisCoin genesis: 1/2 + 1/4 + 1/8 + ... = 1"
    address_version: int = 0x3A  # Base58Check version byte

    def __post_init__(self) -> None:
        if not (0 < self.initial_target <= self.pow_limit < (1 << 256)):
            raise ValueError("require 0 < initial_target <= pow_limit < 2^256")
        if self.halving_interval < 1 or self.retarget_window < 2:
            raise ValueError("halving_interval >= 1 and retarget_window >= 2 required")
        if self.damping < 1 or self.clamp_factor < 1:
            raise ValueError("damping and clamp_factor must be >= 1")

    # Theoretical (real-number) maximum supply: sum_k R0*H/2^k = 2*R0*H.
    @property
    def max_money(self) -> int:
        return 2 * self.initial_reward * self.halving_interval

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @property
    def magic(self) -> bytes:
        return hashlib.sha256(b"QUANTIS/net/v1" + self.canonical_json().encode()).digest()[:4]


DEVNET = NetworkParams(name="devnet")

# Regtest: trivial proof of work and short eras so automated tests run in milliseconds.
REGTEST = NetworkParams(
    name="regtest",
    initial_reward=1000 * COIN,
    halving_interval=10,
    coinbase_maturity=3,
    target_block_time=15,
    retarget_window=5,
    damping=4,
    max_future_drift=60,
    pow_limit=(1 << 255) - 1,
    initial_target=(1 << 255) - 1,
)

NETWORKS = {p.name: p for p in (DEVNET, REGTEST)}


def get_network(name: str) -> NetworkParams:
    try:
        return NETWORKS[name]
    except KeyError:
        raise ValueError(f"unknown network {name!r}; choose one of {sorted(NETWORKS)}") from None
