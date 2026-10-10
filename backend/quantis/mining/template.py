"""Block template construction and a simple single-process nonce search."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..core.block import Block, BlockHeader
from ..core.chainstate import ChainState
from ..core.mempool import Mempool
from ..core.merkle import merkle_root
from ..core.monetary import block_subsidy
from ..core.tx import TxOut, make_coinbase

COINBASE_RESERVE = 300  # bytes reserved for header, tx count and coinbase


@dataclass
class Template:
    header: BlockHeader  # nonce = 0
    txs: list
    subsidy: int
    fees: int

    def block_with_nonce(self, nonce: int) -> Block:
        return Block(header=self.header.with_nonce(nonce), txs=self.txs)


def build_template(chain: ChainState, mempool: Mempool | None, payout_h20: bytes, now: int | None = None,
                   extra: bytes = b"") -> Template:
    p = chain.p
    prev = chain.tip
    height = prev.height + 1
    now = int(time.time()) if now is None else now
    timestamp = max(now, chain.mtp(prev) + 1)
    entries = mempool.select(p.max_block_bytes - COINBASE_RESERVE) if mempool else []
    fees = sum(e.fee for e in entries)
    subsidy = block_subsidy(height, p)
    reward = subsidy + fees
    cb = make_coinbase(height, [TxOut(reward, payout_h20)] if reward > 0 else [], extra[:92])
    txs = [cb] + [e.tx for e in entries]
    header = BlockHeader(
        version=1,
        height=height,
        prev_hash=prev.hash,
        merkle_root=merkle_root([t.txid for t in txs]),
        timestamp=timestamp,
        target=chain.next_target(prev),
        nonce=0,
    )
    return Template(header, txs, subsidy, fees)


def solve(template: Template, max_tries: int = 1 << 32) -> Block:
    """Single-threaded nonce search using a precomputed SHA-256 midstate."""
    import hashlib

    prefix = hashlib.sha256(template.header.prefix())
    target = template.header.target
    for nonce in range(max_tries):
        h = prefix.copy()
        h.update(nonce.to_bytes(8, "little"))
        if int.from_bytes(hashlib.sha256(h.digest()).digest(), "big") <= target:
            return template.block_with_nonce(nonce)
    raise RuntimeError("nonce space exhausted")
