"""Deterministic genesis block.

The genesis block is fully determined by NetworkParams: fixed timestamp, a
coinbase with no outputs (genesis issues nothing), target = pow_limit, and the
smallest nonce >= 0 that satisfies the proof of work. Every node recomputes it,
so independent nodes agree on the genesis hash without any shared files.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache

from .block import Block, BlockHeader
from .merkle import merkle_root
from .params import NetworkParams
from .tx import make_coinbase


# sha256(header prefix) -> smallest valid nonce, for networks whose genesis is slow to search.
KNOWN_NONCES: dict[str, int] = {
    "e5789173cd36e907d645bbfc8ccf4f7a60cb8f8e15b9c2813a1844102c3280bf": 113177371,  # devnet (restarted 2026-10-12, 30-minute blocks)
}


@lru_cache(maxsize=8)
def genesis_block(p: NetworkParams) -> Block:
    cb = make_coinbase(0, [], p.genesis_message.encode()[:92])
    header = BlockHeader(
        version=1,
        height=0,
        prev_hash=b"\0" * 32,
        merkle_root=merkle_root([cb.txid]),
        timestamp=p.genesis_timestamp,
        target=p.pow_limit,
        nonce=0,
    )
    # Smallest nonce that satisfies the proof of work (SHA-256 midstate for speed).
    # Known results are cached below so nodes start instantly; they are still verified
    # (meets_target), and any other parameters fall back to the search.
    base = hashlib.sha256(header.prefix())
    target = header.target
    known = KNOWN_NONCES.get(hashlib.sha256(header.prefix()).hexdigest())
    if known is not None:
        block = Block(header=header.with_nonce(known), txs=[cb])
        if block.header.meets_target():
            return block
    nonce = 0
    while True:
        h = base.copy()
        h.update(nonce.to_bytes(8, "little"))
        if int.from_bytes(hashlib.sha256(h.digest()).digest(), "big") <= target:
            break
        nonce += 1
    block = Block(header=header.with_nonce(nonce), txs=[cb])
    assert block.header.meets_target()
    return block
