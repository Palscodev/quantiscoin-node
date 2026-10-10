"""Transaction root (domain-separated Merkle tree).

  leaf(txid)  = SHA-256d(0x00 || txid)
  node(L, R)  = SHA-256d(0x01 || L || R)

Each level pairs adjacent nodes left to right. If a level has an odd number of
nodes, the last node is promoted unchanged to the next level (it is NOT
duplicated, which avoids the Bitcoin CVE-2012-2459 ambiguity where two different
transaction lists can share one root). The leaf/node tags prevent a 64-byte
transaction from being confused with an interior node.
"""
from __future__ import annotations

from .hashing import sha256d


def merkle_root(txids: list[bytes]) -> bytes:
    if not txids:
        raise ValueError("a block always contains at least the coinbase")
    level = [sha256d(b"\x00" + t) for t in txids]
    while len(level) > 1:
        nxt = [sha256d(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]
