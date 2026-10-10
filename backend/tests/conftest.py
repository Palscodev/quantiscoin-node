from __future__ import annotations

import pytest

from quantis.core.address import pubkey_to_address
from quantis.core.chainstate import ChainState
from quantis.core.crypto import PrivateKey
from quantis.core.fees import FeePolicy
from quantis.core.hashing import hash20
from quantis.core.mempool import Mempool
from quantis.core.params import REGTEST
from quantis.core.tx import Tx, TxIn, TxOut
from quantis.mining.template import build_template, solve
from quantis.storage.db import Database

NOW = REGTEST.genesis_timestamp + 10_000_000


class Key:
    def __init__(self, secret: int, p=REGTEST) -> None:
        self.priv = PrivateKey(secret)
        self.pub = self.priv.public_key()
        self.h20 = hash20(self.pub)
        self.address = pubkey_to_address(self.pub, p.address_version)


class Harness:
    """A regtest chain + mempool with helpers to mine blocks and build signed transactions."""

    def __init__(self, path, params=REGTEST) -> None:
        self.p = params
        self.path = path
        self.db = Database(path)
        self.chain = ChainState(self.db, params, clock=lambda: NOW)
        self.mempool = Mempool(self.chain, FeePolicy(base_rate=10), max_bytes=200_000)

    def reopen(self) -> "Harness":
        self.db.close()
        return Harness(self.path, self.p)

    def next_ts(self, gap: int | None = None) -> int:
        return self.chain.tip.timestamp + (self.p.target_block_time if gap is None else gap)

    def template(self, h20: bytes, ts: int | None = None, use_mempool: bool = True, extra: bytes = b""):
        return build_template(self.chain, self.mempool if use_mempool else None, h20,
                              now=ts if ts is not None else self.next_ts(), extra=extra)

    def mine(self, h20: bytes, n: int = 1, gap: int | None = None, use_mempool: bool = True):
        blocks = []
        for _ in range(n):
            blk = solve(self.template(h20, self.next_ts(gap), use_mempool))
            res = self.chain.process_block(blk, NOW)
            assert res.status == "connected", (res.status, res.reason)
            for b in res.connected:
                self.mempool.remove_for_block(b)
            blocks.append(blk)
        return blocks

    def spend(self, key: Key, outpoints: list[tuple[bytes, int]], outputs: list[tuple[bytes, int]]) -> Tx:
        tx = Tx(inputs=[TxIn(t, v, key.pub) for t, v in outpoints], outputs=[TxOut(a, h) for h, a in outputs])
        d = tx.sighash(self.p.magic)
        for i in tx.inputs:
            i.sig = key.priv.sign(d)
        tx.invalidate_cache()
        return tx


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path / "chain.sqlite3")
    yield h
    h.db.close()


@pytest.fixture
def alice():
    return Key(0xA11CE)


@pytest.fixture
def bob():
    return Key(0xB0B)
