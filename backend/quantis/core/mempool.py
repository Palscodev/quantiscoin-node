"""Memory pool of valid unconfirmed transactions.

Rules:
  * Every tx must pass full consensus checks against (UTXO set + mempool outputs),
    evaluated as if it were included in the next block (height = tip + 1).
  * No two mempool txs may spend the same outpoint (first seen wins; no replacement).
  * Relay policy fee: fee >= size * FeePolicy.rate(current mempool bytes).
  * Bounded size: when full, the lowest fee-rate tx (and its descendants) is evicted
    if the newcomer pays a strictly higher rate; otherwise the newcomer is rejected.
Block template selection orders by fee rate (descending, exact rational compare),
then txid (ascending), and only includes a tx after all its mempool parents.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from fractions import Fraction

from .chainstate import ChainState
from .fees import FeePolicy, feerate_key
from .tx import Tx
from .validation import Utxo, ValidationError, check_tx_inputs, check_tx_syntax


@dataclass
class MempoolEntry:
    tx: Tx
    fee: int
    size: int
    time: int

    @property
    def feerate(self) -> Fraction:
        return Fraction(self.fee, self.size)


class Mempool:
    def __init__(self, chain: ChainState, policy: FeePolicy, max_bytes: int = 256_000) -> None:
        self.chain = chain
        self.policy = policy
        self.max_bytes = max_bytes
        self.entries: dict[bytes, MempoolEntry] = {}
        self.spends: dict[tuple[bytes, int], bytes] = {}  # outpoint -> spending txid
        self.bytes = 0

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.entries

    def lookup(self, op: tuple[bytes, int]) -> Utxo | None:
        """UTXO view = chain UTXO set + mempool outputs, minus outputs spent in the mempool."""
        if op in self.spends:
            return None
        parent = self.entries.get(op[0])
        if parent is not None:
            if op[1] < len(parent.tx.outputs):
                o = parent.tx.outputs[op[1]]
                return Utxo(o.amount, o.h20, self.chain.height + 1, False)
            return None
        return self.chain.get_utxo(op)

    def lookup_spent_prevout(self, op: tuple[bytes, int]) -> Utxo | None:
        """The output referenced by a pending input (ignores the fact that it is being spent)."""
        parent = self.entries.get(op[0])
        if parent is not None:
            if op[1] < len(parent.tx.outputs):
                o = parent.tx.outputs[op[1]]
                return Utxo(o.amount, o.h20, self.chain.height + 1, False)
            return None
        return self.chain.get_utxo(op)

    def min_fee(self, size: int) -> int:
        return self.policy.min_fee(size, self.bytes)

    def accept(self, tx: Tx, enforce_policy: bool = True) -> MempoolEntry:
        txid = tx.txid
        if txid in self.entries:
            raise ValidationError("txn-already-in-mempool")
        if self.chain.tx_location(txid) is not None:
            raise ValidationError("txn-already-confirmed", "transaction is already in the chain (replay)")
        if tx.is_coinbase():
            raise ValidationError("txn-coinbase", "coinbase transactions are only valid in blocks")
        check_tx_syntax(tx, self.chain.p)
        for i in tx.inputs:
            if i.outpoint in self.spends:
                raise ValidationError("txn-mempool-conflict", "input already spent by a pending transaction")
        fee = check_tx_inputs(tx, self.lookup, self.chain.height + 1, self.chain.p)
        size = tx.size
        if enforce_policy:
            need = self.min_fee(size)
            if fee < need:
                raise ValidationError("txn-fee-below-policy", f"fee {fee} below relay minimum {need}")
            self._make_room(size, Fraction(fee, size))
        entry = MempoolEntry(tx, fee, size, int(time.time()))
        self.entries[txid] = entry
        for i in tx.inputs:
            self.spends[i.outpoint] = txid
        self.bytes += size
        return entry

    def _make_room(self, size: int, rate: Fraction) -> None:
        while self.bytes + size > self.max_bytes:
            if not self.entries:
                raise ValidationError("txn-too-large-for-mempool")
            worst = min(self.entries.values(), key=lambda e: (e.feerate, -e.time))
            if worst.feerate >= rate:
                raise ValidationError("mempool-full", "fee rate too low to displace pending transactions")
            self.remove(worst.tx.txid, with_descendants=True)

    def remove(self, txid: bytes, with_descendants: bool = True) -> None:
        entry = self.entries.pop(txid, None)
        if entry is None:
            return
        self.bytes -= entry.size
        for i in entry.tx.inputs:
            if self.spends.get(i.outpoint) == txid:
                del self.spends[i.outpoint]
        if with_descendants:
            for n in range(len(entry.tx.outputs)):
                child = self.spends.get((txid, n))
                if child:
                    self.remove(child, True)

    def remove_for_block(self, block) -> None:
        """Drop txs confirmed by `block` and any tx that now conflicts with it."""
        for t in block.txs[1:]:
            if t.txid in self.entries:
                self.remove(t.txid, with_descendants=False)
            for i in t.inputs:
                other = self.spends.get(i.outpoint)
                if other and other != t.txid:
                    self.remove(other, with_descendants=True)

    def rebuild(self, extra: list[Tx] = ()) -> None:
        """Re-validate everything against the current tip (used after a reorg)."""
        old = sorted(self.entries.values(), key=lambda e: e.time)
        candidates = list(extra) + [e.tx for e in old]
        self.entries.clear()
        self.spends.clear()
        self.bytes = 0
        pending = candidates
        progress = True
        while pending and progress:  # repeat so parents are admitted before children
            progress, retry = False, []
            for t in pending:
                try:
                    self.accept(t, enforce_policy=False)
                    progress = True
                except ValidationError as e:
                    if e.code == "tx-missing-input":
                        retry.append(t)
            pending = retry

    def select(self, max_bytes: int) -> list[MempoolEntry]:
        ordered = sorted(self.entries.values(), key=lambda e: feerate_key(e.fee, e.size, e.tx.txid))
        chosen: list[MempoolEntry] = []
        chosen_ids: set[bytes] = set()
        used = 0
        progress = True
        while progress:
            progress = False
            for e in ordered:
                tid = e.tx.txid
                if tid in chosen_ids or used + e.size > max_bytes:
                    continue
                if any(i.prev_txid in self.entries and i.prev_txid not in chosen_ids for i in e.tx.inputs):
                    continue  # parent not yet selected
                chosen.append(e)
                chosen_ids.add(tid)
                used += e.size
                progress = True
        return chosen
