"""Consensus validation rules. Pure functions: no I/O, no global state.

Each check raises ValidationError with a short machine-readable code and a
human-readable message. Callers (chainstate, mempool) supply chain context.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from . import crypto
from .block import Block, BlockHeader
from .fees import consensus_min_fee
from .hashing import hash20
from .monetary import block_subsidy
from .params import NetworkParams
from .tx import NULL_TXID, Tx


class ValidationError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class Utxo:
    amount: int
    h20: bytes
    height: int
    coinbase: bool


UtxoLookup = Callable[[tuple[bytes, int]], Optional[Utxo]]


def _require(cond: bool, code: str, message: str = "") -> None:
    if not cond:
        raise ValidationError(code, message)


def check_tx_syntax(tx: Tx, p: NetworkParams) -> None:
    """Context-free checks applicable to every transaction."""
    _require(tx.version == 1, "tx-version", "unsupported transaction version")
    _require(len(tx.inputs) >= 1, "tx-no-inputs")
    _require(len(tx.inputs) <= p.max_tx_inputs, "tx-too-many-inputs")
    _require(len(tx.outputs) <= p.max_tx_outputs, "tx-too-many-outputs")
    _require(tx.size <= p.max_tx_bytes, "tx-oversize", f"{tx.size} > {p.max_tx_bytes} bytes")
    total = 0
    for o in tx.outputs:
        _require(len(o.h20) == 20, "tx-bad-output")
        _require(0 < o.amount <= p.max_money, "tx-amount-range", "output amount out of range")
        total += o.amount
        _require(total <= p.max_money, "tx-amount-range", "output total out of range")
    if tx.is_coinbase():
        _require(tx.inputs[0].pubkey == b"", "cb-pubkey", "coinbase input must have no pubkey")
        _require(8 <= len(tx.inputs[0].sig) <= 100, "cb-data", "coinbase data must hold the height")
    else:
        _require(len(tx.outputs) >= 1, "tx-no-outputs")
        seen = set()
        for i in tx.inputs:
            _require(i.prev_txid != NULL_TXID, "tx-null-input", "null prevout outside coinbase")
            _require(i.outpoint not in seen, "tx-duplicate-input", "input spent twice in one tx")
            seen.add(i.outpoint)
            _require(len(i.pubkey) == 33, "tx-bad-pubkey")
            _require(1 <= len(i.sig) <= 72, "tx-bad-sig-length")


def check_tx_inputs(tx: Tx, lookup: UtxoLookup, spend_height: int, p: NetworkParams) -> int:
    """Contextual checks for a non-coinbase tx. Returns the fee (>= 0)."""
    _require(not tx.is_coinbase(), "tx-unexpected-coinbase")
    digest = tx.sighash(p.magic)
    total_in = 0
    for idx, i in enumerate(tx.inputs):
        u = lookup(i.outpoint)
        _require(u is not None, "tx-missing-input", f"input {idx} spends an unknown or already spent output")
        if u.coinbase:
            depth = spend_height - u.height
            _require(
                depth >= p.coinbase_maturity,
                "tx-immature-coinbase",
                f"coinbase output has {depth} of {p.coinbase_maturity} required confirmations",
            )
        _require(hash20(i.pubkey) == u.h20, "tx-wrong-key", f"input {idx} pubkey does not match output address")
        _require(crypto.verify(i.pubkey, digest, i.sig), "tx-bad-signature", f"input {idx} signature invalid")
        total_in += u.amount
        _require(total_in <= p.max_money, "tx-amount-range", "input total out of range")
    fee = total_in - tx.total_out()
    _require(fee >= 0, "tx-insufficient-funds", "outputs exceed inputs")
    _require(
        fee >= consensus_min_fee(tx.size, p.min_fee_per_byte),
        "tx-fee-below-floor",
        f"fee {fee} below consensus floor {consensus_min_fee(tx.size, p.min_fee_per_byte)}",
    )
    return fee


def check_block_syntax(block: Block, p: NetworkParams) -> None:
    """Context-free block checks (no chain state needed)."""
    h = block.header
    _require(h.version == 1, "blk-version")
    _require(block.size <= p.max_block_bytes, "blk-oversize", f"{block.size} > {p.max_block_bytes} bytes")
    _require(0 < h.target <= p.pow_limit, "blk-target-range")
    _require(h.meets_target(), "blk-pow", "hash does not meet the header target")
    _require(len(block.txs) >= 1 and block.txs[0].is_coinbase(), "blk-no-coinbase")
    _require(all(not t.is_coinbase() for t in block.txs[1:]), "blk-multiple-coinbase")
    _require(block.txs[0].coinbase_height() == h.height, "blk-coinbase-height")
    txids = [t.txid for t in block.txs]
    _require(len(set(txids)) == len(txids), "blk-duplicate-tx")
    _require(block.compute_merkle_root() == h.merkle_root, "blk-merkle", "transaction root mismatch")
    for t in block.txs:
        check_tx_syntax(t, p)


def check_header_context(
    header: BlockHeader, prev_height: int, expected: int, mtp_prev: int, now: int, p: NetworkParams
) -> None:
    _require(header.height == prev_height + 1, "blk-height", "height must be parent height + 1")
    _require(header.target == expected, "blk-bad-target", "target differs from the difficulty rule")
    _require(header.timestamp > mtp_prev, "blk-time-too-old", "timestamp not after median time past")
    _require(header.timestamp <= now + p.max_future_drift, "blk-time-too-new", "timestamp too far in the future")


def connect_block_txs(block: Block, lookup: UtxoLookup, p: NetworkParams) -> tuple[int, list[tuple[tuple[bytes, int], Utxo]], dict]:
    """Validate all transactions against a UTXO view in block order.

    Returns (total_fees, spent, created) where `spent` lists consumed outputs (undo
    data) and `created` maps new outpoints to Utxo. Outputs created earlier in the
    same block may be spent later in it.
    """
    height = block.header.height
    created: dict[tuple[bytes, int], Utxo] = {}
    spent_set: set[tuple[bytes, int]] = set()
    spent: list[tuple[tuple[bytes, int], Utxo]] = []

    def view(op):
        if op in spent_set:
            return None
        if op in created:
            return created[op]
        return lookup(op)

    fees = 0
    for t in block.txs[1:]:
        fee = check_tx_inputs(t, view, height, p)
        fees += fee
        for i in t.inputs:
            spent.append((i.outpoint, view(i.outpoint)))
            spent_set.add(i.outpoint)
        for n, o in enumerate(t.outputs):
            created[(t.txid, n)] = Utxo(o.amount, o.h20, height, False)
    cb = block.txs[0]
    allowed = block_subsidy(height, p) + fees
    _require(cb.total_out() <= allowed, "blk-bad-reward", f"coinbase pays {cb.total_out()} > allowed {allowed}")
    for n, o in enumerate(cb.outputs):
        created[(cb.txid, n)] = Utxo(o.amount, o.h20, height, True)
    return fees, spent, created
