"""Read-only views over chain data used by the API (explorer, wallet history)."""
from __future__ import annotations

from .core import crypto
from .core.address import encode_address
from .core.block import Block
from .core.chainstate import ChainState
from .core.mempool import Mempool
from .core.fees import fee_burn
from .core.monetary import block_subsidy
from .core.tx import Tx
from .core.hashing import hash20


def addr(h20: bytes, chain: ChainState) -> str:
    return encode_address(h20, chain.p.address_version)


def resolve_prevout(chain: ChainState, mempool: Mempool | None, txid: bytes, vout: int):
    """Find the output an input spends, from the chain (spent or not) or the mempool."""
    found = chain.get_tx(txid)
    if found is not None:
        tx = found[0]
    elif mempool is not None and txid in mempool.entries:
        tx = mempool.entries[txid].tx
    else:
        return None
    return tx.outputs[vout] if vout < len(tx.outputs) else None


def tx_view(chain: ChainState, mempool: Mempool | None, tx: Tx, height: int | None, block_hash: bytes | None) -> dict:
    coinbase = tx.is_coinbase()
    digest = tx.sighash(chain.p.magic)
    inputs, total_in, all_sigs_ok = [], 0, True
    for i in tx.inputs:
        if coinbase:
            inputs.append({"coinbase": True, "data": i.sig.hex()})
            continue
        prev = resolve_prevout(chain, mempool, i.prev_txid, i.vout)
        sig_ok = crypto.verify(i.pubkey, digest, i.sig) and prev is not None and hash20(i.pubkey) == prev.h20
        all_sigs_ok &= sig_ok
        if prev is not None:
            total_in += prev.amount
        inputs.append(
            {
                "coinbase": False,
                "prev_txid": i.prev_txid.hex(),
                "vout": i.vout,
                "address": addr(prev.h20, chain) if prev else None,
                "amount": prev.amount if prev else None,
                "pubkey": i.pubkey.hex(),
                "signature_valid": sig_ok,
            }
        )
    outputs = [{"n": n, "address": addr(o.h20, chain), "amount": o.amount} for n, o in enumerate(tx.outputs)]
    total_out = tx.total_out()
    confirmations = chain.height - height + 1 if height is not None else 0
    return {
        "txid": tx.txid.hex(),
        "coinbase": coinbase,
        "size": tx.size,
        "inputs": inputs,
        "outputs": outputs,
        "total_out": total_out,
        "fee": 0 if coinbase else total_in - total_out,
        "signatures_valid": True if coinbase else all_sigs_ok,
        "height": height,
        "block_hash": block_hash.hex() if block_hash else None,
        "confirmations": confirmations,
        "status": "confirmed" if height is not None else "pending",
    }


def block_summary(chain: ChainState, height: int) -> dict:
    idx = chain.active[height]
    row = chain.db.one("SELECT n_tx, size, fees FROM blocks WHERE hash=?", (idx.hash,))
    interval = idx.timestamp - chain.active[height - 1].timestamp if height > 1 else None  # genesis time is fixed
    return {
        "height": height,
        "hash": idx.hash.hex(),
        "timestamp": idx.timestamp,
        "interval": interval,
        "n_tx": row[0],
        "size": row[1],
        "fees": row[2] or 0,
        "burned": fee_burn(row[2] or 0, chain.p),
        "subsidy": block_subsidy(height, chain.p),
        "target": f"{idx.target:064x}",
        "difficulty": chain.p.pow_limit / idx.target,
    }


def block_view(chain: ChainState, block: Block) -> dict:
    h = block.header
    idx = chain.index.get(block.hash)
    active = idx is not None and chain.is_active(idx)
    row = chain.db.one("SELECT fees, size FROM blocks WHERE hash=?", (block.hash,))
    return {
        "hash": block.hash.hex(),
        "height": h.height,
        "prev_hash": h.prev_hash.hex(),
        "next_hash": chain.active[h.height + 1].hash.hex() if active and h.height < chain.height else None,
        "merkle_root": h.merkle_root.hex(),
        "timestamp": h.timestamp,
        "target": f"{h.target:064x}",
        "difficulty": chain.p.pow_limit / h.target,
        "nonce": h.nonce,
        "version": h.version,
        "size": row[1] if row else block.size,
        "subsidy": block_subsidy(h.height, chain.p),
        "fees": (row[0] or 0) if row else 0,
        "burned": fee_burn((row[0] or 0) if row else 0, chain.p),
        "reward_paid": block.txs[0].total_out(),
        "chainwork": f"{idx.chainwork:x}" if idx else None,
        "active": active,
        "confirmations": chain.height - h.height + 1 if active else 0,
        "txs": [
            {"txid": t.txid.hex(), "coinbase": t.is_coinbase(), "total_out": t.total_out(), "size": t.size}
            for t in block.txs
        ],
    }
