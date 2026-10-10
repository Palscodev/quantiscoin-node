"""Node: wires chain state, mempool, wallets, miner, peers and the event bus.

All mutation of chain state and mempool happens while holding `Node.lock`.
"""
from __future__ import annotations

import logging
import threading
import time

from .api.events import EventBus
from .auth import Accounts
from .config import NodeConfig
from .core.block import Block
from .core.chainstate import ChainState, ProcessResult
from .core.fees import FeePolicy
from .core.mempool import Mempool
from .core.difficulty import first_retarget_height
from .core.monetary import (
    realized_supply,
    block_subsidy,
    blocks_until_next_halving,
    cumulative_issuance,
    reward_era,
)
from .core.params import SOFTWARE_VERSION, get_network
from .core.tx import Tx
from .core.validation import ValidationError
from .mining.miner import Miner
from .mining.template import Template, build_template
from .mining.webjobs import WebJobs
from .p2p.peers import PeerManager
from .storage.db import Database
from .wallet.wallet import WalletService

log = logging.getLogger("quantis.node")


def next_retarget_height(height: int, p) -> int:
    """Height of the next block at which difficulty will be recalculated."""
    first = first_retarget_height(p)
    nxt = height + 1
    if nxt <= first:
        return first
    w = p.retarget_window
    return -(-nxt // w) * w


class Node:
    def __init__(self, config: NodeConfig, clock=time.time) -> None:
        self.config = config
        self.params = get_network(config.network)
        self.clock = clock
        self.lock = threading.RLock()
        self.db = Database(config.db_path)
        self.chain = ChainState(self.db, self.params, clock)
        self.mempool = Mempool(
            self.chain,
            FeePolicy(config.relay_base_rate, config.relay_max_multiplier, config.relay_target_bytes),
            config.mempool_max_bytes,
        )
        self.wallets = WalletService(self.db, self.chain, self.mempool)
        self.accounts = Accounts(self.db, config.session_days)
        self.events = EventBus()
        self.miner = Miner(self)
        self.peers = PeerManager(self)
        self.webjobs = WebJobs(self)
        self.started_at = time.time()
        self._restore_mempool()

    # ------------------------------------------------------------ mempool
    def persist_mempool(self) -> None:
        """Save pending transactions so a restart does not drop them (like Bitcoin's mempool.dat)."""
        with self.lock, self.db.transaction():
            self.db.execute("DELETE FROM mempool_txs")
            self.db.executemany(
                "INSERT INTO mempool_txs VALUES (?, ?, ?)",
                [(txid, e.tx.serialize(), e.time) for txid, e in self.mempool.entries.items()],
            )

    def _restore_mempool(self) -> None:
        rows = self.db.all("SELECT raw FROM mempool_txs ORDER BY received")
        if not rows:
            return
        with self.lock:
            self.mempool.rebuild(extra=[Tx.deserialize(r[0]) for r in rows])
        log.info("restored %d of %d pending transactions", len(self.mempool), len(rows))
        self.persist_mempool()

    # ----------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.peers.start()

    def shutdown(self) -> None:
        self.miner.stop()
        self.peers.stop()
        self.db.close()

    # ----------------------------------------------------------- ingestion
    def submit_block(self, block: Block, source: str = "local") -> ProcessResult:
        t_wait = time.perf_counter()
        with self.lock:
            t_start = time.perf_counter()
            res = self.chain.process_block(block, int(self.clock()))
            if res.status == "connected":
                if res.disconnected:
                    self.mempool.rebuild(extra=[t for b in res.disconnected for t in b.txs[1:]])
                else:
                    for b in res.connected:
                        self.mempool.remove_for_block(b)
        took, waited = time.perf_counter() - t_start, t_start - t_wait
        if took > 1.0 or waited > 1.0:
            log.warning("slow block processing: waited %.2fs for lock, processed in %.2fs (%s from %s)",
                        waited, took, res.status, source)
        if res.status == "connected":
            self.persist_mempool()
            if res.disconnected:
                log.info("reorg: disconnected %d, connected %d", len(res.disconnected), len(res.connected))
                self.events.publish(
                    "reorg",
                    {"disconnected": [b.hash.hex() for b in res.disconnected], "connected": [b.hash.hex() for b in res.connected]},
                )
            for b in res.connected:
                self.events.publish("block", {"height": b.header.height, "hash": b.hash.hex(), "n_tx": len(b.txs)})
            self.events.publish("status", self.status())
        if res.accepted:
            self.peers.broadcast_block(block, exclude=source)
        return res

    def submit_tx(self, tx: Tx, source: str = "local"):
        with self.lock:
            entry = self.mempool.accept(tx)
            self.persist_mempool()
        self.events.publish("tx", {"txid": tx.txid.hex(), "fee": entry.fee, "size": entry.size})
        self.peers.broadcast_tx(tx, exclude=source)
        return entry

    def build_template(self, payout_h20: bytes, extra: bytes | None = None) -> Template:
        with self.lock:
            return build_template(self.chain, self.mempool, payout_h20, int(self.clock()),
                                  extra=extra if extra is not None else b"QuantisCoin/" + SOFTWARE_VERSION.encode())

    # ------------------------------------------------------- display price
    @property
    def usd_price(self) -> float:
        """Reference USD price per QTS, set by the node operator. NOT a market price."""
        try:
            return max(0.0, float(self.db.get_meta("usd_price") or 0))
        except ValueError:
            return 0.0

    def set_usd_price(self, value: float) -> None:
        if not (0 <= value <= 1e9):
            raise ValueError("price must be between 0 and 1,000,000,000")
        self.db.set_meta("usd_price", repr(float(value)))
        self.events.publish("status", self.status())

    # -------------------------------------------------------------- status
    def observed_interval(self, window: int | None = None) -> float | None:
        # The genesis timestamp is a fixed constant, so the genesis->block-1 gap is
        # not a real interval; measure only between mined blocks (heights >= 1).
        chain = self.chain
        n = min(window or self.params.retarget_window, chain.height - 1)
        if n < 1:
            return None
        newest = chain.active[chain.height].timestamp
        oldest = chain.active[chain.height - n].timestamp
        return (newest - oldest) / n

    def status(self) -> dict:
        with self.lock:
            chain, p = self.chain, self.params
            tip = chain.tip
            height = chain.height
            next_height = height + 1
            target = chain.next_target()
            return {
                "network": p.name,
                "magic": p.magic.hex(),
                "version": SOFTWARE_VERSION,
                "height": height,
                "tip": tip.hash.hex(),
                "tip_time": tip.timestamp,
                "chainwork": f"{tip.chainwork:x}",
                "next_target": f"{target:064x}",
                "difficulty": p.pow_limit / target,
                "target_block_time": p.target_block_time,
                "observed_block_time": self.observed_interval(),
                "reward_era": reward_era(next_height, p),
                "current_reward": block_subsidy(next_height, p),
                "next_reward": block_subsidy(next_height + blocks_until_next_halving(height, p), p),
                "blocks_until_halving": blocks_until_next_halving(height, p),
                "issued": cumulative_issuance(height, p),
                "mempool_count": len(self.mempool),
                "mempool_bytes": self.mempool.bytes,
                "relay_fee_rate": self.mempool.policy.rate(self.mempool.bytes),
                "peers": self.peers.connected_count(),
                "mining": self.miner.state,
                "hashrate": self.miner.hashrate,
                "uptime": time.time() - self.started_at,
                "median_time_past": chain.mtp(tip),
                "usd_price": self.usd_price,
                "node_repo_url": self.config.node_repo_url,
                "public_p2p_url": self.config.public_p2p_url,
                "coinbase_maturity": p.coinbase_maturity,
                "halving_interval": p.halving_interval,
                "retarget_window": p.retarget_window,
                "initial_reward": p.initial_reward,
                "max_supply": realized_supply(p),
                "next_retarget_height": next_retarget_height(height, p),
                "users": self.accounts.count(),
            }
