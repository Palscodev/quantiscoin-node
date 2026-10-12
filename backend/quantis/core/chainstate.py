"""Chain state: block index, active chain, UTXO set, reorganizations.

Chain selection rule: the active chain is the valid chain with the greatest
cumulative work, sum over blocks of floor(2^256 / (target + 1)). On equal work the
chain seen first is kept. Block count alone never decides.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from typing import Optional

from ..storage.db import Database
from .block import Block
from .difficulty import expected_target, median_time_past
from .encoding import Reader, u32, u64, varint
from .genesis import genesis_block
from .hashing import work_from_target
from .monetary import block_subsidy
from .params import NetworkParams
from .tx import Tx
from .validation import (
    Utxo,
    ValidationError,
    check_block_syntax,
    check_header_context,
    connect_block_txs,
)

STATUS_VALID = 1  # stored; syntax and header context valid; may or may not be active
STATUS_INVALID = 2  # failed full validation while connecting
MAX_ORPHANS = 64


class BlockIndex:
    __slots__ = ("hash", "prev_hash", "height", "timestamp", "target", "chainwork", "status", "parent")

    def __init__(self, hash, prev_hash, height, timestamp, target, chainwork, status, parent):
        self.hash = hash
        self.prev_hash = prev_hash
        self.height = height
        self.timestamp = timestamp
        self.target = target
        self.chainwork = chainwork
        self.status = status
        self.parent: Optional[BlockIndex] = parent


@dataclass
class ProcessResult:
    status: str  # connected | side | duplicate | orphan | invalid
    reason: str = ""
    connected: list[Block] = field(default_factory=list)
    disconnected: list[Block] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.status in ("connected", "side")


def _encode_undo(spent: list[tuple[tuple[bytes, int], Utxo]]) -> bytes:
    out = [varint(len(spent))]
    for (txid, vout), u in spent:
        out.append(txid + u32(vout) + u64(u.amount) + u.h20 + u64(u.height) + bytes([1 if u.coinbase else 0]))
    return b"".join(out)


def _decode_undo(data: bytes) -> list[tuple[tuple[bytes, int], Utxo]]:
    r = Reader(data)
    res = []
    for _ in range(r.varint()):
        txid, vout, amount, h20, height, cb = r.read(32), r.u32(), r.u64(), r.read(20), r.u64(), r.read(1)[0]
        res.append(((txid, vout), Utxo(amount, h20, height, bool(cb))))
    r.finish()
    return res


class ChainState:
    def __init__(self, db: Database, params: NetworkParams, clock=time.time) -> None:
        self.db = db
        self.p = params
        self.clock = clock
        self.index: dict[bytes, BlockIndex] = {}
        self.active: list[BlockIndex] = []
        self.orphans: dict[bytes, Block] = {}  # hash -> block whose parent is unknown
        self.rejected: set[bytes] = set()
        self._load()

    # ------------------------------------------------------------------ setup
    def _load(self) -> None:
        g = genesis_block(self.p)
        stored = self.db.get_meta("genesis")
        if stored is None:
            self._init_genesis(g)
        elif stored != g.hash.hex():
            raise RuntimeError(
                "data directory belongs to a different network (genesis mismatch). If the network was "
                "restarted, run:  python -m quantis reset-chain --config <your config> --yes  (keeps all accounts)")
        rows = self.db.all("SELECT hash, prev, height, timestamp, target, chainwork, status FROM blocks ORDER BY height")
        for h, prev, height, ts, target, work, status in rows:
            parent = self.index.get(prev)
            if height > 0 and parent is None:
                continue  # unreachable (should not happen)
            self.index[h] = BlockIndex(
                h, prev, height, ts, int.from_bytes(target, "big"), int.from_bytes(work, "big"), status, parent
            )
        for height, h in self.db.all("SELECT height, hash FROM active ORDER BY height"):
            if height != len(self.active):
                raise RuntimeError("active chain table is corrupt")
            self.active.append(self.index[h])

    def _init_genesis(self, g: Block) -> None:
        work = work_from_target(g.header.target)
        with self.db.transaction():
            self._store_block(g, work, STATUS_VALID)
            self.db.execute("UPDATE blocks SET fees=0 WHERE hash=?", (g.hash,))
            self.db.execute("INSERT INTO active VALUES (0, ?)", (g.hash,))
            self.db.execute("INSERT INTO txindex VALUES (?, ?, 0, 0)", (g.txs[0].txid, g.hash))
            self.db.execute("INSERT INTO undo VALUES (?, ?)", (g.hash, _encode_undo([])))
            self.db.set_meta("genesis", g.hash.hex())
            self.db.set_meta("network", self.p.name)

    def _store_block(self, block: Block, chainwork: int, status: int) -> None:
        h = block.header
        self.db.execute(
            "INSERT INTO blocks (hash, prev, height, timestamp, target, chainwork, status, n_tx, size, fees, received, raw)"
            " VALUES (?,?,?,?,?,?,?,?,?,NULL,?,?)",
            (
                block.hash,
                h.prev_hash,
                h.height,
                h.timestamp,
                h.target.to_bytes(32, "big"),
                chainwork.to_bytes(40, "big"),
                status,
                len(block.txs),
                block.size,
                int(self.clock()),
                block.serialize(),
            ),
        )

    # ---------------------------------------------------------------- queries
    @property
    def tip(self) -> BlockIndex:
        return self.active[-1]

    @property
    def height(self) -> int:
        return len(self.active) - 1

    def is_active(self, idx: BlockIndex) -> bool:
        return idx.height < len(self.active) and self.active[idx.height] is idx

    def ancestor(self, idx: BlockIndex, height: int) -> BlockIndex:
        if height > idx.height or height < 0:
            raise ValueError("ancestor height out of range")
        cur = idx
        while cur.height > height:
            if self.is_active(cur):
                return self.active[height]
            cur = cur.parent
        return cur

    def mtp(self, idx: BlockIndex) -> int:
        return median_time_past(idx, self.ancestor, self.p.mtp_span)

    def next_target(self, prev: BlockIndex | None = None) -> int:
        return expected_target(prev or self.tip, self.ancestor, self.p)

    def get_block(self, h: bytes) -> Block | None:
        row = self.db.one("SELECT raw FROM blocks WHERE hash=?", (h,))
        return Block.deserialize(row[0]) if row else None

    def get_utxo(self, op: tuple[bytes, int]) -> Utxo | None:
        row = self.db.one("SELECT amount, h20, height, coinbase FROM utxo WHERE txid=? AND vout=?", op)
        return Utxo(row[0], row[1], row[2], bool(row[3])) if row else None

    def has_block(self, h: bytes) -> bool:
        return h in self.index or h in self.orphans

    # ------------------------------------------------------------- processing
    def process_block(self, block: Block, now: int | None = None) -> ProcessResult:
        result = self._process_one(block, now)
        if result.accepted:
            # connect any orphans that were waiting for this block (iteratively)
            queue = [block.hash]
            while queue:
                parent = queue.pop()
                children = [b for b in self.orphans.values() if b.header.prev_hash == parent]
                for child in children:
                    del self.orphans[child.hash]
                    r = self._process_one(child, now)
                    if r.accepted:
                        result.connected += r.connected
                        result.disconnected += r.disconnected
                        if r.status == "connected":
                            result.status = "connected"
                        queue.append(child.hash)
        return result

    def _process_one(self, block: Block, now: int | None) -> ProcessResult:
        now = int(self.clock()) if now is None else now
        h = block.hash
        if h in self.index:
            st = self.index[h].status
            return ProcessResult("invalid" if st == STATUS_INVALID else "duplicate", "already known")
        if h in self.rejected:
            return ProcessResult("invalid", "previously rejected")
        prev = self.index.get(block.header.prev_hash)
        if prev is None:
            try:
                check_block_syntax(block, self.p)  # do not hold junk as orphans
            except ValidationError as e:
                return ProcessResult("invalid", e.code)
            if len(self.orphans) >= MAX_ORPHANS:
                self.orphans.pop(next(iter(self.orphans)))
            self.orphans[h] = block
            return ProcessResult("orphan", "parent unknown")
        if prev.status == STATUS_INVALID:
            self.rejected.add(h)
            return ProcessResult("invalid", "bad-prevblk")
        try:
            check_block_syntax(block, self.p)
            check_header_context(
                block.header, prev.height, self.next_target(prev), self.mtp(prev), now, self.p
            )
        except ValidationError as e:
            if e.code != "blk-time-too-new":  # may become valid later; do not cache
                self.rejected.add(h)
            return ProcessResult("invalid", e.code)

        idx = BlockIndex(
            h, prev.hash, prev.height + 1, block.header.timestamp, block.header.target,
            prev.chainwork + work_from_target(block.header.target), STATUS_VALID, prev,
        )
        with self.db.transaction():
            self._store_block(block, idx.chainwork, STATUS_VALID)
        self.index[h] = idx
        if idx.chainwork > self.tip.chainwork:
            return self._activate(idx, block)
        return ProcessResult("side", "stored on a side chain with less cumulative work")

    def _activate(self, new_tip: BlockIndex, new_block: Block) -> ProcessResult:
        branch: list[BlockIndex] = []
        cur = new_tip
        while not self.is_active(cur):
            branch.append(cur)
            cur = cur.parent
        fork = cur
        branch.reverse()
        saved_active = list(self.active)
        disconnected: list[Block] = []
        connected: list[Block] = []
        failing = None
        try:
            with self.db.transaction():
                while self.tip is not fork:
                    disconnected.append(self._disconnect_tip())
                for idx in branch:
                    failing = idx
                    blk = new_block if idx is new_tip else self.get_block(idx.hash)
                    self._connect(idx, blk)
                    connected.append(blk)
        except ValidationError as e:
            self.active = saved_active
            self._mark_invalid(failing)
            return ProcessResult("invalid", e.code)
        return ProcessResult("connected", "", connected, disconnected)

    def _mark_invalid(self, bad: BlockIndex) -> None:
        bad_set = {bad.hash}
        for idx in sorted(self.index.values(), key=lambda i: i.height):
            if idx.parent is not None and idx.parent.hash in bad_set:
                bad_set.add(idx.hash)
        with self.db.transaction():
            for h in bad_set:
                self.index[h].status = STATUS_INVALID
                self.db.execute("UPDATE blocks SET status=? WHERE hash=?", (STATUS_INVALID, h))

    def _connect(self, idx: BlockIndex, block: Block) -> None:
        if idx.height != len(self.active) or idx.parent is not self.tip:
            raise RuntimeError("connect must extend the current tip")
        fees, spent, created = connect_block_txs(block, self.get_utxo, self.p)
        try:
            for (txid, vout), _ in spent:
                self.db.execute("DELETE FROM utxo WHERE txid=? AND vout=?", (txid, vout))
            self.db.executemany(
                "INSERT INTO utxo VALUES (?,?,?,?,?,?)",
                [(t, v, u.amount, u.h20, u.height, int(u.coinbase)) for (t, v), u in created.items()],
            )
            self.db.executemany(
                "INSERT INTO txindex VALUES (?,?,?,?)",
                [(t.txid, idx.hash, idx.height, pos) for pos, t in enumerate(block.txs)],
            )
        except sqlite3.IntegrityError as e:
            raise ValidationError("blk-duplicate-txid", "transaction id already exists") from e
        addr_rows = set()
        for t in block.txs:
            for o in t.outputs:
                addr_rows.add((o.h20, t.txid, idx.height))
        spent_by_tx = {}
        for t in block.txs[1:]:
            for i in t.inputs:
                spent_by_tx[i.outpoint] = t.txid
        for op, u in spent:
            addr_rows.add((u.h20, spent_by_tx[op], idx.height))
        self.db.executemany("INSERT OR IGNORE INTO addrtx VALUES (?,?,?)", list(addr_rows))
        self.db.execute("INSERT INTO undo VALUES (?, ?)", (idx.hash, _encode_undo(spent)))
        self.db.execute("INSERT INTO active VALUES (?, ?)", (idx.height, idx.hash))
        self.db.execute("UPDATE blocks SET fees=? WHERE hash=?", (fees, idx.hash))
        self.active.append(idx)

    def _disconnect_tip(self) -> Block:
        idx = self.tip
        if idx.height == 0:
            raise RuntimeError("cannot disconnect genesis")
        block = self.get_block(idx.hash)
        row = self.db.one("SELECT data FROM undo WHERE block_hash=?", (idx.hash,))
        spent = _decode_undo(row[0])
        for t in block.txs:
            for n in range(len(t.outputs)):
                self.db.execute("DELETE FROM utxo WHERE txid=? AND vout=?", (t.txid, n))
        self.db.executemany(
            "INSERT INTO utxo VALUES (?,?,?,?,?,?)",
            [(t, v, u.amount, u.h20, u.height, int(u.coinbase)) for (t, v), u in spent],
        )
        self.db.execute("DELETE FROM txindex WHERE block_hash=?", (idx.hash,))
        self.db.execute("DELETE FROM addrtx WHERE height=?", (idx.height,))
        self.db.execute("DELETE FROM undo WHERE block_hash=?", (idx.hash,))
        self.db.execute("DELETE FROM active WHERE height=?", (idx.height,))
        self.active.pop()
        return block

    # --------------------------------------------------------------- helpers
    def locator(self) -> list[bytes]:
        """Active-chain hashes at exponentially increasing depth (for sync)."""
        out, step, h = [], 1, self.height
        while h > 0:
            out.append(self.active[h].hash)
            if len(out) >= 10:
                step *= 2
            h -= step
        out.append(self.active[0].hash)
        return out

    def hashes_after_locator(self, locator: list[bytes], limit: int) -> list[bytes]:
        start = 0
        for h in locator:
            idx = self.index.get(h)
            if idx is not None and self.is_active(idx):
                start = idx.height + 1
                break
        return [i.hash for i in self.active[start : start + limit]]

    def tx_location(self, txid: bytes) -> tuple[bytes, int, int] | None:
        return self.db.one("SELECT block_hash, height, pos FROM txindex WHERE txid=?", (txid,))

    def get_tx(self, txid: bytes) -> tuple[Tx, int, bytes] | None:
        loc = self.tx_location(txid)
        if loc is None:
            return None
        block = self.get_block(loc[0])
        return block.txs[loc[2]], loc[1], loc[0]

    def subsidy_at(self, height: int) -> int:
        return block_subsidy(height, self.p)
