"""Mining controller: owns the worker processes and turns solutions into blocks.

The controller never trusts a worker: a reported nonce is re-hashed, and the
resulting block goes through the exact same validation path as a block from a
peer (Node.submit_block). Consensus difficulty comes only from the chain.
"""
from __future__ import annotations

import multiprocessing as mp
import queue
import threading
import time
from collections import deque
from typing import TYPE_CHECKING

from ..core.address import AddressError, decode_address
from .template import Template
from .worker import worker_main

if TYPE_CHECKING:
    from ..node import Node

TEMPLATE_REFRESH_SECONDS = 10
MAX_WORKERS = 64


class MinerError(ValueError):
    pass


class Miner:
    def __init__(self, node: "Node") -> None:
        self.node = node
        self.ctx = mp.get_context("spawn")
        self.state = "stopped"
        self.address: str | None = None
        self.workers = 0
        self.low_power = self.ctx.Value("b", 0)
        self.accepted = 0
        self.rejected = 0
        self.stale = 0
        self.hashrate = 0.0
        self.total_hashes = 0
        self.mining_seconds = 0.0
        self.last_block: dict | None = None
        self.log: deque[dict] = deque(maxlen=200)
        self._procs: list = []
        self._job_qs: list = []
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------- control
    def start(self, address: str, workers: int = 1, low_power: bool = False) -> dict:
        try:
            h20 = decode_address(address.strip(), self.node.params.address_version)
        except AddressError as e:
            raise MinerError(f"invalid payout address: {e}") from e
        if not (1 <= workers <= MAX_WORKERS):
            raise MinerError(f"workers must be between 1 and {MAX_WORKERS}")
        with self._lock:
            if self.state != "stopped":
                self.stop()
            self.address, self._h20, self.workers = address.strip(), h20, workers
            self.low_power.value = 1 if low_power else 0
            self._stop_ev, self._pause_ev = self.ctx.Event(), self.ctx.Event()
            self._result_q = self.ctx.Queue()
            self._counters = self.ctx.Array("Q", workers, lock=False)
            self._job_qs = [self.ctx.Queue() for _ in range(workers)]
            self._procs = [
                self.ctx.Process(
                    target=worker_main,
                    args=(i, self._job_qs[i], self._result_q, self._counters, self._stop_ev, self._pause_ev, self.low_power),
                    daemon=True,
                    name=f"quantis-miner-{i}",
                )
                for i in range(workers)
            ]
            for p in self._procs:
                p.start()
            self.state = "running"
            self._ctl_stop = threading.Event()
            self._thread = threading.Thread(target=self._run, name="quantis-miner-ctl", daemon=True)
            self._thread.start()
            self._log("start", f"mining started with {workers} worker(s){' in low-power mode' if low_power else ''}")
        return self.stats()

    def pause(self) -> dict:
        with self._lock:
            if self.state == "running":
                self._pause_ev.set()
                self.state = "paused"
                self._log("pause", "mining paused")
        return self.stats()

    def resume(self) -> dict:
        with self._lock:
            if self.state == "paused":
                self._pause_ev.clear()
                self.state = "running"
                self._log("resume", "mining resumed")
        return self.stats()

    def set_low_power(self, enabled: bool) -> dict:
        self.low_power.value = 1 if enabled else 0
        self._log("config", f"low-power mode {'on' if enabled else 'off'}")
        return self.stats()

    def stop(self) -> dict:
        with self._lock:
            if self.state == "stopped":
                return self.stats()
            self._ctl_stop.set()
            self._stop_ev.set()
            if self._thread and self._thread is not threading.current_thread():
                self._thread.join(timeout=5)
            for p in self._procs:
                p.join(timeout=3)
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=2)
            for q in self._job_qs + [self._result_q]:
                q.cancel_join_thread()
                q.close()
            self._procs, self._job_qs = [], []
            self.state = "stopped"
            self.hashrate = 0.0
            self._log("stop", "mining stopped")
        return self.stats()

    # --------------------------------------------------------------- loop
    def _run(self) -> None:
        job_id, template, tip, made_at, mempool_n = 0, None, None, 0.0, -1
        last_sample, last_total, last_publish = time.monotonic(), 0, 0.0
        while not self._ctl_stop.is_set():
            now = time.monotonic()
            running = self.state == "running"
            cur_tip = self.node.chain.tip.hash
            if running and (
                cur_tip != tip or now - made_at > TEMPLATE_REFRESH_SECONDS or len(self.node.mempool) != mempool_n
            ):
                template = self.node.build_template(self._h20)
                tip, made_at, mempool_n = cur_tip, now, len(self.node.mempool)
                job_id += 1
                prefix = template.header.prefix()
                for i, q in enumerate(self._job_qs):
                    q.put((job_id, prefix, template.header.target, i, self.workers))
            try:
                got_id, nonce = self._result_q.get(timeout=0.2)
            except queue.Empty:
                got_id = None
            if got_id is not None:
                if got_id == job_id and template is not None:
                    self._submit(template, nonce)
                    made_at = 0  # force a fresh template
                else:
                    self.stale += 1
            now = time.monotonic()
            if now - last_sample >= 1.0:
                total = sum(self._counters)
                rate = (total - last_total) / (now - last_sample)
                self.hashrate = rate if running else 0.0
                self.total_hashes = total
                if running:
                    self.mining_seconds += now - last_sample
                last_sample, last_total = now, total
            if now - last_publish >= 1.0:
                last_publish = now
                self.node.events.publish("miner", self.stats())

    def _submit(self, template: Template, nonce: int) -> None:
        block = template.block_with_nonce(nonce)
        if not block.header.meets_target():
            self.rejected += 1
            self._log("rejected", f"worker reported nonce {nonce} that does not meet the target")
            return
        res = self.node.submit_block(block, source="miner")
        if res.status == "connected":
            self.accepted += 1
            self.last_block = {
                "height": block.header.height,
                "hash": block.hash.hex(),
                "reward": block.txs[0].total_out(),
                "subsidy": template.subsidy,
                "fees": template.fees,
                "n_tx": len(block.txs),
                "time": int(time.time()),
            }
            self._log("accepted", f"block {block.header.height} accepted, reward {template.subsidy + template.fees} quanta",
                      height=block.header.height, hash=block.hash.hex())
        else:
            self.rejected += 1
            self._log("rejected", f"block rejected: {res.status} {res.reason}", hash=block.hash.hex())

    def _log(self, kind: str, message: str, **extra) -> None:
        entry = {"time": time.time(), "kind": kind, "message": message, **extra}
        self.log.append(entry)
        self.node.events.publish("miner_log", entry)

    def stats(self) -> dict:
        chain = self.node.chain
        with self.node.lock:
            target = chain.next_target()
        return {
            "state": self.state,
            "address": self.address,
            "workers": self.workers,
            "low_power": bool(self.low_power.value),
            "hashrate": self.hashrate,
            "total_hashes": self.total_hashes,
            "mining_seconds": self.mining_seconds,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "stale": self.stale,
            "target": f"{target:064x}",
            "difficulty": chain.p.pow_limit / target,
            "expected_hashes": (1 << 256) / (target + 1),
            "expected_seconds": ((1 << 256) / (target + 1)) / self.hashrate if self.hashrate > 0 else None,
            "last_block": self.last_block,
            "cpu_count": mp.cpu_count(),
        }
