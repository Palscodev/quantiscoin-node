"""Browser mining ("getwork"-style jobs for logged-in users).

The server builds a real block template whose coinbase pays the user's own
address, and sends the browser the 116-byte header prefix plus the target. The
browser searches nonces with SHA-256d and submits a solution; the server
re-assembles the block and runs it through exactly the same validation as any
other block. A browser can never claim a reward without real proof of work, and
the template (and therefore the payout) is fixed by the server.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .template import Template

if TYPE_CHECKING:
    from ..node import Node

JOB_TTL = 120.0  # seconds a job stays valid
MAX_JOBS_PER_USER = 8
MAX_JOBS = 5000


@dataclass
class Job:
    id: str
    user_id: int
    template: Template
    created: float


class WebMiningError(ValueError):
    pass


class WebJobs:
    def __init__(self, node: "Node") -> None:
        self.node = node
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.found: dict[int, int] = {}  # user_id -> blocks accepted this server session
        self.rates: dict[str, tuple[float, float]] = {}  # "user:client" -> (hashes/s, reported at)

    def _expire(self) -> None:
        now = time.monotonic()
        tip = self.node.chain.tip.hash
        for jid in [j.id for j in self.jobs.values()
                    if now - j.created > JOB_TTL or j.template.header.prev_hash != tip]:
            del self.jobs[jid]

    def report(self, user_id: int, client: str, hashrate: float) -> None:
        """A miner's current speed, sent with each work request (about every 30 s)."""
        with self.lock:
            self.rates[f"{user_id}:{client}"] = (float(hashrate), time.monotonic())

    def live_hashrate(self, window: float = 90.0) -> tuple[float, int]:
        """Total speed and number of miners that reported within `window` seconds."""
        now = time.monotonic()
        with self.lock:
            self.rates = {k: v for k, v in self.rates.items() if now - v[1] <= window}
            live = [r for r, _ in self.rates.values() if r > 0]
        return sum(live), len(live)

    def new_job(self, user_id: int, payout_h20: bytes) -> dict:
        extra = b"QuantisCoin/web/" + os.urandom(8)  # unique merkle root per job
        template = self.node.build_template(payout_h20, extra=extra)
        job = Job(secrets.token_hex(12), user_id, template, time.monotonic())
        with self.lock:
            self._expire()
            mine = sorted((j for j in self.jobs.values() if j.user_id == user_id), key=lambda j: j.created)
            for old in mine[: max(0, len(mine) - MAX_JOBS_PER_USER + 1)]:
                del self.jobs[old.id]
            if len(self.jobs) >= MAX_JOBS:
                raise WebMiningError("The server is busy; try again shortly.")
            self.jobs[job.id] = job
        h = template.header
        return {
            "job_id": job.id,
            "prefix": h.prefix().hex(),
            "target": f"{h.target:064x}",
            "height": h.height,
            "reward": template.reward,
            "expires_in": JOB_TTL,
        }

    def submit(self, user_id: int, job_id: str, nonce: int) -> dict:
        if not (0 <= nonce < 1 << 64):
            raise WebMiningError("nonce out of range")
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None or job.user_id != user_id:
                return {"status": "stale", "reason": "This job is no longer current (a new block was found)."}
        block = job.template.block_with_nonce(nonce)
        if not block.header.meets_target():
            return {"status": "rejected", "reason": "The hash does not meet the target."}
        res = self.node.submit_block(block, source=f"web:{user_id}")
        with self.lock:
            self.jobs.pop(job_id, None)
        if res.status == "connected":
            self.found[user_id] = self.found.get(user_id, 0) + 1
            return {"status": "accepted", "height": block.header.height, "hash": block.hash.hex(),
                    "reward": block.txs[0].total_out()}
        return {"status": "stale" if res.status in ("side", "duplicate") else "rejected", "reason": res.reason or res.status}
