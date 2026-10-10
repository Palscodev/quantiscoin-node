"""Mining worker process.

Each worker searches nonces start, start+step, start+2*step, ... for the job it
was given. SHA-256 is applied to the fixed 116-byte header prefix once; each
attempt copies that midstate and hashes only the 8 nonce bytes, then applies the
second SHA-256. Workers are separate processes because CPython threads cannot
hash in parallel for inputs this small (the GIL is held).
"""
from __future__ import annotations

import hashlib
import os
import queue
import time

BATCH = 8192


def worker_main(wid, job_q, result_q, counters, stop_ev, pause_ev, low_power) -> None:
    if hasattr(os, "nice"):
        try:
            os.nice(5)
        except OSError:
            pass
    sha256 = hashlib.sha256
    job = None
    while not stop_ev.is_set():
        try:
            while True:  # keep only the newest job
                job = job_q.get(timeout=0.1) if job is None else job_q.get_nowait()
        except queue.Empty:
            pass
        if job is None:
            continue
        if pause_ev.is_set():
            time.sleep(0.1)
            continue
        job_id, prefix, target, nonce, step = job
        base = sha256(prefix)
        t0 = time.perf_counter()
        found = None
        for _ in range(BATCH):
            h = base.copy()
            h.update(nonce.to_bytes(8, "little"))
            if int.from_bytes(sha256(h.digest()).digest(), "big") <= target:
                found = nonce
                break
            nonce += step
        counters[wid] += BATCH if found is None else 1
        if found is not None:
            result_q.put((job_id, found))
            job = None
        elif nonce >= 1 << 64:
            job = None  # nonce space exhausted; wait for a fresh template (new timestamp)
        else:
            job = (job_id, prefix, target, nonce, step)
        if low_power.value:
            time.sleep(time.perf_counter() - t0)  # ~50% duty cycle
