"""Hash-rate benchmark using the real worker code path (no simulated numbers).

Runs the production `worker_main` against an impossible target (0) for a fixed
duration per worker count and reports measured hashes per second.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import platform
import sys
import time

from .core.genesis import genesis_block
from .core.params import get_network
from .mining.worker import worker_main


def measure(workers: int, seconds: float, low_power: bool = False) -> dict:
    ctx = mp.get_context("spawn")
    stop, pause = ctx.Event(), ctx.Event()
    counters = ctx.Array("Q", workers, lock=False)
    result_q = ctx.Queue()
    lp = ctx.Value("b", 1 if low_power else 0)
    qs = [ctx.Queue() for _ in range(workers)]
    procs = [ctx.Process(target=worker_main, args=(i, qs[i], result_q, counters, stop, pause, lp), daemon=True)
             for i in range(workers)]
    for p in procs:
        p.start()
    prefix = genesis_block(get_network("devnet")).header.prefix()
    for i, q in enumerate(qs):
        q.put((1, prefix, 0, i, workers))  # target 0: never solved, pure hashing
    time.sleep(1.0)  # warm-up (process start-up on Windows is slow)
    samples, last, t_last = [], sum(counters), time.perf_counter()
    t_start, c_start = t_last, last
    while time.perf_counter() - t_start < seconds:
        time.sleep(1.0)
        now, total = time.perf_counter(), sum(counters)
        samples.append((total - last) / (now - t_last))
        last, t_last = total, now
    stop.set()
    for p in procs:
        p.join(timeout=3)
        if p.is_alive():
            p.terminate()
    for q in qs + [result_q]:
        q.cancel_join_thread()
        q.close()
    half = sorted(samples[len(samples) // 2 :]) or [0.0]
    return {
        "workers": workers,
        "low_power": low_power,
        "seconds": round(t_last - t_start, 3),
        "hashes": last - c_start,
        "hashes_per_second": round((last - c_start) / (t_last - t_start), 1),  # mean over the run
        "first_second_hps": round(samples[0], 1) if samples else 0.0,
        "sustained_hps": round(half[len(half) // 2], 1),  # median of the second half of the run
        "per_second": [round(x) for x in samples],
    }


def run_benchmark(network: str, worker_counts: list[int], seconds: float) -> dict:
    p = get_network(network)
    results = [measure(w, seconds) for w in worker_counts]
    results.append(measure(1, seconds, low_power=True))
    expected = (1 << 256) / (p.initial_target + 1)
    for r in results:
        r["expected_seconds_per_block_at_initial_target"] = round(expected / r["sustained_hps"], 2) if r["sustained_hps"] else None
    return {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "network": network,
        "expected_hashes_at_initial_target": expected,
        "results": results,
    }
