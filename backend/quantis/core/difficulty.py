"""Damped, bounded proportional difficulty controller.

Let W = retarget window, T = target block time, E = W*T (expected window time).
For a block at height h:
  * h below the first retarget height, or h not a multiple of W:   target(h) = target(h-1)
    (block 1 uses initial_target; the genesis target is not inherited)
  * h a multiple of W and h >= first_retarget_height = ceil((W + mtp_span + 1) / W) * W:
        A  = MTP(h-1) - MTP(h-1-W)                 observed time over W blocks
        A' = clamp(A, E/c, E*c)                    c = clamp_factor (devnet: 4)
        target(h) = min(pow_limit, max(1, floor(target(h-1) * ((d-1)*E + A') / (d*E))))
                                                   d = damping (devnet: 2)
    i.e. the new target moves 1/d of the way toward the proportional correction
    target * A'/E, using exact integer arithmetic (one floor at the end).

MTP(x) is the median of the timestamps of block x and its predecessors (up to
mtp_span blocks). Measuring with MTPs means a single block with a manipulated
timestamp moves the measurement only if it shifts the median.

Per window the target can change by a factor in [((d-1) + 1/c)/d, ((d-1) + c)/d]
= [0.625, 2.5] on devnet (d = 2, c = 4). In log terms, the deviation from the
equilibrium hash rate is multiplied by roughly (1 - 1/d) = 1/2 each window, i.e.
it decays geometrically.
"""
from __future__ import annotations

from typing import Callable, Protocol

from .params import NetworkParams


class IndexLike(Protocol):
    height: int
    timestamp: int
    target: int


def median_time_past(index: IndexLike, ancestor: Callable[[IndexLike, int], IndexLike], span: int) -> int:
    times = []
    h = index.height
    for i in range(span):
        if h - i < 0:
            break
        times.append(ancestor(index, h - i).timestamp)
    times.sort()
    return times[len(times) // 2]


def retarget(old_target: int, actual: int, p: NetworkParams) -> int:
    expected = p.retarget_window * p.target_block_time
    lo, hi = expected // p.clamp_factor, expected * p.clamp_factor
    clamped = min(max(actual, lo), hi)
    # new = old * D / E with D = ((d-1)E + A')/d, evaluated with a single floor division
    new = old_target * ((p.damping - 1) * expected + clamped) // (p.damping * expected)
    return max(1, min(p.pow_limit, new))


def first_retarget_height(p: NetworkParams) -> int:
    """First multiple of W whose start MTP (block h-1-W and its mtp_span-1 predecessors) excludes genesis.

    The genesis timestamp is a fixed constant, not a real mining time, so it must never be part of a
    measurement: we need (h - 1 - W) - (mtp_span - 1) >= 1, i.e. h >= W + mtp_span + 1.
    """
    w = p.retarget_window
    lowest = w + p.mtp_span + 1
    return -(-lowest // w) * w


def is_retarget_height(height: int, p: NetworkParams) -> bool:
    return height >= first_retarget_height(p) and height % p.retarget_window == 0


def expected_target(prev: IndexLike, ancestor: Callable[[IndexLike, int], IndexLike], p: NetworkParams) -> int:
    """Target that the block at prev.height + 1 must carry."""
    height = prev.height + 1
    if prev.height == 0:
        return p.initial_target
    if not is_retarget_height(height, p):
        return prev.target
    t_end = median_time_past(prev, ancestor, p.mtp_span)
    start = ancestor(prev, prev.height - p.retarget_window)
    t_start = median_time_past(start, ancestor, p.mtp_span)
    return retarget(prev.target, t_end - t_start, p)
