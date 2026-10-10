"""Geometric issuance schedule.

For block height h >= 1, the reward era is k = floor((h-1)/H) and the subsidy is
    R_k = floor(R_0 / 2^k)        (computed exactly as R_0 >> k)
The genesis block (h = 0) issues nothing.

Theoretical supply (real numbers):  S = sum_{k>=0} H*R_0/2^k = 2*H*R_0.
Realized supply (integers): using sum_{k>=0} floor(n/2^k) = 2n - popcount(n),
    S_int = H * (2*R_0 - popcount(R_0)).
With R_0 = 10^11 quanta, popcount = 15, so rounding loses exactly 15*H quanta.
"""
from __future__ import annotations

from .params import NetworkParams


def reward_era(height: int, p: NetworkParams) -> int:
    if height < 1:
        raise ValueError("genesis has no reward era")
    return (height - 1) // p.halving_interval


def block_subsidy(height: int, p: NetworkParams) -> int:
    if height == 0:
        return 0
    k = reward_era(height, p)
    return p.initial_reward >> k if k < p.initial_reward.bit_length() else 0


def last_rewarding_era(p: NetworkParams) -> int:
    """Largest k with R_0 >> k > 0."""
    return p.initial_reward.bit_length() - 1


def cumulative_issuance(height: int, p: NetworkParams) -> int:
    """Total subsidy of blocks 1..height (inclusive), computed in O(log R0) without iteration over blocks."""
    if height <= 0:
        return 0
    H = p.halving_interval
    full_eras, partial = divmod(height, H)
    total = 0
    for k in range(min(full_eras, p.initial_reward.bit_length())):
        total += H * (p.initial_reward >> k)
    if partial and full_eras < p.initial_reward.bit_length():
        total += partial * (p.initial_reward >> full_eras)
    return total


def theoretical_supply(p: NetworkParams) -> int:
    return 2 * p.halving_interval * p.initial_reward


def realized_supply(p: NetworkParams) -> int:
    return p.halving_interval * (2 * p.initial_reward - p.initial_reward.bit_count())


def blocks_until_next_halving(height: int, p: NetworkParams) -> int:
    """Blocks after `height` until the first block of the next era is mined."""
    next_h = height + 1
    if next_h < 1:
        next_h = 1
    era = reward_era(next_h, p)
    first_of_next = (era + 1) * p.halving_interval + 1
    return first_of_next - next_h


def schedule(p: NetworkParams, eras: int | None = None) -> list[dict]:
    """Per-era table: era, first/last height, reward, cumulative supply at era end."""
    n = (last_rewarding_era(p) + 2) if eras is None else eras
    rows, cum = [], 0
    for k in range(n):
        reward = p.initial_reward >> k if k < p.initial_reward.bit_length() else 0
        cum += reward * p.halving_interval
        rows.append(
            {
                "era": k,
                "first_height": k * p.halving_interval + 1,
                "last_height": (k + 1) * p.halving_interval,
                "reward": reward,
                "cumulative": cum,
            }
        )
    return rows
