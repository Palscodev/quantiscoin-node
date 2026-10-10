"""Mathematical properties of the geometric issuance schedule."""
from dataclasses import replace

import pytest

from quantis.core.monetary import (
    block_subsidy,
    blocks_until_next_halving,
    cumulative_issuance,
    last_rewarding_era,
    realized_supply,
    reward_era,
    schedule,
    theoretical_supply,
)
from quantis.core.params import COIN, DEVNET, REGTEST


def test_devnet_economics_are_bitcoin_like():
    # 25 QTS per block, halving every 200,000 blocks, at most 10 million QTS.
    assert DEVNET.initial_reward == 25 * COIN
    assert DEVNET.halving_interval == 200_000
    assert theoretical_supply(DEVNET) == 10_000_000 * COIN
    assert DEVNET.max_money == 10_000_000 * COIN


def test_first_block_pays_initial_reward_and_genesis_pays_nothing():
    for p in (DEVNET, REGTEST):
        assert block_subsidy(0, p) == 0
        assert block_subsidy(1, p) == p.initial_reward


@pytest.mark.parametrize("p", [DEVNET, REGTEST])
def test_halving_boundaries(p):
    H, R = p.halving_interval, p.initial_reward
    assert block_subsidy(H, p) == R  # last block of era 0
    assert block_subsidy(H + 1, p) == R // 2  # first block of era 1
    assert block_subsidy(2 * H + 1, p) == R // 4
    assert block_subsidy(3 * H + 1, p) == R // 8
    assert reward_era(1, p) == 0 and reward_era(H, p) == 0 and reward_era(H + 1, p) == 1


def test_devnet_reward_sequence():
    H = DEVNET.halving_interval
    expected = [25, 12.5, 6.25, 3.125, 1.5625]
    for k, qts in enumerate(expected):
        assert block_subsidy(k * H + 1, DEVNET) == int(qts * COIN)


@pytest.mark.parametrize("p", [DEVNET, REGTEST])
def test_reward_is_floor_of_r0_over_power_of_two(p):
    for k in range(70):
        assert block_subsidy(k * p.halving_interval + 1, p) == p.initial_reward // (2**k)


def test_reward_exhaustion():
    n = DEVNET.initial_reward  # 2.5e9 quanta
    k_last = last_rewarding_era(DEVNET)
    assert k_last == n.bit_length() - 1 == 31  # 2.5e9 >> 31 = 1, >> 32 = 0
    H = DEVNET.halving_interval
    assert block_subsidy(k_last * H + 1, DEVNET) == 1
    assert block_subsidy((k_last + 1) * H + 1, DEVNET) == 0
    assert block_subsidy(10**12, DEVNET) == 0


@pytest.mark.parametrize("p", [DEVNET, REGTEST])
def test_supply_identity_2n_minus_popcount(p):
    n = p.initial_reward
    brute = sum(n >> k for k in range(200))
    assert brute == 2 * n - n.bit_count()
    assert realized_supply(p) == p.halving_interval * brute
    assert theoretical_supply(p) - realized_supply(p) == n.bit_count() * p.halving_interval


def test_devnet_realized_supply_exact():
    # 2.5e9 has 11 one-bits, so rounding destroys 11 quanta per block-era slot: 11 * 200,000 quanta.
    assert DEVNET.initial_reward.bit_count() == 11
    assert realized_supply(DEVNET) == 999_999_997_800_000  # 9,999,999.978 QTS


@pytest.mark.parametrize("p", [DEVNET, REGTEST])
def test_cumulative_issuance_matches_brute_force_at_era_edges(p):
    H = p.halving_interval
    # Exact closed form vs. summing era by era (brute force per block is too slow for H = 200,000).
    for era in range(0, 40):
        for h in (era * H, era * H + 1, (era + 1) * H - 1):
            if h < 0:
                continue
            expected = sum(H * (p.initial_reward >> k) for k in range(min(era, 64)))
            expected += max(0, h - era * H) * (p.initial_reward >> era if era < 64 else 0)
            assert cumulative_issuance(h, p) == expected
    assert cumulative_issuance(10**12, p) == realized_supply(p) <= p.max_money


def test_cumulative_issuance_brute_force_regtest():
    p = REGTEST
    total = 0
    for h in range(0, 45 * p.halving_interval):
        total += block_subsidy(h, p)
        assert cumulative_issuance(h, p) == total
    assert total == realized_supply(p)


def test_blocks_until_next_halving():
    H = DEVNET.halving_interval
    assert blocks_until_next_halving(0, DEVNET) == H  # blocks 1..H remain at the initial reward
    assert blocks_until_next_halving(H - 1, DEVNET) == 1
    assert blocks_until_next_halving(H, DEVNET) == H


def test_schedule_table():
    rows = schedule(DEVNET)
    assert rows[0]["reward"] == 25 * COIN and rows[1]["reward"] == int(12.5 * COIN)
    assert rows[0]["cumulative"] == 5_000_000 * COIN
    assert rows[-1]["reward"] == 0
    assert rows[-1]["cumulative"] == realized_supply(DEVNET)


def test_configurable_interval_changes_identity():
    p = replace(DEVNET, halving_interval=7)
    assert p.magic != DEVNET.magic
    assert realized_supply(p) == 7 * (2 * DEVNET.initial_reward - DEVNET.initial_reward.bit_count())
