"""Difficulty controller: bounds, damping, startup, timestamp robustness."""
from dataclasses import dataclass
from dataclasses import replace

from quantis.core.difficulty import expected_target, first_retarget_height, is_retarget_height, median_time_past, retarget
from quantis.core.params import DEVNET, REGTEST

P = DEVNET
E = P.retarget_window * P.target_block_time


@dataclass
class Idx:
    height: int
    timestamp: int
    target: int


def chain_of(timestamps, target=P.initial_target):
    blocks = [Idx(0, timestamps[0], P.pow_limit)] + [Idx(i, t, target) for i, t in enumerate(timestamps[1:], 1)]
    return blocks, (lambda idx, h: blocks[h])


def test_on_schedule_is_fixed_point():
    assert retarget(P.initial_target, E, P) == P.initial_target


def test_bounds_per_window():
    t = 1 << 222
    d, c = P.damping, P.clamp_factor
    # fastest: x((d-1) + 1/c)/d (harder); slowest: x((d-1) + c)/d (easier). Devnet: x0.625 .. x2.5
    assert retarget(t, 0, P) == t * ((d - 1) * c + 1) // (d * c)
    assert retarget(t, 10**9, P) == t * ((d - 1) + c) // d
    assert (d, c) == (2, 4) and retarget(t, 0, P) == t * 5 // 8 and retarget(t, 10**9, P) == t * 5 // 2
    # Clamp means huge and tiny observed times saturate exactly at the bounds.
    assert retarget(t, E // 4, P) == retarget(t, 0, P)
    assert retarget(t, 4 * E, P) == retarget(t, 10**12, P)


def test_direction():
    t = 1 << 222
    assert retarget(t, E // 2, P) < t  # blocks too fast -> smaller target (harder)
    assert retarget(t, 2 * E, P) > t  # too slow -> larger target (easier)


def test_pow_limit_and_minimum():
    assert retarget(P.pow_limit, 10**9, P) == P.pow_limit
    assert retarget(1, 0, P) == 1


def test_damping_halves_error_geometrically():
    # Hash rate is 2x what target t0 was tuned for. Block time is proportional to
    # (expected hashes)/(hash rate) = (2^256/t)/rate, so A = E * (t0/t) / 2 and the
    # equilibrium is t = t0/2. The deviation should shrink geometrically.
    t0 = 1 << 222
    t = t0
    errors = []
    for _ in range(30):
        actual = int(E * (t0 / t) * 0.5)
        t = retarget(t, actual, P)
        errors.append(abs(t / t0 - 0.5))
    assert errors[-1] < 0.01
    # x' = (1 - 1/d) x + 0.5/d analytically, so the error contracts by exactly (1 - 1/d) per window
    # until it reaches the 1-second timestamp resolution (~1/E of the window).
    factor = 1 - 1 / P.damping
    for a, b in zip(errors, errors[1:]):
        if a > 10 / E:
            assert b <= a * (factor + 0.01)


def test_startup_and_non_retarget_heights_inherit():
    T = P.target_block_time
    ts = [P.genesis_timestamp] + [P.genesis_timestamp + 100 + T * i for i in range(1, 100)]
    blocks, anc = chain_of(ts)
    first = first_retarget_height(P)
    assert first == 30  # W = 10, mtp_span = 11: first multiple of 10 that is >= 22
    assert expected_target(blocks[0], anc, P) == P.initial_target  # block 1
    assert not is_retarget_height(2 * P.retarget_window, P)
    assert is_retarget_height(first, P) and not is_retarget_height(first + 1, P)
    for h in range(1, first - 1):
        assert expected_target(blocks[h], anc, P) == P.initial_target


def test_first_measurement_never_includes_genesis():
    # Start MTP for the first retarget must only use mined blocks (heights >= 1).
    for p in (P, REGTEST):
        h = first_retarget_height(p)
        assert (h - 1 - p.retarget_window) - (p.mtp_span - 1) >= 1


def test_retarget_uses_median_time_past():
    W, T = P.retarget_window, P.target_block_time
    first = first_retarget_height(P)
    ts = [P.genesis_timestamp] + [P.genesis_timestamp + 1000 + T * i for i in range(1, first)]
    blocks, anc = chain_of(ts)
    base = expected_target(blocks[first - 1], anc, P)
    assert base == P.initial_target  # exactly on schedule -> unchanged
    # A single wildly-future timestamp on the last block does not move the median.
    ts2 = list(ts)
    ts2[-1] += 10_000
    blocks2, anc2 = chain_of(ts2)
    assert expected_target(blocks2[first - 1], anc2, P) == base


def test_median_time_past():
    blocks, anc = chain_of([0, 5, 1, 9, 3, 7, 2, 8, 4, 6, 10, 100])
    assert median_time_past(blocks[11], anc, 11) == 6  # sorted [1,2,3,4,5,6,7,8,9,10,100]
    assert median_time_past(blocks[0], anc, 11) == 0


def test_custom_params_bounds():
    p = replace(P, damping=1, clamp_factor=2)
    t = 1 << 222
    assert retarget(t, 0, p) == t // 2 and retarget(t, 10**9, p) == 2 * t
