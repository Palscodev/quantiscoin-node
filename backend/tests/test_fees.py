"""Fee formula and mempool policy under empty, moderate and saturated load."""
import pytest

from quantis.core.fees import FeePolicy, consensus_min_fee, feerate_key
from quantis.core.validation import ValidationError

from conftest import Key
from test_tx_security import mature_coin

P = FeePolicy(base_rate=10, max_multiplier=8, target_bytes=64_000)


def test_empty_mempool_rate_is_base():
    assert P.rate(0) == 10
    assert P.min_fee(250, 0) == 2500


def test_moderate_occupancy_linear():
    assert P.rate(32_000) == 10 + 10 * 7 * 32_000 // 64_000 == 45
    assert P.rate(16_000) == 27  # 10 + floor(17.5)


def test_saturated_is_bounded():
    assert P.rate(64_000) == 80
    assert P.rate(10**12) == 80  # bounded at M * base
    assert P.rate(-5) == 10  # negative input clamps


def test_monotone_and_integer():
    rates = [P.rate(b) for b in range(0, 70_000, 997)]
    assert rates == sorted(rates) and all(isinstance(r, int) for r in rates)


def test_invalid_policy():
    with pytest.raises(ValueError):
        FeePolicy(base_rate=-1)
    with pytest.raises(ValueError):
        P.min_fee(-1, 0)


def test_consensus_floor_and_ordering():
    assert consensus_min_fee(300, 1) == 300
    keys = sorted([feerate_key(100, 10, b"b"), feerate_key(100, 10, b"a"), feerate_key(300, 20, b"c")])
    assert [k[1] for k in keys] == [b"c", b"a", b"b"]


def test_policy_rejects_low_fee_and_eviction(harness, alice, bob):
    coins = [mature_coin(harness, alice) for _ in range(3)]
    low = harness.spend(alice, [coins[0][0]], [(bob.h20, coins[0][1] - 500)])  # ~5 q/byte < 10
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(low)
    assert e.value.code == "txn-fee-below-policy"
    # Fill a tiny mempool, then a higher-paying tx displaces the cheapest.
    harness.mempool.max_bytes = 250  # room for exactly one ~180-byte tx
    a = harness.spend(alice, [coins[1][0]], [(bob.h20, coins[1][1] - 3000)])
    harness.mempool.accept(a)
    b = harness.spend(alice, [coins[2][0]], [(bob.h20, coins[2][1] - 9000)])
    harness.mempool.accept(b)
    assert b.txid in harness.mempool and a.txid not in harness.mempool
    c = harness.spend(alice, [coins[1][0]], [(bob.h20, coins[1][1] - 2500)])
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(c)
    assert e.value.code == "mempool-full"


def test_template_orders_by_feerate(harness, alice, bob):
    coins = [mature_coin(harness, alice) for _ in range(3)]
    txs = [harness.spend(alice, [op], [(bob.h20, amt - fee)]) for (op, amt), fee in zip(coins, (3000, 9000, 6000))]
    for t in txs:
        harness.mempool.accept(t)
    blk = harness.mine(Key(7).h20)[0]
    assert [t.txid for t in blk.txs[1:]] == [txs[1].txid, txs[2].txid, txs[0].txid]
