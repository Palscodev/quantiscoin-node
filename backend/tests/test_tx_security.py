"""Signatures, double spends, replay, maturity, value limits and reward enforcement."""
from dataclasses import replace

import pytest

from quantis.core import crypto
from quantis.core.block import Block
from quantis.core.merkle import merkle_root
from quantis.core.monetary import block_subsidy
from quantis.core.params import REGTEST
from quantis.core.tx import TxOut, make_coinbase
from quantis.core.validation import ValidationError
from quantis.mining.template import solve

from conftest import NOW, Key


def mature_coin(h, key):
    """Mine one block to `key`, then enough blocks for its coinbase to mature."""
    blk = h.mine(key.h20)[0]
    h.mine(Key(999).h20, REGTEST.coinbase_maturity)
    return (blk.txs[0].txid, 0), blk.txs[0].outputs[0].amount


def test_sign_verify_low_s_strict_der():
    k = crypto.PrivateKey(12345)
    d = b"\x07" * 32
    for _ in range(20):
        sig = k.sign(d)
        assert crypto.verify(k.public_key(), d, sig)
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

        r, s = decode_dss_signature(sig)
        assert s <= crypto.HALF_ORDER
        high = encode_dss_signature(r, crypto.CURVE_ORDER - s)
        assert not crypto.verify(k.public_key(), d, high)  # malleated high-S rejected
    assert not crypto.verify(k.public_key(), b"\x08" * 32, k.sign(d))
    assert not crypto.verify(crypto.PrivateKey(1).public_key(), d, k.sign(d))
    assert "redacted" in repr(k)


def test_valid_spend_and_fee(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    entry = harness.mempool.accept(tx)
    assert entry.fee == 5000
    blk = harness.mine(alice.h20)[0]
    assert tx.txid in [t.txid for t in blk.txs]
    # 10% of fees are burned: the miner gets the subsidy plus 4500 of the 5000 fee
    assert blk.txs[0].total_out() == block_subsidy(blk.header.height, REGTEST) + 4500
    assert harness.chain.get_utxo((tx.txid, 0)).amount == amount - 5000
    assert harness.chain.get_utxo(op) is None


def test_coinbase_cannot_claim_burned_fees(harness, alice, bob):
    from dataclasses import replace
    from quantis.core.merkle import merkle_root
    from quantis.core.tx import TxOut, make_coinbase
    from quantis.mining.template import Template, solve
    op, amount = mature_coin(harness, alice)
    harness.mempool.accept(harness.spend(alice, [op], [(bob.h20, amount - 5000)]))
    t = harness.template(alice.h20)
    assert (t.fees, t.burned, t.reward) == (5000, 500, t.subsidy + 4500)
    greedy_cb = make_coinbase(t.header.height, [TxOut(t.subsidy + 5000, alice.h20)], b"greedy")
    txs = [greedy_cb] + t.txs[1:]
    greedy = Template(replace(t.header, merkle_root=merkle_root([x.txid for x in txs])), txs, t.subsidy, t.fees)
    res = harness.chain.process_block(solve(greedy), NOW)
    assert (res.status, res.reason) == ("invalid", "blk-bad-reward")


def test_bad_signature_rejected(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    tx.outputs[0].amount -= 1  # tamper after signing
    tx.invalidate_cache()
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx)
    assert e.value.code == "tx-bad-signature"


def test_wrong_key_rejected(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(bob, [op], [(bob.h20, amount - 5000)])  # bob signs alice's coin
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx)
    assert e.value.code == "tx-wrong-key"


def test_insufficient_funds(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op], [(bob.h20, amount + 1)])
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx)
    assert e.value.code == "tx-insufficient-funds"


def test_double_spend_in_mempool_and_block(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx1 = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    tx2 = harness.spend(alice, [op], [(alice.h20, amount - 6000)])
    harness.mempool.accept(tx1)
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx2)
    assert e.value.code == "txn-mempool-conflict"
    # A block containing both spends is invalid.
    t = harness.template(alice.h20, use_mempool=False)
    txs = t.txs + [tx1, tx2]
    cb = make_coinbase(t.header.height, [TxOut(block_subsidy(t.header.height, REGTEST), alice.h20)])
    txs[0] = cb
    header = replace(t.header, merkle_root=merkle_root([x.txid for x in txs]))
    blk = solve(type(t)(header, txs, 0, 0))
    res = harness.chain.process_block(blk, NOW)
    assert res.status == "invalid" and res.reason == "tx-missing-input"


def test_replay_of_confirmed_tx_rejected(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    harness.mempool.accept(tx)
    harness.mine(alice.h20)
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx)
    assert e.value.code == "txn-already-confirmed"


def test_duplicate_input_within_tx(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op, op], [(bob.h20, amount)])
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx)
    assert e.value.code == "tx-duplicate-input"


def test_coinbase_maturity(harness, alice, bob):
    blk = harness.mine(alice.h20)[0]
    op, amount = (blk.txs[0].txid, 0), blk.txs[0].outputs[0].amount
    tx = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    for _ in range(REGTEST.coinbase_maturity - 1):
        with pytest.raises(ValidationError) as e:
            harness.mempool.accept(tx)
        assert e.value.code == "tx-immature-coinbase"
        harness.mine(bob.h20)
    harness.mempool.accept(tx)  # now exactly `coinbase_maturity` blocks deep at next height


def test_amount_overflow_and_zero_rejected(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    for bad in (0, REGTEST.max_money + 1, 2**64 - 1):
        tx = harness.spend(alice, [op], [(bob.h20, bad)])
        with pytest.raises(ValidationError) as e:
            harness.mempool.accept(tx)
        assert e.value.code == "tx-amount-range"
    tx = harness.spend(alice, [op], [(bob.h20, REGTEST.max_money), (bob.h20, REGTEST.max_money)])
    with pytest.raises(ValidationError):
        harness.mempool.accept(tx)


def test_fee_below_consensus_floor(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx = harness.spend(alice, [op], [(bob.h20, amount - 1)])
    with pytest.raises(ValidationError) as e:
        harness.mempool.accept(tx, enforce_policy=False)
    assert e.value.code == "tx-fee-below-floor"


def test_coinbase_cannot_overpay(harness, alice):
    t = harness.template(alice.h20)
    cb = make_coinbase(t.header.height, [TxOut(block_subsidy(t.header.height, REGTEST) + 1, alice.h20)])
    header = replace(t.header, merkle_root=merkle_root([cb.txid]))
    blk = solve(type(t)(header, [cb], 0, 0))
    res = harness.chain.process_block(blk, NOW)
    assert res.status == "invalid" and res.reason == "blk-bad-reward"


def test_standalone_coinbase_not_relayed(harness, alice):
    with pytest.raises(ValidationError):
        harness.mempool.accept(make_coinbase(5, [TxOut(1, alice.h20)]))


def test_unconfirmed_chain_spend(harness, alice, bob):
    op, amount = mature_coin(harness, alice)
    tx1 = harness.spend(alice, [op], [(bob.h20, amount - 5000)])
    harness.mempool.accept(tx1)
    tx2 = harness.spend(bob, [(tx1.txid, 0)], [(alice.h20, amount - 10000)])
    harness.mempool.accept(tx2)
    blk = harness.mine(alice.h20)[0]
    ids = [t.txid for t in blk.txs]
    assert ids.index(tx1.txid) < ids.index(tx2.txid)  # parent before child
    assert len(harness.mempool) == 0
