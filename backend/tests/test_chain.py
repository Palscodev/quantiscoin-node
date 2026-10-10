"""Block validation, chain selection by cumulative work, reorgs, persistence."""
from dataclasses import replace

import pytest

from quantis.core.chainstate import STATUS_INVALID
from quantis.core.hashing import work_from_target
from quantis.core.merkle import merkle_root
from quantis.core.params import REGTEST
from quantis.mining.template import Template, build_template, solve

from conftest import NOW, Harness, Key


def rebuild(t: Template, **changes) -> Template:
    return Template(replace(t.header, **changes), t.txs, t.subsidy, t.fees)


def test_bad_pow_rejected(harness, alice):
    t = harness.template(alice.h20)
    t = rebuild(t, target=1 << 200)  # wrong target AND (almost surely) no valid nonce
    blk = t.block_with_nonce(0)
    assert harness.chain.process_block(blk, NOW).status == "invalid"


def test_wrong_target_rejected_even_with_valid_pow(harness, alice):
    t = harness.template(alice.h20)
    blk = solve(rebuild(t, target=t.header.target >> 1))  # harder than required: still wrong
    res = harness.chain.process_block(blk, NOW)
    assert (res.status, res.reason) == ("invalid", "blk-bad-target")


def test_merkle_mismatch_rejected(harness, alice):
    t = harness.template(alice.h20)
    blk = solve(rebuild(t, merkle_root=b"\x01" * 32))
    assert harness.chain.process_block(blk, NOW).reason == "blk-merkle"


def test_timestamp_rules(harness, alice):
    harness.mine(alice.h20, 3)
    mtp = harness.chain.mtp(harness.chain.tip)
    old = solve(rebuild(harness.template(alice.h20), timestamp=mtp))
    assert harness.chain.process_block(old, NOW).reason == "blk-time-too-old"
    future = solve(harness.template(alice.h20, ts=NOW + REGTEST.max_future_drift + 1))
    assert harness.chain.process_block(future, NOW).reason == "blk-time-too-new"
    ok = solve(harness.template(alice.h20, ts=NOW + REGTEST.max_future_drift))
    assert harness.chain.process_block(ok, NOW).status == "connected"


def test_wrong_height_rejected(harness, alice):
    t = harness.template(alice.h20)
    blk = solve(rebuild(t, height=t.header.height + 1))
    assert harness.chain.process_block(blk, NOW).status == "invalid"


def test_orphan_then_parent(harness, alice, tmp_path):
    other = Harness(tmp_path / "other.sqlite3")
    b1, b2 = other.mine(alice.h20, 2)
    assert harness.chain.process_block(b2, NOW).status == "orphan"
    res = harness.chain.process_block(b1, NOW)
    assert res.status == "connected" and harness.chain.height == 2
    assert [b.hash for b in res.connected] == [b1.hash, b2.hash]
    other.db.close()


def test_reorg_to_more_work_and_back_utxos(harness, alice, bob, tmp_path):
    common = harness.mine(alice.h20, 2)
    a_branch = harness.mine(alice.h20, 2)  # active: 4 blocks
    other = Harness(tmp_path / "fork.sqlite3")
    for b in common:
        assert other.chain.process_block(b, NOW).status == "connected"
    b_branch = other.mine(bob.h20, 3, gap=16)  # longer competing branch
    res = None
    for b in b_branch:
        res = harness.chain.process_block(b, NOW)
    assert res.status == "connected"
    assert [b.hash for b in res.disconnected] == [a_branch[1].hash, a_branch[0].hash]
    assert harness.chain.tip.hash == b_branch[-1].hash
    # UTXO set reflects branch B only
    for b in a_branch:
        assert harness.chain.get_utxo((b.txs[0].txid, 0)) is None
        assert harness.chain.tx_location(b.txs[0].txid) is None
    for b in b_branch:
        assert harness.chain.get_utxo((b.txs[0].txid, 0)) is not None
    other.db.close()


def test_chain_selection_uses_work_not_length(harness, alice, bob):
    """Unit-level: a shorter branch with harder targets must win."""
    chain = harness.chain
    genesis = chain.tip
    w_easy, w_hard = work_from_target(REGTEST.pow_limit), work_from_target(REGTEST.pow_limit >> 4)
    assert 2 * w_easy < w_hard  # one hard block outweighs two easy ones
    # The rule as implemented: compare cumulative chainwork stored in the index.
    from quantis.core.chainstate import BlockIndex

    two_easy = BlockIndex(b"a", b"", 2, 0, REGTEST.pow_limit, genesis.chainwork + 2 * w_easy, 1, None)
    one_hard = BlockIndex(b"b", b"", 1, 0, REGTEST.pow_limit >> 4, genesis.chainwork + w_hard, 1, None)
    assert one_hard.chainwork > two_easy.chainwork and one_hard.height < two_easy.height


def test_equal_work_keeps_first_seen(harness, alice, bob, tmp_path):
    harness.mine(alice.h20, 1)
    first_tip = harness.chain.tip.hash
    other = Harness(tmp_path / "x.sqlite3")
    b = other.mine(bob.h20, 1)[0]
    assert harness.chain.process_block(b, NOW).status == "side"
    assert harness.chain.tip.hash == first_tip
    other.db.close()


def test_invalid_block_in_branch_rolls_back(harness, alice, bob, tmp_path):
    harness.mine(alice.h20, 2)
    snapshot_tip = harness.chain.tip.hash
    other = Harness(tmp_path / "bad.sqlite3")
    good = other.mine(bob.h20, 2, gap=20)
    # third block on the other branch overpays its coinbase (valid PoW and header)
    t = other.template(bob.h20)
    from quantis.core.tx import TxOut, make_coinbase

    cb = make_coinbase(t.header.height, [TxOut(t.subsidy * 2, bob.h20)])
    bad = solve(Template(replace(t.header, merkle_root=merkle_root([cb.txid])), [cb], 0, 0))
    harness.chain.process_block(good[0], NOW)
    res = harness.chain.process_block(good[1], NOW)
    assert res.status == "side"  # equal work: first seen kept
    res = harness.chain.process_block(bad, NOW)
    assert res.status == "invalid"
    assert harness.chain.tip.hash == snapshot_tip
    assert harness.chain.index[bad.hash].status == STATUS_INVALID
    assert harness.chain.get_utxo((good[0].txs[0].txid, 0)) is None  # rolled back
    other.db.close()


def test_persistence_and_restart(harness, alice, bob):
    harness.mine(alice.h20, 5)
    tip, height = harness.chain.tip.hash, harness.chain.height
    utxos = harness.db.all("SELECT * FROM utxo ORDER BY txid, vout")
    h2 = harness.reopen()
    assert h2.chain.tip.hash == tip and h2.chain.height == height
    assert h2.db.all("SELECT * FROM utxo ORDER BY txid, vout") == utxos
    h2.mine(bob.h20, 1)
    assert h2.chain.height == height + 1
    h2.db.close()


def test_wrong_network_data_dir(tmp_path):
    h = Harness(tmp_path / "c.sqlite3")
    h.db.close()
    from quantis.core.chainstate import ChainState
    from quantis.core.params import DEVNET
    from quantis.storage.db import Database

    with pytest.raises(RuntimeError):
        ChainState(Database(tmp_path / "c.sqlite3"), DEVNET)


def test_atomic_rollback_on_failure(harness, alice, monkeypatch):
    """If connecting fails midway, no partial state is written."""
    harness.mine(alice.h20, 1)
    before = harness.db.all("SELECT COUNT(*) FROM utxo")[0][0], harness.chain.height
    blk = solve(harness.template(alice.h20))
    import quantis.core.chainstate as cs

    def boom(*a, **k):
        raise cs.ValidationError("injected")

    monkeypatch.setattr(cs, "connect_block_txs", boom)
    assert harness.chain.process_block(blk, NOW).status == "invalid"
    assert (harness.db.all("SELECT COUNT(*) FROM utxo")[0][0], harness.chain.height) == before


def test_difficulty_enforced_on_chain(tmp_path, alice):
    """Mining fast blocks on a retarget network yields a harder required target."""
    from quantis.core.difficulty import first_retarget_height

    p = replace(REGTEST, pow_limit=(1 << 255) - 1, initial_target=1 << 250, retarget_window=4)
    h = Harness(tmp_path / "d.sqlite3", p)
    first = first_retarget_height(p)  # 16 for W = 4
    h.mine(alice.h20, first - 1, gap=1)  # far faster than 15 s
    assert h.chain.tip.target == p.initial_target  # unchanged before the first retarget
    expected = h.chain.next_target()
    assert expected < p.initial_target  # the next block is at a retarget height
    t = h.template(alice.h20)
    assert t.header.target == expected
    h.db.close()
