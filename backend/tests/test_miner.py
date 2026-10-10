"""Multi-process miner: finds valid blocks, pauses, resumes and stops cleanly."""
import time

from quantis.config import NodeConfig
from quantis.core.address import pubkey_to_address
from quantis.core.crypto import PrivateKey
from quantis.core.params import REGTEST
from quantis.node import Node

from nodeutil import wait_for


def test_miner_lifecycle(tmp_path):
    node = Node(NodeConfig(network="regtest", data_dir=str(tmp_path / "m")))
    addr = pubkey_to_address(PrivateKey(77).public_key(), REGTEST.address_version)
    try:
        node.miner.start(addr, workers=2)
        wait_for(lambda: node.miner.accepted >= 3, timeout=60, msg="3 mined blocks")
        assert node.chain.height >= 3
        assert node.miner.rejected == 0
        procs = list(node.miner._procs)
        assert all(p.is_alive() for p in procs)

        node.miner.pause()
        time.sleep(1.0)
        h = node.chain.height
        time.sleep(1.5)
        assert node.chain.height == h  # no progress while paused
        assert node.miner.state == "paused"

        node.miner.resume()
        wait_for(lambda: node.chain.height > h, timeout=60, msg="mining after resume")

        node.miner.set_low_power(True)
        assert node.miner.stats()["low_power"] is True

        t0 = time.time()
        node.miner.stop()
        assert time.time() - t0 < 10
        assert node.miner.state == "stopped"
        assert not any(p.is_alive() for p in procs)
        kinds = [e["kind"] for e in node.miner.log]
        assert {"start", "accepted", "pause", "resume", "stop"} <= set(kinds)
        assert node.miner.last_block["reward"] > 0
    finally:
        node.shutdown()


def test_miner_rejects_bad_address(tmp_path):
    node = Node(NodeConfig(network="regtest", data_dir=str(tmp_path / "m")))
    try:
        import pytest

        from quantis.mining.miner import MinerError

        with pytest.raises(MinerError):
            node.miner.start("notanaddress0000000000", workers=1)
        with pytest.raises(MinerError):
            node.miner.start(pubkey_to_address(PrivateKey(1).public_key(), REGTEST.address_version), workers=0)
    finally:
        node.shutdown()
