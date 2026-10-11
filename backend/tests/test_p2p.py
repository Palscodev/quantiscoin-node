"""Multi-node networking over real localhost HTTP servers."""
import httpx
import pytest

from quantis.core.address import pubkey_to_address
from quantis.core.crypto import PrivateKey
from quantis.core.params import COIN, REGTEST

from nodeutil import RunningNode, wait_for

PASS = "correct horse battery"
ADDR_A = pubkey_to_address(PrivateKey(101).public_key(), REGTEST.address_version)
ADDR_C = pubkey_to_address(PrivateKey(303).public_key(), REGTEST.address_version)


def gen(node: RunningNode, address: str, n: int):
    r = node.admin().post("/api/admin/generate", json={"address": address, "blocks": n})
    assert r.status_code == 200, r.text


@pytest.fixture
def nodes(tmp_path):
    started = []

    def make(name, **kw):
        n = RunningNode(tmp_path / name, **kw)
        started.append(n)
        return n

    yield make
    for n in started:
        n.stop()


def test_block_and_tx_propagation_and_reconnect(nodes):
    a = nodes("a")
    b = nodes("b", peers=[a.p2p_url])
    gen(a, ADDR_A, 5)
    wait_for(lambda: b.node.chain.tip.hash == a.node.chain.tip.hash, msg="b syncs to a")
    assert a.p2p_url in [p["url"] for p in b.node.peers.list()]
    wait_for(lambda: b.p2p_url in [p["url"] for p in a.node.peers.list()], msg="a learns b (registration)")

    # Transaction relay: a user on A pays a user on B
    ua, ub = a.user("alice"), b.user("bob")
    wa, wb = ua.get("/api/me/wallet").json(), ub.get("/api/me/wallet").json()
    gen(a, wa["addresses"][0]["address"], 1)
    gen(a, ADDR_A, REGTEST.coinbase_maturity)
    to = wb["addresses"][0]["address"]
    pv = ua.post("/api/me/preview", json={"to": to, "amount": 10 * COIN}).json()
    r = ua.post("/api/me/send", json={"to": to, "amount": 10 * COIN, "fee": pv["fee"], "passphrase": PASS})
    assert r.status_code == 200, r.text
    txid = bytes.fromhex(r.json()["txid"])
    wait_for(lambda: txid in b.node.mempool, msg="tx relayed to b")
    gen(a, ADDR_A, 1)
    wait_for(lambda: b.node.chain.tx_location(txid) is not None, msg="confirmed on b")
    assert len(b.node.mempool) == 0
    bal = ub.get("/api/me/wallet").json()["balance"]["confirmed"]
    assert bal == 10 * COIN

    # Temporary disconnection: B drops A, A advances, B re-adds A and catches up.
    b.node.peers.remove(a.p2p_url)
    a.node.peers.remove(b.p2p_url)
    gen(a, ADDR_A, 4)
    assert b.node.chain.height < a.node.chain.height
    b.node.peers.add(a.p2p_url)
    wait_for(lambda: b.node.chain.tip.hash == a.node.chain.tip.hash, msg="b catches up after reconnect")


def test_competing_chains_resolve_by_work(nodes):
    a = nodes("a")
    c = nodes("c")
    gen(a, ADDR_A, 3)
    gen(c, ADDR_C, 6)  # isolated, more cumulative work (equal targets on regtest)
    assert a.node.chain.tip.hash != c.node.chain.tip.hash
    a.node.peers.add(c.p2p_url)
    wait_for(lambda: a.node.chain.tip.hash == c.node.chain.tip.hash, msg="a reorgs to c's heavier chain")
    assert a.node.chain.height == 6
    # A's original blocks remain stored as a side chain; its coinbases are no longer spendable.
    assert len(a.node.chain.index) == 1 + 3 + 6


def test_malformed_and_oversized_messages_rejected(nodes):
    a = nodes("a", max_message_bytes=4096)
    h = {"X-Quantis-Magic": REGTEST.magic.hex(), "X-Quantis-Peer": "http://127.0.0.1:1"}
    r = httpx.post(f"{a.p2p_url}/p2p/block", content=b"\x00garbage", headers=h)
    assert r.status_code == 400
    r = httpx.post(f"{a.p2p_url}/p2p/tx", content=b"\xff" * 10, headers=h)
    assert r.status_code == 400
    r = httpx.post(f"{a.p2p_url}/p2p/block", content=b"\0" * 5000, headers=h)
    assert r.status_code == 413
    r = httpx.get(f"{a.p2p_url}/p2p/hello", headers={"X-Quantis-Magic": "deadbeef"})
    assert r.status_code == 400
    # Repeated garbage gets the sender banned.
    for _ in range(5):
        httpx.post(f"{a.p2p_url}/p2p/block", content=b"\x01junk", headers=h)
    assert httpx.get(f"{a.p2p_url}/p2p/hello", headers=h).status_code == 403
    r = httpx.post(f"{a.p2p_url}/p2p/hello", json={"url": "http://10.9.9.9:9000"})
    assert r.status_code == 400  # may only advertise its own host


def test_wrong_network_peer_ignored(nodes):
    a = nodes("a")
    d = nodes("d", network="devnet")  # different consensus params -> different magic and genesis
    gen(a, ADDR_A, 2)
    a.node.peers.add(d.p2p_url)
    a.node.peers.request_sync()
    wait_for(lambda: a.node.peers.peers[d.p2p_url].last_error != "", msg="handshake rejected")
    assert not a.node.peers.peers[d.p2p_url].connected
    assert a.node.chain.height == 2 and d.node.chain.height == 0


def test_peer_url_normalization():
    from quantis.p2p.peers import normalize_url

    assert normalize_url("https://p2p.example.org") == "https://p2p.example.org:443"
    assert normalize_url("http://127.0.0.1:9331/") == "http://127.0.0.1:9331"
    assert normalize_url("http://host.example") == "http://host.example:80"
    for bad in ("ftp://x:1", "http://x:1/path", "http://user@x:1", "http://x:99999", "not a url"):
        with pytest.raises(ValueError):
            normalize_url(bad)


def test_proxied_loopback_registration_refused(nodes):
    a = nodes("a")
    # Through a tunnel/proxy every request looks local; a loopback URL would point at the hub itself.
    r = httpx.post(f"{a.p2p_url}/p2p/hello", json={"url": "http://127.0.0.1:9999"},
                   headers={"X-Forwarded-For": "203.0.113.7"})
    assert r.status_code == 400
    assert "http://127.0.0.1:9999" not in [p["url"] for p in a.node.peers.list()]
    # A direct local registration (local test networks) still works.
    r = httpx.post(f"{a.p2p_url}/p2p/hello", json={"url": "http://127.0.0.1:9998"})
    assert r.status_code == 200 and r.json()["added"]


def test_local_host_classification():
    from quantis.p2p.peers import _is_local_host

    assert _is_local_host("127.0.0.1") and _is_local_host("192.168.1.20") and _is_local_host("localhost")
    assert not _is_local_host("p2p.example.org") and not _is_local_host("8.8.8.8")


def test_home_node_joins_through_the_website_address_without_approval(nodes):
    # The public site answers P2P on its own web address; a home node is given only that address.
    site = nodes("site", p2p_on_api=True)
    home = nodes("home", peers=[site.api_url])
    gen(site, ADDR_A, 3)
    wait_for(lambda: home.node.chain.tip.hash == site.node.chain.tip.hash, msg="home node syncs from the site")
    gen(home, ADDR_C, 2)  # blocks mined at home reach the site with nobody adding the home node
    wait_for(lambda: site.node.chain.tip.hash == home.node.chain.tip.hash, msg="site accepts the home node's blocks")
    assert site.node.chain.height == 5
