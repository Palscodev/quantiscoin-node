"""End-to-end through the website API: accounts -> wallet -> mining -> transfer -> explorer."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from quantis.api.app import create_api_app
from quantis.config import NodeConfig
from quantis.core.params import COIN, REGTEST
from quantis.node import Node
from quantis.wallet.keystore import Keystore, derive_secret

PASS = "correct horse battery"


class Site:
    """A node plus helpers to act as different browser sessions."""

    def __init__(self, tmp_path, **cfg):
        self.node = Node(NodeConfig(network="regtest", data_dir=str(tmp_path / "n"), **cfg))
        self.app = create_api_app(self.node)
        self.log: list[str] = []

    def client(self) -> TestClient:
        c = TestClient(self.app)
        original = c.request

        def logged(*a, **k):
            r = original(*a, **k)
            self.log.append(r.text)
            return r

        c.request = logged
        return c

    def admin(self) -> TestClient:
        c = self.client()
        r = c.post("/api/auth/setup", json={"username": "om", "password": PASS, "setup_code": self.node.accounts.setup_code})
        assert r.status_code == 200, r.text
        return c

    def user(self, name: str, password: str = PASS) -> TestClient:
        c = self.client()
        r = c.post("/api/auth/signup", json={"username": name, "password": password})
        assert r.status_code == 200, r.text
        return c


@pytest.fixture
def site(tmp_path):
    s = Site(tmp_path)
    yield s
    s.node.shutdown()


def gen(admin: TestClient, address: str, n: int):
    r = admin.post("/api/admin/generate", json={"address": address, "blocks": n})
    assert r.status_code == 200, r.text


def addr_of(c: TestClient) -> str:
    return c.get("/api/me/wallet").json()["addresses"][0]["address"]


def test_setup_requires_code_and_happens_once(site):
    c = site.client()
    state = c.get("/api/auth/state").json()
    assert state["setup_required"] and state["user"] is None
    r = c.post("/api/auth/signup", json={"username": "early", "password": PASS})
    assert r.status_code == 409  # no signups before an administrator exists
    r = c.post("/api/auth/setup", json={"username": "om", "password": PASS, "setup_code": "WRONG-CODE"})
    assert r.status_code == 403
    admin = site.admin()
    me = admin.get("/api/auth/state").json()["user"]
    assert me["username"] == "om" and me["is_admin"]
    r = site.client().post("/api/auth/setup", json={"username": "x2", "password": PASS, "setup_code": "ABCD-1234"})
    assert r.status_code == 409


def test_full_flow(site):
    admin = site.admin()
    alice, bob = site.user("alice"), site.user("bob")
    a_addr, b_addr = addr_of(alice), addr_of(bob)
    assert a_addr != b_addr

    gen(admin, a_addr, 2)
    w = alice.get("/api/me/wallet").json()
    assert w["balance"]["confirmed"] == 0 and w["balance"]["immature"] == 2000 * COIN
    gen(admin, b_addr, REGTEST.coinbase_maturity)
    assert alice.get("/api/me/wallet").json()["balance"]["confirmed"] == 2000 * COIN

    preview = alice.post("/api/me/preview", json={"to": b_addr, "amount": 1500 * COIN}).json()
    assert preview["fee"] >= preview["policy_min_fee"] > 0 and preview["meets_policy"]
    bad = alice.post("/api/me/send", json={"to": b_addr, "amount": 1500 * COIN, "fee": preview["fee"], "passphrase": "wrong pass"})
    assert bad.status_code == 400
    sent = alice.post("/api/me/send", json={"to": b_addr, "amount": 1500 * COIN, "fee": preview["fee"], "passphrase": PASS})
    assert sent.status_code == 200, sent.text
    txid = sent.json()["txid"]
    assert site.client().get(f"/api/tx/{txid}").json()["status"] == "pending"  # explorer is public
    assert bob.get("/api/me/wallet").json()["balance"]["unconfirmed"] == 1500 * COIN

    gen(admin, b_addr, 1)
    tx = site.client().get(f"/api/tx/{txid}").json()
    assert tx["confirmations"] == 1 and tx["fee"] == preview["fee"] and tx["signatures_valid"]
    a = alice.get("/api/me/wallet").json()
    assert a["balance"]["confirmed"] == 500 * COIN - preview["fee"]
    hist = alice.get("/api/me/history").json()["items"]
    assert hist[0]["txid"] == txid and hist[0]["net"] == -(1500 * COIN + preview["fee"])

    # Explorer and policy are public.
    pub = site.client()
    assert pub.get(f"/api/search?q={txid}").json()["kind"] == "tx"
    assert pub.get(f"/api/address/{b_addr}").json()["balance"] > 0
    assert pub.get("/api/policy").json()["supply"]["realized"] == REGTEST.halving_interval * (2 * 10**11 - 15)

    # Backup -> restore into a brand-new account with a different password.
    backup = alice.get("/api/me/backup").text
    r = site.client().post("/api/auth/signup", json={"username": "alice2", "password": "another password",
                                                      "backup": backup, "backup_passphrase": PASS})
    assert r.status_code == 200, r.text
    restored = site.client()
    restored.post("/api/auth/login", json={"username": "alice2", "password": "another password"})
    assert addr_of(restored) == a_addr
    assert restored.get("/api/me/wallet").json()["balance"]["confirmed"] == a["balance"]["confirmed"]

    # No private key, seed or password appears in ANY response (the encrypted backup included).
    seed = Keystore.from_json(backup, REGTEST.magic).unlock(PASS)
    secret = derive_secret(seed, 0)
    blob = "\n".join(site.log)
    for needle in (seed.hex(), f"{secret:064x}", str(secret), PASS, "another password"):
        assert needle not in blob


def test_wallets_are_private_and_admin_is_protected(site):
    admin = site.admin()
    alice = site.user("alice")
    anon = site.client()
    assert anon.get("/api/me/wallet").status_code == 401
    assert anon.post("/api/me/mine/job").status_code == 401
    for path in ("/api/admin/miner", "/api/admin/peers", "/api/admin/diagnostics", "/api/admin/users"):
        assert anon.get(path).status_code == 401
        assert alice.get(path).status_code == 403
        assert admin.get(path).status_code == 200
    # Logging out ends the session.
    alice.post("/api/auth/logout")
    assert alice.get("/api/me/wallet").status_code == 401


def test_login_rate_limit_and_password_change(site):
    site.admin()
    c = site.user("carol")
    c.post("/api/auth/logout")
    for _ in range(10):
        assert c.post("/api/auth/login", json={"username": "carol", "password": "nope nope"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "carol", "password": PASS}).status_code == 429

    d = site.user("dave")
    addr = addr_of(d)
    r = d.post("/api/auth/password", json={"current": PASS, "new": "brand new password"})
    assert r.status_code == 200, r.text
    d2 = site.client()
    assert d2.post("/api/auth/login", json={"username": "dave", "password": PASS}).status_code == 401
    assert d2.post("/api/auth/login", json={"username": "dave", "password": "brand new password"}).status_code == 200
    assert addr_of(d2) == addr
    # The wallet was re-encrypted: new address derivation needs the NEW password.
    assert d2.post("/api/me/addresses", json={"passphrase": PASS}).status_code == 400
    assert d2.post("/api/me/addresses", json={"passphrase": "brand new password"}).status_code == 200


def solve_job(job: dict) -> int:
    target = int(job["target"], 16)
    base = hashlib.sha256(bytes.fromhex(job["prefix"]))
    for nonce in range(1 << 20):
        h = base.copy()
        h.update(nonce.to_bytes(8, "little"))
        if int.from_bytes(hashlib.sha256(h.digest()).digest(), "big") <= target:
            return nonce
    raise AssertionError("no solution found")


def test_browser_mining_pays_the_user(site):
    site.admin()
    alice = site.user("alice")
    job = alice.post("/api/me/mine/job").json()
    assert len(bytes.fromhex(job["prefix"])) == 116 and job["height"] == 1
    # A wrong nonce is rejected, a real solution is accepted and pays alice.
    target = int(job["target"], 16)
    bad = next(n for n in range(1000) if int.from_bytes(hashlib.sha256(hashlib.sha256(
        bytes.fromhex(job["prefix"]) + n.to_bytes(8, "little")).digest()).digest(), "big") > target)
    assert alice.post("/api/me/mine/submit", json={"job_id": job["job_id"], "nonce": str(bad)}).json()["status"] == "rejected"
    r = alice.post("/api/me/mine/submit", json={"job_id": job["job_id"], "nonce": str(solve_job(job))}).json()
    assert r["status"] == "accepted" and r["height"] == 1 and r["reward"] == 1000 * COIN
    w = alice.get("/api/me/wallet").json()
    assert w["balance"]["immature"] == 1000 * COIN and w["blocks_mined_this_session"] == 1
    # Another user's job id cannot be used, and an old job is stale after the tip moves.
    bob = site.user("bob")
    assert bob.post("/api/me/mine/submit", json={"job_id": job["job_id"], "nonce": "0"}).json()["status"] == "stale"


def test_no_invented_dollar_price(site):
    admin = site.admin()
    assert site.client().get("/api/status").json()["usd_price"] is None
    assert admin.post("/api/admin/price", json={"usd_per_qts": 2.5}).status_code == 404


def test_input_validation_and_errors(site):
    site.admin()
    c = site.client()
    assert c.post("/api/auth/signup", json={"username": "x y", "password": PASS}).status_code == 422
    assert c.post("/api/auth/signup", json={"username": "okname", "password": "short"}).status_code == 422
    u = site.user("okname")
    assert site.client().post("/api/auth/signup", json={"username": "OKNAME", "password": PASS}).status_code == 400
    r = u.post("/api/me/preview", json={"to": "Q" * 30, "amount": 5})
    assert r.status_code == 400 and "address" in r.json()["detail"]
    r = u.post("/api/me/preview", json={"to": addr_of(u), "amount": 5})
    assert r.status_code == 400 and "insufficient" in r.json()["detail"]
    assert c.get("/api/blocks/99999").status_code == 404
    assert c.get("/api/tx/zz").status_code == 400
    assert c.get("/api/nope").status_code == 404


def test_host_and_origin_guards(site):
    c = site.client()
    assert c.get("/api/status", headers={"host": "evil.example:8331"}).status_code == 403
    r = c.post("/api/auth/login", json={"username": "a", "password": "b"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.get("/api/status")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]


def test_allowed_hosts_for_public_domain(tmp_path):
    s = Site(tmp_path, allowed_hosts=["quantis.example.org"])
    c = s.client()
    assert c.get("/api/status", headers={"host": "quantis.example.org"}).status_code == 200
    assert c.get("/api/status", headers={"host": "other.example.org"}).status_code == 403
    # Behind a tunnel that rewrites Host to 127.0.0.1, a POST from the public site is still accepted...
    r = c.post("/api/auth/login", json={"username": "x1", "password": "y"},
               headers={"host": "127.0.0.1:8080", "origin": "https://quantis.example.org"})
    assert r.status_code == 401  # reached the login handler (wrong credentials), not refused as cross-origin
    # ...but a POST from any other site is refused.
    r = c.post("/api/auth/login", json={"username": "x1", "password": "y"},
               headers={"host": "127.0.0.1:8080", "origin": "https://evil.example"})
    assert r.status_code == 403
    s.node.shutdown()


def test_generate_disabled_off_regtest(tmp_path):
    node = Node(NodeConfig(network="devnet", data_dir=str(tmp_path / "d")))
    c = TestClient(create_api_app(node))
    c.post("/api/auth/setup", json={"username": "om", "password": PASS, "setup_code": node.accounts.setup_code})
    r = c.post("/api/admin/generate", json={"address": "Q" * 30, "blocks": 1})
    assert r.status_code == 403
    node.shutdown()


def test_send_max_sweeps_wallet(site):
    admin = site.admin()
    alice, bob = site.user("alice"), site.user("bob")
    gen(admin, addr_of(alice), 2)
    gen(admin, addr_of(bob), REGTEST.coinbase_maturity)
    m = alice.get("/api/me/max").json()
    assert m["inputs"] == 2 and m["amount"] == 2000 * COIN - m["fee"]
    pv = alice.post("/api/me/preview", json={"to": addr_of(bob), "amount": m["amount"], "fee": m["fee"]}).json()
    assert pv["change"] == 0
    r = alice.post("/api/me/send", json={"to": addr_of(bob), "amount": m["amount"], "fee": m["fee"], "passphrase": PASS})
    assert r.status_code == 200, r.text
    assert alice.get("/api/me/wallet").json()["balance"]["confirmed"] == 0


def test_pending_payments_survive_restart(tmp_path):
    s = Site(tmp_path)
    admin = s.admin()
    alice, bob = s.user("alice"), s.user("bob")
    gen(admin, addr_of(alice), 1)
    gen(admin, addr_of(bob), REGTEST.coinbase_maturity)
    pv = alice.post("/api/me/preview", json={"to": addr_of(bob), "amount": 5 * COIN}).json()
    txid = alice.post("/api/me/send", json={"to": addr_of(bob), "amount": 5 * COIN, "fee": pv["fee"], "passphrase": PASS}).json()["txid"]
    s.node.shutdown()
    s2 = Site(tmp_path)  # same data directory: a restart
    assert bytes.fromhex(txid) in s2.node.mempool
    assert s2.client().get(f"/api/tx/{txid}").json()["status"] == "pending"
    s2.node.shutdown()


def test_health_robots_sitemap_and_hsts(site):
    c = site.client()
    h = c.get("/api/health").json()
    assert h["ok"] and h["height"] == 0
    robots = c.get("/robots.txt").text
    assert "Disallow: /wallet" in robots and "Sitemap: http://testserver/sitemap.xml" in robots
    sm = c.get("/sitemap.xml")
    assert sm.headers["content-type"].startswith("application/xml") and "<loc>http://testserver/faq</loc>" in sm.text
    assert "strict-transport-security" not in c.get("/api/status").headers  # plain HTTP: no HSTS


def test_hsts_behind_https_proxy(tmp_path):
    s = Site(tmp_path, trust_proxy=True)
    r = s.client().get("/api/status", headers={"x-forwarded-proto": "https"})
    assert "max-age=31536000" in r.headers["strict-transport-security"]
    s.node.shutdown()


def test_delete_account(site):
    admin = site.admin()
    bob = site.user("bob")
    assert bob.post("/api/auth/delete", json={"password": PASS, "confirm": "delete"}).status_code == 422
    assert bob.post("/api/auth/delete", json={"password": "wrong pw", "confirm": "DELETE"}).status_code == 400
    assert bob.post("/api/auth/delete", json={"password": PASS, "confirm": "DELETE"}).status_code == 200
    assert bob.get("/api/me/wallet").status_code == 401
    assert site.client().post("/api/auth/login", json={"username": "bob", "password": PASS}).status_code == 401
    assert not site.node.wallets.exists("u-2")
    # The only administrator cannot delete themselves.
    r = admin.post("/api/auth/delete", json={"password": PASS, "confirm": "DELETE"})
    assert r.status_code == 400 and "only administrator" in r.json()["detail"]


def test_admin_backup_is_a_valid_database(site, tmp_path):
    import sqlite3

    admin = site.admin()
    site.user("carol")
    r = admin.get("/api/admin/backup")
    assert r.status_code == 200
    copy = tmp_path / "copy.sqlite3"
    copy.write_bytes(r.content)
    db = sqlite3.connect(copy)
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    assert db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 1
    db.close()
    assert site.client().get("/api/admin/backup").status_code == 401


def test_backups_are_pruned(tmp_path):
    s = Site(tmp_path, backup_keep=2)
    for _ in range(4):
        s.node.backup_database()
    assert len(list(s.node.backup_dir.glob("chain-*.sqlite3"))) == 2
    s.node.shutdown()


def test_demo_exchange_moves_nothing(site):
    site.admin()
    u = site.user("trader")
    assert site.client().get("/api/exchange/info").json() == {"provider": "demo", "demo": True}
    q = u.post("/api/me/exchange/quote", json={"side": "buy", "qts": 10 * COIN}).json()
    assert q["demo"] and q["usd_cents"] == 1000 + q["fee_cents"]
    r = u.post("/api/me/exchange/order", json={"side": "buy", "qts": 10 * COIN}).json()
    assert r["status"] == "simulated" and r["demo"]
    assert u.get("/api/me/wallet").json()["balance"]["confirmed"] == 0  # no coins created
    assert len(u.get("/api/me/exchange/orders").json()["items"]) == 1
    assert site.client().post("/api/me/exchange/order", json={"side": "buy", "qts": 1}).status_code == 401


def test_partner_exchange_requires_key_and_live_flag(tmp_path):
    with pytest.raises(ValueError):
        Site(tmp_path, exchange_provider="partner")
    s = Site(tmp_path / "b", exchange_provider="partner", exchange_api_key="k", exchange_live=True)
    s.admin()
    r = s.user("xy").post("/api/me/exchange/quote", json={"side": "buy", "qts": COIN})
    assert r.status_code == 400 and "not been connected" in r.json()["detail"]
    s.node.shutdown()
