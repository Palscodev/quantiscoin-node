"""Website API + SSE + static frontend.

Access levels
  public  : network status, explorer, monetary policy, live events (read-only)
  user    : own wallet (balances, send, backup), browser mining   [session cookie]
  admin   : node CPU miner, peers, diagnostics, reference price, users

The browser is never trusted: every write goes through the same validation as
P2P data, and no endpoint returns private keys or seeds.
"""
from __future__ import annotations

import asyncio
import logging
import mimetypes
import os
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse

from ..auth import AuthError, RateLimiter, User
from ..core.address import AddressError, decode_address
from ..core.block import Block
from ..core.difficulty import first_retarget_height, is_retarget_height
from ..core.encoding import DecodeError
from ..core.monetary import realized_supply, schedule, theoretical_supply
from ..core.params import COIN, SOFTWARE_VERSION, TICKER
from ..core.tx import Tx
from ..core.validation import ValidationError
from ..explorer import block_summary, block_view, tx_view
from ..exchange import ExchangeError
from ..mining.miner import MinerError
from ..mining.template import solve
from ..mining.webjobs import WebMiningError
from ..wallet.keystore import KeystoreError
from ..wallet.wallet import WalletError
from . import schemas

if TYPE_CHECKING:
    from ..node import Node

log = logging.getLogger("quantis.api")
mimetypes.add_type("application/manifest+json", ".webmanifest")
FRONTEND_DIST = Path(os.environ.get("QUANTIS_FRONTEND_DIST", Path(__file__).resolve().parents[3] / "frontend" / "dist"))
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "testserver"}
COOKIE = "quantis_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    ),
}


def _hex32(s: str) -> bytes:
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise HTTPException(400, "expected a 64-character hex hash")
    if len(b) != 32:
        raise HTTPException(400, "expected a 64-character hex hash")
    return b


def create_api_app(node: "Node") -> FastAPI:
    app = FastAPI(title="QuantisCoin API", version=SOFTWARE_VERSION, docs_url="/api/docs", openapi_url="/api/openapi.json")
    p = node.params
    cfg = node.config
    allowed_hosts = LOOPBACK_HOSTS | {h.lower() for h in cfg.allowed_hosts}
    limits = {
        "login_ip": RateLimiter(30, 900),
        "login_user": RateLimiter(10, 900),
        "signup_ip": RateLimiter(10, 3600),
        "job": RateLimiter(240, 60),
        "submit": RateLimiter(120, 60),
        "send": RateLimiter(30, 60),
        "secret": RateLimiter(20, 300),  # passphrase-checking endpoints
    }

    # ------------------------------------------------------------ helpers
    def client_ip(request: Request) -> str:
        if cfg.trust_proxy:
            for header in ("cf-connecting-ip", "x-forwarded-for"):
                v = request.headers.get(header)
                if v:
                    return v.split(",")[0].strip()[:64]
        return request.client.host if request.client else "?"

    def is_https(request: Request) -> bool:
        if cfg.cookie_secure == "always":
            return True
        if cfg.cookie_secure == "never":
            return False
        if request.url.scheme == "https":
            return True
        return cfg.trust_proxy and request.headers.get("x-forwarded-proto", "") == "https"

    def limit(name: str, key: str) -> None:
        if not limits[name].hit(key):
            raise HTTPException(429, "Too many attempts. Please wait a few minutes and try again.")

    def optional_user(request: Request) -> User | None:
        return node.accounts.session_user(request.cookies.get(COOKIE))

    def require_user(request: Request) -> User:
        user = optional_user(request)
        if user is None:
            raise HTTPException(401, "Please log in.")
        return user

    def require_admin(user: User = Depends(require_user)) -> User:
        if not user.is_admin:
            raise HTTPException(403, "Administrator access required.")
        return user

    def start_session(response: Response, request: Request, user: User) -> dict:
        token = node.accounts.new_session(user)
        response.set_cookie(COOKIE, token, max_age=node.accounts.session_seconds, httponly=True,
                            samesite="strict", secure=is_https(request), path="/")
        return {"user": user.public()}

    def ensure_wallet(user: User, password: str) -> None:
        """Create the user's wallet if it does not exist yet (e.g. accounts made from the CLI)."""
        if not node.wallets.exists(user.wallet_name):
            node.wallets.create_with_seed(user.wallet_name, password)

    # --------------------------------------------------------- middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Host check: defends against DNS rebinding. Origin check: defends against CSRF.
        host = (request.headers.get("host") or "").lower()
        hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if not cfg.allow_remote_api and hostname not in allowed_hosts:
            return JSONResponse({"detail": "host not allowed (add it to allowed_hosts in the config)"}, status_code=403)
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and origin != "null":
                o = urlparse(origin)
                same_host = o.netloc.lower() == host
                configured = (o.hostname or "").lower() in {h.lower() for h in cfg.allowed_hosts}
                if not (same_host or configured):
                    return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
        t0 = time.perf_counter()
        response = await call_next(request)
        took = time.perf_counter() - t0
        if took > 2.0 and request.url.path != "/api/events":
            log.warning("slow API request %s %s took %.2fs", request.method, request.url.path, took)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if is_https(request):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.exception_handler(WalletError)
    @app.exception_handler(ValidationError)
    @app.exception_handler(AuthError)
    @app.exception_handler(KeystoreError)
    @app.exception_handler(MinerError)
    @app.exception_handler(ExchangeError)
    @app.exception_handler(WebMiningError)
    @app.exception_handler(ValueError)
    async def bad_request(_: Request, exc: Exception):
        msg = exc.message if isinstance(exc, ValidationError) else str(exc)
        return JSONResponse({"detail": msg}, status_code=400)

    # ================================================================ auth
    @app.get("/api/auth/state")
    def auth_state(request: Request):
        user = optional_user(request)
        return {
            "user": user.public() if user else None,
            "setup_required": not node.accounts.has_admin(),
            "signup_open": cfg.allow_signup,
        }

    @app.post("/api/auth/setup")
    def auth_setup(body: schemas.Setup, request: Request, response: Response):
        limit("signup_ip", client_ip(request))
        with node.lock:
            code = node.accounts.setup_code
            if code is None:
                raise HTTPException(409, "Setup has already been completed.")
            if body.setup_code.strip().upper() != code:
                raise HTTPException(403, "Wrong setup code. It is printed in the node's console window.")
            return _signup(body, request, response, admin=True)

    @app.post("/api/auth/signup")
    def auth_signup(body: schemas.Signup, request: Request, response: Response):
        if not cfg.allow_signup:
            raise HTTPException(403, "New accounts are disabled on this server.")
        if not node.accounts.has_admin():
            raise HTTPException(409, "This server has not been set up yet.")
        limit("signup_ip", client_ip(request))
        with node.lock:
            return _signup(body, request, response, admin=False)

    def _signup(body: schemas.Signup, request: Request, response: Response, admin: bool) -> dict:
        seed, n_addr = None, 1
        if body.backup:
            seed, n_addr = node.wallets.seed_from_backup(body.backup, body.backup_passphrase or "")
        user = node.accounts.create(body.username, body.password, is_admin=admin)
        try:
            node.wallets.create_with_seed(user.wallet_name, body.password, seed=seed, n_addresses=n_addr)
        except Exception:
            node.db.execute("DELETE FROM users WHERE id=?", (user.id,))
            raise
        log.info("account created: %s%s", user.username, " (administrator)" if admin else "")
        return start_session(response, request, user)

    @app.post("/api/auth/login")
    def auth_login(body: schemas.Credentials, request: Request, response: Response):
        ip = client_ip(request)
        limit("login_ip", ip)
        limit("login_user", body.username.lower())
        user = node.accounts.authenticate(body.username, body.password)
        if user is None:
            raise HTTPException(401, "Wrong username or password.")
        limits["login_user"].reset(body.username.lower())
        with node.lock:
            ensure_wallet(user, body.password)
        return start_session(response, request, user)

    @app.post("/api/auth/logout")
    def auth_logout(request: Request, response: Response):
        node.accounts.end_session(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.post("/api/auth/password")
    def auth_password(body: schemas.PasswordChange, request: Request, response: Response,
                      user: User = Depends(require_user)):
        limit("secret", f"u{user.id}")
        if node.accounts.authenticate(user.username, body.current) is None:
            raise HTTPException(400, "Your current password is not correct.")
        with node.lock:
            node.wallets.change_passphrase(user.wallet_name, body.current, body.new)
            node.accounts.set_password(user.id, body.new)
            node.accounts.end_all_sessions(user.id)
        return start_session(response, request, user)

    @app.post("/api/auth/delete")
    def auth_delete(body: schemas.DeleteAccount, request: Request, response: Response,
                    user: User = Depends(require_user)):
        limit("secret", f"u{user.id}")
        if node.accounts.authenticate(user.username, body.password) is None:
            raise HTTPException(400, "Your password is not correct.")
        if user.is_admin and node.accounts.admin_count() <= 1:
            raise HTTPException(400, "You are the only administrator. Make someone else an administrator first.")
        with node.lock:
            node.accounts.delete(user.id)
        response.delete_cookie(COOKIE, path="/")
        log.info("account deleted: %s", user.username)
        return {"ok": True}

    # ============================================================ public
    @app.get("/api/health")
    def health():
        """Liveness/readiness probe for hosting platforms and uptime monitors."""
        try:
            node.db.one("SELECT 1")
            return {"ok": True, "height": node.chain.height, "version": SOFTWARE_VERSION,
                    "uptime": round(time.time() - node.started_at)}
        except Exception as e:  # database unavailable
            return JSONResponse({"ok": False, "error": type(e).__name__}, status_code=503)

    @app.get("/api/status")
    def status():
        return node.status()

    @app.get("/api/policy")
    def policy(window: int = 200):
        window = max(10, min(window, 2000))
        with node.lock:
            chain = node.chain
            start = max(2, chain.height - window + 1)
            blocks = []
            for h in range(start, chain.height + 1):
                idx = chain.active[h]
                blocks.append(
                    {
                        "height": h,
                        "timestamp": idx.timestamp,
                        "interval": idx.timestamp - chain.active[h - 1].timestamp,
                        "difficulty": p.pow_limit / idx.target,
                        "retarget": is_retarget_height(h, p),
                    }
                )
            mempool_bytes = node.mempool.bytes
            next_target = chain.next_target()
        pol = node.mempool.policy
        return {
            "ticker": TICKER,
            "coin": COIN,
            "consensus": asdict(p) | {"pow_limit": f"{p.pow_limit:064x}", "initial_target": f"{p.initial_target:064x}"},
            "magic": p.magic.hex(),
            "supply": {
                "theoretical": theoretical_supply(p),
                "realized": realized_supply(p),
                "rounding_loss": theoretical_supply(p) - realized_supply(p),
                "popcount_r0": p.initial_reward.bit_count(),
                "last_rewarding_era": p.initial_reward.bit_length() - 1,
            },
            "schedule": schedule(p),
            "difficulty": {
                "window": p.retarget_window,
                "first_retarget_height": first_retarget_height(p),
                "expected_window_seconds": p.retarget_window * p.target_block_time,
                "damping": p.damping,
                "clamp_factor": p.clamp_factor,
                "min_factor": ((p.damping - 1) + 1 / p.clamp_factor) / p.damping,
                "max_factor": ((p.damping - 1) + p.clamp_factor) / p.damping,
                "next_target": f"{next_target:064x}",
                "next_difficulty": p.pow_limit / next_target,
                "blocks": blocks,
            },
            "fees": {
                "base_rate": pol.base_rate,
                "max_multiplier": pol.max_multiplier,
                "target_bytes": pol.target_bytes,
                "mempool_bytes": mempool_bytes,
                "current_rate": pol.rate(mempool_bytes),
                "consensus_floor_rate": p.min_fee_per_byte,
            },
        }

    @app.get("/api/blocks")
    def blocks(offset: int = 0, limit: int = 25):
        limit = max(1, min(limit, 100))
        with node.lock:
            top = node.chain.height - max(0, offset)
            items = [block_summary(node.chain, h) for h in range(top, max(-1, top - limit), -1)]
            return {"total": node.chain.height + 1, "offset": offset, "items": items}

    @app.get("/api/blocks/{ident}")
    def block(ident: str):
        with node.lock:
            if ident.isdigit():
                h = int(ident)
                if h > node.chain.height:
                    raise HTTPException(404, "There is no block at that height yet.")
                blk = node.chain.get_block(node.chain.active[h].hash)
            else:
                blk = node.chain.get_block(_hex32(ident))
                if blk is None:
                    raise HTTPException(404, "Block not found.")
            return block_view(node.chain, blk)

    @app.get("/api/tx/{txid}")
    def tx(txid: str):
        t = _hex32(txid)
        with node.lock:
            found = node.chain.get_tx(t)
            if found:
                tx_, height, bh = found
                return tx_view(node.chain, node.mempool, tx_, height, bh)
            entry = node.mempool.entries.get(t)
            if entry:
                return tx_view(node.chain, node.mempool, entry.tx, None, None)
        raise HTTPException(404, "Transaction not found.")

    @app.get("/api/address/{address}")
    def address(address: str, limit: int = 50):
        try:
            h20 = decode_address(address, p.address_version)
        except AddressError as e:
            raise HTTPException(400, str(e))
        with node.lock:
            utxos = node.db.all("SELECT txid, vout, amount, height, coinbase FROM utxo WHERE h20=?", (h20,))
            rows = node.db.all("SELECT txid, height FROM addrtx WHERE h20=? ORDER BY height DESC LIMIT ?",
                               (h20, max(1, min(limit, 200))))
            tip = node.chain.height
        return {
            "address": address,
            "balance": sum(u[2] for u in utxos),
            "utxo_count": len(utxos),
            "utxos": [
                {"txid": u[0].hex(), "vout": u[1], "amount": u[2], "height": u[3], "coinbase": bool(u[4]),
                 "confirmations": tip - u[3] + 1}
                for u in utxos[:200]
            ],
            "txs": [{"txid": r[0].hex(), "height": r[1], "confirmations": tip - r[1] + 1} for r in rows],
        }

    @app.get("/api/search")
    def search(q: str):
        q = q.strip()
        if q.isdigit():
            if int(q) <= node.chain.height:
                return {"kind": "block", "id": q}
            raise HTTPException(404, "There is no block at that height yet.")
        try:
            decode_address(q, p.address_version)
            return {"kind": "address", "id": q}
        except AddressError:
            pass
        try:
            b = bytes.fromhex(q)
        except ValueError:
            raise HTTPException(404, "Enter a block number, block hash, transaction ID or address.")
        if len(b) == 32:
            if b in node.chain.index:
                return {"kind": "block", "id": q.lower()}
            if node.chain.tx_location(b) or b in node.mempool:
                return {"kind": "tx", "id": q.lower()}
        raise HTTPException(404, "Nothing found.")

    @app.get("/api/mempool")
    def mempool():
        with node.lock:
            entries = sorted(node.mempool.entries.values(), key=lambda e: (-e.feerate, e.tx.txid))
            return {
                "count": len(entries),
                "bytes": node.mempool.bytes,
                "max_bytes": node.mempool.max_bytes,
                "relay_rate": node.mempool.policy.rate(node.mempool.bytes),
                "items": [
                    {"txid": e.tx.txid.hex(), "fee": e.fee, "size": e.size, "fee_rate": e.fee / e.size,
                     "time": e.time, "total_out": e.tx.total_out()}
                    for e in entries[:500]
                ],
            }

    @app.get("/api/events")
    async def events(request: Request):
        q = node.events.subscribe()

        async def stream():
            try:
                yield 'event: status\ndata: {"data": null}\n\n'
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(q.get(), timeout=15)
                        yield item
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                node.events.unsubscribe(q)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ============================================================== user
    @app.get("/api/me/wallet")
    def my_wallet(user: User = Depends(require_user)):
        with node.lock:
            summary = node.wallets.summary(user.wallet_name)
        summary["name"] = user.username
        summary["blocks_mined_this_session"] = node.webjobs.found.get(user.id, 0)
        return summary

    @app.get("/api/me/history")
    def my_history(limit: int = 50, user: User = Depends(require_user)):
        with node.lock:
            return {"items": node.wallets.history(user.wallet_name, max(1, min(limit, 200)))}

    @app.post("/api/me/addresses")
    def my_new_address(body: schemas.Passphrase, user: User = Depends(require_user)):
        limit("secret", f"u{user.id}")
        with node.lock:
            e = node.wallets.new_address(user.wallet_name, body.passphrase)
            return {"index": e["index"], "address": e["address"]}

    @app.post("/api/me/preview")
    def my_preview(body: schemas.TxPreview, user: User = Depends(require_user)):
        with node.lock:
            return node.wallets.preview(user.wallet_name, body.to, body.amount, body.fee_rate, body.fee)

    @app.get("/api/me/max")
    def my_max(fee_rate: int | None = None, user: User = Depends(require_user)):
        if fee_rate is not None and not (0 <= fee_rate <= 1_000_000):
            raise HTTPException(400, "fee rate out of range")
        with node.lock:
            return node.wallets.max_sendable(user.wallet_name, fee_rate)

    @app.post("/api/me/send")
    def my_send(body: schemas.TxSend, user: User = Depends(require_user)):
        limit("send", f"u{user.id}")
        with node.lock:
            result = node.wallets.send(user.wallet_name, body.passphrase, body.to, body.amount, body.fee)
            entry = node.mempool.entries[bytes.fromhex(result["txid"])]
            node.persist_mempool()
        node.events.publish("tx", {"txid": result["txid"], "fee": entry.fee, "size": entry.size})
        node.peers.broadcast_tx(entry.tx)
        return result

    @app.get("/api/me/backup")
    def my_backup(user: User = Depends(require_user)):
        text = node.wallets.export_backup(user.wallet_name)
        return PlainTextResponse(
            text, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="quantiscoin-wallet-{user.username}.json"'},
        )

    @app.post("/api/me/mine/job")
    def mine_job(user: User = Depends(require_user)):
        limit("job", f"u{user.id}")
        payout = decode_address(node.wallets.first_address(user.wallet_name), p.address_version)
        return node.webjobs.new_job(user.id, payout)

    @app.post("/api/me/mine/submit")
    def mine_submit(body: schemas.MineSubmit, user: User = Depends(require_user)):
        limit("submit", f"u{user.id}")
        return node.webjobs.submit(user.id, body.job_id, int(body.nonce))

    @app.get("/api/exchange/info")
    def exchange_info():
        return node.exchange.info()

    @app.get("/api/me/exchange/account")
    def exchange_account(user: User = Depends(require_user)):
        return node.exchange.account(user.id)

    @app.post("/api/me/exchange/quote")
    def exchange_quote(body: schemas.ExchangeQuote, user: User = Depends(require_user)):
        return node.exchange.quote(user.id, body.side, body.qts, body.usd_cents).view()

    @app.post("/api/me/exchange/buy")
    def exchange_buy(body: schemas.ExchangeBuy, user: User = Depends(require_user)):
        limit("send", f"u{user.id}")
        return node.exchange.buy(user.id, body.quote_id, body.method, body.card.model_dump() if body.card else None)

    @app.post("/api/me/exchange/sell")
    def exchange_sell(body: schemas.ExchangeSell, user: User = Depends(require_user)):
        limit("send", f"u{user.id}")
        return node.exchange.sell(user.id, body.quote_id)

    @app.post("/api/tx/raw")
    def submit_raw(body: schemas.RawTx, user: User = Depends(require_user)):
        try:
            t = Tx.deserialize(bytes.fromhex(body.hex))
        except DecodeError as e:
            raise HTTPException(400, f"malformed transaction: {e}")
        node.submit_tx(t)
        return {"txid": t.txid.hex()}

    # ============================================================= admin
    @app.get("/api/admin/miner")
    def miner(_: User = Depends(require_admin)):
        return node.miner.stats()

    @app.get("/api/admin/miner/log")
    def miner_log(_: User = Depends(require_admin)):
        return {"items": list(node.miner.log)[::-1]}

    @app.post("/api/admin/miner/start")
    def miner_start(body: schemas.MinerStart, _: User = Depends(require_admin)):
        return node.miner.start(body.address, body.workers, body.low_power)

    @app.post("/api/admin/miner/pause")
    def miner_pause(_: User = Depends(require_admin)):
        return node.miner.pause()

    @app.post("/api/admin/miner/resume")
    def miner_resume(_: User = Depends(require_admin)):
        return node.miner.resume()

    @app.post("/api/admin/miner/stop")
    def miner_stop(_: User = Depends(require_admin)):
        return node.miner.stop()

    @app.post("/api/admin/miner/low-power")
    def miner_low_power(body: schemas.LowPower, _: User = Depends(require_admin)):
        return node.miner.set_low_power(body.enabled)

    @app.get("/api/admin/peers")
    def peers(_: User = Depends(require_admin)):
        return {"self": node.peers.self_url, "items": node.peers.list(),
                "banned": [{"peer": k, "until": v} for k, v in node.peers.banned.items()]}

    @app.post("/api/admin/peers")
    def peer_add(body: schemas.PeerAdd, _: User = Depends(require_admin)):
        node.peers.add(body.url)
        return {"items": node.peers.list()}

    @app.delete("/api/admin/peers")
    def peer_remove(url: str, _: User = Depends(require_admin)):
        node.peers.remove(url)
        return {"items": node.peers.list()}

    @app.get("/api/admin/users")
    def users(_: User = Depends(require_admin)):
        return {"items": [u.public() for u in node.accounts.list()]}

    @app.post("/api/admin/users/{user_id}/admin")
    def set_admin(user_id: int, body: schemas.AdminFlag, me: User = Depends(require_admin)):
        if user_id == me.id and not body.is_admin:
            raise HTTPException(400, "You cannot remove your own administrator access.")
        if node.accounts.get(user_id) is None:
            raise HTTPException(404, "No such user.")
        node.accounts.set_admin(user_id, body.is_admin)
        return {"items": [u.public() for u in node.accounts.list()]}

    @app.get("/api/admin/backup")
    def admin_backup(_: User = Depends(require_admin)):
        path = node.backup_database()
        return FileResponse(path, media_type="application/octet-stream", filename=path.name)

    @app.get("/api/admin/diagnostics")
    def diagnostics(_: User = Depends(require_admin)):
        db_file = node.config.db_path
        with node.lock:
            counts = {
                "blocks_stored": node.db.one("SELECT COUNT(*) FROM blocks")[0],
                "blocks_invalid": node.db.one("SELECT COUNT(*) FROM blocks WHERE status=2")[0],
                "utxos": node.db.one("SELECT COUNT(*) FROM utxo")[0],
                "indexed_txs": node.db.one("SELECT COUNT(*) FROM txindex")[0],
                "orphans": len(node.chain.orphans),
                "side_chain_blocks": len(node.chain.index) - len(node.chain.active),
            }
        return {
            "software_version": SOFTWARE_VERSION,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "uptime": time.time() - node.started_at,
            "database": {"path": str(db_file), "bytes": db_file.stat().st_size if db_file.exists() else 0, **counts},
            "events_published": node.events.counter,
            "users": node.accounts.count(),
            "local_config": node.config.public_dict(),
            "consensus": {k: (f"{v:064x}" if k in ("pow_limit", "initial_target") else v) for k, v in asdict(p).items()},
            "magic": p.magic.hex(),
            "genesis": node.chain.active[0].hash.hex(),
        }

    @app.post("/api/admin/generate")
    def generate(body: schemas.Generate, _: User = Depends(require_admin)):
        if p.name != "regtest":
            raise HTTPException(403, "Instant block generation is only available on regtest.")
        h20 = decode_address(body.address, p.address_version)
        hashes = []
        for _i in range(body.blocks):
            blk: Block = solve(node.build_template(h20))
            res = node.submit_block(blk, source="generate")
            if res.status != "connected":
                raise HTTPException(500, f"generated block not accepted: {res.reason}")
            hashes.append(blk.hash.hex())
        return {"hashes": hashes}

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def api_not_found(rest: str):
        raise HTTPException(404, "Unknown API endpoint.")

    # ===================================================== search engines
    PUBLIC_PAGES = ["", "how-it-works", "get-started", "mining", "economics", "economics/technical",
                    "explorer", "network", "faq", "terms", "privacy", "signup"]

    def site_origin(request: Request) -> str:
        scheme = "https" if is_https(request) else request.url.scheme
        return f"{scheme}://{request.headers.get('host', 'localhost')}"

    @app.get("/robots.txt", include_in_schema=False)
    def robots(request: Request):
        return PlainTextResponse(
            "User-agent: *\nDisallow: /api/\nDisallow: /wallet\nDisallow: /mine\nDisallow: /account\n"
            f"Disallow: /admin\nSitemap: {site_origin(request)}/sitemap.xml\n"
        )

    @app.get("/sitemap.xml", include_in_schema=False)
    def sitemap(request: Request):
        base = site_origin(request)
        urls = "".join(f"<url><loc>{base}/{p}</loc></url>" for p in PUBLIC_PAGES)
        return Response(
            f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
            media_type="application/xml",
        )

    # ========================================================== frontend
    dist = FRONTEND_DIST.resolve()
    if dist.is_dir():
        index = dist / "index.html"

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            # Serve real files (assets, favicon); every other path is a page of the single-page app.
            candidate = (dist / path).resolve()
            if path and candidate.is_file() and dist in candidate.parents:
                cache = "public, max-age=31536000, immutable" if path.startswith("assets/") else "no-cache"
                return FileResponse(candidate, headers={"Cache-Control": cache})
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
    else:
        @app.get("/", include_in_schema=False)
        def no_ui():
            return PlainTextResponse(
                "QuantisCoin node is running.\n"
                "No website files are installed on this node; the blockchain, P2P network and API are working.\n"
                "API documentation: /api/docs    Status: /api/status\n"
            )

    return app
