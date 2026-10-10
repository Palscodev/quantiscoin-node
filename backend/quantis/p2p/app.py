"""P2P HTTP server. Untrusted input: every body is size-limited and fully validated."""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..core.block import Block
from ..core.encoding import DecodeError
from ..core.params import PROTOCOL_VERSION, SOFTWARE_VERSION
from ..core.tx import Tx
from ..core.validation import ValidationError
from .peers import normalize_url

if TYPE_CHECKING:
    from ..node import Node

# Transaction rejection codes that indicate a malformed/invalid tx rather than a policy
# difference or a race (those are not punished).
PUNISHABLE_TX = {"tx-bad-signature", "tx-wrong-key", "tx-bad-pubkey", "tx-bad-sig-length", "tx-amount-range",
                 "tx-duplicate-input", "tx-null-input", "tx-version", "tx-oversize", "txn-coinbase"}


class BodyLimit:
    """ASGI middleware: reject request bodies larger than `limit` bytes, even if chunked."""

    def __init__(self, app, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length" and v.isdigit() and int(v) > self.limit:
                return await JSONResponse({"error": "message too large"}, status_code=413)(scope, receive, send)
        seen = 0

        async def limited():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.limit:
                    raise HTTPException(413, "message too large")
            return msg

        return await self.app(scope, limited, send)


def create_p2p_app(node: "Node") -> FastAPI:
    app = FastAPI(title="QuantisCoin P2P", docs_url=None, redoc_url=None, openapi_url=None)
    magic = node.params.magic.hex()
    peers = node.peers

    def client_id(request: Request) -> str:
        return request.headers.get("x-quantis-peer") or (request.client.host if request.client else "?")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        who = client_id(request)
        host = request.client.host if request.client else "?"
        if peers.is_banned(who) or peers.is_banned(host):
            return JSONResponse({"error": "banned"}, status_code=403)
        if request.headers.get("x-quantis-magic", magic) != magic:
            return JSONResponse({"error": "wrong network"}, status_code=400)
        return await call_next(request)

    @app.get("/p2p/hello")
    def hello():
        with node.lock:
            tip = node.chain.tip
            return {
                "agent": f"QuantisCoin/{SOFTWARE_VERSION}",
                "protocol": PROTOCOL_VERSION,
                "network": node.params.name,
                "magic": magic,
                "genesis": node.chain.active[0].hash.hex(),
                "height": tip.height,
                "tip": tip.hash.hex(),
                "chainwork": f"{tip.chainwork:x}",
                "peers": [p["url"] for p in peers.list() if p["connected"]][:16],
            }

    @app.post("/p2p/hello")
    async def register(request: Request):
        try:
            body = await request.json()
            url = normalize_url(str(body.get("url", "")))
        except Exception:
            raise HTTPException(400, "expected {\"url\": \"http://host:port\"}")
        # Only accept a URL that points back at the host that sent the request. Requests that came
        # through a reverse proxy or tunnel all appear to come from 127.0.0.1, so a loopback URL from
        # them would point at THIS machine, not the sender: never accept that.
        sender = request.client.host if request.client else ""
        target = urlparse(url).hostname or ""
        loop = {"127.0.0.1", "::1", "localhost"}
        proxied = any(h in request.headers for h in ("x-forwarded-for", "cf-connecting-ip", "x-real-ip", "forwarded"))
        if proxied and target in loop:
            raise HTTPException(400, "a loopback address cannot be registered through a proxy")
        if not (target == sender or (target in loop and sender in loop)):
            raise HTTPException(400, "advertised URL must point at the requesting host")
        try:
            peers.add(url, persistent=False, save=False)
        except ValueError as e:
            return {"added": False, "reason": str(e)}
        return {"added": True}

    @app.get("/p2p/blocks")
    def block_hashes(locator: str = "", limit: int = 200):
        try:
            loc = [bytes.fromhex(h) for h in locator.split(",") if h][:64]
        except ValueError:
            raise HTTPException(400, "bad locator")
        with node.lock:
            hashes = node.chain.hashes_after_locator(loc, max(1, min(limit, 500)))
        return {"hashes": [h.hex() for h in hashes]}

    @app.get("/p2p/block/{block_hash}")
    def get_block(block_hash: str):
        try:
            h = bytes.fromhex(block_hash)
        except ValueError:
            raise HTTPException(400, "bad hash")
        block = node.chain.get_block(h) if len(h) == 32 else None
        if block is None:
            raise HTTPException(404, "unknown block")
        return Response(block.serialize(), media_type="application/octet-stream")

    @app.post("/p2p/block")
    async def push_block(request: Request):
        who = client_id(request)
        raw = await request.body()
        try:
            block = Block.deserialize(raw, node.params.max_block_bytes)
        except DecodeError as e:
            peers.penalize(who, 20, f"malformed block: {e}")
            raise HTTPException(400, f"malformed block: {e}")
        res = await run_in_threadpool(node.submit_block, block, who)
        if res.status == "invalid" and res.reason not in ("blk-time-too-new", "already known"):
            peers.penalize(who, 50, f"invalid block: {res.reason}")
        if res.status == "orphan":
            peers.request_sync()  # we are missing ancestors; pull them from peers
        return {"status": res.status, "reason": res.reason}

    @app.get("/p2p/mempool")
    def mempool():
        with node.lock:
            return {"txids": [t.hex() for t in list(node.mempool.entries)[:5000]]}

    @app.get("/p2p/tx/{txid}")
    def get_tx(txid: str):
        try:
            entry = node.mempool.entries.get(bytes.fromhex(txid))
        except ValueError:
            raise HTTPException(400, "bad txid")
        if entry is None:
            raise HTTPException(404, "unknown transaction")
        return Response(entry.tx.serialize(), media_type="application/octet-stream")

    @app.post("/p2p/tx")
    async def push_tx(request: Request):
        who = client_id(request)
        raw = await request.body()
        try:
            tx = Tx.deserialize(raw)
        except DecodeError as e:
            peers.penalize(who, 20, f"malformed tx: {e}")
            raise HTTPException(400, f"malformed transaction: {e}")
        try:
            await run_in_threadpool(node.submit_tx, tx, who)
        except ValidationError as e:
            if e.code in PUNISHABLE_TX:
                peers.penalize(who, 10, e.code)
            return {"status": "rejected", "reason": e.code}
        return {"status": "accepted"}

    return BodyLimit(app, node.config.max_message_bytes)
