"""Outbound peer management and chain synchronization.

Protocol (HTTP, see p2p/app.py):
  GET  /p2p/hello              -> identity, tip, cumulative work, known peers
  POST /p2p/hello {url}        -> register our advertised URL with the peer
  GET  /p2p/blocks?locator=..  -> active-chain hashes after the first locator hash the peer knows
  GET  /p2p/block/{hash}       -> raw block bytes
  POST /p2p/block (raw bytes)  -> announce/push a block
  GET  /p2p/mempool            -> pending txids
  GET  /p2p/tx/{txid}          -> raw pending transaction
  POST /p2p/tx (raw bytes)     -> push a transaction
Every request carries X-Quantis-Magic; a mismatch is a different network.

Sync loop (every `sync_interval` seconds, per peer): hello; if the peer reports
more cumulative work than our tip, download its active chain from our locator
and process each block through full validation; periodically pull its mempool.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from ..core.block import Block
from ..core.encoding import DecodeError
from ..core.tx import Tx
from ..core.validation import ValidationError

if TYPE_CHECKING:
    from ..node import Node

log = logging.getLogger("quantis.p2p")
BAN_SCORE = 100
BAN_SECONDS = 600
MAX_SYNC_ROUNDS = 50
LOCATOR_LIMIT = 200


@dataclass
class Peer:
    url: str
    persistent: bool = False
    connected: bool = False
    last_seen: float = 0.0
    last_error: str = ""
    height: int = -1
    chainwork: int = 0
    tip: str = ""
    latency_ms: float | None = None
    registered: bool = False
    failures: int = 0
    rounds: int = 0
    blocks_received: int = 0
    txs_received: int = 0

    def view(self) -> dict:
        return {
            "url": self.url,
            "persistent": self.persistent,
            "connected": self.connected,
            "last_seen": self.last_seen or None,
            "last_error": self.last_error or None,
            "height": self.height if self.height >= 0 else None,
            "tip": self.tip or None,
            "latency_ms": self.latency_ms,
            "blocks_received": self.blocks_received,
            "txs_received": self.txs_received,
        }


def _is_local_host(host: str) -> bool:
    """Loopback, private-LAN or link-local address (or 'localhost')."""
    import ipaddress

    if host.lower() in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a DNS name: treat as public
    return ip.is_loopback or ip.is_private or ip.is_link_local


def normalize_url(url: str) -> str:
    """Canonical peer URL: scheme://host:port (port defaults to 443 for https, 80 for http)."""
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("peer URL must look like http://host:port or https://host")
    if u.path not in ("", "/") or u.query or u.fragment or u.username:
        raise ValueError("peer URL must not contain a path, query or credentials")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError as e:
        raise ValueError("peer URL has an invalid port") from e
    return f"{u.scheme}://{u.hostname}:{port}"


class PeerManager:
    def __init__(self, node: "Node") -> None:
        self.node = node
        self.cfg = node.config
        self.peers: dict[str, Peer] = {}
        self.scores: dict[str, int] = {}
        self.banned: dict[str, float] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="quantis-p2p-push")
        self.self_url = normalize_url(self.cfg.advertise_url)
        self.headers = {"X-Quantis-Magic": node.params.magic.hex(), "X-Quantis-Peer": self.self_url}
        for url in self.cfg.peers:
            self.add(url, persistent=True, save=False)
        for (url,) in node.db.all("SELECT url FROM peers"):
            self.add(url, persistent=True, save=False)

    # ---------------------------------------------------------- membership
    def add(self, url: str, persistent: bool = True, save: bool = True) -> Peer:
        url = normalize_url(url)
        if url == self.self_url:
            raise ValueError("refusing to connect to ourselves")
        with self._lock:
            if url in self.peers:
                return self.peers[url]
            if len(self.peers) >= self.cfg.max_peers:
                raise ValueError(f"peer limit reached ({self.cfg.max_peers})")
            peer = Peer(url=url, persistent=persistent)
            self.peers[url] = peer
        if save:
            self.node.db.execute("INSERT OR IGNORE INTO peers VALUES (?, ?)", (url, int(time.time())))
        self._wake.set()
        return peer

    def remove(self, url: str) -> None:
        url = normalize_url(url)
        with self._lock:
            self.peers.pop(url, None)
        self.node.db.execute("DELETE FROM peers WHERE url=?", (url,))

    def list(self) -> list[dict]:
        with self._lock:
            return [p.view() for p in self.peers.values()]

    def connected_count(self) -> int:
        with self._lock:
            return sum(1 for p in self.peers.values() if p.connected)

    # --------------------------------------------------------- misbehavior
    def penalize(self, who: str, points: int, reason: str) -> None:
        score = self.scores.get(who, 0) + points
        self.scores[who] = score
        log.warning("peer %s misbehaved (+%d, %s); score %d", who, points, reason, score)
        if score >= BAN_SCORE:
            self.banned[who] = time.time() + BAN_SECONDS
            self.scores[who] = 0
            with self._lock:
                p = self.peers.get(who)
                if p is not None and not p.persistent:
                    self.peers.pop(who, None)

    def is_banned(self, who: str) -> bool:
        until = self.banned.get(who)
        if until is None:
            return False
        if until < time.time():
            del self.banned[who]
            return False
        return True

    # ---------------------------------------------------------------- loop
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="quantis-p2p-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=self.cfg.peer_timeout + 2)
        self._pool.shutdown(wait=False, cancel_futures=True)

    def request_sync(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        with httpx.Client(timeout=self.cfg.peer_timeout, headers=self.headers) as client:
            while not self._stop.is_set():
                with self._lock:
                    peers = list(self.peers.values())
                for peer in peers:
                    if self._stop.is_set():
                        break
                    if self.is_banned(peer.url):
                        continue
                    try:
                        self.sync_peer(client, peer)
                    except (httpx.HTTPError, ValueError, DecodeError) as e:
                        peer.connected = False
                        peer.failures += 1
                        peer.last_error = f"{type(e).__name__}: {e}"[:200]
                self._wake.wait(self.cfg.sync_interval)
                self._wake.clear()

    def sync_peer(self, client: httpx.Client, peer: Peer) -> None:
        t0 = time.perf_counter()
        r = client.get(f"{peer.url}/p2p/hello")
        r.raise_for_status()
        hello = r.json()
        peer.latency_ms = (time.perf_counter() - t0) * 1000
        if hello.get("magic") != self.node.params.magic.hex() or hello.get("genesis") != self.node.chain.active[0].hash.hex():
            peer.connected = False
            peer.last_error = "peer is on a different network"
            return
        peer.connected, peer.last_seen, peer.last_error, peer.failures = True, time.time(), "", 0
        peer.height, peer.tip = int(hello["height"]), str(hello["tip"])
        peer.chainwork = int(hello["chainwork"], 16)
        if not peer.registered:
            client.post(f"{peer.url}/p2p/hello", json={"url": self.self_url})
            peer.registered = True
        if self.cfg.discover:
            # Addresses like 127.0.0.1 or 192.168.x.x only mean something on the peer's own machine or
            # network; accept them only from a peer that is itself local.
            peer_is_local = _is_local_host(urlparse(peer.url).hostname or "")
            for url in hello.get("peers", [])[:16]:
                try:
                    if not peer_is_local and _is_local_host(urlparse(str(url)).hostname or ""):
                        continue
                    if url != self.self_url and url not in self.peers:
                        self.add(url, persistent=False, save=False)
                except ValueError:
                    pass
        if peer.chainwork > self.node.chain.tip.chainwork:
            self._download(client, peer)
        if peer.rounds % 5 == 0:
            self._pull_mempool(client, peer)
        peer.rounds += 1

    def _download(self, client: httpx.Client, peer: Peer) -> None:
        for _ in range(MAX_SYNC_ROUNDS):
            with self.node.lock:
                locator = self.node.chain.locator()
            r = client.get(
                f"{peer.url}/p2p/blocks",
                params={"locator": ",".join(h.hex() for h in locator), "limit": LOCATOR_LIMIT},
            )
            r.raise_for_status()
            hashes = [bytes.fromhex(h) for h in r.json()["hashes"]]
            new = [h for h in hashes if not self.node.chain.has_block(h)]
            if not new:
                return
            for h in new:
                rb = client.get(f"{peer.url}/p2p/block/{h.hex()}")
                rb.raise_for_status()
                block = Block.deserialize(rb.content, self.node.params.max_block_bytes)
                if block.hash != h:
                    self.penalize(peer.url, 50, "served block with wrong hash")
                    return
                res = self.node.submit_block(block, source=peer.url)
                peer.blocks_received += 1
                if res.status == "invalid":
                    self.penalize(peer.url, 50, f"invalid block {res.reason}")
                    return
            if peer.chainwork <= self.node.chain.tip.chainwork:
                return

    def _pull_mempool(self, client: httpx.Client, peer: Peer) -> None:
        r = client.get(f"{peer.url}/p2p/mempool")
        r.raise_for_status()
        for txid_hex in r.json()["txids"][:500]:
            txid = bytes.fromhex(txid_hex)
            if txid in self.node.mempool:
                continue
            rt = client.get(f"{peer.url}/p2p/tx/{txid_hex}")
            if rt.status_code != 200:
                continue
            try:
                tx = Tx.deserialize(rt.content)
                self.node.submit_tx(tx, source=peer.url)
                peer.txs_received += 1
            except ValidationError:
                pass  # policy differences between nodes are not misbehavior
            except DecodeError:
                self.penalize(peer.url, 20, "malformed transaction")

    # ----------------------------------------------------------- broadcast
    def _push(self, path: str, body: bytes, exclude: str) -> None:
        with self._lock:
            targets = [p.url for p in self.peers.values() if p.connected and p.url != exclude]
        for url in targets:
            try:
                self._pool.submit(self._post, url + path, body)
            except RuntimeError:  # executor already shut down
                return

    def _post(self, url: str, body: bytes) -> None:
        try:
            httpx.post(url, content=body, headers={**self.headers, "Content-Type": "application/octet-stream"},
                       timeout=self.cfg.peer_timeout)
        except httpx.HTTPError as e:
            log.debug("push to %s failed: %s", url, e)

    def broadcast_block(self, block: Block, exclude: str = "") -> None:
        if not self._stop.is_set():
            self._push("/p2p/block", block.serialize(), exclude)

    def broadcast_tx(self, tx: Tx, exclude: str = "") -> None:
        if not self._stop.is_set():
            self._push("/p2p/tx", tx.serialize(), exclude)
