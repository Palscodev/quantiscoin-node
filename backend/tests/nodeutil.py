"""Helpers to run real nodes (API + P2P HTTP servers) inside the test process."""
from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time

import httpx
import uvicorn

from quantis.api.app import create_api_app
from quantis.config import NodeConfig
from quantis.node import Node
from quantis.p2p.app import create_p2p_app


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):
        yield


class RunningNode:
    def __init__(self, data_dir, peers=(), sync_interval=0.3, network="regtest", **extra) -> None:
        self.api_port, self.p2p_port = free_port(), free_port()
        self.cfg = NodeConfig(network=network, data_dir=str(data_dir), api_port=self.api_port,
                              p2p_port=self.p2p_port, peers=list(peers), sync_interval=sync_interval,
                              peer_timeout=3.0, **extra)
        self.node = Node(self.cfg)
        self.api_url = f"http://127.0.0.1:{self.api_port}"
        self.p2p_url = f"http://127.0.0.1:{self.p2p_port}"
        self._servers = [
            _Server(uvicorn.Config(create_api_app(self.node), host="127.0.0.1", port=self.api_port, log_level="error")),
            _Server(uvicorn.Config(create_p2p_app(self.node), host="127.0.0.1", port=self.p2p_port, log_level="error")),
        ]
        self._thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self._thread.start()
        deadline = time.time() + 10
        while not all(s.started for s in self._servers):
            if time.time() > deadline:
                raise RuntimeError("servers did not start")
            time.sleep(0.05)
        self.node.start()

    def admin(self, password: str = "correct horse battery") -> httpx.Client:
        """An HTTP client logged in as this node's administrator (created on first use)."""
        if getattr(self, "_admin", None) is None:
            c = httpx.Client(base_url=self.api_url, timeout=30)
            r = c.post("/api/auth/setup", json={"username": "admin", "password": password,
                                                 "setup_code": self.node.accounts.setup_code})
            assert r.status_code == 200, r.text
            self._admin = c
        return self._admin

    def user(self, username: str, password: str = "correct horse battery") -> httpx.Client:
        """Sign up a regular user (the admin must exist first) and return a logged-in client."""
        self.admin()
        c = httpx.Client(base_url=self.api_url, timeout=30)
        r = c.post("/api/auth/signup", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return c

    async def _main(self):
        await asyncio.gather(*(s.serve() for s in self._servers))

    def stop(self) -> None:
        for c in (getattr(self, "_admin", None),):
            if c is not None:
                c.close()
        for s in self._servers:
            s.should_exit = True
        self._thread.join(timeout=10)
        self.node.shutdown()


def wait_for(cond, timeout=20.0, interval=0.1, msg="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {msg}")
