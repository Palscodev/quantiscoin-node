"""Local node configuration (NOT consensus). Loaded from a TOML file.

Consensus parameters live in core/params.py and are selected by `network`.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@dataclass
class NodeConfig:
    network: str = "devnet"
    data_dir: str = "data/node1"
    api_host: str = "127.0.0.1"
    api_port: int = 8331
    p2p_bind: str = "127.0.0.1"
    p2p_port: int = 9331
    advertise_url: str = ""  # how peers reach our P2P server; default http://127.0.0.1:<p2p_port>
    peers: list[str] = field(default_factory=list)
    discover: bool = True  # learn peers from peers' hello responses
    max_peers: int = 8
    sync_interval: float = 3.0
    peer_timeout: float = 5.0
    max_message_bytes: int = 1 << 20
    allow_remote_api: bool = False
    # --- hosting the website -------------------------------------------------
    allowed_hosts: list[str] = field(default_factory=list)  # e.g. ["quantis.duckdns.org"]
    trust_proxy: bool = False  # trust X-Forwarded-For/-Proto from a reverse proxy on this machine
    allow_signup: bool = True  # anyone can create an account
    session_days: float = 7.0
    cookie_secure: str = "auto"  # "auto" (secure when served over HTTPS), "always" or "never"
    node_repo_url: str = ""  # public source code of the node software, linked from the website
    public_p2p_url: str = ""  # address other people's nodes should connect to (shown on the website)
    mining_workers: int = 1
    mining_low_power: bool = False
    mining_address: str = ""
    relay_base_rate: int = 10
    relay_max_multiplier: int = 8
    relay_target_bytes: int = 64_000
    mempool_max_bytes: int = 256_000
    log_level: str = "info"
    source: str = "defaults"

    def __post_init__(self) -> None:
        if not self.advertise_url:
            host = "127.0.0.1" if self.p2p_bind in ("0.0.0.0", "::", "127.0.0.1") else self.p2p_bind
            self.advertise_url = f"http://{host}:{self.p2p_port}"
        if self.api_host not in LOOPBACK and not self.allow_remote_api:
            raise ValueError("api_host must be a loopback address unless allow_remote_api = true")
        for port in (self.api_port, self.p2p_port):
            if not (1 <= port <= 65535):
                raise ValueError("ports must be in 1..65535")

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "chain.sqlite3"

    @classmethod
    def load(cls, path: str | Path) -> "NodeConfig":
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        flat: dict = {}
        for k, v in raw.items():
            if isinstance(v, dict):  # [mining], [relay], [mempool] tables
                for k2, v2 in v.items():
                    flat[f"{k}_{k2}"] = v2
            else:
                flat[k] = v
        known = set(cls.__dataclass_fields__)
        unknown = set(flat) - known
        if unknown:
            raise ValueError(f"unknown configuration keys: {sorted(unknown)}")
        flat["source"] = str(path)
        return cls(**flat)

    def public_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}
