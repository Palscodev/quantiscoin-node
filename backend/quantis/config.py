"""Local node configuration (NOT consensus). Loaded from a TOML file.

Consensus parameters live in core/params.py and are selected by `network`.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Mapping

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
    # Also answer peer-to-peer requests (/p2p/...) on the website's own address, so anyone's node can
    # join through the same domain and HTTPS as the site: no extra port, tunnel or operator approval.
    p2p_on_api: bool = False
    mining_workers: int = 1
    mining_low_power: bool = False
    mining_address: str = ""
    relay_base_rate: int = 10
    relay_max_multiplier: int = 8
    relay_target_bytes: int = 64_000
    mempool_max_bytes: int = 256_000
    log_level: str = "info"
    exchange_provider: str = "demo"  # "demo" (simulated) or "partner" (licensed partner, see exchange.py)
    exchange_api_key: str = ""  # set with QUANTIS_EXCHANGE_API_KEY, never in a committed file
    exchange_live: bool = False  # must be true, on purpose, before any real-money provider is used
    backup_interval_hours: float = 24.0  # automatic database backups (0 = off)
    backup_keep: int = 7  # how many automatic backups to keep
    source: str = "defaults"

    def __post_init__(self) -> None:
        if not self.advertise_url:
            host = "127.0.0.1" if self.p2p_bind in ("0.0.0.0", "::", "127.0.0.1") else self.p2p_bind
            self.advertise_url = f"http://{host}:{self.p2p_port}"
        if self.api_host not in LOOPBACK and not (self.allow_remote_api or self.allowed_hosts):
            raise ValueError(
                "api_host is not a loopback address: list your public domain(s) in allowed_hosts "
                "(or set allow_remote_api = true, which disables the host check)"
            )
        for port in (self.api_port, self.p2p_port):
            if not (1 <= port <= 65535):
                raise ValueError("ports must be in 1..65535")

    @classmethod
    def env_overrides(cls, env: Mapping[str, str] | None = None) -> dict:
        """Read QUANTIS_<SETTING> environment variables (how hosting platforms configure apps).

        Examples: QUANTIS_ALLOWED_HOSTS="a.com,b.com", QUANTIS_TRUST_PROXY=true. A plain PORT
        variable (set by most hosting platforms) becomes api_port.
        """
        env = os.environ if env is None else env
        defaults = cls()  # default instance: tells us each setting's type
        changes: dict = {}
        for f in fields(cls):
            raw = env.get(f"QUANTIS_{f.name.upper()}")
            if raw is None or f.name == "source":
                continue
            current = getattr(defaults, f.name)
            if isinstance(current, bool):
                if raw.strip().lower() not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                    raise ValueError(f"QUANTIS_{f.name.upper()} must be true or false")
                changes[f.name] = raw.strip().lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                changes[f.name] = int(raw)
            elif isinstance(current, float):
                changes[f.name] = float(raw)
            elif isinstance(current, list):
                changes[f.name] = [x.strip() for x in raw.split(",") if x.strip()]
            else:
                changes[f.name] = raw
        if "PORT" in env and "api_port" not in changes:
            changes["api_port"] = int(env["PORT"])
        return changes

    def with_env(self, env: Mapping[str, str] | None = None) -> "NodeConfig":
        """This configuration with environment-variable overrides applied."""
        changes = self.env_overrides(env)
        return replace(self, **changes) if changes else self

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "chain.sqlite3"

    @classmethod
    def load(cls, path: str | Path, env: Mapping[str, str] | None = None) -> "NodeConfig":
        """Read a TOML file; QUANTIS_* environment variables (if any) take precedence."""
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
        flat.update(cls.env_overrides(env))
        return cls(**flat)

    def public_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}
