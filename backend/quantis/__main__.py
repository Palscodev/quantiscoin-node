"""Command-line entry point.

  python -m quantis node --config config/devnet-node1.toml
  python -m quantis bench [--seconds 5] [--workers 1,2,4] [--network devnet]
  python -m quantis genesis [--network devnet]
  python -m quantis policy  [--network devnet]
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import signal
import sys


def _cmd_node(args) -> int:
    import uvicorn

    from .api.app import create_api_app
    from .config import NodeConfig
    from .node import Node
    from .p2p.app import create_p2p_app

    cfg = (NodeConfig.load(args.config) if args.config else NodeConfig()).with_env()
    logging.basicConfig(level=cfg.log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    node = Node(cfg)

    class _Server(uvicorn.Server):
        @contextlib.contextmanager
        def capture_signals(self):  # signals are handled once, below, for both servers
            yield

    api = _Server(uvicorn.Config(create_api_app(node), host=cfg.api_host, port=cfg.api_port,
                                 log_level="warning", access_log=False))
    p2p = _Server(uvicorn.Config(create_p2p_app(node), host=cfg.p2p_bind, port=cfg.p2p_port, log_level="warning",
                                 access_log=False, limit_concurrency=64, timeout_keep_alive=5))

    def stop(*_):
        api.should_exit = p2p.should_exit = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    log = logging.getLogger("quantis")
    log.info("network=%s genesis=%s height=%d", node.params.name, node.chain.active[0].hash.hex(), node.chain.height)
    log.info("API + web UI: http://%s:%d   P2P: %s:%d (advertised as %s)", cfg.api_host, cfg.api_port,
             cfg.p2p_bind, cfg.p2p_port, cfg.advertise_url)
    if node.accounts.setup_code:
        bar = "=" * 64
        log.warning("\n%s\n  FIRST-TIME SETUP: open the website and create the administrator\n"
                    "  account with this one-time setup code:   %s\n%s",
                    bar, node.accounts.setup_code, bar)
    node.start()
    if cfg.mining_address:
        node.miner.start(cfg.mining_address, cfg.mining_workers, cfg.mining_low_power)

    async def main():
        await asyncio.gather(api.serve(), p2p.serve())

    try:
        asyncio.run(main())
    finally:
        log.info("shutting down")
        node.shutdown()
    return 0


def _cmd_bench(args) -> int:
    from .bench import run_benchmark

    workers = [int(w) for w in args.workers.split(",")]
    report = run_benchmark(args.network, workers, args.seconds)
    print(json.dumps(report, indent=2))
    return 0


def _cmd_genesis(args) -> int:
    from .core.genesis import genesis_block
    from .core.params import get_network

    p = get_network(args.network)
    g = genesis_block(p)
    print(json.dumps({"network": p.name, "magic": p.magic.hex(), "hash": g.hash.hex(),
                      "nonce": g.header.nonce, "merkle_root": g.header.merkle_root.hex(),
                      "header": g.header.serialize().hex()}, indent=2))
    return 0


def _cmd_policy(args) -> int:
    from .core.monetary import realized_supply, schedule, theoretical_supply
    from .core.params import COIN, get_network

    p = get_network(args.network)
    print(f"network {p.name}: R0={p.initial_reward / COIN:g} QTS, H={p.halving_interval} blocks")
    print(f"theoretical supply 2*R0*H = {theoretical_supply(p) / COIN:,.8f} QTS")
    print(f"realized supply H*(2*R0 - popcount(R0)) = {realized_supply(p) / COIN:,.8f} QTS")
    print(f"{'era':>4} {'heights':>17} {'reward (QTS)':>18} {'cumulative (QTS)':>22}")
    for row in schedule(p):
        print(f"{row['era']:>4} {row['first_height']:>8}-{row['last_height']:<8} {row['reward'] / COIN:>18.8f} "
              f"{row['cumulative'] / COIN:>22.8f}")
    return 0


def _cmd_admin(args) -> int:
    import getpass

    from .auth import Accounts, AuthError
    from .config import NodeConfig
    from .core.params import get_network
    from .storage.db import Database

    cfg = (NodeConfig.load(args.config) if args.config else NodeConfig()).with_env()
    get_network(cfg.network)
    db = Database(cfg.db_path)
    accounts = Accounts(db, cfg.session_days)
    try:
        if args.action == "list":
            for u in accounts.list():
                print(f"{u.id:>4}  {u.username:<32} {'admin' if u.is_admin else 'user'}")
            return 0
        if not args.username:
            print("a username is required", file=sys.stderr)
            return 2
        if args.action == "create":
            pw = getpass.getpass(f"Password for {args.username}: ")
            if pw != getpass.getpass("Repeat password: "):
                print("passwords do not match", file=sys.stderr)
                return 2
            u = accounts.create(args.username, pw, is_admin=True)
            print(f"created administrator {u.username}; their wallet is created at first login")
        elif args.action == "promote":
            u = accounts.by_name(args.username)
            if u is None:
                print("no such user", file=sys.stderr)
                return 2
            accounts.set_admin(u.id, True)
            print(f"{u.username} is now an administrator")
        elif args.action == "reset-password":
            u = accounts.by_name(args.username)
            if u is None:
                print("no such user", file=sys.stderr)
                return 2
            print("WARNING: the user's wallet stays encrypted with their OLD password. Without the old\n"
                  "password (or a backup file and its password) the coins in it cannot be spent.")
            pw = getpass.getpass("New login password: ")
            accounts.set_password(u.id, pw)
            accounts.end_all_sessions(u.id)
            print("password reset; all sessions logged out")
    except AuthError as e:
        print(e, file=sys.stderr)
        return 2
    finally:
        db.close()
    return 0


def _cmd_export_data(args) -> int:
    """Write a consistent copy of this node's data to a folder, ready to upload to a new host's
    data volume under import/ (the node swaps it in at its next start)."""
    import shutil
    import sqlite3
    from pathlib import Path

    from .config import NodeConfig

    cfg = (NodeConfig.load(args.config) if args.config else NodeConfig()).with_env()
    src = Path(cfg.db_path)
    if not src.is_file():
        print(f"no database at {src}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "chain.sqlite3"
    dest.unlink(missing_ok=True)
    with sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True) as s, sqlite3.connect(dest) as d:
        s.backup(d)  # safe even while the node is running
    secret = Path(cfg.data_dir) / "exchange-treasury.secret"
    if secret.is_file():
        shutil.copyfile(secret, out / secret.name)
    print(f"wrote {out.resolve()}  (keep it private: it contains the exchange reserve's key)")
    for f in sorted(out.iterdir()):
        print(f"  {f.name}  {f.stat().st_size:,} bytes")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="quantis", description="QuantisCoin educational blockchain node")
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("node", help="run a full node (API, web UI, P2P, miner)")
    n.add_argument("--config", help="TOML configuration file")
    b = sub.add_parser("bench", help="measure CPU mining hash rate on this machine")
    b.add_argument("--network", default="devnet")
    b.add_argument("--workers", default="1")
    b.add_argument("--seconds", type=float, default=15.0)
    g = sub.add_parser("genesis", help="print the deterministic genesis block")
    g.add_argument("--network", default="devnet")
    pol = sub.add_parser("policy", help="print the monetary schedule")
    pol.add_argument("--network", default="devnet")
    a = sub.add_parser("admin", help="manage website accounts (create, list, promote, reset-password)")
    a.add_argument("action", choices=["create", "list", "promote", "reset-password"])
    a.add_argument("username", nargs="?")
    a.add_argument("--config", help="TOML configuration file")
    e = sub.add_parser("export-data", help="copy this node's data into a folder, ready to move to a new host")
    e.add_argument("--config", help="TOML configuration file")
    e.add_argument("--out", default="data-export")
    args = ap.parse_args(argv)
    return {"node": _cmd_node, "bench": _cmd_bench, "genesis": _cmd_genesis, "policy": _cmd_policy,
            "admin": _cmd_admin, "export-data": _cmd_export_data}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
