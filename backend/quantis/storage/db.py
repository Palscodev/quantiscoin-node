"""SQLite persistence.

One connection per node, guarded by a re-entrant lock. Every block connect /
disconnect / reorg happens inside a single `BEGIN IMMEDIATE` transaction, so a
crash leaves either the old or the new chain state on disk, never a mix.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocks (
    hash      BLOB PRIMARY KEY,
    prev      BLOB NOT NULL,
    height    INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    target    BLOB NOT NULL,
    chainwork BLOB NOT NULL,
    status    INTEGER NOT NULL,
    n_tx      INTEGER NOT NULL,
    size      INTEGER NOT NULL,
    fees      INTEGER,
    received  INTEGER NOT NULL,
    raw       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS blocks_height ON blocks(height);
CREATE TABLE IF NOT EXISTS active (height INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS utxo (
    txid BLOB NOT NULL, vout INTEGER NOT NULL,
    amount INTEGER NOT NULL, h20 BLOB NOT NULL, height INTEGER NOT NULL, coinbase INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX IF NOT EXISTS utxo_h20 ON utxo(h20);
CREATE TABLE IF NOT EXISTS undo (block_hash BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS txindex (
    txid BLOB PRIMARY KEY, block_hash BLOB NOT NULL, height INTEGER NOT NULL, pos INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS txindex_height ON txindex(height);
CREATE TABLE IF NOT EXISTS addrtx (
    h20 BLOB NOT NULL, txid BLOB NOT NULL, height INTEGER NOT NULL, PRIMARY KEY (h20, txid)
);
CREATE INDEX IF NOT EXISTS addrtx_height ON addrtx(height);
CREATE TABLE IF NOT EXISTS wallets (name TEXT PRIMARY KEY, keystore TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS peers (url TEXT PRIMARY KEY, added INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS mempool_txs (txid BLOB PRIMARY KEY, raw BLOB NOT NULL, received INTEGER NOT NULL);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)
        self._depth = 0
        with self.transaction():
            row = self.one("SELECT value FROM meta WHERE key='schema_version'")
            if row is None:
                self.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif int(row[0]) != SCHEMA_VERSION:
                raise RuntimeError(f"database schema {row[0]} is not supported (expected {SCHEMA_VERSION})")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Re-entrant transaction: nested uses join the outer transaction."""
        with self.lock:
            if self._depth == 0:
                self.conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if self._depth == 0:
                    self.conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if self._depth == 0:
                    self.conn.execute("COMMIT")

    def execute(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, args)

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        with self.lock:
            self.conn.executemany(sql, rows)

    def one(self, sql: str, args: tuple = ()) -> Any:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def get_meta(self, key: str) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def close(self) -> None:
        with self.lock:
            self.conn.close()
