"""User accounts, sessions and rate limiting for the hosted website.

* Passwords are stored only as scrypt hashes (N=2^14, r=8, p=1, 16-byte salt).
* A session is a random 256-bit token held in an HttpOnly, SameSite=Strict cookie.
  Only SHA-256(token) is stored, so a database leak does not reveal live sessions.
* The first administrator is created with a one-time setup code that the node
  prints to its console, so a public server cannot be claimed by a stranger who
  happens to open the site first.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from .storage.db import Database

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")
MIN_PASSWORD = 8
MAX_PASSWORD = 256
SCRYPT = (1 << 14, 8, 1)


class AuthError(ValueError):
    pass


@dataclass(frozen=True)
class User:
    id: int
    username: str
    is_admin: bool
    created: int

    @property
    def wallet_name(self) -> str:
        return f"u-{self.id}"

    def public(self) -> dict:
        return {"id": self.id, "username": self.username, "is_admin": self.is_admin, "created": self.created}


def hash_password(password: str) -> str:
    n, r, p = SCRYPT
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(bytes.fromhex(dk)), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got, bytes.fromhex(dk))
    except (ValueError, TypeError):
        return False


def check_new_credentials(username: str, password: str) -> None:
    if not USERNAME_RE.match(username or ""):
        raise AuthError("Username must be 2–32 characters: letters, digits, '.', '_' or '-'.")
    if not (MIN_PASSWORD <= len(password or "") <= MAX_PASSWORD):
        raise AuthError(f"Password must be at least {MIN_PASSWORD} characters.")


class RateLimiter:
    """Sliding-window counter: at most `limit` events per `window` seconds per key."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self.events: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record an event; return False if the key is over its limit."""
        now = time.monotonic()
        with self.lock:
            q = self.events[key]
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.events) > 50_000:  # bound memory under abuse
                self.events = defaultdict(deque, {k: v for k, v in self.events.items() if v})
            return True

    def reset(self, key: str) -> None:
        with self.lock:
            self.events.pop(key, None)


class Accounts:
    def __init__(self, db: Database, session_days: float = 7.0) -> None:
        self.db = db
        self.session_seconds = int(session_days * 86400)
        self.setup_code: str | None = None
        if not self.has_admin():
            raw = secrets.token_hex(4).upper()
            self.setup_code = f"{raw[:4]}-{raw[4:]}"

    # ------------------------------------------------------------- users
    def has_admin(self) -> bool:
        return self.db.one("SELECT 1 FROM users WHERE is_admin=1 LIMIT 1") is not None

    def count(self) -> int:
        return self.db.one("SELECT COUNT(*) FROM users")[0]

    def _row(self, row) -> User | None:
        return User(row[0], row[1], bool(row[2]), row[3]) if row else None

    def get(self, user_id: int) -> User | None:
        return self._row(self.db.one("SELECT id, username, is_admin, created FROM users WHERE id=?", (user_id,)))

    def by_name(self, username: str) -> User | None:
        return self._row(self.db.one(
            "SELECT id, username, is_admin, created FROM users WHERE username=? COLLATE NOCASE", (username,)))

    def list(self) -> list[User]:
        return [self._row(r) for r in self.db.all("SELECT id, username, is_admin, created FROM users ORDER BY id")]

    def create(self, username: str, password: str, is_admin: bool = False) -> User:
        check_new_credentials(username, password)
        if self.by_name(username):
            raise AuthError("That username is already taken.")
        cur = self.db.execute(
            "INSERT INTO users (username, pw_hash, is_admin, created) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), int(is_admin), int(time.time())),
        )
        if is_admin:
            self.setup_code = None
        return self.get(cur.lastrowid)

    def authenticate(self, username: str, password: str) -> User | None:
        row = self.db.one("SELECT id, pw_hash FROM users WHERE username=? COLLATE NOCASE", (username,))
        if row is None:
            verify_password(password, hash_password("timing-equalizer"))  # similar cost for unknown users
            return None
        return self.get(row[0]) if verify_password(password, row[1]) else None

    def set_password(self, user_id: int, password: str) -> None:
        if not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
            raise AuthError(f"Password must be at least {MIN_PASSWORD} characters.")
        self.db.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(password), user_id))

    def set_admin(self, user_id: int, is_admin: bool) -> None:
        self.db.execute("UPDATE users SET is_admin=? WHERE id=?", (int(is_admin), user_id))

    def admin_count(self) -> int:
        return self.db.one("SELECT COUNT(*) FROM users WHERE is_admin=1")[0]

    def delete(self, user_id: int) -> None:
        """Remove an account, its sessions and its encrypted wallet."""
        with self.db.transaction():
            self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            self.db.execute("DELETE FROM wallets WHERE name=?", (f"u-{user_id}",))
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))

    # ---------------------------------------------------------- sessions
    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode()).digest()

    def new_session(self, user: User) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        self.db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
        self.db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                        (self._digest(token), user.id, now, now + self.session_seconds))
        return token

    def session_user(self, token: str | None) -> User | None:
        if not token or len(token) > 100:
            return None
        row = self.db.one("SELECT user_id, expires FROM sessions WHERE token_hash=?", (self._digest(token),))
        if row is None or row[1] < time.time():
            return None
        return self.get(row[0])

    def end_session(self, token: str | None) -> None:
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (self._digest(token),))

    def end_all_sessions(self, user_id: int) -> None:
        self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
