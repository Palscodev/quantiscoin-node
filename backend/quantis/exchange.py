"""Buy / sell QTS through a pluggable exchange provider.

Selling cryptocurrency for real money is a regulated activity (money transmission,
identity checks, anti-money-laundering rules). This module therefore never handles
real money itself. It defines one interface and two providers:

* DemoProvider (default): a complete, self-consistent practice exchange. Every user
  gets a demo account holding "demo QTS" and "demo cash". Buying is paid with a test
  card (the same public test numbers card processors such as Stripe use) or with demo
  cash; selling needs demo QTS you actually hold and pays out to demo cash. Nothing
  touches the real blockchain or any real card: real card numbers are refused and card
  numbers are never stored (only brand + last 4 digits).
* PartnerProvider: the slot for a *licensed* exchange or on-ramp partner. It is used
  only when exchange_provider = "partner", an API key is configured
  (QUANTIS_EXCHANGE_API_KEY) AND exchange_live = true. In live mode card details must
  be collected by the partner's own hosted checkout, never by this server, so the
  partner implementation replaces `buy` with a redirect to that checkout.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .node import Node

COIN = 100_000_000
DEMO_PRICE_USD = 1.00  # fixed, labelled demo price; NOT a market price
DEMO_FEE_RATE = 0.015  # 1.5% simulated fee
MIN_CENTS = 100  # $1 minimum order
MAX_CENTS = 500_000  # $5,000 maximum order
QUOTE_TTL = 60  # seconds a quoted price stays locked

# Public test card numbers (the same ones Stripe documents); anything else is refused.
TEST_CARDS = {
    "4242424242424242": ("visa", None),
    "5555555555554444": ("mastercard", None),
    "4000000000000002": ("visa", "Your card was declined."),
    "4000000000009995": ("visa", "Your card has insufficient funds."),
    "4000000000000069": ("visa", "Your card has expired."),
}


class ExchangeError(ValueError):
    pass


@dataclass
class Quote:
    id: str
    user_id: int
    side: str
    qts: int  # quanta
    gross_cents: int
    fee_cents: int
    total_cents: int  # buy: what you pay; sell: what you receive
    price_usd: float
    expires: int
    demo: bool

    def view(self) -> dict:
        return {"quote_id": self.id, "side": self.side, "qts": self.qts, "gross_cents": self.gross_cents,
                "fee_cents": self.fee_cents, "total_cents": self.total_cents, "price_usd": self.price_usd,
                "expires": self.expires, "demo": self.demo}


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0


class ExchangeProvider:
    name = "base"
    demo = True

    def info(self) -> dict:
        return {"provider": self.name, "demo": self.demo}

    def quote(self, user_id: int, side: str, qts: int | None, usd_cents: int | None) -> Quote:  # pragma: no cover
        raise NotImplementedError

    def account(self, user_id: int) -> dict:  # pragma: no cover
        raise NotImplementedError

    def buy(self, user_id: int, quote_id: str, method: str, card: dict | None) -> dict:  # pragma: no cover
        raise NotImplementedError

    def sell(self, user_id: int, quote_id: str) -> dict:  # pragma: no cover
        raise NotImplementedError


class DemoProvider(ExchangeProvider):
    name = "demo"
    demo = True

    def __init__(self, node: "Node") -> None:
        self.node = node
        self._quotes: dict[str, Quote] = {}
        self._lock = threading.Lock()

    def info(self) -> dict:
        return super().info() | {
            "price_usd": DEMO_PRICE_USD, "fee_rate": DEMO_FEE_RATE, "min_cents": MIN_CENTS, "max_cents": MAX_CENTS,
            "quote_ttl": QUOTE_TTL,
            "test_cards": [{"number": n, "brand": b, "result": err or "Payment succeeds"} for n, (b, err) in TEST_CARDS.items()],
        }

    # ------------------------------------------------------------- quotes
    def quote(self, user_id: int, side: str, qts: int | None, usd_cents: int | None) -> Quote:
        if side not in ("buy", "sell"):
            raise ExchangeError("side must be buy or sell")
        rate = DEMO_PRICE_USD * 100 / COIN  # cents per quanta
        if qts is None:
            if not usd_cents or usd_cents <= 0:
                raise ExchangeError("Enter an amount.")
            # usd_cents is the total: what you pay (buy) or the gross you sell (sell)
            gross = round(usd_cents / (1 + DEMO_FEE_RATE)) if side == "buy" else usd_cents
            qts = int(gross / rate)
        if qts <= 0:
            raise ExchangeError("Enter an amount.")
        gross = round(qts * rate)
        fee = max(1, round(gross * DEMO_FEE_RATE))
        total = gross + fee if side == "buy" else gross - fee
        if gross < MIN_CENTS:
            raise ExchangeError(f"The minimum order is ${MIN_CENTS / 100:.2f}.")
        if gross > MAX_CENTS:
            raise ExchangeError(f"The maximum order is ${MAX_CENTS / 100:,.2f}.")
        q = Quote("q_" + secrets.token_hex(8), user_id, side, qts, gross, fee, total, DEMO_PRICE_USD,
                  int(time.time()) + QUOTE_TTL, True)
        with self._lock:
            now = time.time()
            self._quotes = {k: v for k, v in self._quotes.items() if v.expires > now}
            self._quotes[q.id] = q
        return q

    def _take(self, user_id: int, quote_id: str, side: str) -> Quote:
        with self._lock:
            q = self._quotes.get(quote_id)
            if q is None or q.user_id != user_id or q.side != side:
                raise ExchangeError("This price quote was not found. Get a new quote.")
            if q.expires < time.time():
                self._quotes.pop(quote_id, None)
                raise ExchangeError("This price quote expired. Get a new quote.")
            self._quotes.pop(quote_id)
        return q

    # ------------------------------------------------------------ account
    def account(self, user_id: int) -> dict:
        db = self.node.db
        row = db.one(
            "SELECT COALESCE(SUM(CASE side WHEN 'buy' THEN qts ELSE -qts END), 0),"
            " COALESCE(SUM(CASE WHEN side='sell' THEN total_cents WHEN method='cash' THEN -total_cents ELSE 0 END), 0)"
            " FROM exchange_trades WHERE user_id=? AND status='completed'", (user_id,))
        cols = ["id", "side", "qts", "gross_cents", "fee_cents", "total_cents", "method", "card_brand", "card_last4",
                "status", "failure", "created"]
        rows = db.all(f"SELECT {', '.join(cols)} FROM exchange_trades WHERE user_id=? ORDER BY created DESC, rowid DESC LIMIT 50",
                      (user_id,))
        return {"demo": True, "qts": row[0], "cash_cents": row[1], "orders": [dict(zip(cols, r)) for r in rows]}

    def _record(self, user_id: int, q: Quote, method: str, brand: str | None, last4: str | None,
                status: str, failure: str | None) -> dict:
        order_id = "ord_" + secrets.token_hex(6)
        self.node.db.execute(
            "INSERT INTO exchange_trades (id, user_id, side, qts, gross_cents, fee_cents, total_cents, method, card_brand,"
            " card_last4, status, failure, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (order_id, user_id, q.side, q.qts, q.gross_cents, q.fee_cents, q.total_cents, method, brand, last4, status,
             failure, int(time.time())))
        return {"order_id": order_id, "status": status, "failure": failure, "demo": True, "quote": q.view(),
                "method": method, "card_brand": brand, "card_last4": last4, "account": self.account(user_id)}

    # --------------------------------------------------------------- trade
    def buy(self, user_id: int, quote_id: str, method: str, card: dict | None) -> dict:
        if method == "cash":
            with self.node.db.transaction():
                q = self._take(user_id, quote_id, "buy")
                if self.account(user_id)["cash_cents"] < q.total_cents:
                    raise ExchangeError("Not enough demo cash. Pay by card instead, or sell some demo QTS first.")
                return self._record(user_id, q, "cash", None, None, "completed", None)
        if method != "card" or not card:
            raise ExchangeError("Choose a payment method.")
        number = "".join(c for c in str(card.get("number", "")) if c.isdigit())
        if not (12 <= len(number) <= 19) or not luhn_ok(number):
            raise ExchangeError("That card number is not valid.")
        if number not in TEST_CARDS:
            raise ExchangeError("Demo mode only accepts test cards. Never enter a real card here.")
        try:
            month, year = int(card.get("exp_month", 0)), int(card.get("exp_year", 0))
        except (TypeError, ValueError):
            raise ExchangeError("Enter the card's expiry date.") from None
        if year < 100:
            year += 2000
        now = time.gmtime()
        if not 1 <= month <= 12 or (year, month) < (now.tm_year, now.tm_mon):
            raise ExchangeError("The card's expiry date is in the past.")
        if not str(card.get("cvc", "")).isdigit() or len(str(card.get("cvc"))) not in (3, 4):
            raise ExchangeError("Enter the 3-digit security code (CVC).")
        q = self._take(user_id, quote_id, "buy")
        brand, failure = TEST_CARDS[number]
        return self._record(user_id, q, "card", brand, number[-4:], "declined" if failure else "completed", failure)

    def sell(self, user_id: int, quote_id: str) -> dict:
        with self.node.db.transaction():
            q = self._take(user_id, quote_id, "sell")
            if self.account(user_id)["qts"] < q.qts:
                raise ExchangeError("You don't hold that much demo QTS. Buy some first.")
            return self._record(user_id, q, "cash", None, None, "completed", None)


class PartnerProvider(ExchangeProvider):
    """Licensed partner integration. Intentionally not implemented: it must be built against
    the real partner's API, under that partner's compliance rules (identity checks, limits).
    `buy` should create a checkout session on the partner and return its URL."""

    name = "partner"
    demo = False

    def __init__(self, node: "Node", api_key: str) -> None:
        self.node, self.api_key = node, api_key

    def _nope(self, *_a, **_k):
        raise ExchangeError("The licensed exchange partner integration has not been connected yet.")

    quote = account = buy = sell = _nope


def make_provider(node: "Node") -> ExchangeProvider:
    cfg = node.config
    if cfg.exchange_provider == "partner":
        if not (cfg.exchange_live and cfg.exchange_api_key):
            raise ValueError("exchange_provider = 'partner' needs exchange_api_key and exchange_live = true")
        return PartnerProvider(node, cfg.exchange_api_key)
    return DemoProvider(node)
