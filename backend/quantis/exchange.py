"""Buy / sell QTS through a pluggable exchange provider.

Selling cryptocurrency for real money is a regulated activity (money transmission,
identity checks, anti-money-laundering rules). This module therefore never handles
real money itself. It defines one interface and two providers:

* DemoProvider (default): simulated quotes and orders. No dollars move, no QTS is
  created or transferred, every response says demo=True, and the UI labels it.
* PartnerProvider: the slot for a *licensed* exchange or on-ramp partner. It is used
  only when exchange_provider = "partner", an API key is configured
  (QUANTIS_EXCHANGE_API_KEY) AND exchange_live = true. Fill in its methods with the
  partner's API calls once the business is licensed or partnered.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .node import Node

COIN = 100_000_000
DEMO_PRICE_USD = 1.00  # fixed, labelled demo price; NOT a market price
DEMO_FEE_RATE = 0.01  # 1% simulated fee


class ExchangeError(ValueError):
    pass


@dataclass
class Quote:
    side: str
    qts: int  # quanta
    usd_cents: int
    fee_cents: int
    price_usd: float
    demo: bool

    def view(self) -> dict:
        return {"side": self.side, "qts": self.qts, "usd_cents": self.usd_cents, "fee_cents": self.fee_cents,
                "price_usd": self.price_usd, "demo": self.demo}


class ExchangeProvider:
    name = "base"
    demo = True

    def quote(self, side: str, qts: int) -> Quote:  # pragma: no cover - interface
        raise NotImplementedError

    def place(self, user_id: int, quote: Quote, address: str) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class DemoProvider(ExchangeProvider):
    name = "demo"
    demo = True

    def __init__(self, node: "Node") -> None:
        self.node = node

    def quote(self, side: str, qts: int) -> Quote:
        gross = round(qts / COIN * DEMO_PRICE_USD * 100)
        fee = max(1, round(gross * DEMO_FEE_RATE))
        total = gross + fee if side == "buy" else max(0, gross - fee)
        return Quote(side, qts, total, fee, DEMO_PRICE_USD, True)

    def place(self, user_id: int, quote: Quote, address: str) -> dict:
        order_id = "demo-" + secrets.token_hex(6)
        self.node.db.execute(
            "INSERT INTO exchange_orders VALUES (?,?,?,?,?,?,?,?)",
            (order_id, user_id, quote.side, quote.qts, quote.usd_cents, address, "simulated", int(time.time())),
        )
        return {"order_id": order_id, "status": "simulated", "demo": True,
                "message": "Demo order recorded. No money was charged and no QTS was moved."}


class PartnerProvider(ExchangeProvider):
    """Licensed partner integration. Intentionally not implemented: it must be built against
    the real partner's API, under that partner's compliance rules (identity checks, limits)."""

    name = "partner"
    demo = False

    def __init__(self, node: "Node", api_key: str) -> None:
        self.node, self.api_key = node, api_key

    def quote(self, side: str, qts: int) -> Quote:
        raise ExchangeError("The licensed exchange partner integration has not been connected yet.")

    def place(self, user_id: int, quote: Quote, address: str) -> dict:
        raise ExchangeError("The licensed exchange partner integration has not been connected yet.")


def make_provider(node: "Node") -> ExchangeProvider:
    cfg = node.config
    if cfg.exchange_provider == "partner":
        if not (cfg.exchange_live and cfg.exchange_api_key):
            raise ValueError("exchange_provider = 'partner' needs exchange_api_key and exchange_live = true")
        return PartnerProvider(node, cfg.exchange_api_key)
    return DemoProvider(node)
