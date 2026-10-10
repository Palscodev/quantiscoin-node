"""Request models (validated by Pydantic). Amounts are integers in quanta."""
from __future__ import annotations

from pydantic import BaseModel, Field

MAX_AMOUNT = 10**16


class Credentials(BaseModel):
    username: str = Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class Signup(Credentials):
    password: str = Field(min_length=8, max_length=256)
    backup: str | None = Field(default=None, max_length=64_000)
    backup_passphrase: str | None = Field(default=None, max_length=256)


class Setup(Signup):
    setup_code: str = Field(min_length=4, max_length=20)


class PasswordChange(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=8, max_length=256)


class DeleteAccount(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    confirm: str = Field(pattern=r"^DELETE$")  # the user must type DELETE


class ExchangeQuote(BaseModel):
    side: str = Field(pattern=r"^(buy|sell)$")
    qts: int | None = Field(default=None, gt=0, le=MAX_AMOUNT)
    usd_cents: int | None = Field(default=None, gt=0, le=10**9)


class DemoCard(BaseModel):
    number: str = Field(max_length=30)
    exp_month: int = Field(ge=0, le=99)
    exp_year: int = Field(ge=0, le=9999)
    cvc: str = Field(max_length=4)
    name: str = Field(default="", max_length=100)
    postal: str = Field(default="", max_length=12)


class ExchangeBuy(BaseModel):
    quote_id: str = Field(max_length=40)
    method: str = Field(pattern=r"^(card|cash)$")
    card: DemoCard | None = None


class ExchangeSell(BaseModel):
    quote_id: str = Field(max_length=40)


class Passphrase(BaseModel):
    passphrase: str = Field(min_length=1, max_length=256)


class TxPreview(BaseModel):
    to: str = Field(min_length=20, max_length=40)
    amount: int = Field(gt=0, le=MAX_AMOUNT)
    fee_rate: int | None = Field(default=None, ge=0, le=1_000_000)
    fee: int | None = Field(default=None, ge=0, le=MAX_AMOUNT)


class TxSend(BaseModel):
    to: str = Field(min_length=20, max_length=40)
    amount: int = Field(gt=0, le=MAX_AMOUNT)
    fee: int = Field(ge=0, le=MAX_AMOUNT)
    passphrase: str = Field(min_length=1, max_length=256)


class RawTx(BaseModel):
    hex: str = Field(min_length=2, max_length=40_000, pattern=r"^[0-9a-fA-F]+$")


class MineSubmit(BaseModel):
    job_id: str = Field(min_length=8, max_length=64, pattern=r"^[0-9a-f]+$")
    nonce: str = Field(min_length=1, max_length=20, pattern=r"^[0-9]+$")  # decimal u64 (exact in JSON)


class MinerStart(BaseModel):
    address: str = Field(min_length=20, max_length=40)
    workers: int = Field(default=1, ge=1, le=64)
    low_power: bool = False


class LowPower(BaseModel):
    enabled: bool


class PeerAdd(BaseModel):
    url: str = Field(min_length=8, max_length=200)


class Price(BaseModel):
    usd_per_qts: float = Field(ge=0, le=1_000_000_000)


class AdminFlag(BaseModel):
    is_admin: bool


class Generate(BaseModel):
    address: str = Field(min_length=20, max_length=40)
    blocks: int = Field(default=1, ge=1, le=200)
