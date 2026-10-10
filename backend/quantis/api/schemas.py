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
