"""Wallet service: balances, history, transaction construction and signing.

Private keys exist only transiently inside `send()`: the seed is decrypted with
the passphrase, the needed keys are derived, the transaction is signed, and the
references are dropped. Nothing secret is returned or logged.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..core.address import AddressError, decode_address
from ..core.chainstate import ChainState
from ..core.crypto import PrivateKey
from ..core.mempool import Mempool
from ..core.tx import Tx, TxIn, TxOut
from ..core.validation import ValidationError
from ..explorer import tx_view
from ..storage.db import Database
from .keystore import Keystore, KeystoreError, derive_secret

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
DUMMY_SIG_LEN = 72
WRONG_PASSWORD = "That password is not correct."  # upper bound on a low-S strict-DER signature, used for size estimates


class WalletError(ValueError):
    pass


@dataclass
class Coin:
    txid: bytes
    vout: int
    amount: int
    h20: bytes
    height: int | None  # None = unconfirmed (mempool)


class WalletService:
    def __init__(self, db: Database, chain: ChainState, mempool: Mempool) -> None:
        self.db, self.chain, self.mempool = db, chain, mempool
        self.p = chain.p

    @property
    def legacy(self) -> frozenset[str]:
        """Fingerprints of networks this node ran before a chain restart (see `quantis reset-chain`).
        Wallets made there keep their addresses and still open with the same password."""
        raw = self.db.get_meta("legacy_magics") or ""
        return frozenset(m for m in raw.split(",") if m)

    def _upgrade(self, name: str, ks: Keystore, seed: bytes, passphrase: str) -> None:
        """Re-seal a wallet from an earlier network for this one (same seed, so same addresses)."""
        if ks.data.get("network_magic") == self.p.magic.hex():
            return
        fresh = Keystore.create(passphrase, self.p.magic, self.p.address_version, seed=seed, n_addresses=len(ks.addresses))
        fresh.data["created"] = ks.data.get("created", fresh.data["created"])
        self._save(name, fresh, new=False)

    # ------------------------------------------------------------- storage
    def names(self) -> list[str]:
        return [r[0] for r in self.db.all("SELECT name FROM wallets ORDER BY name")]

    def _load(self, name: str) -> Keystore:
        row = self.db.one("SELECT keystore FROM wallets WHERE name=?", (name,))
        if row is None:
            raise WalletError(f"wallet {name!r} not found")
        return Keystore.from_json(row[0], self.p.magic, self.legacy)

    def _save(self, name: str, ks: Keystore, new: bool) -> None:
        if new:
            self.db.execute("INSERT INTO wallets VALUES (?, ?, ?)", (name, ks.to_json(), int(time.time())))
        else:
            self.db.execute("UPDATE wallets SET keystore=? WHERE name=?", (ks.to_json(), name))

    def _check_new_name(self, name: str) -> None:
        if not NAME_RE.match(name):
            raise WalletError("wallet name must be 1-32 characters: letters, digits, _ or -")
        if self.db.one("SELECT 1 FROM wallets WHERE name=?", (name,)):
            raise WalletError(f"wallet {name!r} already exists")

    def create(self, name: str, passphrase: str) -> dict:
        self._check_new_name(name)
        ks = Keystore.create(passphrase, self.p.magic, self.p.address_version)
        self._save(name, ks, new=True)
        return self.summary(name)

    def import_backup(self, name: str, backup_json: str, passphrase: str) -> dict:
        self._check_new_name(name)
        ks = Keystore.from_json(backup_json, self.p.magic, self.legacy)
        ks.verify_addresses(passphrase, self.p.address_version)
        self._save(name, ks, new=True)
        return self.summary(name)

    def create_with_seed(self, name: str, passphrase: str, seed: bytes | None = None, n_addresses: int = 1) -> dict:
        """Create a wallet (optionally from an existing seed, e.g. a restored backup)."""
        self._check_new_name(name)
        ks = Keystore.create(passphrase, self.p.magic, self.p.address_version, seed=seed,
                             n_addresses=max(1, min(n_addresses, 1000)))
        self._save(name, ks, new=True)
        return self.summary(name)

    def seed_from_backup(self, backup_json: str, backup_passphrase: str) -> tuple[bytes, int]:
        """Decrypt and verify a backup file; return (seed, number of addresses)."""
        ks = Keystore.from_json(backup_json, self.p.magic, self.legacy)
        ks.verify_addresses(backup_passphrase, self.p.address_version)
        return ks.unlock(backup_passphrase), len(ks.addresses)

    def exists(self, name: str) -> bool:
        return self.db.one("SELECT 1 FROM wallets WHERE name=?", (name,)) is not None

    def change_passphrase(self, name: str, old: str, new: str) -> None:
        """Re-encrypt the wallet seed under a new passphrase (addresses are unchanged)."""
        ks = self._load(name)
        try:
            seed = ks.unlock(old)
        except KeystoreError as e:
            raise WalletError(WRONG_PASSWORD) from e
        fresh = Keystore.create(new, self.p.magic, self.p.address_version, seed=seed, n_addresses=len(ks.addresses))
        fresh.data["created"] = ks.data.get("created", fresh.data["created"])
        self._save(name, fresh, new=False)

    def first_address(self, name: str) -> str:
        return self._load(name).addresses[0]["address"]

    def export_backup(self, name: str) -> str:
        return self._load(name).to_json()

    def new_address(self, name: str, passphrase: str) -> dict:
        ks = self._load(name)
        try:
            entry = ks.new_address(passphrase, self.p.address_version)
        except KeystoreError as e:
            raise WalletError(WRONG_PASSWORD) from e
        self._save(name, ks, new=False)
        return entry

    # ------------------------------------------------------------ balances
    def _owned(self, ks: Keystore) -> dict[bytes, dict]:
        return {decode_address(a["address"], self.p.address_version): a for a in ks.addresses}

    def _coins(self, owned: dict[bytes, dict]) -> tuple[list[Coin], list[Coin], list[Coin]]:
        """(spendable, immature, pending-incoming) coins, excluding outputs spent in the mempool."""
        next_h = self.chain.height + 1
        spendable, immature, pending = [], [], []
        for h20 in owned:
            for txid, vout, amount, height, cb in self.db.all(
                "SELECT txid, vout, amount, height, coinbase FROM utxo WHERE h20=?", (h20,)
            ):
                if (txid, vout) in self.mempool.spends:
                    continue
                c = Coin(txid, vout, amount, h20, height)
                if cb and next_h - height < self.p.coinbase_maturity:
                    immature.append(c)
                else:
                    spendable.append(c)
        for txid, e in self.mempool.entries.items():
            for n, o in enumerate(e.tx.outputs):
                if o.h20 in owned and (txid, n) not in self.mempool.spends:
                    pending.append(Coin(txid, n, o.amount, o.h20, None))
        return spendable, immature, pending

    def summary(self, name: str) -> dict:
        ks = self._load(name)
        owned = self._owned(ks)
        spendable, immature, pending = self._coins(owned)
        per_addr = {h: {"confirmed": 0, "immature": 0, "unconfirmed": 0} for h in owned}
        for c in spendable:
            per_addr[c.h20]["confirmed"] += c.amount
        for c in immature:
            per_addr[c.h20]["immature"] += c.amount
        for c in pending:
            per_addr[c.h20]["unconfirmed"] += c.amount
        maturity_heights = sorted({c.height + self.p.coinbase_maturity for c in immature})
        return {
            "name": name,
            "addresses": [{**{k: v for k, v in owned[h].items() if k != "pubkey"}, **per_addr[h]} for h in owned],
            "balance": {
                "confirmed": sum(c.amount for c in spendable),
                "immature": sum(c.amount for c in immature),
                "unconfirmed": sum(c.amount for c in pending),
                "next_maturity_height": maturity_heights[0] if maturity_heights else None,
            },
        }

    def history(self, name: str, limit: int = 50) -> list[dict]:
        owned = self._owned(self._load(name))
        if not owned:
            return []
        marks = ",".join("?" * len(owned))
        rows = self.db.all(
            f"SELECT DISTINCT txid, height FROM addrtx WHERE h20 IN ({marks}) ORDER BY height DESC LIMIT ?",
            (*owned.keys(), limit),
        )
        items = []
        for txid, e in self.mempool.entries.items():
            if any(o.h20 in owned for o in e.tx.outputs) or any(
                (u := self.mempool.lookup_spent_prevout(i.outpoint)) is not None and u.h20 in owned
                for i in e.tx.inputs
            ):
                items.append(self._history_item(e.tx, None, None, owned))
        for txid, height in rows:
            found = self.chain.get_tx(txid)
            if found:
                tx, h, bh = found
                items.append(self._history_item(tx, h, bh, owned))
        return items

    def _history_item(self, tx: Tx, height, block_hash, owned) -> dict:
        v = tx_view(self.chain, self.mempool, tx, height, block_hash)
        received = sum(o["amount"] for o, raw in zip(v["outputs"], tx.outputs) if raw.h20 in owned)
        sent = sum(
            i["amount"] or 0
            for i in v["inputs"]
            if not i["coinbase"] and i["address"] and decode_address(i["address"], self.p.address_version) in owned
        )
        ts = self.chain.active[height].timestamp if height is not None else None
        return {
            "txid": v["txid"],
            "height": height,
            "confirmations": v["confirmations"],
            "status": v["status"],
            "coinbase": v["coinbase"],
            "net": received - sent,
            "fee": v["fee"] if sent else 0,
            "timestamp": ts,
        }

    # -------------------------------------------------------- transactions
    def _estimate_size(self, n_in: int, n_out: int) -> int:
        dummy = Tx(
            inputs=[TxIn(b"\0" * 32, 0, b"\0" * 33, b"\0" * DUMMY_SIG_LEN) for _ in range(n_in)],
            outputs=[TxOut(1, b"\0" * 20) for _ in range(n_out)],
        )
        return dummy.size

    def _plan(self, name: str, to_address: str, amount: int, fee_rate: int | None, fee: int | None) -> dict:
        try:
            to_h20 = decode_address(to_address.strip(), self.p.address_version)
        except AddressError as e:
            raise WalletError(f"invalid recipient address: {e}") from e
        if not (0 < amount <= self.p.max_money):
            raise WalletError("amount out of range")
        ks = self._load(name)
        owned = self._owned(ks)
        if not owned:
            raise WalletError("wallet has no addresses")
        spendable, _, pending = self._coins(owned)
        coins = sorted(spendable, key=lambda c: (-c.amount, c.txid, c.vout)) + sorted(
            pending, key=lambda c: (-c.amount, c.txid, c.vout)
        )
        policy_rate = self.mempool.policy.rate(self.mempool.bytes)
        rate = policy_rate if fee_rate is None else fee_rate
        if rate < 0 or (fee is not None and fee < 0):
            raise WalletError("fee must be non-negative")
        chosen, total = [], 0
        for c in coins:
            chosen.append(c)
            total += c.amount
            size = self._estimate_size(len(chosen), 2)
            need_fee = fee if fee is not None else size * rate
            if total >= amount + need_fee:
                break
        else:
            size = self._estimate_size(max(len(chosen), 1), 2)
            need_fee = fee if fee is not None else size * rate
            raise WalletError(
                f"insufficient spendable funds: have {total}, need {amount + need_fee} (amount + fee) quanta"
            )
        change = total - amount - need_fee
        change_h20 = next(iter(owned))
        outputs = [TxOut(amount, to_h20)] + ([TxOut(change, change_h20)] if change > 0 else [])
        tx = Tx(inputs=[TxIn(c.txid, c.vout) for c in chosen], outputs=outputs)
        return {
            "tx": tx,
            "coins": chosen,
            "owned": owned,
            "fee": need_fee,
            "change": change,
            "size_estimate": size,
            "policy_min_fee": self.mempool.min_fee(size),
            "consensus_min_fee": size * self.p.min_fee_per_byte,
            "policy_rate": policy_rate,
        }

    def max_sendable(self, name: str, fee_rate: int | None = None) -> dict:
        """Largest amount that can be sent (all spendable coins minus the fee for spending them)."""
        owned = self._owned(self._load(name))
        spendable, _, pending = self._coins(owned)
        coins = spendable + pending
        rate = self.mempool.policy.rate(self.mempool.bytes) if fee_rate is None else fee_rate
        if not coins:
            return {"amount": 0, "fee": 0, "inputs": 0}
        fee = self._estimate_size(len(coins), 2) * rate
        total = sum(c.amount for c in coins)
        return {"amount": max(0, total - fee), "fee": fee, "inputs": len(coins)}

    def preview(self, name: str, to_address: str, amount: int, fee_rate: int | None = None, fee: int | None = None) -> dict:
        plan = self._plan(name, to_address, amount, fee_rate, fee)
        return {
            "recipient": to_address.strip(),
            "amount": amount,
            "fee": plan["fee"],
            "change": plan["change"],
            "size_estimate": plan["size_estimate"],
            "fee_rate": plan["fee"] / plan["size_estimate"],
            "policy_min_fee": plan["policy_min_fee"],
            "policy_rate": plan["policy_rate"],
            "consensus_min_fee": plan["consensus_min_fee"],
            "meets_policy": plan["fee"] >= plan["policy_min_fee"],
            "inputs": [
                {"txid": c.txid.hex(), "vout": c.vout, "amount": c.amount, "confirmed": c.height is not None}
                for c in plan["coins"]
            ],
            "total_debit": amount + plan["fee"],
        }

    def send(self, name: str, passphrase: str, to_address: str, amount: int, fee: int) -> dict:
        """Sign exactly `amount` + `fee` (the values the user reviewed) and submit to the mempool."""
        plan = self._plan(name, to_address, amount, None, fee)
        ks = self._load(name)
        try:
            seed = ks.unlock(passphrase)
        except KeystoreError as e:
            raise WalletError(WRONG_PASSWORD) from e
        tx: Tx = plan["tx"]
        keys = []
        for c, inp in zip(plan["coins"], tx.inputs):
            k = PrivateKey(derive_secret(seed, plan["owned"][c.h20]["index"]))
            inp.pubkey = k.public_key()
            keys.append(k)
        digest = tx.sighash(self.p.magic)
        for k, inp in zip(keys, tx.inputs):
            inp.sig = k.sign(digest)
        tx.invalidate_cache()
        self._upgrade(name, ks, seed, passphrase)
        del seed, keys
        try:
            self.mempool.accept(tx)
        except ValidationError as e:
            raise WalletError(f"transaction rejected: {e.message}") from e
        return {"txid": tx.txid.hex(), "size": tx.size, "fee": fee}
