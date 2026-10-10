"""Encrypted wallet keystore.

A wallet is a random 32-byte seed. Signing keys are derived deterministically:
    k_i = (int(HMAC-SHA512(seed, "quantis/key" || i:u32be)[:32]) mod (n-1)) + 1
so a single backup of the seed covers every address the wallet will ever use.
This derivation is a documented QuantisCoin design choice, NOT BIP-32/BIP-39.

At rest the seed is encrypted with AES-256-GCM under a key from scrypt
(N=2^14, r=8, p=1) applied to the passphrase. Public data (addresses, pubkeys)
is stored in clear so balances can be shown without the passphrase.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.address import pubkey_to_address
from ..core.crypto import CURVE_ORDER, PrivateKey

KEYSTORE_VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 14, 8, 1
MIN_PASSPHRASE = 8


class KeystoreError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


def _kdf(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)


def derive_secret(seed: bytes, index: int) -> int:
    d = hmac.new(seed, b"quantis/key" + index.to_bytes(4, "big"), hashlib.sha512).digest()
    return int.from_bytes(d[:32], "big") % (CURVE_ORDER - 1) + 1


@dataclass
class Keystore:
    data: dict  # JSON-serializable; contains only ciphertext + public data

    @classmethod
    def create(cls, passphrase: str, magic: bytes, address_version: int, seed: bytes | None = None,
               n_addresses: int = 1) -> "Keystore":
        if len(passphrase) < MIN_PASSPHRASE:
            raise KeystoreError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
        seed = seed or os.urandom(32)
        salt, nonce = os.urandom(16), os.urandom(12)
        aad = cls._aad(magic)
        ct = AESGCM(_kdf(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, seed, aad)
        ks = cls(
            {
                "version": KEYSTORE_VERSION,
                "network_magic": magic.hex(),
                "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
                "cipher": {"name": "aes-256-gcm", "nonce": _b64(nonce), "ciphertext": _b64(ct)},
                "addresses": [],
                "created": int(time.time()),
            }
        )
        for _ in range(n_addresses):
            ks._append_address(seed, address_version)
        return ks

    @staticmethod
    def _aad(magic: bytes) -> bytes:
        return b"QUANTIS/keystore/v1|" + magic

    @classmethod
    def from_json(cls, text: str, magic: bytes) -> "Keystore":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise KeystoreError("backup is not valid JSON") from e
        if not isinstance(data, dict) or data.get("version") != KEYSTORE_VERSION:
            raise KeystoreError("unsupported keystore version")
        if data.get("network_magic") != magic.hex():
            raise KeystoreError("backup belongs to a different network")
        for key in ("kdf", "cipher", "addresses"):
            if key not in data:
                raise KeystoreError(f"backup missing field {key!r}")
        return cls(data)

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2, sort_keys=True)

    def unlock(self, passphrase: str) -> bytes:
        kdf, c = self.data["kdf"], self.data["cipher"]
        try:
            key = _kdf(passphrase, _unb64(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
            seed = AESGCM(key).decrypt(_unb64(c["nonce"]), _unb64(c["ciphertext"]),
                                       self._aad(bytes.fromhex(self.data["network_magic"])))
        except (InvalidTag, ValueError, KeyError) as e:
            raise KeystoreError("Wrong password for this wallet or backup file, or the file is damaged.") from e
        if len(seed) != 32:
            raise KeystoreError("corrupted seed")
        return seed

    def _append_address(self, seed: bytes, address_version: int) -> dict:
        i = len(self.data["addresses"])
        pub = PrivateKey(derive_secret(seed, i)).public_key()
        entry = {"index": i, "pubkey": pub.hex(), "address": pubkey_to_address(pub, address_version)}
        self.data["addresses"].append(entry)
        return entry

    def new_address(self, passphrase: str, address_version: int) -> dict:
        return self._append_address(self.unlock(passphrase), address_version)

    def verify_addresses(self, passphrase: str, address_version: int) -> None:
        """Check that every stored public address really derives from the encrypted seed."""
        seed = self.unlock(passphrase)
        for a in self.data["addresses"]:
            pub = PrivateKey(derive_secret(seed, a["index"])).public_key()
            if pub.hex() != a["pubkey"] or pubkey_to_address(pub, address_version) != a["address"]:
                raise KeystoreError("backup address list does not match its seed")

    @property
    def addresses(self) -> list[dict]:
        return list(self.data["addresses"])
