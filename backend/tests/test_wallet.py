"""Keystore encryption, deterministic derivation, backup/restore."""
import json

import pytest

from quantis.core.crypto import PrivateKey
from quantis.core.params import DEVNET, REGTEST
from quantis.wallet.keystore import Keystore, KeystoreError, derive_secret


def test_create_unlock_and_derive():
    ks = Keystore.create("correct horse", REGTEST.magic, REGTEST.address_version, n_addresses=3)
    seed = ks.unlock("correct horse")
    assert len(seed) == 32 and len(ks.addresses) == 3
    for a in ks.addresses:
        assert PrivateKey(derive_secret(seed, a["index"])).public_key().hex() == a["pubkey"]
    assert len({a["address"] for a in ks.addresses}) == 3


def test_wrong_passphrase_and_short_passphrase():
    ks = Keystore.create("correct horse", REGTEST.magic, REGTEST.address_version)
    with pytest.raises(KeystoreError):
        ks.unlock("wrong horse")
    with pytest.raises(KeystoreError):
        Keystore.create("short", REGTEST.magic, REGTEST.address_version)


def test_backup_contains_no_plaintext_seed_and_restores():
    seed = bytes(range(32))
    ks = Keystore.create("correct horse", REGTEST.magic, REGTEST.address_version, seed=seed, n_addresses=2)
    text = ks.to_json()
    assert seed.hex() not in text
    secret = derive_secret(seed, 0)
    assert f"{secret:x}" not in text and str(secret) not in text
    restored = Keystore.from_json(text, REGTEST.magic)
    assert restored.unlock("correct horse") == seed
    restored.verify_addresses("correct horse", REGTEST.address_version)


def test_tampered_backup_detected():
    ks = Keystore.create("correct horse", REGTEST.magic, REGTEST.address_version)
    data = json.loads(ks.to_json())
    data["addresses"][0]["address"] = "QZZZ"
    with pytest.raises(KeystoreError):
        Keystore.from_json(json.dumps(data), REGTEST.magic).verify_addresses("correct horse", REGTEST.address_version)
    ct = data["cipher"]["ciphertext"]
    data["cipher"]["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    with pytest.raises(KeystoreError):
        Keystore.from_json(json.dumps(data), REGTEST.magic).unlock("correct horse")


def test_backup_bound_to_network():
    ks = Keystore.create("correct horse", REGTEST.magic, REGTEST.address_version)
    with pytest.raises(KeystoreError):
        Keystore.from_json(ks.to_json(), DEVNET.magic)
    with pytest.raises(KeystoreError):
        Keystore.from_json("not json", REGTEST.magic)
