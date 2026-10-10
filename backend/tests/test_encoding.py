"""Deterministic serialization, hashing, Merkle roots, addresses, malformed input."""
import pytest

from quantis.core.address import AddressError, b58decode, b58encode, decode_address, encode_address
from quantis.core.block import HEADER_BYTES, Block, BlockHeader
from quantis.core.encoding import DecodeError, Reader, varint
from quantis.core.genesis import genesis_block
from quantis.core.hashing import sha256d
from quantis.core.merkle import merkle_root
from quantis.core.params import DEVNET, REGTEST
from quantis.core.tx import Tx, TxIn, TxOut, make_coinbase


def test_sha256d_known_vector():
    # SHA-256d("") from Bitcoin test vectors
    assert sha256d(b"").hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"


def test_header_layout_is_fixed():
    h = BlockHeader(1, 7, b"\x11" * 32, b"\x22" * 32, 1234, (1 << 240) + 5, 0xDEADBEEF)
    raw = h.serialize()
    assert len(raw) == HEADER_BYTES == 124
    assert raw[:4] == b"\x01\0\0\0" and raw[4:12] == (7).to_bytes(8, "little")
    assert raw[76:84] == (1234).to_bytes(8, "little")
    assert raw[84:116] == ((1 << 240) + 5).to_bytes(32, "big")
    assert raw[116:] == (0xDEADBEEF).to_bytes(8, "little")
    assert BlockHeader.deserialize(raw) == h
    assert h.hash == sha256d(raw)


def test_genesis_is_deterministic_and_valid():
    g1, g2 = genesis_block(DEVNET), genesis_block(DEVNET)
    assert g1.hash == g2.hash
    assert g1.header.meets_target()
    assert genesis_block(REGTEST).hash != g1.hash
    assert Block.deserialize(g1.serialize()).hash == g1.hash


def test_tx_roundtrip_and_txid_stability():
    tx = Tx(inputs=[TxIn(b"\x01" * 32, 3, b"\x02" * 33, b"\x30" * 70)], outputs=[TxOut(5, b"\x09" * 20)])
    raw = tx.serialize()
    back = Tx.deserialize(raw)
    assert back == tx and back.txid == tx.txid == sha256d(raw)
    # the signature-free serialization (sighash preimage) ignores signatures
    other = Tx.deserialize(raw)
    other.inputs[0].sig = b"\x30" * 10
    assert other.sighash(DEVNET.magic) == tx.sighash(DEVNET.magic)
    assert tx.sighash(DEVNET.magic) != tx.sighash(REGTEST.magic)  # cross-network replay protection


def test_varint_canonical():
    for n in (0, 0xFC, 0xFD, 0xFFFF, 0x10000, 2**32):
        assert Reader(varint(n)).varint() == n
    with pytest.raises(DecodeError):
        Reader(b"\xfd\x10\x00").varint()  # 16 encoded in 3 bytes is non-canonical


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x01\0\0\0",
        b"\x01\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff",  # absurd input count
        b"\x01\0\0\0\x00\x00\0\0\0\0\x00",  # trailing byte
    ],
)
def test_malformed_tx_rejected(raw):
    with pytest.raises(DecodeError):
        Tx.deserialize(raw)


def test_block_size_limit_on_decode():
    g = genesis_block(REGTEST)
    with pytest.raises(DecodeError):
        Block.deserialize(g.serialize(), max_bytes=10)
    with pytest.raises(DecodeError):
        Block.deserialize(g.serialize() + b"\0")


def test_merkle_root_rules():
    a, b, c = (bytes([i]) * 32 for i in (1, 2, 3))
    leaf = lambda t: sha256d(b"\x00" + t)
    node = lambda l, r: sha256d(b"\x01" + l + r)
    assert merkle_root([a]) == leaf(a)
    assert merkle_root([a, b]) == node(leaf(a), leaf(b))
    assert merkle_root([a, b, c]) == node(node(leaf(a), leaf(b)), leaf(c))  # odd node promoted
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])  # no duplication ambiguity
    assert merkle_root([a, b]) != merkle_root([b, a])
    with pytest.raises(ValueError):
        merkle_root([])


def test_address_roundtrip_and_checksum():
    h20 = bytes(range(20))
    addr = encode_address(h20, DEVNET.address_version)
    assert decode_address(addr, DEVNET.address_version) == h20
    bad = addr[:-1] + ("2" if addr[-1] != "2" else "3")
    with pytest.raises(AddressError):
        decode_address(bad, DEVNET.address_version)
    with pytest.raises(AddressError):
        decode_address(addr, DEVNET.address_version + 1)
    with pytest.raises(AddressError):
        decode_address("0OIl" * 6, DEVNET.address_version)
    assert b58decode(b58encode(b"\0\0abc")) == b"\0\0abc"


def test_coinbase_structure():
    cb = make_coinbase(42, [TxOut(1, b"\0" * 20)])
    assert cb.is_coinbase() and cb.coinbase_height() == 42
    assert make_coinbase(43, [TxOut(1, b"\0" * 20)]).txid != cb.txid
