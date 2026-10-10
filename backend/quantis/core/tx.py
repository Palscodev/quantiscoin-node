"""Transaction format (UTXO model).

Serialization (all integers little-endian):
  tx     = version:u32 | n_in:varint | input*  | n_out:varint | output* | locktime:u32
  input  = prev_txid:32 | vout:u32 | pubkey:varbytes | sig:varbytes
  output = amount:u64 | h20:20

txid    = SHA-256d(serialize(tx))                   (displayed as plain big-endian hex)
sighash = SHA-256d("QUANTIS/sig/v1" | magic:4 | serialize(tx with every sig emptied))

A coinbase has exactly one input with prev_txid = 32 zero bytes, vout = 0xFFFFFFFF,
an empty pubkey, and sig = height:u64 || up to 92 extra bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .encoding import DecodeError, Reader, u32, u64, varbytes, varint
from .hashing import sha256d

NULL_TXID = b"\0" * 32
COINBASE_VOUT = 0xFFFFFFFF
SIGHASH_TAG = b"QUANTIS/sig/v1"
MAX_SCRIPT_FIELD = 100  # bound for pubkey / signature fields during parsing
MIN_INPUT_BYTES = 32 + 4 + 1 + 1
OUTPUT_BYTES = 8 + 20


@dataclass
class TxIn:
    prev_txid: bytes
    vout: int
    pubkey: bytes = b""
    sig: bytes = b""

    def serialize(self, with_sig: bool = True) -> bytes:
        return self.prev_txid + u32(self.vout) + varbytes(self.pubkey) + varbytes(self.sig if with_sig else b"")

    @property
    def outpoint(self) -> tuple[bytes, int]:
        return (self.prev_txid, self.vout)


@dataclass
class TxOut:
    amount: int
    h20: bytes

    def serialize(self) -> bytes:
        return u64(self.amount) + self.h20


@dataclass
class Tx:
    inputs: list[TxIn]
    outputs: list[TxOut]
    version: int = 1
    locktime: int = 0
    _txid: bytes | None = field(default=None, repr=False, compare=False)

    def serialize(self, with_sigs: bool = True) -> bytes:
        parts = [u32(self.version), varint(len(self.inputs))]
        parts += [i.serialize(with_sigs) for i in self.inputs]
        parts.append(varint(len(self.outputs)))
        parts += [o.serialize() for o in self.outputs]
        parts.append(u32(self.locktime))
        return b"".join(parts)

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def txid(self) -> bytes:
        if self._txid is None:
            self._txid = sha256d(self.serialize())
        return self._txid

    def invalidate_cache(self) -> None:
        self._txid = None

    def sighash(self, magic: bytes) -> bytes:
        return sha256d(SIGHASH_TAG + magic + self.serialize(with_sigs=False))

    def is_coinbase(self) -> bool:
        return (
            len(self.inputs) == 1
            and self.inputs[0].prev_txid == NULL_TXID
            and self.inputs[0].vout == COINBASE_VOUT
        )

    def coinbase_height(self) -> int | None:
        if not self.is_coinbase() or len(self.inputs[0].sig) < 8:
            return None
        return int.from_bytes(self.inputs[0].sig[:8], "little")

    def total_out(self) -> int:
        return sum(o.amount for o in self.outputs)

    @classmethod
    def read(cls, r: Reader, max_inputs: int = 10_000, max_outputs: int = 10_000) -> "Tx":
        version = r.u32()
        inputs = []
        for _ in range(r.count(max_inputs, MIN_INPUT_BYTES)):
            prev = r.read(32)
            vout = r.u32()
            pubkey = r.varbytes(MAX_SCRIPT_FIELD)
            sig = r.varbytes(MAX_SCRIPT_FIELD)
            inputs.append(TxIn(prev, vout, pubkey, sig))
        outputs = [TxOut(r.u64(), r.read(20)) for _ in range(r.count(max_outputs, OUTPUT_BYTES))]
        locktime = r.u32()
        return cls(inputs=inputs, outputs=outputs, version=version, locktime=locktime)

    @classmethod
    def deserialize(cls, data: bytes) -> "Tx":
        r = Reader(data)
        tx = cls.read(r)
        r.finish()
        return tx


def make_coinbase(height: int, outputs: list[TxOut], extra: bytes = b"") -> Tx:
    if len(extra) > MAX_SCRIPT_FIELD - 8:
        raise ValueError("coinbase extra data too long")
    return Tx(inputs=[TxIn(NULL_TXID, COINBASE_VOUT, b"", u64(height) + extra)], outputs=outputs)


__all__ = ["Tx", "TxIn", "TxOut", "make_coinbase", "NULL_TXID", "COINBASE_VOUT", "DecodeError"]
