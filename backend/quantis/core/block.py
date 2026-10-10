"""Block header and block serialization.

Header (exactly 124 bytes):
  version:u32 | height:u64 | prev_hash:32 | merkle_root:32 | timestamp:u64 | target:32 | nonce:u64
`target` is a 256-bit unsigned integer stored big-endian. The nonce is the final
field so that miners can precompute the SHA-256 state of the first 116 bytes.

block_hash = SHA-256d(header). The proof of work is valid iff
    int.from_bytes(block_hash, "big") <= target
Block = header | n_tx:varint | tx*
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from .encoding import Reader, u32, u64, varint
from .hashing import hash_to_int, sha256d
from .merkle import merkle_root
from .tx import MIN_INPUT_BYTES, Tx

HEADER_BYTES = 124
HEADER_PREFIX_BYTES = 116  # everything before the nonce


@dataclass(frozen=True)
class BlockHeader:
    version: int
    height: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    target: int
    nonce: int

    def prefix(self) -> bytes:
        return (
            u32(self.version)
            + u64(self.height)
            + self.prev_hash
            + self.merkle_root
            + u64(self.timestamp)
            + self.target.to_bytes(32, "big")
        )

    def serialize(self) -> bytes:
        return self.prefix() + u64(self.nonce)

    @property
    def hash(self) -> bytes:
        return sha256d(self.serialize())

    def meets_target(self) -> bool:
        return hash_to_int(self.hash) <= self.target

    def with_nonce(self, nonce: int) -> "BlockHeader":
        return replace(self, nonce=nonce)

    @classmethod
    def read(cls, r: Reader) -> "BlockHeader":
        return cls(
            version=r.u32(),
            height=r.u64(),
            prev_hash=r.read(32),
            merkle_root=r.read(32),
            timestamp=r.u64(),
            target=int.from_bytes(r.read(32), "big"),
            nonce=r.u64(),
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "BlockHeader":
        r = Reader(data)
        h = cls.read(r)
        r.finish()
        return h


@dataclass
class Block:
    header: BlockHeader
    txs: list[Tx]
    _raw: bytes | None = field(default=None, repr=False, compare=False)

    @property
    def hash(self) -> bytes:
        return self.header.hash

    def serialize(self) -> bytes:
        if self._raw is None:
            self._raw = self.header.serialize() + varint(len(self.txs)) + b"".join(t.serialize() for t in self.txs)
        return self._raw

    @property
    def size(self) -> int:
        return len(self.serialize())

    def compute_merkle_root(self) -> bytes:
        return merkle_root([t.txid for t in self.txs])

    @classmethod
    def deserialize(cls, data: bytes, max_bytes: int | None = None) -> "Block":
        if max_bytes is not None and len(data) > max_bytes:
            from .encoding import DecodeError

            raise DecodeError("block exceeds size limit")
        r = Reader(data)
        header = BlockHeader.read(r)
        n = r.count(100_000, 4 + 1 + MIN_INPUT_BYTES + 1 + 4)
        txs = [Tx.read(r) for _ in range(n)]
        r.finish()
        return cls(header=header, txs=txs, _raw=bytes(data))
