"""secp256k1 ECDSA via the `cryptography` library (OpenSSL backend).

We do not implement any curve arithmetic ourselves. Two consensus rules are added
on top of plain ECDSA to make signatures non-malleable:
  * strict DER: the signature must re-encode to exactly the same bytes;
  * low-S: s <= n/2 (signers normalize s, verifiers reject high-S).
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_ORDER = CURVE_ORDER // 2
_ALGO = ec.ECDSA(Prehashed(hashes.SHA256()))


class PrivateKey:
    """Wraps a secret scalar. repr() never reveals the secret."""

    __slots__ = ("_key",)

    def __init__(self, secret: int) -> None:
        if not (1 <= secret < CURVE_ORDER):
            raise ValueError("secret out of range")
        self._key = ec.derive_private_key(secret, ec.SECP256K1())

    def __repr__(self) -> str:
        return "PrivateKey(<redacted>)"

    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )

    def sign(self, digest32: bytes) -> bytes:
        if len(digest32) != 32:
            raise ValueError("digest must be 32 bytes")
        r, s = decode_dss_signature(self._key.sign(digest32, _ALGO))
        if s > HALF_ORDER:
            s = CURVE_ORDER - s
        return encode_dss_signature(r, s)


def is_valid_pubkey(pubkey: bytes) -> bool:
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey)
        return True
    except ValueError:
        return False


def verify(pubkey: bytes, digest32: bytes, sig: bytes) -> bool:
    if len(digest32) != 32 or not (8 <= len(sig) <= 72) or len(pubkey) != 33:
        return False
    try:
        r, s = decode_dss_signature(sig)
    except ValueError:
        return False
    if not (1 <= r < CURVE_ORDER and 1 <= s <= HALF_ORDER):
        return False
    if encode_dss_signature(r, s) != sig:  # strict, canonical DER only
        return False
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey)
        key.verify(sig, digest32, _ALGO)
        return True
    except (ValueError, InvalidSignature):
        return False
