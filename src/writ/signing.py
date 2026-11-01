"""Ed25519 signing for authorizations and receipts.

Keys are encoded as base64url raw 32-byte values, prefixed with a key id derived
from the public key so that verifiers can rotate keys without ambiguity. A `KeyRing`
holds every public key a peer currently accepts, so a new key can be deployed on one side
before the other side stops using the old one.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canon import canonical_bytes, sha256_hex


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True)
class Signer:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_encoded(cls, encoded: str) -> Signer:
        raw = _b64d(encoded.strip())
        if len(raw) != 32:
            raise ValueError("ed25519 private key must be 32 raw bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def encoded_private(self) -> str:
        return _b64e(
            self.private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )

    @property
    def verifier(self) -> Verifier:
        return Verifier(self.private_key.public_key())

    def sign(self, payload: Any) -> str:
        """Sign canonical JSON of payload. Returns base64url signature."""
        return _b64e(self.private_key.sign(canonical_bytes(payload)))


@dataclass(frozen=True)
class Verifier:
    public_key: Ed25519PublicKey

    @classmethod
    def from_encoded(cls, encoded: str) -> Verifier:
        raw = _b64d(encoded.strip())
        if len(raw) != 32:
            raise ValueError("ed25519 public key must be 32 raw bytes")
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def encoded_public(self) -> str:
        return _b64e(self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @property
    def key_id(self) -> str:
        return sha256_hex(
            self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )[:16]

    def verify(self, payload: Any, signature: str) -> bool:
        try:
            self.public_key.verify(_b64d(signature), canonical_bytes(payload))
            return True
        except (InvalidSignature, ValueError):
            return False


class KeyRing:
    """The set of public keys a peer currently trusts, looked up by key id."""

    def __init__(self, verifiers: Iterable[Verifier]):
        self._by_id: dict[str, Verifier] = {}
        for v in verifiers:
            self._by_id[v.key_id] = v
        if not self._by_id:
            raise ValueError("key ring must hold at least one public key")

    @classmethod
    def from_encoded(cls, encoded: str) -> KeyRing:
        """Parse one or more base64url public keys separated by commas or whitespace."""
        parts = [p for p in encoded.replace(",", " ").split() if p]
        return cls(Verifier.from_encoded(p) for p in parts)

    @classmethod
    def coerce(cls, v: KeyRing | Verifier | Iterable[Verifier]) -> KeyRing:
        if isinstance(v, KeyRing):
            return v
        if isinstance(v, Verifier):
            return cls([v])
        return cls(v)

    @property
    def key_ids(self) -> list[str]:
        return sorted(self._by_id)

    @property
    def verifiers(self) -> list[Verifier]:
        return [self._by_id[k] for k in self.key_ids]

    def get(self, key_id: str) -> Verifier | None:
        return self._by_id.get(key_id)

    def describe(self, algorithm: str = "Ed25519") -> list[dict]:
        return [
            {"key_id": v.key_id, "public_key": v.encoded_public(), "algorithm": algorithm}
            for v in self.verifiers
        ]


def signed_envelope(signer: Signer, payload: dict) -> dict:
    """Wrap payload with key id and signature. The signature covers payload only."""
    return {"payload": payload, "key_id": signer.verifier.key_id, "signature": signer.sign(payload)}


def verify_envelope(trusted: Verifier | KeyRing, envelope: Any) -> bool:
    """True iff envelope is a well-formed {payload, key_id, signature} signed by a trusted key."""
    if not isinstance(envelope, dict):
        return False
    key_id = envelope.get("key_id")
    sig = envelope.get("signature")
    payload = envelope.get("payload")
    if not isinstance(key_id, str) or not isinstance(sig, str) or not isinstance(payload, dict):
        return False
    verifier = trusted.get(key_id) if isinstance(trusted, KeyRing) else trusted
    if verifier is None or verifier.key_id != key_id:
        return False
    return verifier.verify(payload, sig)
