"""Temporary in-memory public-key store with a Stage 5-friendly interface."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SupportedPublicKey = Ed25519PublicKey | EllipticCurvePublicKey


class PubkeyStore:
    """Map public-key identifiers to parsed public keys.

    The public ``register_pubkey`` and ``get_pubkey`` methods are deliberately
    small so a Stage 5 JWK Set/database registry can implement the same API.
    """

    def __init__(self) -> None:
        self._keys: dict[str, SupportedPublicKey] = {}

    def register_pubkey(self, pubkey_id: str, public_key_bytes: bytes) -> None:
        """Store a DER SubjectPublicKeyInfo key under its public identifier."""
        if not isinstance(pubkey_id, str) or not pubkey_id:
            raise ValueError("pubkey_id must be a non-empty string")
        if not isinstance(public_key_bytes, bytes):
            raise TypeError("public_key_bytes must be bytes")
        public_key = serialization.load_der_public_key(public_key_bytes)
        if not isinstance(public_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
            raise ValueError("unsupported public key type")
        self._keys[pubkey_id] = public_key

    def get_pubkey(self, pubkey_id: str) -> SupportedPublicKey | None:
        """Return a registered public key, or ``None`` when the ID is unknown."""
        return self._keys.get(pubkey_id)
