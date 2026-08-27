"""Fail-fast signature verification for incoming AoR prompt envelopes."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from crypto_core import hash_payload, verify

from .models import SignedEnvelope
from .nonce_store import NonceStore


class PublicKeyLookup(Protocol):
    """Minimal Stage 4 lookup interface implemented by both key-store versions."""

    def get_pubkey(self, pubkey_id: str) -> bytes | Ed25519PublicKey | EllipticCurvePublicKey | None: ...


def _load_registered_public_key(
    stored_key: bytes | Ed25519PublicKey | EllipticCurvePublicKey,
) -> Ed25519PublicKey | EllipticCurvePublicKey:
    """Accept legacy parsed keys or Stage 5's registered key-byte format."""
    if isinstance(stored_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        return stored_key
    try:
        parsed_key = serialization.load_der_public_key(stored_key)
    except ValueError:
        if len(stored_key) == 32:
            return Ed25519PublicKey.from_public_bytes(stored_key)
        raise
    if not isinstance(parsed_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise ValueError("unsupported registered public key")
    return parsed_key


@dataclass(frozen=True)
class VerificationResult:
    """The internal result of one envelope verification attempt."""

    valid: bool
    reason: str | None = None


class SignatureVerifier:
    """Verify a Stage 3 signed envelope before any downstream action occurs."""

    def __init__(
        self,
        pubkey_store: PublicKeyLookup,
        nonce_store: NonceStore,
        freshness_seconds: int = 60,
    ) -> None:
        self._pubkey_store = pubkey_store
        self._nonce_store = nonce_store
        self._freshness_seconds = freshness_seconds

    @staticmethod
    def _parse_timestamp(timestamp: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    def _timestamp_is_fresh(self, timestamp: str) -> bool:
        parsed = self._parse_timestamp(timestamp)
        if parsed is None:
            return False
        age_seconds = abs((datetime.now(timezone.utc) - parsed).total_seconds())
        return age_seconds <= self._freshness_seconds

    def verify_envelope(self, envelope: SignedEnvelope) -> VerificationResult:
        """Fail fast on freshness, replay, key, and signature failures, in order."""
        if not self._timestamp_is_fresh(envelope.timestamp):
            return VerificationResult(False, "timestamp_stale")

        if self._nonce_store.has_seen(envelope.nonce):
            return VerificationResult(False, "nonce_reused")
        # The requested flow consumes a fresh nonce before key/signature checks.
        self._nonce_store.mark_seen(envelope.nonce)

        stored_key = self._pubkey_store.get_pubkey(envelope.pubkey_id)
        if stored_key is None:
            return VerificationResult(False, "unknown_pubkey")
        try:
            public_key = _load_registered_public_key(stored_key)
        except (TypeError, ValueError):
            return VerificationResult(False, "unknown_pubkey")

        if envelope.signature_algorithm != "ECDSA-P256-SHA256":
            return VerificationResult(False, "signature_mismatch")
        try:
            signature = base64.b64decode(envelope.signature, validate=True)
        except (ValueError, binascii.Error):
            return VerificationResult(False, "signature_mismatch")

        # Stage 1 owns JCS canonicalization and SHA3-256. Do not accept any
        # client-provided diagnostic hash/canonical representation as trusted.
        payload_hash = hash_payload(envelope.signing_payload())
        if not verify(public_key, signature, payload_hash):
            return VerificationResult(False, "signature_mismatch")
        return VerificationResult(True)
