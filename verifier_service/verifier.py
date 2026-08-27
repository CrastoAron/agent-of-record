"""Fail-fast signature verification for incoming AoR prompt envelopes."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone

from crypto_core import hash_payload, verify

from .models import SignedEnvelope
from .nonce_store import NonceStore
from .pubkey_store import PubkeyStore


@dataclass(frozen=True)
class VerificationResult:
    """The internal result of one envelope verification attempt."""

    valid: bool
    reason: str | None = None


class SignatureVerifier:
    """Verify a Stage 3 signed envelope before any downstream action occurs."""

    def __init__(
        self,
        pubkey_store: PubkeyStore,
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

        public_key = self._pubkey_store.get_pubkey(envelope.pubkey_id)
        if public_key is None:
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
