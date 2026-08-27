"""Validity-aware public-key registry with a Stage 4-compatible lookup boundary."""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jwks import _load_supported_public_key, export_jwks
from .models import AgentKeyRecord
from .storage import SQLiteKeyStorage


class KeyRegistry:
    """Register agent public keys and expose only currently-valid keys.

    ``get_pubkey`` returns ``None`` for unknown, revoked, not-yet-valid, and
    expired keys. Stage 4 intentionally treats all of these as an unknown key
    at its external boundary, preventing a client from learning registry state.
    """

    def __init__(self, storage: SQLiteKeyStorage | None = None) -> None:
        self._storage = storage or SQLiteKeyStorage()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _algorithm_for_key(public_key_bytes: bytes) -> str:
        public_key = _load_supported_public_key(public_key_bytes)
        if isinstance(public_key, Ed25519PublicKey):
            return "Ed25519"
        if isinstance(public_key, EllipticCurvePublicKey) and isinstance(public_key.curve, SECP256R1):
            return "ECDSA-P256-SHA256"
        raise ValueError("unsupported public key algorithm")

    @staticmethod
    def _is_active(record: AgentKeyRecord, now: datetime) -> bool:
        return (
            not record.revoked
            and now >= record.valid_from
            and (record.valid_until is None or now <= record.valid_until)
        )

    def register_key(
        self,
        agent_id: str,
        pubkey_id: str,
        public_key_bytes: bytes,
        algorithm: str,
        valid_from: datetime,
        valid_until: datetime | None = None,
    ) -> AgentKeyRecord:
        """Persist a public key for an agent and return its immutable record."""
        expected_algorithm = self._algorithm_for_key(public_key_bytes)
        accepted_algorithm_ids = {
            "Ed25519": {"Ed25519", "EdDSA"},
            "ECDSA-P256-SHA256": {"ECDSA-P256-SHA256", "ES256"},
        }
        if algorithm not in accepted_algorithm_ids[expected_algorithm]:
            raise ValueError(f"algorithm does not match public key: expected {expected_algorithm}")
        record = AgentKeyRecord(
            agent_id=agent_id,
            pubkey_id=pubkey_id,
            public_key_bytes=public_key_bytes,
            algorithm=expected_algorithm,
            valid_from=valid_from,
            valid_until=valid_until,
            created_at=self._now(),
        )
        self._storage.insert_key(record)
        return record

    def register_pubkey(self, pubkey_id: str, public_key_bytes: bytes) -> None:
        """Stage 4 compatibility shim; prefer ``register_key`` for new callers."""
        self.register_key(
            agent_id="unassigned",
            pubkey_id=pubkey_id,
            public_key_bytes=public_key_bytes,
            algorithm=self._algorithm_for_key(public_key_bytes),
            valid_from=self._now(),
        )

    def get_pubkey(self, pubkey_id: str) -> bytes | None:
        """Return active public-key bytes, otherwise ``None`` without disclosure."""
        record = self._storage.get_key_by_id(pubkey_id)
        if record is None or not self._is_active(record, self._now()):
            return None
        return record.public_key_bytes

    def revoke_key(self, pubkey_id: str) -> bool:
        """Revoke a key permanently. Returns ``False`` when no such key exists."""
        return self._storage.revoke_key(pubkey_id)

    def list_active_keys(self, agent_id: str) -> list[AgentKeyRecord]:
        """Return currently-valid, non-revoked records for an agent."""
        now = self._now()
        return [record for record in self._storage.get_keys_by_agent(agent_id) if self._is_active(record, now)]

    def export_jwks(self) -> dict[str, list[dict[str, str]]]:
        """Publish all currently active public keys as a standard JWK Set."""
        now = self._now()
        active_records = [record for record in self._storage.all_keys() if self._is_active(record, now)]
        return export_jwks(active_records)
