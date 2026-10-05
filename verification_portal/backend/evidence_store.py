"""Small in-memory evidence boundary used by the Stage 8 demo and tests.

Stage 8 verifies evidence captured at action time. A database/persistent audit
store can replace this interface later without changing the verification logic.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Protocol

from ledger_core import Ledger, LedgerEntry
from verifier_service.models import SignedEnvelope


@dataclass
class ActionEvidence:
    action_id: str
    user_envelope: SignedEnvelope
    system_prompt: str
    ledger: Ledger
    # Number of leaves present when the PoI committed its context root.
    ledger_entry_count_at_action: int
    eml_bytes: bytes | None = None
    # Stage 9 will store a validated RFC 3161 token here.
    timestamp_token: bytes | None = None


class EvidencePersistence(Protocol):
    def save_action_evidence(self, action_id: str, payload: str) -> None: ...

    def get_action_evidence(self, action_id: str) -> str | None: ...


class ActionEvidenceStore:
    """Action-ID evidence lookup with optional durable persistence."""

    def __init__(self, persistence: EvidencePersistence | None = None) -> None:
        self._evidence: dict[str, ActionEvidence] = {}
        self._persistence = persistence

    def register(self, evidence: ActionEvidence) -> None:
        self._evidence[evidence.action_id] = evidence
        if self._persistence is not None:
            self._persistence.save_action_evidence(evidence.action_id, self._serialize(evidence))

    def get(self, action_id: str) -> ActionEvidence | None:
        evidence = self._evidence.get(action_id)
        if evidence is not None or self._persistence is None:
            return evidence
        payload = self._persistence.get_action_evidence(action_id)
        if payload is None:
            return None
        evidence = self._deserialize(action_id, payload)
        self._evidence[action_id] = evidence
        return evidence

    @staticmethod
    def _serialize(evidence: ActionEvidence) -> str:
        entries = evidence.ledger.all_entries()[: evidence.ledger_entry_count_at_action]
        payload = {
            "user_envelope": evidence.user_envelope.model_dump(mode="json"),
            "system_prompt": evidence.system_prompt,
            "ledger_entry_count_at_action": evidence.ledger_entry_count_at_action,
            "ledger_entries": [
                {
                    "entry_id": entry.entry_id,
                    "entry_type": entry.entry_type,
                    "content": entry.content,
                    "timestamp": entry.timestamp,
                    "prev_hash": entry.prev_hash.hex(),
                    "leaf_hash": entry.leaf_hash.hex(),
                }
                for entry in entries
            ],
            "eml_bytes": base64.b64encode(evidence.eml_bytes).decode("ascii") if evidence.eml_bytes is not None else None,
            "timestamp_token": base64.b64encode(evidence.timestamp_token).decode("ascii") if evidence.timestamp_token is not None else None,
        }
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def _deserialize(action_id: str, serialized: str) -> ActionEvidence:
        payload = json.loads(serialized)
        entries = [
            LedgerEntry(
                entry_id=entry["entry_id"],
                entry_type=entry["entry_type"],
                content=entry["content"],
                timestamp=entry["timestamp"],
                prev_hash=bytes.fromhex(entry["prev_hash"]),
                leaf_hash=bytes.fromhex(entry["leaf_hash"]),
            )
            for entry in payload["ledger_entries"]
        ]
        return ActionEvidence(
            action_id=action_id,
            user_envelope=SignedEnvelope.model_validate(payload["user_envelope"]),
            system_prompt=payload["system_prompt"],
            ledger=Ledger.from_entries(entries),
            ledger_entry_count_at_action=payload["ledger_entry_count_at_action"],
            eml_bytes=base64.b64decode(payload["eml_bytes"]) if payload["eml_bytes"] is not None else None,
            timestamp_token=base64.b64decode(payload["timestamp_token"]) if payload["timestamp_token"] is not None else None,
        )
