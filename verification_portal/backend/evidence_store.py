"""Small in-memory evidence boundary used by the Stage 8 demo and tests.

Stage 8 verifies evidence captured at action time. A database/persistent audit
store can replace this interface later without changing the verification logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from ledger_core import Ledger
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


class ActionEvidenceStore:
    """Minimal action-ID to captured evidence lookup for an in-memory demo."""

    def __init__(self) -> None:
        self._evidence: dict[str, ActionEvidence] = {}

    def register(self, evidence: ActionEvidence) -> None:
        self._evidence[evidence.action_id] = evidence

    def get(self, action_id: str) -> ActionEvidence | None:
        return self._evidence.get(action_id)
