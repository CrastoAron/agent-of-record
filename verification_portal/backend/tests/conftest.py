"""End-to-end evidence fixture assembled exclusively from prior AoR stages."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from action_executor import ActionExecutor, SMTPConfig
from crypto_core import hash_payload, serialize_public_key_raw
from key_registry import KeyRegistry, SQLiteKeyStorage
from ledger_core import Ledger
from poi_generator import build_poi, sign_poi
from poi_generator.agent_keys import agent_pubkey_id
from verifier_service.models import SignedEnvelope
from verification_portal.backend.eml_parser import parse_eml
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.verify_pipeline import VerificationPipeline


@dataclass
class PortalScenario:
    pipeline: VerificationPipeline
    registry: KeyRegistry
    evidence_store: ActionEvidenceStore
    action_id: str
    eml_bytes: bytes
    poi_agent_key_id: str
    ledger: Ledger


def _user_envelope(private_key: ec.EllipticCurvePrivateKey) -> SignedEnvelope:
    payload = {
        "prompt": "Send Bob an approved update.",
        "user_id": "u123",
        "session_id": "session-1",
        "timestamp": "2026-08-27T10:00:00Z",
        "nonce": "portal-test-nonce",
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return SignedEnvelope(
        **payload,
        signature=base64.b64encode(raw_signature).decode("ascii"),
        pubkey_id="user-p256-key",
    )


@pytest.fixture
def portal_scenario(tmp_path: Path) -> PortalScenario:
    registry = KeyRegistry(SQLiteKeyStorage(tmp_path / "keys.sqlite3"))
    user_private_key = ec.generate_private_key(ec.SECP256R1())
    user_public_der = user_private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    registry.register_key(
        "u123", "user-p256-key", user_public_der, "ECDSA-P256-SHA256", datetime.now(timezone.utc)
    )

    agent_private_key = Ed25519PrivateKey.generate()
    agent_key_id = agent_pubkey_id(agent_private_key)
    registry.register_key(
        "demo-agent", agent_key_id, serialize_public_key_raw(agent_private_key.public_key()), "Ed25519", datetime.now(timezone.utc)
    )

    payload = {
        "to": "bob@example.com",
        "subject": "Approved update",
        "body": "The approved project update is attached.",
    }
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved email."})
    ledger.append("user_prompt", {"text": "Send Bob an approved update."})
    poi = sign_poi(
        build_poi(
            "Send Bob an approved update.",
            "Only send approved email.",
            ledger,
            payload,
            "demo-model",
        ),
        agent_private_key,
    )
    executor = ActionExecutor(SMTPConfig(output_dir=tmp_path / "outbox"))
    action = executor.execute_action("email", payload, poi)
    assert action.success and action.action_id
    eml_path = next((tmp_path / "outbox").glob("*.eml"))
    eml_bytes = eml_path.read_bytes()
    parsed = parse_eml(eml_bytes)
    assert parsed["action_id"] == action.action_id

    evidence_store = ActionEvidenceStore()
    evidence_store.register(
        ActionEvidence(
            action_id=action.action_id,
            user_envelope=_user_envelope(user_private_key),
            system_prompt="Only send approved email.",
            ledger=ledger,
            ledger_entry_count_at_action=len(ledger.all_entries()),
            eml_bytes=eml_bytes,
        )
    )
    return PortalScenario(
        pipeline=VerificationPipeline(registry, evidence_store),
        registry=registry,
        evidence_store=evidence_store,
        action_id=action.action_id,
        eml_bytes=eml_bytes,
        poi_agent_key_id=agent_key_id,
        ledger=ledger,
    )
