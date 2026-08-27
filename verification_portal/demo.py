"""Stage 8 presentation walkthrough: valid, body-tampered, and revoked-key traces."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

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
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.verify_pipeline import VerificationPipeline


def _print_trace(title, trace) -> None:
    print(f"\n{title}: {'VERIFIED' if trace.overall_valid else 'TAMPERED / INVALID'}")
    for link in trace.links:
        marker = "PASS" if link.passed else "FAIL"
        print(f"  {marker:4} {link.link_name:22} {link.detail}")


def main() -> None:
    with TemporaryDirectory() as temporary:
        path = Path(temporary)
        registry = KeyRegistry(SQLiteKeyStorage(path / "keys.sqlite3"))
        user_private = ec.generate_private_key(ec.SECP256R1())
        registry.register_key(
            "u123", "demo-user-p256",
            user_private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            "ECDSA-P256-SHA256", datetime.now(timezone.utc),
        )
        signing_payload = {"prompt": "Send Bob an approved update.", "user_id": "u123", "session_id": "demo-session", "timestamp": "2026-08-27T10:00:00Z", "nonce": "demo-nonce"}
        der = user_private.sign(hash_payload(signing_payload), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        envelope = SignedEnvelope(**signing_payload, signature=base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(), pubkey_id="demo-user-p256")

        ledger = Ledger()
        system_prompt = "Only send approved email."
        ledger.append("system_prompt", {"text": system_prompt})
        ledger.append("user_prompt", {"text": envelope.prompt})
        payload = {"to": "bob@example.com", "subject": "Approved update", "body": "The approved project update is attached."}
        agent_private = Ed25519PrivateKey.generate()
        poi = sign_poi(build_poi(envelope.prompt, system_prompt, ledger, payload, "demo-model"), agent_private)
        registry.register_key("demo-agent", agent_pubkey_id(agent_private), serialize_public_key_raw(agent_private.public_key()), "Ed25519", datetime.now(timezone.utc))
        result = ActionExecutor(SMTPConfig(output_dir=path / "outbox")).execute_action("email", payload, poi)
        eml_bytes = next((path / "outbox").glob("*.eml")).read_bytes()
        evidence = ActionEvidence(result.action_id, envelope, system_prompt, ledger, len(ledger.all_entries()), eml_bytes)
        store = ActionEvidenceStore(); store.register(evidence)
        pipeline = VerificationPipeline(registry, store)

        _print_trace("Valid action", pipeline.run_verification(eml_bytes))
        tampered = eml_bytes.replace(b"The approved project update is attached.", b"The approved project update was replaced!")
        _print_trace("Body tampered after delivery", pipeline.run_verification(tampered))
        registry.revoke_key(poi.agent_pubkey_id or "")
        _print_trace("Agent key revoked after delivery", pipeline.run_verification(eml_bytes))


if __name__ == "__main__":
    main()
