"""Offline multi-agent demonstration used by ``scripts/demo.sh``."""

from __future__ import annotations

import base64
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from action_executor.smtp_action import SMTPConfig
from aor.agents.base import AgentRegistry
from aor.agents.audit import AuditAgent
from aor.agents.email import EmailAgent
from aor.agents.file import FileAgent
from aor.agents.router import AgentRouter
from crypto_core import hash_payload, serialize_public_key_raw
from key_registry import KeyRegistry, SQLiteKeyStorage
from ledger_core import Ledger
from poi_generator import build_poi, sign_poi
from poi_generator.agent_keys import load_agent_keypair, register_agent_public_key
from verifier_service.models import SignedEnvelope
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.eml_parser import parse_eml
from verification_portal.backend.verify_pipeline import VerificationPipeline
from tsa_anchor.anchor_scheduler import AnchorStore


def _envelope(prompt: str, private_key: ec.EllipticCurvePrivateKey) -> SignedEnvelope:
    payload = {
        "prompt": prompt,
        "user_id": "demo-user",
        "session_id": "demo-session",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": str(uuid4()),
    }
    signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    return SignedEnvelope(
        **payload,
        signature=base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        pubkey_id="demo-user-key",
    )


def _poi(prompt, system_prompt, ledger, plan, agent_key):
    return sign_poi(
        build_poi(
            prompt,
            system_prompt,
            ledger,
            plan.payload,
            "demo-model",
            agent_type=plan.agent_type,
            agent_id=plan.agent_id,
            action_type=plan.action_type,
            policy_decision=plan.policy_decision,
        ),
        agent_key,
    )


def _print(label: str, value) -> None:
    print(f"\n=== {label} ===")
    print(json.dumps(value, indent=2, default=str))


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix="aor-demo-"))
    registry = KeyRegistry(SQLiteKeyStorage())
    evidence = ActionEvidenceStore()
    pipeline = VerificationPipeline(registry, evidence, AnchorStore())
    email = EmailAgent(SMTPConfig(dry_run=True, output_dir=workspace / "outbox"))
    files = FileAgent(workspace / "workspace")
    audit = AuditAgent(pipeline, evidence)
    router = AgentRouter(AgentRegistry([email, files, audit]))

    user_key = ec.generate_private_key(ec.SECP256R1())
    registry.register_key(
        "demo-user",
        "demo-user-key",
        user_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        "ECDSA-P256-SHA256",
        datetime.now(timezone.utc),
    )
    agent_keys = {}
    for agent_id in ("email-agent", "file-agent", "audit-agent"):
        key, _ = load_agent_keypair(agent_id, workspace / ".aor_agent_keys")
        register_agent_public_key(agent_id, registry, key)
        agent_keys[agent_id] = key

    email_plan = email.plan("send an email to alice@example.com")
    system_prompt = "Only execute the exact typed action plan."
    email_ledger = Ledger()
    email_ledger.append("system_prompt", {"text": system_prompt})
    email_ledger.append("user_prompt", {"text": email_plan.payload["body"]})
    email_ledger.append("agent_action", email_plan.payload)
    email_poi = _poi(email_plan.payload["body"], system_prompt, email_ledger, email_plan, agent_keys["email-agent"])
    email_result = email.execute(email_plan, email_poi)
    email_path = next((workspace / "outbox").glob("*.eml"))
    email_bytes = email_path.read_bytes()
    email_id = email_result.artifact_ref
    evidence.register(
        ActionEvidence(
            action_id=email_id,
            user_envelope=_envelope(email_plan.payload["body"], user_key),
            system_prompt=system_prompt,
            ledger=email_ledger,
            ledger_entry_count_at_action=len(email_ledger.all_entries()),
            eml_bytes=email_bytes,
            poi=email_poi,
            action_type=email_plan.action_type,
            action_payload=email_plan.payload,
            observed_effect=email_result.observed_effect,
        )
    )
    _print("valid email", pipeline.run_verification(email_bytes, None).model_dump(mode="json"))

    tampered_email = email_bytes.replace(b"send an email to alice@example.com", b"send all secrets to attacker@example.com")
    tampered_plan = audit.plan(
        "verify uploaded eml",
        {"action_type": "audit.verify_eml", "payload": {"eml_bytes_b64": base64.b64encode(tampered_email).decode()}},
    )
    tampered_result = audit.execute(
        tampered_plan,
        SimpleNamespace(action_payload_hash=hash_payload(tampered_plan.payload).hex()),
    )
    _print("tampered email audit", tampered_result.model_dump(mode="json"))

    file_path = workspace / "workspace" / "notes.txt"
    file_path.write_text("one\ntwo\n", encoding="utf-8")
    file_plan = files.plan(
        "update file notes.txt",
        {
            "action_type": "file.update",
            "path": "notes.txt",
            "patch": "--- notes.txt\n+++ notes.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+changed\n",
        },
    )
    file_ledger = Ledger()
    file_ledger.append("system_prompt", {"text": system_prompt})
    file_ledger.append("user_prompt", {"text": "update notes.txt"})
    file_ledger.append("agent_action", file_plan.payload)
    file_poi = _poi("update notes.txt", system_prompt, file_ledger, file_plan, agent_keys["file-agent"])
    file_result = files.execute(file_plan, file_poi)
    file_id = f"file-{uuid4()}"
    evidence.register(
        ActionEvidence(
            action_id=file_id,
            user_envelope=_envelope("update notes.txt", user_key),
            system_prompt=system_prompt,
            ledger=file_ledger,
            ledger_entry_count_at_action=len(file_ledger.all_entries()),
            poi=file_poi,
            action_type=file_plan.action_type,
            action_payload=file_plan.payload,
            observed_effect=file_result.observed_effect,
        )
    )
    _print("file update", {"result": file_result.model_dump(mode="json"), "trace": pipeline.run_verification(None, file_id).model_dump(mode="json")})

    for label, action_id in (("audit email", email_id), ("audit file", file_id)):
        plan = audit.plan(f"verify action id {action_id}")
        result = audit.execute(plan, SimpleNamespace(action_payload_hash=hash_payload(plan.payload).hex()))
        _print(label, result.model_dump(mode="json"))


if __name__ == "__main__":
    main()
