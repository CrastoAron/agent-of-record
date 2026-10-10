"""Small local CLI for routing and executing PoI-bound demo actions."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from aor.agents.base import AgentRegistry
from aor.agents.audit import AuditAgent
from aor.agents.email import EmailAgent
from aor.agents.file import FileAgent
from aor.agents.router import AgentRouter
from action_executor.smtp_action import SMTPConfig
from crypto_core import hash_payload, serialize_public_key_raw
from key_registry import KeyRegistry, SQLiteKeyStorage
from ledger_core import Ledger
from poi_generator import build_poi, sign_poi
from poi_generator.agent_keys import load_agent_keypair, register_agent_public_key
from verifier_service.models import SignedEnvelope
from verifier_service.nonce_store import NonceStore
from verifier_service.verifier import SignatureVerifier
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.verify_pipeline import VerificationPipeline
from tsa_anchor.anchor_scheduler import AnchorStore


def _signed_envelope(prompt: str, private_key: ec.EllipticCurvePrivateKey) -> SignedEnvelope:
    payload = {
        "prompt": prompt,
        "user_id": "cli-user",
        "session_id": "cli-session",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": str(uuid4()),
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return SignedEnvelope(
        **payload,
        signature=base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii"),
        pubkey_id="cli-user-key",
    )


def run_request(request: str, workspace: Path, *, assume_yes: bool = False) -> int:
    workspace = workspace.resolve()
    registry = KeyRegistry(SQLiteKeyStorage())
    evidence_store = ActionEvidenceStore()
    pipeline = VerificationPipeline(registry, evidence_store, AnchorStore())
    email_agent = EmailAgent(
        smtp_config=SMTPConfig(dry_run=True, output_dir=workspace / ".aor_outbox")
    )
    file_agent = FileAgent(workspace)
    audit_agent = AuditAgent(pipeline, evidence_store)
    agent_registry = AgentRegistry([email_agent, file_agent, audit_agent])
    router = AgentRouter(agent_registry)
    route = router.route(request)
    print(json.dumps(route.model_dump(mode="json"), indent=2))
    if not route.handled:
        return 2

    plans = router.plan(request)
    print("Action plans:")
    for plan in plans:
        print(json.dumps(plan.model_dump(mode="json"), indent=2))

    user_private_key = ec.generate_private_key(ec.SECP256R1())
    registry.register_key(
        "cli-user",
        "cli-user-key",
        user_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "ECDSA-P256-SHA256",
        datetime.now(timezone.utc),
    )
    verifier = SignatureVerifier(registry, NonceStore())
    previous_result = None
    for plan in plans:
        if plan.requires_confirmation:
            approved = assume_yes or input(f"Confirm {plan.action_type} on {plan.payload.get('path', '')}? [y/N] ").lower() in {"y", "yes"}
            if not approved:
                print(json.dumps({"status": "cancelled", "reason": "confirmation_denied"}, indent=2))
                return 1
            plan = plan.model_copy(update={"confirmed": True})

        if previous_result and plan.action_type == "file.create" and not plan.payload.get("content"):
            report = previous_result.details.get("report_markdown") if previous_result.details else None
            if isinstance(report, str):
                plan = plan.model_copy(update={"payload": {**plan.payload, "content": report}})

        user_envelope = _signed_envelope(request, user_private_key)
        verified = verifier.verify_envelope(user_envelope)
        if not verified.valid:
            print(json.dumps({"status": "rejected", "reason": verified.reason}, indent=2))
            return 1
        ledger = Ledger()
        system_prompt = "Only execute the exact typed action plan selected by the router."
        ledger.append("system_prompt", {"text": system_prompt})
        ledger.append("user_prompt", {"text": request})
        ledger.append("agent_action", plan.payload)
        agent_private_key, _ = load_agent_keypair(
            plan.agent_id or f"{plan.agent_type}-agent",
            key_directory=workspace / ".aor_agent_keys",
        )
        register_agent_public_key(plan.agent_id or f"{plan.agent_type}-agent", registry, agent_private_key)
        poi = sign_poi(
            build_poi(
                request,
                system_prompt,
                ledger,
                plan.payload,
                "cli-demo-model",
                agent_type=plan.agent_type,
                agent_id=plan.agent_id,
                action_type=plan.action_type,
                policy_decision=plan.policy_decision,
            ),
            agent_private_key,
        )
        result = agent_registry.get(plan.agent_type).execute(plan, poi)
        previous_result = result
        action_id = result.artifact_ref or f"cli-{uuid4()}"
        evidence_store.register(
            ActionEvidence(
                action_id=action_id,
                user_envelope=user_envelope,
                system_prompt=system_prompt,
                ledger=ledger,
                ledger_entry_count_at_action=len(ledger.all_entries()),
                poi=poi,
                action_type=plan.action_type,
                action_payload=plan.payload,
                observed_effect=result.observed_effect,
            )
        )
        trace = pipeline.run_verification(None, action_id)
        print(json.dumps({"action_result": result.model_dump(mode="json"), "verification": trace.model_dump(mode="json")}, indent=2))
        if not result.success or not trace.overall_valid:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aor", description="Route and execute a PoI-bound AoR action")
    parser.add_argument("request", nargs="+", help="natural-language request")
    parser.add_argument("--workspace", type=Path, default=Path(".aor_workspace"))
    parser.add_argument("--yes", action="store_true", help="automatically confirm destructive actions")
    args = parser.parse_args(argv)
    return run_request(" ".join(args.request), args.workspace, assume_yes=args.yes)


if __name__ == "__main__":
    sys.exit(main())
