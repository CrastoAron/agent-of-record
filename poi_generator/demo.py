"""Run a verified prompt through a LangChain tool-start PoI callback."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from langchain_core.tools import tool

from crypto_core import hash_payload
from key_registry import KeyRegistry
from ledger_core import Ledger
from poi_generator import PoICallbackHandler, VerifiedSessionContext, verify_poi_signature
from verifier_service.models import SignedEnvelope
from verifier_service.nonce_store import NonceStore
from verifier_service.verifier import SignatureVerifier


def _verified_stage4_envelope(
    private_key: ec.EllipticCurvePrivateKey, pubkey_id: str, session_id: str
) -> SignedEnvelope:
    payload = {
        "prompt": "Send Bob the approved project update.",
        "user_id": "u123",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": "poi-demo-user-nonce",
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return SignedEnvelope(
        **payload,
        signature=base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        pubkey_id=pubkey_id,
    )


@tool
def fake_send_email(to: str, subject: str, body: str) -> str:
    """Demo-only email tool; it prints instead of making an outbound request."""
    print(f"Fake send: to={to}, subject={subject}, body={body}")
    return "accepted by demo tool"


def main() -> None:
    registry = KeyRegistry()
    user_private_key = ec.generate_private_key(ec.SECP256R1())
    user_pubkey_id = "stage6-demo-user-key"
    registry.register_key(
        "user-u123",
        user_pubkey_id,
        user_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "ECDSA-P256-SHA256",
        datetime.now(timezone.utc),
    )
    session_id = "poi-demo-session"
    envelope = _verified_stage4_envelope(user_private_key, user_pubkey_id, session_id)
    verification = SignatureVerifier(registry, NonceStore()).verify_envelope(envelope)
    if not verification.valid:
        raise RuntimeError(f"expected a verified demo envelope, got {verification.reason}")
    print("Stage 4 verification: True")

    system_prompt = "Only send approved project updates."
    ledger = Ledger()
    ledger.append("system_prompt", {"text": system_prompt})
    ledger.append("user_prompt", {"text": envelope.prompt, "user_id": envelope.user_id})
    session_context = VerifiedSessionContext(
        session_id=session_id,
        user_prompt=envelope.prompt,
        system_prompt=system_prompt,
        ledger=ledger,
        model_id="demo-langchain-model",
    )
    callback = PoICallbackHandler(
        {session_id: session_context}, agent_id="email-agent", registry=registry
    )
    run_id = uuid4()
    tool_result = fake_send_email.invoke(
        {
            "to": "bob@example.com",
            "subject": "Project update",
            "body": "The approved project update is attached.",
        },
        config={
            "callbacks": [callback],
            "metadata": {"session_id": session_id},
            "run_id": run_id,
        },
    )
    poi = callback.get_poi(run_id)
    agent_public_key = callback._agent_private_key.public_key()  # Demo-only inspection.

    print("Tool result:", tool_result)
    print("Signed PoI:", json.dumps(poi.model_dump(), indent=2))
    print("PoI signature verified:", verify_poi_signature(poi, agent_public_key))


if __name__ == "__main__":
    main()
