"""Build and sign compact Proof of Intent artifacts from existing AoR primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_core import canonicalize, hash_payload, hash_sha3_256, sign, verify
from ledger_core import Ledger, build_merkle_tree

from .agent_keys import agent_pubkey_id
from .models import ProofOfIntent


def _poi_signing_hash(poi: ProofOfIntent) -> bytes:
    """JCS canonicalize and SHA3-256 hash the exact agent-signed PoI fields."""
    return hash_sha3_256(canonicalize(poi.signing_payload()))


def build_poi(
    user_prompt: str,
    system_prompt: str,
    ledger: Ledger,
    action_payload: dict[str, Any],
    model_id: str,
) -> ProofOfIntent:
    """Create an unsigned PoI immediately before a tool invocation.

    A ledger with no context has no Merkle root in Stage 2 and therefore blocks
    PoI creation rather than inventing an empty-context sentinel.
    """
    if not user_prompt or not system_prompt or not model_id:
        raise ValueError("user_prompt, system_prompt, and model_id are required")
    if not isinstance(action_payload, dict):
        raise TypeError("action_payload must be a dictionary")
    context_root = build_merkle_tree(ledger.all_entries()).root()
    return ProofOfIntent(
        user_prompt_hash=hash_payload({"prompt": user_prompt}).hex(),
        system_prompt_hash=hash_payload({"system_prompt": system_prompt}).hex(),
        context_root=context_root.hex(),
        action_payload_hash=hash_payload(action_payload).hex(),
        model_id=model_id,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        nonce=str(uuid4()),
    )


def sign_poi(poi: ProofOfIntent, agent_private_key: Ed25519PrivateKey) -> ProofOfIntent:
    """Return a copy signed by the agent, binding its public key ID as well."""
    with_key_id = poi.model_copy(
        update={"agent_pubkey_id": agent_pubkey_id(agent_private_key), "agent_signature": None}
    )
    signature = sign(agent_private_key, _poi_signing_hash(with_key_id))
    return with_key_id.model_copy(update={"agent_signature": signature.hex()})


def verify_poi_signature(poi: ProofOfIntent, agent_public_key: Ed25519PublicKey) -> bool:
    """Verify a signed PoI independently of the LangChain callback/runtime."""
    if poi.agent_signature is None or poi.agent_pubkey_id is None:
        return False
    try:
        signature = bytes.fromhex(poi.agent_signature)
    except ValueError:
        return False
    return verify(agent_public_key, signature, _poi_signing_hash(poi))
