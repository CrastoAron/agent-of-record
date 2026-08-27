"""In-memory orchestration fixture shared by Stage 10 tests and panel demo."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

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
from verifier_service.nonce_store import NonceStore
from verifier_service.verifier import SignatureVerifier, VerificationResult
from verification_portal.backend.eml_parser import parse_eml
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.models import VerificationTrace
from verification_portal.backend.verify_pipeline import VerificationPipeline
from tsa_anchor.anchor_scheduler import AnchorStore


SYSTEM_PROMPT = "Only send the exact email that the authenticated user requested."


@dataclass(frozen=True)
class SubmittedAction:
    stage4: VerificationResult
    trace: VerificationTrace | None
    envelope: SignedEnvelope
    poi_agent_key_id: str | None = None
    action_id: str | None = None
    eml_bytes: bytes | None = None
    context_entry_ids: tuple[int, ...] = ()


class FullPipeline:
    """A complete, local AoR pipeline with two users and two agent identities."""

    def __init__(self, work_dir: Path) -> None:
        self.ledger = Ledger()
        self.registry = KeyRegistry(SQLiteKeyStorage(work_dir / "keys.sqlite3"))
        self.evidence_store = ActionEvidenceStore()
        self.anchor_store = AnchorStore()
        self.stage4 = SignatureVerifier(self.registry, NonceStore())
        self.portal = VerificationPipeline(self.registry, self.evidence_store, self.anchor_store)
        self.executor = ActionExecutor(SMTPConfig(output_dir=work_dir / "outbox"))
        self.user_keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.agent_keys: dict[str, Ed25519PrivateKey] = {}
        self.agent_key_ids: dict[str, str] = {}
        self._register_users()
        self._register_agents()

    def _register_users(self) -> None:
        for user_id in ("u123", "u456"):
            private_key = ec.generate_private_key(ec.SECP256R1())
            key_id = f"{user_id}-p256"
            self.registry.register_key(
                user_id,
                key_id,
                private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                "ECDSA-P256-SHA256",
                datetime.now(timezone.utc),
            )
            self.user_keys[user_id] = private_key

    def _register_agents(self) -> None:
        for agent_name in ("primary", "secondary"):
            private_key = Ed25519PrivateKey.generate()
            key_id = agent_pubkey_id(private_key)
            self.registry.register_key(
                f"agent-{agent_name}",
                key_id,
                serialize_public_key_raw(private_key.public_key()),
                "Ed25519",
                datetime.now(timezone.utc),
            )
            self.agent_keys[agent_name] = private_key
            self.agent_key_ids[agent_name] = key_id

    @staticmethod
    def _sign_user_payload(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, str]) -> str:
        der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")

    def make_envelope(
        self,
        prompt: str,
        user_id: str = "u123",
        *,
        timestamp: datetime | None = None,
        nonce: str | None = None,
        private_key: ec.EllipticCurvePrivateKey | None = None,
        pubkey_id: str | None = None,
    ) -> SignedEnvelope:
        """Produce the same P-256 raw-signature envelope as the Stage 3 client."""
        signing_key = private_key or self.user_keys[user_id]
        payload = {
            "prompt": prompt,
            "user_id": user_id,
            "session_id": f"session-{user_id}",
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
            "nonce": nonce or str(uuid4()),
        }
        return SignedEnvelope(
            **payload,
            signature=self._sign_user_payload(signing_key, payload),
            pubkey_id=pubkey_id or f"{user_id}-p256",
        )

    def submit_envelope(
        self,
        envelope: SignedEnvelope,
        tool_call: dict[str, str],
        *,
        agent_name: str = "primary",
        context_before_action: list[tuple[str, dict[str, str]]] | None = None,
    ) -> SubmittedAction:
        """Run Stage 4 -> ledger -> PoI -> executor -> portal in this order."""
        stage4_result = self.stage4.verify_envelope(envelope)
        if not stage4_result.valid:
            return SubmittedAction(stage4_result, None, envelope)

        context_ids = [
            self.ledger.append("system_prompt", {"text": SYSTEM_PROMPT}).entry_id,
            self.ledger.append("user_prompt", {"text": envelope.prompt}).entry_id,
        ]
        for entry_type, content in context_before_action or []:
            context_ids.append(self.ledger.append(entry_type, content).entry_id)
        entry_count_at_action = len(self.ledger.all_entries())
        poi = sign_poi(
            build_poi(envelope.prompt, SYSTEM_PROMPT, self.ledger, tool_call, "e2e-demo-model"),
            self.agent_keys[agent_name],
        )
        execution = self.executor.execute_action("email", tool_call, poi)
        if not execution.success or not execution.action_id:
            raise AssertionError(f"valid PoI was not executed: {execution.detail}")
        eml_path = max(self.executor._smtp_config.output_dir.glob("*.eml"), key=lambda path: path.stat().st_mtime_ns)
        eml_bytes = eml_path.read_bytes()
        assert parse_eml(eml_bytes)["action_id"] == execution.action_id
        self.evidence_store.register(
            ActionEvidence(
                action_id=execution.action_id,
                user_envelope=envelope,
                system_prompt=SYSTEM_PROMPT,
                ledger=self.ledger,
                ledger_entry_count_at_action=entry_count_at_action,
                eml_bytes=eml_bytes,
            )
        )
        trace = self.portal.run_verification(eml_bytes)
        return SubmittedAction(
            stage4_result,
            trace,
            envelope,
            poi.agent_pubkey_id,
            execution.action_id,
            eml_bytes,
            tuple(context_ids),
        )

    def submit_and_verify(
        self, prompt: str, user_key: str, tool_call: dict[str, str]
    ) -> VerificationTrace:
        """Convenience requested by Stage 10; yields a portal trace on success."""
        submitted = self.submit_envelope(self.make_envelope(prompt, user_key), tool_call)
        if submitted.trace is None:
            raise AssertionError(f"Stage 4 rejected the envelope: {submitted.stage4.reason}")
        return submitted.trace

    def stale_envelope(self, prompt: str, user_id: str = "u123") -> SignedEnvelope:
        return self.make_envelope(prompt, user_id, timestamp=datetime.now(timezone.utc) - timedelta(seconds=61))
