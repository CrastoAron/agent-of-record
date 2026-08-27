"""Six-link forensic verification pipeline for Stage 8 AoR actions."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from action_executor.poi_encoding import decode_poi_header
from crypto_core import hash_payload, verify
from key_registry import KeyRegistry
from ledger_core import Ledger, LedgerEntry, build_merkle_tree, verify_merkle_proof
from poi_generator import verify_poi_signature
from poi_generator.models import ProofOfIntent
from tsa_anchor.anchor_scheduler import AnchorStore

from .eml_parser import parse_eml
from .evidence_store import ActionEvidence, ActionEvidenceStore
from .models import LinkResult, VerificationTrace
from .tsa_verify import verify_timestamp_token


def _load_public_key(key_bytes: bytes) -> Ed25519PublicKey | EllipticCurvePublicKey:
    try:
        parsed = serialization.load_der_public_key(key_bytes)
    except ValueError:
        if len(key_bytes) == 32:
            return Ed25519PublicKey.from_public_bytes(key_bytes)
        raise
    if not isinstance(parsed, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise ValueError("unsupported registered public key")
    return parsed


def _recomputed_entries(entries: list[LedgerEntry]) -> list[LedgerEntry]:
    """Rebuild leaves from live content without trusting stored leaf hashes.

    This is crucial for forensic checks: direct mutation of ``entry.content``
    leaves the Stage 2 stored digest untouched, but must still alter the root we
    recompute at verification time.
    """
    previous = b""
    recomputed: list[LedgerEntry] = []
    for entry in entries:
        leaf_hash = Ledger._compute_leaf_hash(entry.content, previous)
        recomputed.append(
            LedgerEntry(
                entry_id=entry.entry_id,
                entry_type=entry.entry_type,
                content=entry.content,
                timestamp=entry.timestamp,
                prev_hash=previous,
                leaf_hash=leaf_hash,
            )
        )
        previous = leaf_hash
    return recomputed


def _unavailable(link_name: str, detail: str) -> LinkResult:
    return LinkResult(link_name=link_name, passed=False, status="unavailable", detail=detail)


class VerificationPipeline:
    """Verify artifacts using injectable registry and captured-evidence stores."""

    def __init__(
        self,
        key_registry: KeyRegistry,
        evidence_store: ActionEvidenceStore,
        anchor_store: AnchorStore | None = None,
    ) -> None:
        self._key_registry = key_registry
        self._evidence_store = evidence_store
        self._anchor_store = anchor_store

    def run_verification(
        self, eml_bytes: bytes | None = None, action_id: str | None = None
    ) -> VerificationTrace:
        links: list[LinkResult] = []
        parsed: dict[str, Any] = {}
        poi: ProofOfIntent | None = None
        evidence: ActionEvidence | None = None

        # Step 1: parse/extract. An action-ID request reuses its saved artifact.
        # Parsing remains intentionally non-fatal.
        if action_id:
            evidence = self._evidence_store.get(action_id)
        if eml_bytes is not None:
            try:
                parsed = parse_eml(eml_bytes)
                action_id = action_id or parsed.get("action_id")
            except Exception as exc:  # malformed MIME is evidence, not a 500
                links.append(LinkResult(link_name="poi_extraction", passed=False, status="failed", detail=f"invalid .eml: {exc}"))
        if action_id:
            evidence = self._evidence_store.get(action_id)
        if eml_bytes is None and evidence is not None and evidence.eml_bytes is not None:
            try:
                parsed = parse_eml(evidence.eml_bytes)
            except Exception as exc:
                links.append(LinkResult(link_name="poi_extraction", passed=False, status="failed", detail=f"stored .eml is invalid: {exc}"))
        if not links:
            header = parsed.get("poi_header")
            if not header:
                links.append(LinkResult(link_name="poi_extraction", passed=False, status="failed", detail="X-AoR-Proof-of-Intent header is missing"))
            else:
                try:
                    poi = decode_poi_header(str(header))
                    links.append(LinkResult(link_name="poi_extraction", passed=True, detail="signed PoI decoded from email header"))
                except Exception as exc:
                    links.append(LinkResult(link_name="poi_extraction", passed=False, status="failed", detail=f"malformed PoI header: {exc}"))

        # Step 2: independently recompute every content commitment.
        recomputed_root: bytes | None = None
        recomputed_ledger_entries: list[LedgerEntry] = []
        if poi is None or evidence is None:
            missing = "PoI" if poi is None else "captured action evidence"
            links.append(_unavailable("hash_recomputation", f"unable to recompute hashes: {missing} unavailable"))
        else:
            mismatches: list[str] = []
            if hash_payload({"prompt": evidence.user_envelope.prompt}).hex() != poi.user_prompt_hash:
                mismatches.append("user_prompt_hash")
            if hash_payload({"system_prompt": evidence.system_prompt}).hex() != poi.system_prompt_hash:
                mismatches.append("system_prompt_hash")
            if eml_bytes is not None:
                action_payload = parsed.get("action_payload")
                if not isinstance(action_payload, dict) or hash_payload(action_payload).hex() != poi.action_payload_hash:
                    mismatches.append("action_payload_hash")
            else:
                # Action-ID verification uses the exact stored artifact when available.
                if evidence.eml_bytes is None:
                    mismatches.append("action_payload_hash (no stored .eml)")
                else:
                    try:
                        stored_payload = parse_eml(evidence.eml_bytes)["action_payload"]
                        if hash_payload(stored_payload).hex() != poi.action_payload_hash:
                            mismatches.append("action_payload_hash")
                    except Exception:
                        mismatches.append("action_payload_hash")
            live_entries = evidence.ledger.all_entries()[: evidence.ledger_entry_count_at_action]
            try:
                recomputed_ledger_entries = _recomputed_entries(live_entries)
                recomputed_root = build_merkle_tree(recomputed_ledger_entries).root()
                if recomputed_root.hex() != poi.context_root:
                    mismatches.append("context_root")
            except Exception as exc:
                mismatches.append(f"context_root ({exc})")
            if mismatches:
                links.append(LinkResult(link_name="hash_recomputation", passed=False, status="failed", detail="mismatched: " + ", ".join(mismatches)))
            else:
                links.append(LinkResult(link_name="hash_recomputation", passed=True, detail="user, system, context, and action hashes all match PoI"))

        # Step 3: resolve the currently valid agent key and verify its commitment.
        if poi is None:
            links.append(_unavailable("agent_signature", "unable to check: PoI unavailable"))
        else:
            agent_bytes = self._key_registry.get_pubkey(poi.agent_pubkey_id or "")
            if agent_bytes is None:
                links.append(LinkResult(link_name="agent_signature", passed=False, status="failed", detail="agent public key is unknown, expired, or currently revoked; this current trust failure alone does not prove the historical action was fraudulent"))
            else:
                try:
                    valid_agent_signature = verify_poi_signature(poi, _load_public_key(agent_bytes))
                except Exception as exc:
                    valid_agent_signature = False
                    agent_error = str(exc)
                else:
                    agent_error = ""
                links.append(LinkResult(link_name="agent_signature", passed=valid_agent_signature, status="passed" if valid_agent_signature else "failed", detail="agent signature verified" if valid_agent_signature else f"agent signature did not verify {agent_error}".strip()))

        # Step 4: verify the original browser signature captured at intake.
        if poi is None or evidence is None:
            links.append(_unavailable("user_signature", "unable to check: original signed envelope unavailable"))
        else:
            user_key_bytes = self._key_registry.get_pubkey(evidence.user_envelope.pubkey_id)
            if user_key_bytes is None:
                links.append(LinkResult(link_name="user_signature", passed=False, status="failed", detail="user public key is unknown, expired, or revoked"))
            else:
                try:
                    signature = base64.b64decode(evidence.user_envelope.signature, validate=True)
                    valid_user_signature = verify(_load_public_key(user_key_bytes), signature, hash_payload(evidence.user_envelope.signing_payload()))
                except (ValueError, TypeError, binascii.Error):
                    valid_user_signature = False
                links.append(LinkResult(link_name="user_signature", passed=valid_user_signature, status="passed" if valid_user_signature else "failed", detail="original user prompt signature verified" if valid_user_signature else "original user prompt signature did not verify"))

        # Step 5: prove an entry against the independently rebuilt ledger root.
        if poi is None or evidence is None or recomputed_root is None or not recomputed_ledger_entries:
            links.append(_unavailable("merkle_root_match", "unable to check: ledger evidence unavailable"))
        else:
            try:
                tree = build_merkle_tree(recomputed_ledger_entries)
                proof = tree.get_proof(recomputed_ledger_entries[0].entry_id)
                proof_valid = verify_merkle_proof(recomputed_ledger_entries[0].leaf_hash, proof, tree.root())
                chain_break = evidence.ledger.first_invalid_entry_id()
                valid_merkle = proof_valid and chain_break is None and recomputed_root.hex() == poi.context_root
                detail = "recomputed root matches signed PoI and ledger chain" if valid_merkle else (
                    f"recomputed context root {recomputed_root.hex()} != signed root {poi.context_root}" if recomputed_root.hex() != poi.context_root else f"ledger hash chain invalid at entry_id {chain_break}"
                )
                links.append(LinkResult(link_name="merkle_root_match", passed=valid_merkle, status="passed" if valid_merkle else "failed", detail=detail))
            except Exception as exc:
                links.append(LinkResult(link_name="merkle_root_match", passed=False, status="failed", detail=f"unable to verify Merkle proof: {exc}"))

        # Step 6: intentionally distinct pending state until Stage 9 adds RFC 3161.
        if evidence is None or recomputed_root is None:
            links.append(_unavailable("timestamp_anchor", "unable to check: ledger root unavailable"))
        else:
            timestamp_token = evidence.timestamp_token
            if timestamp_token is None and self._anchor_store is not None and poi is not None:
                # Look up the exact root signed at action time. Verification still
                # uses the freshly recomputed root, detecting later ledger edits.
                try:
                    signed_root = bytes.fromhex(poi.context_root)
                    anchored = self._anchor_store.latest_anchored(signed_root)
                    timestamp_token = anchored.token_bytes if anchored else None
                except ValueError:
                    timestamp_token = None
            timestamp_result = verify_timestamp_token(timestamp_token, recomputed_root)
            links.append(LinkResult(link_name="timestamp_anchor", passed=timestamp_result.pending or timestamp_result.verified, status="pending" if timestamp_result.pending else ("passed" if timestamp_result.verified else "failed"), detail=timestamp_result.detail))

        overall_valid = all(link.passed for link in links)
        return VerificationTrace(action_id=action_id, overall_valid=overall_valid, links=links, timestamp_verified=bool(links and links[-1].status == "passed"))


def run_verification(
    eml_bytes: bytes | None,
    action_id: str | None,
    *,
    key_registry: KeyRegistry,
    evidence_store: ActionEvidenceStore,
    anchor_store: AnchorStore | None = None,
) -> VerificationTrace:
    """Functional convenience entry point for callers that do not retain a pipeline."""
    return VerificationPipeline(key_registry, evidence_store, anchor_store).run_verification(eml_bytes, action_id)
