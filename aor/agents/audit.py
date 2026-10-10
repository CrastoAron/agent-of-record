"""Read-only audit agent for AoR artifacts, traces, and replay evidence."""

from __future__ import annotations

import base64
import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

from crypto_core import hash_payload
from verification_portal.backend.evidence_store import ActionEvidenceStore
from verification_portal.backend.verify_pipeline import VerificationPipeline

from .base import ActionPlan, ActionResult, Agent


class AuditAgentError(ValueError):
    """Raised when an audit request is missing its read-only target."""


class AuditAgent(Agent):
    """Verify AoR evidence without mutating the ledger or workspace."""

    agent_type = "audit"
    capabilities = (
        "audit.verify_action",
        "audit.verify_eml",
        "audit.explain_failure",
        "audit.list_tampered",
        "audit.detect_replay",
        "audit.generate_report",
        "audit.compare_effect",
    )

    def __init__(
        self,
        pipeline: VerificationPipeline,
        evidence_store: ActionEvidenceStore | None = None,
        *,
        agent_id: str = "audit-agent",
    ) -> None:
        super().__init__(agent_id=agent_id)
        self._pipeline = pipeline
        self._evidence_store = evidence_store

    def can_handle(self, request: str) -> bool:
        if not request or not request.strip():
            return False
        return bool(re.search(r"\b(audit|verify|tamper|replay|ledger|proof|report)\b", request, re.IGNORECASE))

    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> ActionPlan:
        if not request or not request.strip():
            raise AuditAgentError("audit_request_empty")
        values = dict(context or {})
        action_type = values.get("action_type") or self._action_type_from_request(request)
        if action_type not in self.capabilities:
            raise AuditAgentError("audit_action_type_required")
        payload = dict(values.get("payload") or {})
        action_id = values.get("action_id") or self._extract_action_id(request)
        if action_type in {"audit.verify_action", "audit.explain_failure", "audit.generate_report", "audit.compare_effect"}:
            if not action_id:
                raise AuditAgentError("audit_action_id_required")
            payload["action_id"] = action_id
        if action_type == "audit.verify_eml" and "eml_bytes_b64" not in payload:
            raise AuditAgentError("audit_eml_required")
        return ActionPlan(
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            action_type=action_type,
            payload=payload,
            policy_decision="allow",
        )

    def execute(self, plan: ActionPlan, poi: Any) -> ActionResult:
        if plan.agent_type != self.agent_type:
            return self._failure("agent_type_mismatch")
        if plan.agent_id is not None and plan.agent_id != self.agent_id:
            return self._failure("agent_id_mismatch")
        if plan.action_type not in self.capabilities:
            return self._failure("unsupported_action_type")
        if plan.policy_decision != "allow":
            return self._failure("policy_decision_rejected")
        if poi is not None and hash_payload(plan.payload).hex() != getattr(poi, "action_payload_hash", None):
            return self._failure("action_payload_hash_mismatch")

        try:
            if plan.action_type in {"audit.verify_action", "audit.explain_failure", "audit.generate_report"}:
                trace = self._pipeline.run_verification(None, self._required_action_id(plan))
                report = self._markdown_report(trace)
                if plan.action_type == "audit.explain_failure":
                    details = {
                        "action_id": trace.action_id,
                        "failed_checks": [link.model_dump(mode="json") for link in trace.links if not link.passed],
                    }
                else:
                    details = {"trace": trace.model_dump(mode="json"), "report_markdown": report}
                return ActionResult(
                    success=trace.overall_valid,
                    artifact_ref=trace.action_id,
                    details=details,
                    observed_effect={"overall_valid": trace.overall_valid},
                )

            if plan.action_type == "audit.verify_eml":
                raw = base64.b64decode(self._required_string(plan.payload, "eml_bytes_b64"), validate=True)
                trace = self._pipeline.run_verification(raw, None)
                return ActionResult(
                    success=trace.overall_valid,
                    artifact_ref=trace.action_id,
                    details={"trace": trace.model_dump(mode="json"), "report_markdown": self._markdown_report(trace)},
                    observed_effect={"overall_valid": trace.overall_valid},
                )

            if plan.action_type == "audit.list_tampered":
                tampered = []
                for evidence in self._all_evidence():
                    trace = self._pipeline.run_verification(None, evidence.action_id)
                    failed = [link.link_name for link in trace.links if not link.passed and link.status == "failed"]
                    if failed:
                        tampered.append({"action_id": evidence.action_id, "failed_checks": failed})
                report = "# Agent-of-Record Tamper Report\n\n"
                report += "No tampered actions detected.\n" if not tampered else "".join(
                    f"- `{item['action_id']}` failed: {', '.join(item['failed_checks'])}\n" for item in tampered
                )
                return ActionResult(
                    success=True,
                    details={"actions": tampered, "report_markdown": report},
                    observed_effect={"count": len(tampered)},
                )

            if plan.action_type == "audit.detect_replay":
                nonces = [evidence.user_envelope.nonce for evidence in self._all_evidence()]
                duplicates = sorted(nonce for nonce, count in Counter(nonces).items() if count > 1)
                return ActionResult(success=True, details={"replayed_nonces": duplicates}, observed_effect={"count": len(duplicates)})

            if plan.action_type == "audit.compare_effect":
                observed = plan.payload.get("observed_effect")
                expected = plan.payload.get("expected_effect")
                if not isinstance(observed, dict) or not isinstance(expected, dict):
                    raise AuditAgentError("observed_and_expected_effect_required")
                mismatches = sorted(key for key in set(observed) | set(expected) if observed.get(key) != expected.get(key))
                return ActionResult(
                    success=not mismatches,
                    details={"mismatches": mismatches},
                    observed_effect={"compared": True},
                )
        except (AuditAgentError, ValueError, TypeError) as exc:
            return self._failure(str(exc))
        return self._failure("unsupported_action_type")

    def _all_evidence(self):
        if self._evidence_store is None:
            raise AuditAgentError("evidence_store_required")
        return self._evidence_store.all()

    @staticmethod
    def _required_action_id(plan: ActionPlan) -> str:
        return AuditAgent._required_string(plan.payload, "action_id")

    @staticmethod
    def _required_string(payload: Mapping[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise AuditAgentError(f"{key}_required")
        return value

    @staticmethod
    def _failure(detail: str) -> ActionResult:
        return ActionResult(success=False, details={"error": detail})

    @staticmethod
    def _action_type_from_request(request: str) -> str | None:
        lowered = request.lower()
        if "replay" in lowered or "nonce" in lowered:
            return "audit.detect_replay"
        if "tamper" in lowered or "changed" in lowered:
            return "audit.list_tampered"
        if "report" in lowered and re.search(r"\b(action[_ -]?id|id)\b", lowered):
            return "audit.generate_report"
        if "explain" in lowered or "failed" in lowered:
            return "audit.explain_failure"
        if re.search(r"\b(action[_ -]?id|id)\b", lowered):
            return "audit.verify_action"
        if "eml" in lowered or "email" in lowered:
            return "audit.verify_eml"
        if "audit" in lowered:
            return "audit.list_tampered"
        return "audit.verify_action"

    @staticmethod
    def _extract_action_id(request: str) -> str | None:
        match = re.search(r"(?:action[_ -]?id|id)\s*[:=]?\s*([\w@.<>:/-]+)", request, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _markdown_report(trace) -> str:
        lines = [
            "# Agent-of-Record Audit Report",
            "",
            f"- Action ID: `{trace.action_id or 'unknown'}`",
            f"- Overall valid: `{trace.overall_valid}`",
            "",
            "## Verification checks",
            "",
        ]
        for link in trace.links:
            lines.append(f"- **{link.link_name}** — `{link.status}` — {link.detail}")
        return "\n".join(lines) + "\n"
