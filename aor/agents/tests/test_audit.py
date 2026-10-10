from __future__ import annotations

from types import SimpleNamespace

from aor.agents.audit import AuditAgent
from crypto_core import hash_payload


class FakeLink:
    def __init__(self, name: str, passed: bool, status: str = "passed"):
        self.link_name = name
        self.passed = passed
        self.status = status
        self.detail = "ok" if passed else "tampered"

    def model_dump(self, mode="json"):
        return {"link_name": self.link_name, "passed": self.passed, "status": self.status, "detail": self.detail}


class FakeTrace:
    action_id = "action-1"
    overall_valid = False
    links = [FakeLink("action_payload_hash", False, "failed")]

    def model_dump(self, mode="json"):
        return {"action_id": self.action_id, "overall_valid": self.overall_valid, "links": [link.model_dump() for link in self.links]}


class FakePipeline:
    def run_verification(self, eml_bytes=None, action_id=None):
        return FakeTrace()


def test_audit_agent_returns_read_only_failure_explanation() -> None:
    agent = AuditAgent(FakePipeline())
    plan = agent.plan("explain failed action id action-1")
    plan = plan.model_copy(update={"payload": {"action_id": "action-1"}})
    poi = SimpleNamespace(action_payload_hash=hash_payload(plan.payload).hex())

    result = agent.execute(plan, poi)

    assert result.success is False
    assert result.details["failed_checks"][0]["link_name"] == "action_payload_hash"


def test_audit_agent_creates_report_without_writing() -> None:
    agent = AuditAgent(FakePipeline())
    plan = agent.plan("generate report for action id action-1")
    poi = SimpleNamespace(action_payload_hash=hash_payload(plan.payload).hex())

    result = agent.execute(plan, poi)

    assert "# Agent-of-Record Audit Report" in result.details["report_markdown"]
