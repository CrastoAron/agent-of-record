from __future__ import annotations

import pytest

from aor.agents.base import AgentRegistry
from aor.agents.database import DatabaseAgent
from aor.agents.email import EmailAgent
from aor.agents.file import FileAgent
from aor.agents.router import AgentRouter


def test_router_selects_email_agent() -> None:
    router = AgentRouter(AgentRegistry([EmailAgent()]))

    result = router.route("send an email to alice@example.com")

    assert result.handled is True
    assert result.steps[0].agent_type == "email"


def test_router_supports_chained_audit_then_file_request(tmp_path) -> None:
    class AuditStub(EmailAgent):
        agent_type = "audit"
        agent_id = "audit-agent"

        def can_handle(self, request: str) -> bool:
            return True

    router = AgentRouter(AgentRegistry([AuditStub(), FileAgent(tmp_path)]))

    result = router.route("audit the action then write report.md")

    assert result.handled is True
    assert [step.agent_type for step in result.steps] == ["audit", "file"]


def test_router_returns_clear_unknown_result_and_does_not_fallback(tmp_path) -> None:
    router = AgentRouter(AgentRegistry([FileAgent(tmp_path)]))

    result = router.route("translate this paragraph into French")

    assert result.handled is False
    assert result.reason == "no_agent_can_handle_request"
    with pytest.raises(ValueError, match="no_agent_can_handle_request"):
        router.plan("translate this paragraph into French")


def test_router_prioritizes_database_intent_over_create_keyword(tmp_path) -> None:
    router = AgentRouter(AgentRegistry([DatabaseAgent(workspace_dir=tmp_path), FileAgent(tmp_path)]))

    result = router.route("create a database named student")

    assert result.handled is True
    assert result.steps[0].agent_type == "database"
