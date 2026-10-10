from __future__ import annotations

import pytest

from aor.agents.base import ActionPlan, ActionResult, Agent, AgentRegistry


class StubAgent(Agent):
    agent_type = "stub"
    agent_id = "stub-agent"
    capabilities = ("stub.run",)

    def plan(self, request: str, context=None) -> ActionPlan:
        return ActionPlan(
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            action_type="stub.run",
            payload={"request": request},
        )

    def execute(self, plan: ActionPlan, poi) -> ActionResult:
        return ActionResult(success=True, observed_effect=plan.payload)


def test_action_plan_and_result_are_typed_models() -> None:
    plan = StubAgent().plan("hello")
    result = StubAgent().execute(plan, None)

    assert plan.agent_type == "stub"
    assert plan.action_type == "stub.run"
    assert result.success is True
    assert result.observed_effect == {"request": "hello"}


def test_registry_registers_and_resolves_by_type() -> None:
    registry = AgentRegistry([StubAgent()])

    assert registry.get("stub").agent_id == "stub-agent"
    assert registry.types() == ("stub",)
    assert registry.list_agents()[0].agent_type == "stub"


def test_registry_rejects_duplicate_or_unknown_types() -> None:
    registry = AgentRegistry([StubAgent()])

    with pytest.raises(ValueError, match="already registered"):
        registry.register(StubAgent())
    with pytest.raises(KeyError, match="unknown agent_type"):
        registry.get("missing")
