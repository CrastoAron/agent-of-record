"""Backward-compatible facade for the deterministic AoR email agent."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aor.agents.base import ActionPlan
from aor.agents.email import AgentRuntimeError, EmailAction, EmailAgent


class AgentRuntime:
    """Compatibility boundary delegating behavior to ``EmailAgent``."""

    mode = "mock"

    def __init__(self, email_agent: EmailAgent | None = None) -> None:
        self.email_agent = email_agent or EmailAgent()

    def plan_email(
        self,
        prompt: str,
        *,
        history: list[dict[str, str]] | None = None,
    ) -> EmailAction:
        return self.email_agent.plan_email(prompt, history=history)

    def plan_action(
        self,
        prompt: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ActionPlan:
        return self.email_agent.plan(prompt, context)
