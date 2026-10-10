"""Deterministic natural-language routing without direct execution."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .base import ActionPlan, AgentRegistry


class RouteStep(BaseModel):
    """One delegated request in a possibly chained route."""

    sequence: int = Field(ge=1)
    request: str = Field(min_length=1)
    agent_type: str | None = None
    agent_id: str | None = None
    reason: str | None = None


class RouteResult(BaseModel):
    """A routing-only result; it contains no execution result or side effect."""

    model_config = ConfigDict(extra="forbid")

    request: str
    handled: bool
    steps: list[RouteStep] = Field(default_factory=list)
    reason: str | None = None


class AgentRouter:
    """Choose registered specialized agents using fixed keyword rules."""

    _RULES = (
        ("audit", re.compile(r"\b(audit|verify|tamper|replay|proof|ledger)\b", re.IGNORECASE)),
        ("database", re.compile(r"\b(database|sqlite|query|records|table|sql)\b", re.IGNORECASE)),
        ("file", re.compile(r"\b(file|folder|directory|read|create|write|edit|update|rename|delete)\b", re.IGNORECASE)),
        ("email", re.compile(r"\b(send|email|mail|reply|forward)\b", re.IGNORECASE)),
    )

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def route(self, request: str) -> RouteResult:
        """Return one or more agent decisions without planning or executing."""
        if not request or not request.strip():
            return RouteResult(request=request, handled=False, reason="request_empty")
        segments = [segment.strip() for segment in re.split(r"\s+then\s+", request, flags=re.IGNORECASE) if segment.strip()]
        steps: list[RouteStep] = []
        for sequence, segment in enumerate(segments, start=1):
            agent = self._agent_for(segment)
            if agent is None:
                steps.append(RouteStep(sequence=sequence, request=segment, reason="no_agent_can_handle_request"))
            else:
                steps.append(RouteStep(sequence=sequence, request=segment, agent_type=agent.agent_type, agent_id=agent.agent_id))
        handled = bool(steps) and all(step.agent_type is not None for step in steps)
        return RouteResult(
            request=request,
            handled=handled,
            steps=steps,
            reason=None if handled else "no_agent_can_handle_request",
        )

    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> list[ActionPlan]:
        """Delegate planning to selected agents, never to an executor."""
        result = self.route(request)
        if not result.handled:
            raise ValueError(result.reason or "no_agent_can_handle_request")
        plans: list[ActionPlan] = []
        for step in result.steps:
            plans.append(self._registry.get(step.agent_type or "").plan(step.request, context))
        return plans

    def _agent_for(self, request: str):
        for agent_type, pattern in self._RULES:
            if pattern.search(request):
                # A file request can contain the word "database" as a filename;
                # require an actual database intent before selecting that agent.
                if agent_type == "database" and re.search(r"\b(file|folder|directory)\b", request, re.IGNORECASE):
                    continue
                try:
                    agent = self._registry.get(agent_type)
                except KeyError:
                    continue
                if agent.can_handle(request):
                    return agent
        return None
