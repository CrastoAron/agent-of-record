"""Common contracts shared by every Agent-of-Record agent.

Agents only plan and execute typed actions through this interface. The PoI,
policy, and executor layers remain responsible for cryptographic binding and
side-effect enforcement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ActionPlan(BaseModel):
    """A typed, serializable proposal produced by one specialized agent."""

    model_config = ConfigDict(extra="forbid")

    agent_type: str = Field(min_length=1)
    agent_id: str | None = Field(default=None, min_length=1)
    action_type: str = Field(min_length=1)
    payload: dict[str, Any]
    requires_confirmation: bool = False
    confirmed: bool = False
    policy_decision: str = "allow"

    @field_validator("payload")
    @classmethod
    def payload_must_be_a_dict(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError("payload must be a dictionary")
        return value

    @field_validator("policy_decision")
    @classmethod
    def policy_decision_must_be_nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("policy_decision cannot be empty")
        return value


class ActionResult(BaseModel):
    """The observed result of executing an approved action plan."""

    model_config = ConfigDict(extra="forbid")

    success: bool
    artifact_ref: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    observed_effect: dict[str, Any] = Field(default_factory=dict)


class Agent(ABC):
    """Base contract for a specialized AoR agent."""

    agent_type: str
    agent_id: str
    capabilities: tuple[str, ...] = ()

    def __init__(self, *, agent_id: str | None = None) -> None:
        if agent_id is not None:
            if not agent_id.strip():
                raise ValueError("agent_id must be a non-empty string")
            self.agent_id = agent_id
        if not getattr(self, "agent_type", "").strip():
            raise ValueError("agent_type must be a non-empty string")

    def can_handle(self, request: str) -> bool:
        """Return whether this agent can plan the natural-language request."""
        return bool(request and request.strip())

    @abstractmethod
    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> ActionPlan:
        """Convert a request into a validated typed action plan."""

    @abstractmethod
    def execute(self, plan: ActionPlan, poi: Any) -> ActionResult:
        """Execute an already-approved plan bound to a PoI."""


class AgentRegistry:
    """Registry of agents addressable by their stable agent type."""

    def __init__(self, agents: list[Agent] | None = None) -> None:
        self._agents: dict[str, Agent] = {}
        for agent in agents or []:
            self.register(agent)

    def register(self, agent: Agent) -> None:
        """Register an agent, rejecting duplicate agent types."""
        if not isinstance(agent, Agent):
            raise TypeError("agent must be an Agent instance")
        if agent.agent_type in self._agents:
            raise ValueError(f"agent_type already registered: {agent.agent_type}")
        self._agents[agent.agent_type] = agent

    def get(self, agent_type: str) -> Agent:
        """Return a registered agent or raise a clear lookup error."""
        try:
            return self._agents[agent_type]
        except KeyError as exc:
            raise KeyError(f"unknown agent_type: {agent_type}") from exc

    def list_agents(self) -> list[Agent]:
        """Return registered agents in registration order."""
        return list(self._agents.values())

    def types(self) -> tuple[str, ...]:
        """Return registered agent types in registration order."""
        return tuple(self._agents)
