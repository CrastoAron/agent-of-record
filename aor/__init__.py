"""Shared multi-agent orchestration primitives for Agent-of-Record."""

from .agents.base import ActionPlan, ActionResult, Agent, AgentRegistry

__all__ = ["ActionPlan", "ActionResult", "Agent", "AgentRegistry"]
