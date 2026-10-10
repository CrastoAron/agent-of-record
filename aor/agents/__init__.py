"""Specialized agents for Agent-of-Record.

Specialized modules are intentionally imported directly so importing one agent
does not eagerly initialize unrelated executor integrations.
"""

from .base import ActionPlan, ActionResult, Agent, AgentRegistry

__all__ = ["ActionPlan", "ActionResult", "Agent", "AgentRegistry"]
