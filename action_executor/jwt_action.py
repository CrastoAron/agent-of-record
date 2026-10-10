"""Reserved Stage 7 extension point for signed trade/database action tokens."""

from __future__ import annotations

from typing import Any

from poi_generator.models import ProofOfIntent
from aor.agents.database import DatabaseAgent
from aor.agents.base import ActionResult


def execute_jwt_action(
    action_type: str,
    action_payload: dict[str, Any],
    poi: ProofOfIntent,
    *,
    database_agent: DatabaseAgent | None = None,
) -> ActionResult:
    """Execute only the read-only database action through a registered agent."""
    if action_type != "db":
        return ActionResult(success=False, details={"error": "unsupported_jwt_action_type"})
    if database_agent is None:
        return ActionResult(success=False, details={"error": "database_agent_required"})
    plan = database_agent.plan(
        "database query",
        {
            "database": action_payload.get("database"),
            "template": action_payload.get("template"),
            "params": action_payload.get("params", []),
        },
    )
    return database_agent.execute(plan, poi)
