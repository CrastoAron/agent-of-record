"""Reserved Stage 7 extension point for signed trade/database action tokens."""

from __future__ import annotations

from typing import Any

from poi_generator.models import ProofOfIntent


def execute_jwt_action(action_type: str, action_payload: dict[str, Any], poi: ProofOfIntent) -> None:
    """Fail closed until a protocol-specific JWT policy is implemented."""
    raise NotImplementedError(f"{action_type} action execution is not implemented yet")
