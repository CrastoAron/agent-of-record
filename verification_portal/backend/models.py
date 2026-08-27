"""Presentation-safe verification results for the AoR portal."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LinkResult(BaseModel):
    """The outcome of one independently checkable link in an AoR action."""

    link_name: str
    passed: bool
    detail: str
    # ``pending`` is deliberately not a failure: Stage 9 anchors periodically.
    status: str = "passed"


class VerificationTrace(BaseModel):
    """A complete, forensic trace returned even when individual checks fail."""

    action_id: str | None = None
    overall_valid: bool
    links: list[LinkResult] = Field(default_factory=list)
    timestamp_verified: bool = False
